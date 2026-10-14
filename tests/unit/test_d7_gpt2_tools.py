"""Unit coverage for the D7 real-GPT-2 tooling.

The frozen checkpoint is 548 MB and lives outside the repository, so the
hermetic cases build their own container and their own tiny "gpt2" layout and
exercise the reader, the slicing rules, the program geometry, the calibration
and the reference maths. The cases that need the real weights verify the source
when it is present and skip with a reason when it is not.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import numpy as np
import pytest

from client.gpt2_bpe import Gpt2BpeError, bytes_to_unicode, load_bpe
from infra.d7_vectors import (
    build_history_one_hot,
    build_run,
    encode_prompt,
    reference_step,
)
from model.calibration import (
    CalibrationError,
    calibrate_tensor,
    calibrate_tensors,
    layer_error_report,
    widest_safe_bits,
)
from model.export import export_arrays
from model.graph import convert_gpt2_graph, convert_tiny_decoder_graph
from model.gpt2 import (
    Gpt2Config,
    Gpt2Error,
    candidate_token_ids,
    candidate_vocabulary_digest,
    load_gpt2_weights,
    weight_tensor_names,
)
from model.safetensors import SafetensorsError, open_safetensors
from mpc.spu_backend.d7_program import (
    D7Config,
    D7ProgramError,
    build_gpt2_program,
    ir_name,
    program_inputs,
)


FROZEN_GPT2 = Path(__file__).resolve().parents[2] / "artifacts" / "gpt2-frozen"


def _write_safetensors(path: Path, tensors: dict[str, np.ndarray]) -> None:
    """Write a container the way the released tooling writes one."""
    header: dict[str, object] = {"__metadata__": {"format": "pt"}}
    offset = 0
    payload = bytearray()
    for name in sorted(tensors):
        array = np.ascontiguousarray(tensors[name])
        raw = array.tobytes(order="C")
        header[name] = {
            "dtype": "F64",
            "shape": list(array.shape),
            "data_offsets": [offset, offset + len(raw)],
        }
        offset += len(raw)
        payload.extend(raw)
    text = json.dumps(header, separators=(",", ":")).encode("utf-8")
    path.write_bytes(struct.pack("<Q", len(text)) + text + bytes(payload))


def _tiny_gpt2_tensors(config: Gpt2Config) -> dict[str, np.ndarray]:
    """A checkpoint laid out exactly like GPT-2's, with the pinned names."""
    rng = np.random.default_rng(20261013)
    d = config.n_embd
    inter = config.intermediate_size
    tensors: dict[str, np.ndarray] = {
        "wte.weight": rng.standard_normal((config.vocab_size, d)) * 0.02,
        "wpe.weight": rng.standard_normal((config.n_positions, d)) * 0.01,
        "ln_f.weight": np.ones(d),
        "ln_f.bias": np.zeros(d),
    }
    for index in range(config.n_layer):
        prefix = f"h.{index}."
        tensors[prefix + "attn.c_attn.weight"] = rng.standard_normal((d, 3 * d)) * 0.02
        tensors[prefix + "attn.c_attn.bias"] = rng.standard_normal(3 * d) * 0.01
        tensors[prefix + "attn.c_proj.weight"] = rng.standard_normal((d, d)) * 0.02
        tensors[prefix + "attn.c_proj.bias"] = np.zeros(d)
        tensors[prefix + "ln_1.weight"] = np.ones(d)
        tensors[prefix + "ln_1.bias"] = np.zeros(d)
        tensors[prefix + "ln_2.weight"] = np.ones(d)
        tensors[prefix + "ln_2.bias"] = np.zeros(d)
        tensors[prefix + "mlp.c_fc.weight"] = rng.standard_normal((d, inter)) * 0.02
        tensors[prefix + "mlp.c_fc.bias"] = np.zeros(inter)
        tensors[prefix + "mlp.c_proj.weight"] = rng.standard_normal((inter, d)) * 0.02
        tensors[prefix + "mlp.c_proj.bias"] = np.zeros(d)
    return tensors


def _tiny_config() -> Gpt2Config:
    return Gpt2Config(
        vocab_size=32,
        n_positions=16,
        n_ctx=16,
        n_embd=8,
        n_head=2,
        n_layer=2,
        layer_norm_epsilon=1e-5,
        activation_function="gelu_new",
        bos_token_id=31,
        eos_token_id=31,
    )


def test_safetensors_reader_round_trips_and_refuses_damage(tmp_path: Path) -> None:
    path = tmp_path / "model.safetensors"
    tensors = {"a": np.arange(6, dtype=np.float64).reshape(2, 3), "b": np.ones(4)}
    _write_safetensors(path, tensors)
    store = open_safetensors(path)
    assert store.names == ("a", "b")
    assert np.array_equal(store.read("a"), tensors["a"])
    assert store.shapes()["a"] == [2, 3]
    assert store.metadata == {"format": "pt"}

    truncated = tmp_path / "short.safetensors"
    truncated.write_bytes(b"\x00\x01")
    with pytest.raises(SafetensorsError, match="too short"):
        open_safetensors(truncated)

    damaged = tmp_path / "damaged.safetensors"
    raw = bytearray(path.read_bytes())
    struct.pack_into("<Q", raw, 0, 1 << 40)
    damaged.write_bytes(bytes(raw))
    with pytest.raises(SafetensorsError, match="out of range"):
        open_safetensors(damaged)


def test_gpt2_weight_slicing_splits_the_fused_projection(tmp_path: Path) -> None:
    config = _tiny_config()
    store_path = tmp_path / "model.safetensors"
    source = _tiny_gpt2_tensors(config)
    _write_safetensors(store_path, source)
    store = open_safetensors(store_path)
    run = build_run(
        config,
        model_version="tiny-gpt2",
        sequence=4,
        layers=2,
        candidate_size=8,
        required_tokens=(17,),
    )
    weights = load_gpt2_weights(
        store,
        config,
        layers=run.layers,
        token_ids=run.candidate_tokens,
        sequence=run.sequence,
    )
    assert tuple(sorted(weights)) == tuple(sorted(weight_tensor_names(2)))
    fused = source["h.0.attn.c_attn.weight"]
    assert np.array_equal(
        weights["layer_0.attn.q.weight"], np.ascontiguousarray(fused[:, : config.n_embd])
    )
    assert np.array_equal(
        weights["layer_0.attn.v.weight"],
        np.ascontiguousarray(fused[:, 2 * config.n_embd :]),
    )
    # GPT-2 ties the output projection to the input embedding.
    rows = np.asarray(list(run.candidate_tokens), dtype=np.int64)
    assert np.array_equal(
        weights["lm_head.weight"],
        np.ascontiguousarray(source["wte.weight"][rows].transpose(1, 0)),
    )
    assert np.array_equal(
        weights["position_embedding.weight"], source["wpe.weight"][:4]
    )
    assert np.array_equal(
        weights["token_embedding.weight"], source["wte.weight"][rows]
    )
    assert weights["lm_head.bias"].shape == (len(run.candidate_tokens),)
    assert not weights["lm_head.bias"].any()

    with pytest.raises(Gpt2Error, match="layer range"):
        load_gpt2_weights(
            store, config, layers=3, token_ids=(0,), sequence=4
        )


def test_candidate_set_rule_is_public_and_ordered() -> None:
    assert candidate_token_ids(5) == (0, 1, 2, 3, 4)
    assert candidate_token_ids(3, required=(9, 1)) == (0, 1, 2, 9)
    with pytest.raises(Gpt2Error, match="outside the vocabulary"):
        candidate_token_ids(3, required=(99,), vocab_size=10)
    digest = candidate_vocabulary_digest((0, 1, 2))
    assert digest == candidate_vocabulary_digest([0, 1, 2])
    with pytest.raises(Gpt2Error, match="ascending"):
        candidate_vocabulary_digest((2, 1))


def test_program_interface_matches_the_manifest_tensor_names() -> None:
    config = D7Config(sequence=4, layers=2, hidden_size=8, num_heads=2,
                      intermediate_size=16, vocab_size=6)
    specs = program_inputs(config)
    names = tuple(spec.name for spec in specs)
    assert names[0] == "history"
    assert names[1:] == weight_tensor_names(2)
    assert dict(zip(names, (spec.shape for spec in specs)))["history"] == (4, 6)

    program = build_gpt2_program(config)
    assert program.input_names == names
    assert program.output_names == ("hidden", "logits", "token")
    assert "history" not in {spec.name for spec in program.inputs if spec.name != "history"}
    # The runtime binds each share with ``SetVar`` on the manifest key, so the IR
    # parameter has to keep the manifest spelling, dots and all.
    assert ir_name("layer_0.attn.q.weight") == "%layer_0.attn.q.weight"
    assert all(name in program.text for name in ("%history", "%layer_0.attn.q.weight"))
    assert "mhlo.tanh" in program.text
    assert program.text.count("mhlo.rsqrt") == 2 * 2 + 1

    with pytest.raises(D7ProgramError, match="decode_row"):
        build_gpt2_program(config, decode_row=9)
    sliced = build_gpt2_program(config, decode_row=1)
    assert "start_indices = dense<[1, 0]>" in sliced.text


def test_graph_conversion_is_deterministic_and_versioned() -> None:
    graph = convert_gpt2_graph(
        num_layers=12, hidden_size=768, num_heads=12, intermediate_size=3072,
        vocab_size=1024,
    )
    again = convert_gpt2_graph(
        num_layers=12, hidden_size=768, num_heads=12, intermediate_size=3072,
        vocab_size=1024,
    )
    assert graph.digest() == again.digest()
    assert graph.graph_version == "a122-gpt2-decoder-graph-v1"
    assert graph.nodes[-1].op == "secure_argmax"
    assert len(graph.nodes) == 3 + 12 * 10 + 3
    assert dict(graph.nodes[-2].attrs)["vocab_size"] == 1024
    tiny = convert_tiny_decoder_graph(
        num_layers=2, hidden_size=8, num_heads=2, intermediate_size=16
    )
    assert tiny.graph_version == "a122-tiny-decoder-graph-v1"
    assert tiny.digest() != graph.digest()


def test_calibration_picks_the_narrowest_width_that_meets_the_bound() -> None:
    values = np.array([1.0, -0.1, 1.0 / 3.0], dtype=np.float64)
    coarse = calibrate_tensor("w", values, error_bound=0.5)
    fine = calibrate_tensor("w", values, error_bound=1e-6)
    assert coarse.fractional_bits < fine.fractional_bits
    assert coarse.max_abs_error <= 0.5
    assert fine.max_abs_error <= 1e-6
    # A unit-scale tensor is capped by the plan's own ceiling; a tensor whose
    # peak is already near the ring's edge is capped by the ring instead.
    assert widest_safe_bits(1.0) == 30
    assert widest_safe_bits(2.0**40) == 21
    assert widest_safe_bits(0.0) == 30

    plan, records = calibrate_tensors(
        {"a": values, "b": values * 2.0}, plan_id="calibration-case", error_bound=1e-4
    )
    assert plan["scales"]["a"] == records[0].fractional_bits
    assert plan["error_thresholds"]["max_abs_error"] == 1e-4
    with pytest.raises(CalibrationError):
        calibrate_tensor("w", np.array([np.inf]), error_bound=1.0)
    with pytest.raises(CalibrationError, match="missing"):
        layer_error_report(exact={"a": values}, quantized={})


def test_export_arrays_is_deterministic_and_matches_the_torch_path() -> None:
    torch = pytest.importorskip("torch")
    arrays = {"b": np.arange(3, dtype=np.float64), "a": np.ones((2, 2), dtype=np.float64)}
    first = export_arrays(arrays, model_version="v1")
    second = export_arrays(dict(reversed(list(arrays.items()))), model_version="v1")
    assert first.model_hash == second.model_hash
    assert first.payload == second.payload

    class Module(torch.nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.weight = torch.nn.Parameter(torch.arange(4, dtype=torch.float32))

    state = {"weight": Module().weight, "matrix": torch.ones(2, 3)}
    bundle = export_arrays(state, model_version="torch-v1")
    assert [tensor.dtype for tensor in bundle.tensors] == ["float32", "float32"]
    assert [tensor.shape for tensor in bundle.tensors] == [(2, 3), (4,)]
    assert [tensor.name for tensor in bundle.tensors] == ["matrix", "weight"]


def test_reference_step_matches_a_hand_computed_single_layer(tmp_path: Path) -> None:
    config = _tiny_config()
    store_path = tmp_path / "model.safetensors"
    _write_safetensors(store_path, _tiny_gpt2_tensors(config))
    store = open_safetensors(store_path)
    run = build_run(
        config, model_version="tiny-gpt2", sequence=4, layers=1, candidate_size=6
    )
    weights = load_gpt2_weights(
        store, config, layers=1, token_ids=run.candidate_tokens, sequence=4
    )
    d7 = D7Config(sequence=4, layers=1, hidden_size=8, num_heads=2,
                  intermediate_size=16, vocab_size=run.vocab_size)
    indices = encode_prompt(run, (0, 1))
    result = reference_step(indices, weights, d7)
    assert result["logits"].shape == (4, run.vocab_size)
    assert result["decode_row"] == 1
    assert int(result["token"][0]) == int(np.argmax(result["logits"][1]))

    # The padding rows sit behind the decode row and the causal mask removes
    # them, so what is behind the history cannot change the answer.
    shifted = reference_step(indices, weights, d7)
    assert np.allclose(result["logits"][1], shifted["logits"][1])
    with pytest.raises(Exception):
        encode_prompt(run, (500,))
    matrix = build_history_one_hot(indices, sequence=4, vocab_size=run.vocab_size)
    assert matrix[0, indices[0]] == 1.0 and matrix[1, indices[1]] == 1.0
    # The unused rows behind the decode row carry the pad index, which is a
    # real token id rather than an all-zero row, and they are unreachable from
    # every row the step reads.
    assert np.array_equal(matrix[2:].sum(axis=1), np.ones(2))


def test_gpt2_bpe_matches_the_released_tokenizer_on_a_pinned_corpus() -> None:
    if not (FROZEN_GPT2 / "vocab.json").is_file():
        pytest.skip("the frozen GPT-2 tokenizer is not present")
    encoder = load_bpe(FROZEN_GPT2)
    assert encoder.vocab_size == 50257
    assert encoder.encode("the cipher key is secret") == [1169, 38012, 1994, 318, 3200]
    assert encoder.decode([1169, 38012, 1994, 318, 3200]) == "the cipher key is secret"
    assert encoder.encode(" Hello, world!") == [18435, 11, 995, 0]
    assert bytes_to_unicode()[33] == "!"
    with pytest.raises(Gpt2BpeError, match="no tokenizable bytes"):
        encoder.encode("")

    transformers = pytest.importorskip("transformers")
    released = transformers.GPT2TokenizerFast.from_pretrained(
        str(FROZEN_GPT2), local_files_only=True
    )
    for text in (
        "the cipher key is secret",
        "  double  spaces ",
        "numbers 12345 and 3.14159",
        "Caf\u00e9 na\u00efve \u4e2d\u6587",
        "don't stop, won't stop",
        "_under_score_",
        "\t\ttabs\n\nnewlines",
        "R\u00e9sum\u00e9: \u201cquoted\u201d",
    ):
        assert encoder.encode(text) == released.encode(text), text


def test_frozen_source_verifies_and_runs_the_whole_pipeline(tmp_path: Path) -> None:
    if not (FROZEN_GPT2 / "model.safetensors").is_file():
        pytest.skip("the frozen GPT-2 checkpoint is not present")
    from model.gpt2 import load_config, require_gpt2_source, tokenizer_sha256

    record = require_gpt2_source(FROZEN_GPT2)
    assert record["verified"] is True
    assert record["revision"] == "607a30d783dfa663caf39e06633721c8d4cfcd7e"
    assert len(tokenizer_sha256(FROZEN_GPT2)) == 64
    config = load_config(FROZEN_GPT2)
    assert (config.n_layer, config.n_embd, config.n_head) == (12, 768, 12)

    from model.export import export_gpt2_run

    result = export_gpt2_run(
        source_directory=FROZEN_GPT2,
        output_directory=tmp_path / "run",
        model_version="gpt2-small-d7-test",
        layers=1,
        sequence=8,
        candidate_size=64,
        prompt="the cipher key is secret",
    )
    assert result["vocab_size"] > 64
    assert result["elements"] == sum(
        int(np.prod(tensor.shape))
        for tensor in __import__("model.export", fromlist=["x"]).load_model_bundle(
            tmp_path / "run" / "model" / "model.json"
        ).tensors
    )
    plan = json.loads((tmp_path / "run" / "precision_plan.json").read_text())
    manifest = json.loads((tmp_path / "run" / "model-manifest.json").read_text())
    from contracts import canonical_hash

    assert canonical_hash(plan) == manifest["precision_plan_hash"]
    assert manifest["tokenizer_hash"] == tokenizer_sha256(FROZEN_GPT2)
    freeze = json.loads((tmp_path / "run" / "source-freeze.json").read_text())
    assert freeze["verified"] is True
    assert all(entry["verified"] for entry in freeze["files"])
