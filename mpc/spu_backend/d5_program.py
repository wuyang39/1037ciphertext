"""D5 secure Transformer-block programs compiled by the real SPU runtime.

The D4 program covered the six arithmetic operators the RSS grid already had.
D5 adds the non-linear operators a decoder block needs and expresses all of
them in MHLO, so they run through the same SecretFlow-SPU 0.9.5 front end and
the same YACL/BRPC link the D4 acceptance proved. Nothing here reveals a share:
Softmax, LayerNorm, GELU and Argmax are built from the SPU protocol operators
(``mhlo.exponential``, ``mhlo.rsqrt``, ``mhlo.tanh``, ``mhlo.reduce``, compare
and select), which the three parties evaluate over their shares.

Several MHLO ops carry no custom assembly form in this front end and must be
written in the generic form; ``transpose``, ``broadcast_in_dim``, ``slice``,
``select``, ``concatenate`` and the ``reduce`` region all fall in that group.
The op set below was confirmed against the shipped ``libspu.so`` on the
acceptance instances rather than taken from the upstream documentation.

Only the *shape* of a program is baked into the IR text; the secret inputs
arrive as shares at run time. The one data-dependent constant, the causal
attention mask, is a public 0/1 pattern rather than a value.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Sequence


FXP_FRACTION_BITS = 18
"""Fractional bits the D5 runtime config pins; it must match the node config."""

LAYERNORM_EPSILON = 1e-5
GELU_TANH_C1 = math.sqrt(2.0 / math.pi)
GELU_TANH_C2 = 0.044715


class D5ProgramError(ValueError):
    """A D5 program cannot be built for the requested shape."""


def _type_of(shape: Sequence[int]) -> str:
    if not shape:
        return "tensor<f64>"
    return "tensor<" + "x".join(str(int(size)) for size in shape) + "xf64>"


@dataclass(frozen=True)
class TensorSpec:
    """One named secret tensor entering or leaving a program."""

    name: str
    shape: tuple[int, ...]

    def __post_init__(self) -> None:
        if not self.name:
            raise D5ProgramError("a tensor spec needs a name")
        if any(int(size) <= 0 for size in self.shape):
            raise D5ProgramError(f"{self.name} has a non-positive dimension")

    @property
    def type(self) -> str:
        return _type_of(self.shape)


@dataclass(frozen=True)
class SpuProgram:
    """One compiled-at-run-time MHLO program and its typed interface."""

    name: str
    text: str
    inputs: tuple[TensorSpec, ...]
    outputs: tuple[TensorSpec, ...]

    @property
    def input_names(self) -> tuple[str, ...]:
        return tuple(spec.name for spec in self.inputs)

    @property
    def output_names(self) -> tuple[str, ...]:
        return tuple(spec.name for spec in self.outputs)

    def compile(self, libspu: Any) -> bytes:
        source_ir = getattr(libspu, "STABLEHLO", None)
        if source_ir is None:
            raise D5ProgramError("libspu does not expose the STABLEHLO IR type")
        source = libspu.CompilationSource(
            ir_type=source_ir,
            ir_txt=self.text.encode("utf-8"),
            input_visibility=[libspu.VIS_SECRET] * len(self.inputs),
        )
        try:
            return libspu.compile(source, libspu.CompilerOptions())
        except Exception as exc:  # pragma: no cover - reported by the node
            raise D5ProgramError(
                f"the SPU compiler rejected program {self.name}: {exc}"
            ) from exc

    def executable(self, libspu: Any) -> Any:
        return libspu.Executable(
            name=self.name,
            input_names=list(self.input_names),
            output_names=list(self.output_names),
            code=self.compile(libspu),
        )


class _Emitter:
    """Tiny SSA helper so the IR text stays readable."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self._counter = 0

    def name(self, prefix: str = "v") -> str:
        self._counter += 1
        return f"%{prefix}{self._counter}"

    def raw(self, text: str) -> None:
        self.lines.append(text)

    def assign(self, prefix: str, text: str) -> str:
        name = self.name(prefix)
        self.lines.append(f"  {name} = {text}")
        return name


def _literal(value: Any) -> str:
    """Render a float the MLIR dense parser accepts.

    The parser rejects scientific notation in this front end, so small values
    such as the LayerNorm epsilon are written out in plain decimal.
    """
    number = float(value)
    text = repr(number)
    if "e" in text or "E" in text:
        text = f"{number:.12f}".rstrip("0")
        if text.endswith("."):
            text += "0"
    if "." not in text:
        text += ".0"
    return text


def _dims(dimensions: Sequence[int]) -> str:
    if not dimensions:
        # An empty dense list is not a legal literal; the scalar broadcast uses
        # the bare form ``dense<>``.
        return "dense<>"
    return "dense<[" + ", ".join(str(int(value)) for value in dimensions) + "]>"


def _broadcast(
    emitter: _Emitter,
    operand: str,
    source_type: str,
    result_type: str,
    dimensions: Sequence[int],
) -> str:
    rank = len(dimensions)
    return emitter.assign(
        "bc",
        f"\"mhlo.broadcast_in_dim\"({operand}) {{broadcast_dimensions = "
        f"{_dims(dimensions)} : tensor<{rank}xi64>}} : ({source_type}) -> {result_type}",
    )


def _reduce(
    emitter: _Emitter,
    operand: str,
    operand_type: str,
    result_type: str,
    init: float,
    inner_op: str,
    axis: int,
) -> str:
    scalar = "tensor<f64>"
    init_name = emitter.assign(
        "in", f"mhlo.constant dense<{_literal(init)}> : {scalar}"
    )
    name = emitter.name("rd")
    emitter.raw(
        f"  {name} = \"mhlo.reduce\"({operand}, {init_name}) ({{\n"
        f"  ^bb0(%ra: {scalar}, %rb: {scalar}):\n"
        f"    %rc = {inner_op} %ra, %rb : {scalar}\n"
        f"    \"mhlo.return\"(%rc) : ({scalar}) -> ()\n"
        f"  }}) {{dimensions = dense<[{int(axis)}]> : tensor<1xi64>}} : "
        f"({operand_type}, {scalar}) -> {result_type}"
    )
    return name


def _function(
    emitter: _Emitter,
    inputs: Sequence[TensorSpec],
    outputs: Sequence[TensorSpec],
    returns: Sequence[str],
) -> str:
    signature = ", ".join(f"%{spec.name}: {spec.type}" for spec in inputs)
    types = ", ".join(spec.type for spec in outputs)
    returned = ", ".join(returns)
    return (
        f"func.func @main({signature}) -> ({types}) {{\n"
        f"{chr(10).join(emitter.lines)}\n"
        f"  return {returned} : {types}\n"
        "}\n"
    )


def build_softmax_program(rows: int, cols: int) -> SpuProgram:
    """Row-wise Softmax over the last axis of a ``rows x cols`` matrix."""
    if rows < 1 or cols < 1:
        raise D5ProgramError("softmax dimensions must be positive")
    matrix = _type_of((rows, cols))
    vector = _type_of((rows,))
    emitter = _Emitter()
    maximum = _reduce(emitter, "%scores", matrix, vector, -1e9, "mhlo.maximum", 1)
    maximum_b = _broadcast(emitter, maximum, vector, matrix, [0])
    shifted = emitter.assign("sh", f"mhlo.subtract %scores, {maximum_b} : {matrix}")
    exponentials = emitter.assign("ex", f"mhlo.exponential {shifted} : {matrix}")
    denominator = _reduce(emitter, exponentials, matrix, vector, 0.0, "mhlo.add", 1)
    denominator_b = _broadcast(emitter, denominator, vector, matrix, [0])
    result = emitter.assign(
        "sm", f"mhlo.divide {exponentials}, {denominator_b} : {matrix}"
    )
    inputs = (TensorSpec("scores", (rows, cols)),)
    outputs = (TensorSpec("probs", (rows, cols)),)
    return SpuProgram(
        name="softmax",
        text=_function(emitter, inputs, outputs, [result]),
        inputs=inputs,
        outputs=outputs,
    )


def build_layernorm_program(rows: int, cols: int) -> SpuProgram:
    """LayerNorm over the last axis with secret gamma and beta."""
    if rows < 1 or cols < 1:
        raise D5ProgramError("layernorm dimensions must be positive")
    matrix = _type_of((rows, cols))
    vector = _type_of((rows,))
    emitter = _Emitter()
    total = _reduce(emitter, "%h", matrix, vector, 0.0, "mhlo.add", 1)
    inverse_count = emitter.assign(
        "ic", f"mhlo.constant dense<{_literal(1.0 / float(cols))}> : {vector}"
    )
    mean = emitter.assign("mn", f"mhlo.multiply {total}, {inverse_count} : {vector}")
    mean_b = _broadcast(emitter, mean, vector, matrix, [0])
    centered = emitter.assign("ct", f"mhlo.subtract %h, {mean_b} : {matrix}")
    squared = emitter.assign("sq", f"mhlo.multiply {centered}, {centered} : {matrix}")
    var_total = _reduce(emitter, squared, matrix, vector, 0.0, "mhlo.add", 1)
    variance = emitter.assign(
        "vr", f"mhlo.multiply {var_total}, {inverse_count} : {vector}"
    )
    epsilon = emitter.assign(
        "ep", f"mhlo.constant dense<{_literal(LAYERNORM_EPSILON)}> : {vector}"
    )
    shifted_variance = emitter.assign("sv", f"mhlo.add {variance}, {epsilon} : {vector}")
    inverse_std = emitter.assign("is", f"mhlo.rsqrt {shifted_variance} : {vector}")
    inverse_std_b = _broadcast(emitter, inverse_std, vector, matrix, [0])
    scaled = emitter.assign("sc", f"mhlo.multiply {centered}, {inverse_std_b} : {matrix}")
    gamma_b = _broadcast(emitter, "%gamma", _type_of((cols,)), matrix, [1])
    beta_b = _broadcast(emitter, "%beta", _type_of((cols,)), matrix, [1])
    scaled_gamma = emitter.assign("sg", f"mhlo.multiply {scaled}, {gamma_b} : {matrix}")
    normalized = emitter.assign("ln", f"mhlo.add {scaled_gamma}, {beta_b} : {matrix}")
    inputs = (
        TensorSpec("h", (rows, cols)),
        TensorSpec("gamma", (cols,)),
        TensorSpec("beta", (cols,)),
    )
    outputs = (TensorSpec("norm", (rows, cols)),)
    return SpuProgram(
        name="layernorm",
        text=_function(emitter, inputs, outputs, [normalized]),
        inputs=inputs,
        outputs=outputs,
    )


def build_gelu_program(rows: int, cols: int) -> SpuProgram:
    """GELU in the tanh form, the variant SPU can evaluate on shares."""
    if rows < 1 or cols < 1:
        raise D5ProgramError("gelu dimensions must be positive")
    matrix = _type_of((rows, cols))
    emitter = _Emitter()
    square = emitter.assign("x2", f"mhlo.multiply %x, %x : {matrix}")
    cube = emitter.assign("x3", f"mhlo.multiply {square}, %x : {matrix}")
    c2 = emitter.assign("c2", f"mhlo.constant dense<{_literal(GELU_TANH_C2)}> : {matrix}")
    inner2 = emitter.assign("i2", f"mhlo.multiply {c2}, {cube} : {matrix}")
    inner = emitter.assign("i1", f"mhlo.add %x, {inner2} : {matrix}")
    c1 = emitter.assign("c1", f"mhlo.constant dense<{_literal(GELU_TANH_C1)}> : {matrix}")
    argument = emitter.assign("ar", f"mhlo.multiply {c1}, {inner} : {matrix}")
    tanh_argument = emitter.assign("th", f"mhlo.tanh {argument} : {matrix}")
    one = emitter.assign("on", f"mhlo.constant dense<1.0> : {matrix}")
    raised = emitter.assign("ra", f"mhlo.add {one}, {tanh_argument} : {matrix}")
    product = emitter.assign("pr", f"mhlo.multiply %x, {raised} : {matrix}")
    half = emitter.assign("hf", f"mhlo.constant dense<0.5> : {matrix}")
    result = emitter.assign("gl", f"mhlo.multiply {half}, {product} : {matrix}")
    inputs = (TensorSpec("x", (rows, cols)),)
    outputs = (TensorSpec("y", (rows, cols)),)
    return SpuProgram(
        name="gelu",
        text=_function(emitter, inputs, outputs, [result]),
        inputs=inputs,
        outputs=outputs,
    )


def build_argmax_program(vocab: int) -> SpuProgram:
    """Secure Argmax: the smallest index attaining the maximum logit.

    Every position that does not attain the maximum is replaced by a sentinel
    larger than any index, and the minimum over the vector is the answer. Only
    the reconstructing party learns the index.
    """
    if vocab < 1:
        raise D5ProgramError("argmax vocabulary must be positive")
    vector = _type_of((vocab,))
    scalar = "tensor<f64>"
    one = "tensor<1xf64>"
    emitter = _Emitter()
    maximum = _reduce(emitter, "%logits", vector, scalar, -1e9, "mhlo.maximum", 0)
    maximum_b = _broadcast(emitter, maximum, scalar, vector, [])
    is_max = emitter.assign(
        "mx",
        f"mhlo.compare GE, %logits, {maximum_b} : ({vector}, {vector}) -> "
        f"tensor<{vocab}xi1>",
    )
    indices = emitter.assign(
        "ix",
        "mhlo.constant dense<["
        + ", ".join(_literal(index) for index in range(vocab))
        + f"]> : {vector}",
    )
    sentinel = emitter.assign(
        "sn", f"mhlo.constant dense<{_literal(vocab)}> : {vector}"
    )
    candidates = emitter.assign(
        "cd",
        f"\"mhlo.select\"({is_max}, {indices}, {sentinel}) : "
        f"(tensor<{vocab}xi1>, {vector}, {vector}) -> {vector}",
    )
    chosen = _reduce(emitter, candidates, vector, scalar, 1e9, "mhlo.minimum", 0)
    result = emitter.assign(
        "tf",
        f"\"mhlo.broadcast_in_dim\"({chosen}) {{broadcast_dimensions = "
        f"dense<[]> : tensor<0xi64>}} : ({scalar}) -> {one}",
    )
    inputs = (TensorSpec("logits", (vocab,)),)
    outputs = (TensorSpec("index", (1,)),)
    return SpuProgram(
        name="argmax",
        text=_function(emitter, inputs, outputs, [result]),
        inputs=inputs,
        outputs=outputs,
    )


@dataclass(frozen=True)
class D5Config:
    """The Tiny Decoder geometry the block program is built for."""

    sequence: int = 8
    hidden_size: int = 8
    num_heads: int = 2
    intermediate_size: int = 16
    vocab_size: int = 32
    fractional_bits: int = FXP_FRACTION_BITS

    def __post_init__(self) -> None:
        if self.hidden_size % self.num_heads:
            raise D5ProgramError("hidden_size must be divisible by num_heads")
        for field in (
            "sequence",
            "hidden_size",
            "num_heads",
            "intermediate_size",
            "vocab_size",
        ):
            if getattr(self, field) <= 0:
                raise D5ProgramError(f"{field} must be positive")

    @property
    def head_size(self) -> int:
        return self.hidden_size // self.num_heads


def _mask_literal(sequence: int) -> str:
    rows = [
        "[" + ", ".join(_literal(1.0 if column <= row else 0.0) for column in range(sequence)) + "]"
        for row in range(sequence)
    ]
    return "[" + ", ".join(rows) + "]"


def _emit_layernorm(
    emitter: _Emitter,
    operand: str,
    operand_type: str,
    rows: int,
    cols: int,
    gamma: str,
    beta: str,
) -> str:
    vector = _type_of((rows,))
    column = _type_of((cols,))
    total = _reduce(emitter, operand, operand_type, vector, 0.0, "mhlo.add", 1)
    inverse_count = emitter.assign(
        "ic", f"mhlo.constant dense<{_literal(1.0 / float(cols))}> : {vector}"
    )
    mean = emitter.assign("mn", f"mhlo.multiply {total}, {inverse_count} : {vector}")
    mean_b = _broadcast(emitter, mean, vector, operand_type, [0])
    centered = emitter.assign("ct", f"mhlo.subtract {operand}, {mean_b} : {operand_type}")
    squared = emitter.assign("sq", f"mhlo.multiply {centered}, {centered} : {operand_type}")
    var_total = _reduce(emitter, squared, operand_type, vector, 0.0, "mhlo.add", 1)
    variance = emitter.assign(
        "vr", f"mhlo.multiply {var_total}, {inverse_count} : {vector}"
    )
    epsilon = emitter.assign(
        "ep", f"mhlo.constant dense<{_literal(LAYERNORM_EPSILON)}> : {vector}"
    )
    shifted = emitter.assign("sv", f"mhlo.add {variance}, {epsilon} : {vector}")
    inverse_std = emitter.assign("is", f"mhlo.rsqrt {shifted} : {vector}")
    inverse_std_b = _broadcast(emitter, inverse_std, vector, operand_type, [0])
    scaled = emitter.assign(
        "sc", f"mhlo.multiply {centered}, {inverse_std_b} : {operand_type}"
    )
    gamma_b = _broadcast(emitter, gamma, column, operand_type, [1])
    beta_b = _broadcast(emitter, beta, column, operand_type, [1])
    scaled_gamma = emitter.assign(
        "sg", f"mhlo.multiply {scaled}, {gamma_b} : {operand_type}"
    )
    return emitter.assign("ln", f"mhlo.add {scaled_gamma}, {beta_b} : {operand_type}")


def _emit_linear(
    emitter: _Emitter,
    x: str,
    x_type: str,
    w: str,
    w_type: str,
    b: str,
    b_type: str,
    result_type: str,
    bias_dimensions: Sequence[int],
) -> str:
    product = emitter.assign(
        "mm",
        f"\"mhlo.dot_general\"({x}, {w}) {{dot_dimension_numbers = "
        f"#mhlo.dot<lhs_contracting_dimensions = [1], rhs_contracting_dimensions = [0]>}} "
        f": ({x_type}, {w_type}) -> {result_type}",
    )
    bias_b = _broadcast(emitter, b, b_type, result_type, bias_dimensions)
    return emitter.assign("bs", f"mhlo.add {product}, {bias_b} : {result_type}")


def _emit_gelu(emitter: _Emitter, x: str, x_type: str) -> str:
    square = emitter.assign("x2", f"mhlo.multiply {x}, {x} : {x_type}")
    cube = emitter.assign("x3", f"mhlo.multiply {square}, {x} : {x_type}")
    c2 = emitter.assign("c2", f"mhlo.constant dense<{_literal(GELU_TANH_C2)}> : {x_type}")
    inner2 = emitter.assign("i2", f"mhlo.multiply {c2}, {cube} : {x_type}")
    inner = emitter.assign("i1", f"mhlo.add {x}, {inner2} : {x_type}")
    c1 = emitter.assign("c1", f"mhlo.constant dense<{_literal(GELU_TANH_C1)}> : {x_type}")
    argument = emitter.assign("ar", f"mhlo.multiply {c1}, {inner} : {x_type}")
    tanh_argument = emitter.assign("th", f"mhlo.tanh {argument} : {x_type}")
    one = emitter.assign("on", f"mhlo.constant dense<1.0> : {x_type}")
    raised = emitter.assign("ra", f"mhlo.add {one}, {tanh_argument} : {x_type}")
    product = emitter.assign("pr", f"mhlo.multiply {x}, {raised} : {x_type}")
    half = emitter.assign("hf", f"mhlo.constant dense<0.5> : {x_type}")
    return emitter.assign("gl", f"mhlo.multiply {half}, {product} : {x_type}")


BLOCK_INPUT_SPECS: tuple[tuple[str, str], ...] = (
    ("h", "matrix"),
    ("ln1_weight", "hidden"),
    ("ln1_bias", "hidden"),
    ("wq", "square"),
    ("wk", "square"),
    ("wv", "square"),
    ("bq", "hidden"),
    ("bk", "hidden"),
    ("bv", "hidden"),
    ("attention_out_weight", "square"),
    ("attention_out_bias", "hidden"),
    ("ln2_weight", "hidden"),
    ("ln2_bias", "hidden"),
    ("ffn_in_weight", "expand"),
    ("ffn_in_bias", "intermediate"),
    ("ffn_out_weight", "contract"),
    ("ffn_out_bias", "hidden"),
    ("ln_f_weight", "hidden"),
    ("ln_f_bias", "hidden"),
    ("lm_weight", "head"),
    ("lm_bias", "vocab"),
)


def _block_shape(kind: str, config: D5Config) -> tuple[int, ...]:
    seq, d, inter, vocab = (
        config.sequence,
        config.hidden_size,
        config.intermediate_size,
        config.vocab_size,
    )
    table = {
        "matrix": (seq, d),
        "hidden": (d,),
        "square": (d, d),
        "expand": (d, inter),
        "intermediate": (inter,),
        "contract": (inter, d),
        "head": (d, vocab),
        "vocab": (vocab,),
    }
    try:
        return table[kind]
    except KeyError as exc:  # pragma: no cover - the table is fixed
        raise D5ProgramError(f"unknown block input kind {kind!r}") from exc


def build_block_program(config: D5Config) -> SpuProgram:
    """One pre-norm Tiny Decoder block followed by a final norm, LM head and
    secure Argmax, expressed with no plaintext reveal.

    The mask is applied by multiplying the exponentials by a public 0/1 causal
    pattern before the sum, which is exactly the shifted Softmax with the
    future positions removed and avoids ever feeding a huge negative exponent
    to the SPU exponential protocol.
    """
    seq, d, heads, head, inter, vocab = (
        config.sequence,
        config.hidden_size,
        config.num_heads,
        config.head_size,
        config.intermediate_size,
        config.vocab_size,
    )
    matrix = _type_of((seq, d))
    hidden = _type_of((d,))
    square = _type_of((d, d))
    expand = _type_of((d, inter))
    intermediate = _type_of((inter,))
    contract = _type_of((inter, d))
    vocab_vector = _type_of((vocab,))
    head_table = _type_of((d, vocab))
    logits_table = _type_of((seq, vocab))
    split = _type_of((seq, heads, head))
    per_head = _type_of((heads, seq, head))
    keys = _type_of((heads, head, seq))
    scores_type = _type_of((heads, seq, seq))
    heads_seq = _type_of((heads, seq))
    mask_type = _type_of((seq, seq))
    one = "tensor<1xf64>"

    emitter = _Emitter()
    inputs = tuple(
        TensorSpec(name, _block_shape(kind, config)) for name, kind in BLOCK_INPUT_SPECS
    )
    normalized_1 = _emit_layernorm(
        emitter, "%h", matrix, seq, d, "%ln1_weight", "%ln1_bias"
    )
    query = _emit_linear(
        emitter, normalized_1, matrix, "%wq", square, "%bq", hidden, matrix, [1]
    )
    key = _emit_linear(
        emitter, normalized_1, matrix, "%wk", square, "%bk", hidden, matrix, [1]
    )
    value = _emit_linear(
        emitter, normalized_1, matrix, "%wv", square, "%bv", hidden, matrix, [1]
    )

    def to_heads(operand: str, permutation: Sequence[int]) -> str:
        reshaped = emitter.assign("rs", f"mhlo.reshape {operand} : ({matrix}) -> {split}")
        return emitter.assign(
            "tp",
            f"\"mhlo.transpose\"({reshaped}) {{permutation = {_dims(permutation)} : "
            f"tensor<3xi64>}} : ({split}) -> "
            f"{per_head if permutation == [1, 0, 2] else keys}",
        )

    query_heads = to_heads(query, [1, 0, 2])
    key_heads = to_heads(key, [1, 2, 0])
    value_heads = to_heads(value, [1, 0, 2])

    scores = emitter.assign(
        "sc",
        f"\"mhlo.dot_general\"({query_heads}, {key_heads}) {{dot_dimension_numbers = "
        f"#mhlo.dot<lhs_batching_dimensions = [0], rhs_batching_dimensions = [0], "
        f"lhs_contracting_dimensions = [2], rhs_contracting_dimensions = [1]>}} : "
        f"({per_head}, {keys}) -> {scores_type}",
    )
    scale = emitter.assign(
        "sl", f"mhlo.constant dense<{_literal(1.0 / math.sqrt(head))}> : {scores_type}"
    )
    scaled_scores = emitter.assign("ss", f"mhlo.multiply {scores}, {scale} : {scores_type}")
    row_max = _reduce(emitter, scaled_scores, scores_type, heads_seq, -1e9, "mhlo.maximum", 2)
    row_max_b = _broadcast(emitter, row_max, heads_seq, scores_type, [0, 1])
    shifted_scores = emitter.assign(
        "sh", f"mhlo.subtract {scaled_scores}, {row_max_b} : {scores_type}"
    )
    exponentials = emitter.assign("ex", f"mhlo.exponential {shifted_scores} : {scores_type}")
    mask = emitter.assign(
        "mk",
        f"mhlo.constant dense<{_mask_literal(seq)}> : {mask_type}",
    )
    mask_b = _broadcast(emitter, mask, mask_type, scores_type, [1, 2])
    masked = emitter.assign("me", f"mhlo.multiply {exponentials}, {mask_b} : {scores_type}")
    denominator = _reduce(emitter, masked, scores_type, heads_seq, 0.0, "mhlo.add", 2)
    denominator_b = _broadcast(emitter, denominator, heads_seq, scores_type, [0, 1])
    probabilities = emitter.assign(
        "pr", f"mhlo.divide {masked}, {denominator_b} : {scores_type}"
    )
    attended = emitter.assign(
        "at",
        f"\"mhlo.dot_general\"({probabilities}, {value_heads}) {{dot_dimension_numbers = "
        f"#mhlo.dot<lhs_batching_dimensions = [0], rhs_batching_dimensions = [0], "
        f"lhs_contracting_dimensions = [2], rhs_contracting_dimensions = [1]>}} : "
        f"({scores_type}, {per_head}) -> {per_head}",
    )
    restored = emitter.assign(
        "rr",
        f"\"mhlo.transpose\"({attended}) {{permutation = {_dims([1, 0, 2])} : tensor<3xi64>}} "
        f": ({per_head}) -> {split}",
    )
    merged = emitter.assign("mg", f"mhlo.reshape {restored} : ({split}) -> {matrix}")
    projected = _emit_linear(
        emitter,
        merged,
        matrix,
        "%attention_out_weight",
        square,
        "%attention_out_bias",
        hidden,
        matrix,
        [1],
    )
    residual = emitter.assign("rz", f"mhlo.add %h, {projected} : {matrix}")
    normalized_2 = _emit_layernorm(
        emitter, residual, matrix, seq, d, "%ln2_weight", "%ln2_bias"
    )
    expanded = _emit_linear(
        emitter,
        normalized_2,
        matrix,
        "%ffn_in_weight",
        expand,
        "%ffn_in_bias",
        intermediate,
        _type_of((seq, inter)),
        [1],
    )
    activated = _emit_gelu(emitter, expanded, _type_of((seq, inter)))
    ffn = _emit_linear(
        emitter,
        activated,
        _type_of((seq, inter)),
        "%ffn_out_weight",
        contract,
        "%ffn_out_bias",
        hidden,
        matrix,
        [1],
    )
    hidden_out = emitter.assign("ho", f"mhlo.add {residual}, {ffn} : {matrix}")
    normalized_final = _emit_layernorm(
        emitter, hidden_out, matrix, seq, d, "%ln_f_weight", "%ln_f_bias"
    )
    logits = _emit_linear(
        emitter,
        normalized_final,
        matrix,
        "%lm_weight",
        head_table,
        "%lm_bias",
        vocab_vector,
        logits_table,
        [1],
    )
    last_row = emitter.assign(
        "lr",
        f"\"mhlo.slice\"({logits}) {{start_indices = dense<[{seq - 1}, 0]> : tensor<2xi64>, "
        f"limit_indices = dense<[{seq}, {vocab}]> : tensor<2xi64>, strides = dense<[1, 1]> "
        f": tensor<2xi64>}} : ({logits_table}) -> tensor<1x{vocab}xf64>",
    )
    logits_vector = emitter.assign(
        "lv", f"mhlo.reshape {last_row} : (tensor<1x{vocab}xf64>) -> {vocab_vector}"
    )
    maximum = _reduce(emitter, logits_vector, vocab_vector, "tensor<f64>", -1e9, "mhlo.maximum", 0)
    maximum_b = _broadcast(emitter, maximum, "tensor<f64>", vocab_vector, [])
    is_max = emitter.assign(
        "mx",
        f"mhlo.compare GE, {logits_vector}, {maximum_b} : ({vocab_vector}, {vocab_vector}) "
        f"-> tensor<{vocab}xi1>",
    )
    indices = emitter.assign(
        "ix",
        "mhlo.constant dense<["
        + ", ".join(_literal(index) for index in range(vocab))
        + f"]> : {vocab_vector}",
    )
    sentinel = emitter.assign(
        "sn", f"mhlo.constant dense<{_literal(vocab)}> : {vocab_vector}"
    )
    candidates = emitter.assign(
        "cd",
        f"\"mhlo.select\"({is_max}, {indices}, {sentinel}) : "
        f"(tensor<{vocab}xi1>, {vocab_vector}, {vocab_vector}) -> {vocab_vector}",
    )
    chosen = _reduce(emitter, candidates, vocab_vector, "tensor<f64>", 1e9, "mhlo.minimum", 0)
    token = emitter.assign(
        "tk",
        f"\"mhlo.broadcast_in_dim\"({chosen}) {{broadcast_dimensions = dense<> : "
        f"tensor<0xi64>}} : (tensor<f64>) -> {one}",
    )

    outputs = (
        TensorSpec("hidden", (seq, d)),
        TensorSpec("logits", (seq, vocab)),
        TensorSpec("token", (1,)),
    )
    return SpuProgram(
        name="block",
        text=_function(emitter, inputs, outputs, [hidden_out, logits, token]),
        inputs=inputs,
        outputs=outputs,
    )


__all__ = [
    "BLOCK_INPUT_SPECS",
    "D5Config",
    "D5ProgramError",
    "FXP_FRACTION_BITS",
    "GELU_TANH_C1",
    "GELU_TANH_C2",
    "LAYERNORM_EPSILON",
    "SpuProgram",
    "TensorSpec",
    "build_argmax_program",
    "build_block_program",
    "build_gelu_program",
    "build_layernorm_program",
    "build_softmax_program",
]
