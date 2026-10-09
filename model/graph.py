"""Deterministic static graph conversion for the Tiny Decoder."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from contracts import canonical_hash


class GraphError(ValueError):
    """A graph is not a valid fixed inference graph."""


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    op: str
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    attrs: tuple[tuple[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "op": self.op,
            "inputs": list(self.inputs),
            "outputs": list(self.outputs),
            "attrs": {name: value for name, value in self.attrs},
        }


@dataclass(frozen=True)
class StaticGraph:
    graph_version: str
    nodes: tuple[GraphNode, ...]

    def __post_init__(self) -> None:
        if not self.graph_version:
            raise GraphError("graph_version must not be empty")
        node_ids = [node.node_id for node in self.nodes]
        if len(node_ids) != len(set(node_ids)):
            raise GraphError("graph node IDs must be unique")
        available = {"input_ids", "position_ids"}
        for node in self.nodes:
            if any(value not in available for value in node.inputs):
                raise GraphError(f"node {node.node_id} has an undefined input")
            available.update(node.outputs)
        if not self.nodes:
            raise GraphError("a static graph must contain nodes")

    def to_dict(self) -> dict[str, Any]:
        return {
            "graph_version": self.graph_version,
            "nodes": [node.to_dict() for node in self.nodes],
        }

    def digest(self) -> str:
        return canonical_hash(self.to_dict())


def convert_tiny_decoder_graph(
    *,
    num_layers: int,
    hidden_size: int,
    num_heads: int,
    intermediate_size: int,
) -> StaticGraph:
    """Create the fixed operator sequence used by the TEE runtime."""
    if min(num_layers, hidden_size, num_heads, intermediate_size) <= 0:
        raise GraphError("all model dimensions must be positive")
    nodes: list[GraphNode] = [
        GraphNode(
            node_id="embedding",
            op="secure_embedding/Idx2v",
            inputs=("input_ids",),
            outputs=("hidden",),
            attrs=(("vocab_width", hidden_size),),
        ),
        GraphNode(
            node_id="position_embedding",
            op="secure_embedding/position",
            inputs=("position_ids",),
            outputs=("position",),
        ),
        GraphNode(
            node_id="embedding_add",
            op="rss_add",
            inputs=("hidden", "position"),
            outputs=("hidden_0",),
        ),
    ]
    current = "hidden_0"
    for layer in range(num_layers):
        prefix = f"layer_{layer}"
        nodes.extend(
            [
                GraphNode(
                    f"{prefix}.ln1",
                    "layernorm",
                    (current,),
                    (f"{prefix}.norm1",),
                ),
                GraphNode(
                    f"{prefix}.qkv",
                    "rss_matmul",
                    (f"{prefix}.norm1",),
                    (
                        f"{prefix}.q",
                        f"{prefix}.k",
                        f"{prefix}.v",
                    ),
                    (("split", 3), ("num_heads", num_heads)),
                ),
                GraphNode(
                    f"{prefix}.attention",
                    "causal_attention",
                    (f"{prefix}.q", f"{prefix}.k", f"{prefix}.v"),
                    (f"{prefix}.attended",),
                    (("head_size", hidden_size // num_heads),),
                ),
                GraphNode(
                    f"{prefix}.out_proj",
                    "rss_matmul",
                    (f"{prefix}.attended",),
                    (f"{prefix}.projected",),
                ),
                GraphNode(
                    f"{prefix}.residual1",
                    "rss_add",
                    (current, f"{prefix}.projected"),
                    (f"{prefix}.residual",),
                ),
                GraphNode(
                    f"{prefix}.ln2",
                    "layernorm",
                    (f"{prefix}.residual",),
                    (f"{prefix}.norm2",),
                ),
                GraphNode(
                    f"{prefix}.ffn_in",
                    "rss_matmul",
                    (f"{prefix}.norm2",),
                    (f"{prefix}.ffn_hidden",),
                ),
                GraphNode(
                    f"{prefix}.gelu",
                    "gelu_piecewise",
                    (f"{prefix}.ffn_hidden",),
                    (f"{prefix}.gelu",),
                ),
                GraphNode(
                    f"{prefix}.ffn_out",
                    "rss_matmul",
                    (f"{prefix}.gelu",),
                    (f"{prefix}.ffn",),
                ),
                GraphNode(
                    f"{prefix}.residual2",
                    "rss_add",
                    (f"{prefix}.residual", f"{prefix}.ffn"),
                    (f"{prefix}.output",),
                ),
            ]
        )
        current = f"{prefix}.output"
    nodes.extend(
        [
            GraphNode("final_norm", "layernorm", (current,), ("final_norm",)),
            GraphNode("lm_head", "rss_matmul", ("final_norm",), ("logits",)),
            GraphNode("argmax", "secure_argmax", ("logits",), ("token_id",)),
        ]
    )
    return StaticGraph("a122-tiny-decoder-graph-v1", tuple(nodes))


__all__ = [
    "GraphError",
    "GraphNode",
    "StaticGraph",
    "convert_tiny_decoder_graph",
]
