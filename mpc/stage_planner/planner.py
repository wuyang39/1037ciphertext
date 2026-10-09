"""Conservative stage planning over the frozen static graph."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from contracts import canonical_hash
from model.graph import GraphNode, StaticGraph


class StagePlannerError(ValueError):
    """A graph or precision plan cannot be safely staged."""


@dataclass(frozen=True)
class Stage:
    stage_id: str
    nodes: tuple[str, ...]
    scale: int | None
    layout: str
    fused: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "stage_id": self.stage_id,
            "nodes": list(self.nodes),
            "scale": self.scale,
            "layout": self.layout,
            "fused": self.fused,
        }


@dataclass(frozen=True)
class StagePlan:
    graph_version: str
    stages: tuple[Stage, ...]
    before_hash: str
    after_hash: str
    removed_nodes: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "graph_version": self.graph_version,
            "stages": [stage.to_dict() for stage in self.stages],
            "before_hash": self.before_hash,
            "after_hash": self.after_hash,
            "removed_nodes": list(self.removed_nodes),
        }

    def digest(self) -> str:
        return canonical_hash(self.to_dict())


class StagePlanner:
    """Merge adjacent layout-compatible operations without changing semantics.

    Fusion is intentionally limited to a shared output layout/scale and adjacent
    linear stages. The planner records a before/after graph digest so an
    optimization can be disabled if it changes the safety or numerical profile.
    """

    FUSABLE_OPS = {"rss_matmul", "rss_add", "layernorm"}

    def __init__(
        self,
        *,
        precision_scales: Mapping[str, int] | None = None,
        tensor_layout: str = "row-major",
    ) -> None:
        self.precision_scales = dict(precision_scales or {})
        self.tensor_layout = tensor_layout

    def plan(self, graph: StaticGraph) -> StagePlan:
        before_hash = graph.digest()
        stages: list[Stage] = []
        index = 0
        removed: list[str] = []
        while index < len(graph.nodes):
            start = graph.nodes[index]
            if start.op not in self.FUSABLE_OPS:
                stages.append(
                    Stage(
                        stage_id=f"stage-{len(stages):04d}",
                        nodes=(start.node_id,),
                        scale=self._scale_for(start),
                        layout=self.tensor_layout,
                        fused=False,
                    )
                )
                index += 1
                continue
            grouped = [start]
            cursor = index + 1
            while (
                cursor < len(graph.nodes)
                and graph.nodes[cursor].op in self.FUSABLE_OPS
                and self._can_fuse(grouped[-1], graph.nodes[cursor])
            ):
                grouped.append(graph.nodes[cursor])
                cursor += 1
            if len(grouped) > 1:
                removed.extend(node.node_id for node in grouped[1:])
            stages.append(
                Stage(
                    stage_id=f"stage-{len(stages):04d}",
                    nodes=tuple(node.node_id for node in grouped),
                    scale=self._scale_for(grouped[-1]),
                    layout=self.tensor_layout,
                    fused=len(grouped) > 1,
                )
            )
            index = cursor
        after_document = {
            "graph_version": f"{graph.graph_version}:planned-v1",
            "stages": [stage.to_dict() for stage in stages],
        }
        return StagePlan(
            graph_version=graph.graph_version,
            stages=tuple(stages),
            before_hash=before_hash,
            after_hash=canonical_hash(after_document),
            removed_nodes=tuple(removed),
        )

    def _can_fuse(self, left: GraphNode, right: GraphNode) -> bool:
        return (
            left.op in {"rss_matmul", "rss_add", "layernorm"}
            and right.op in {"rss_matmul", "rss_add", "layernorm"}
            and self._scale_for(left) == self._scale_for(right)
        )

    def _scale_for(self, node: GraphNode) -> int | None:
        return self.precision_scales.get(node.node_id)


__all__ = ["Stage", "StagePlan", "StagePlanner", "StagePlannerError"]
