"""Top-level graph container that holds parsed code data."""

from __future__ import annotations

from dataclasses import dataclass, field

from trailmark.models.annotations import Annotation, AnnotationKind, EntrypointTag
from trailmark.models.edges import CodeEdge
from trailmark.models.nodes import CodeUnit


@dataclass
class CodeGraph:
    """A complete code graph for a parsed project or file."""

    nodes: dict[str, CodeUnit] = field(default_factory=dict)
    edges: list[CodeEdge] = field(default_factory=list)
    annotations: dict[str, list[Annotation]] = field(
        default_factory=dict,
    )
    entrypoints: dict[str, EntrypointTag] = field(
        default_factory=dict,
    )
    subgraphs: dict[str, set[str]] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    language: str = ""
    root_path: str = ""

    def add_annotation(
        self,
        node_id: str,
        annotation: Annotation,
    ) -> None:
        """Append an annotation to the given node."""
        self.annotations.setdefault(node_id, []).append(annotation)

    def clear_annotations(
        self,
        node_id: str,
        kind: AnnotationKind | None = None,
    ) -> None:
        """Remove annotations for a node, optionally filtered by kind.

        If kind is None, removes all annotations for the node.
        Cleans up empty annotation lists from the dict.
        """
        if node_id not in self.annotations:
            return
        if kind is None:
            del self.annotations[node_id]
        else:
            self.annotations[node_id] = [a for a in self.annotations[node_id] if a.kind != kind]
            if not self.annotations[node_id]:
                del self.annotations[node_id]

    def merge(self, other: CodeGraph) -> None:
        """Merge another graph into this one."""
        self.nodes.update(other.nodes)
        self.edges.extend(other.edges)
        for node_id, anns in other.annotations.items():
            self.annotations.setdefault(node_id, []).extend(anns)
        self.entrypoints.update(other.entrypoints)
        for name, ids in other.subgraphs.items():
            self.subgraphs.setdefault(name, set()).update(ids)
        for dep in other.dependencies:
            if dep not in self.dependencies:
                self.dependencies.append(dep)
