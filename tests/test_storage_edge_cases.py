"""Tests for GraphStore edge cases."""

from __future__ import annotations

from trailmark.models import (
    CodeEdge,
    CodeGraph,
    CodeUnit,
    EdgeKind,
    NodeKind,
    SourceLocation,
)
from trailmark.storage.graph_store import GraphStore

_LOC = SourceLocation(file_path="test.py", start_line=1, end_line=10)


def _make_node(node_id: str, name: str) -> CodeUnit:
    return CodeUnit(
        id=node_id,
        name=name,
        kind=NodeKind.FUNCTION,
        location=_LOC,
    )


def _build_store() -> GraphStore:
    nodes = {
        "mod:a": _make_node("mod:a", "a"),
        "mod:b": _make_node("mod:b", "b"),
        "mod:Cls.method": _make_node("mod:Cls.method", "method"),
    }
    edges = [
        CodeEdge(
            source_id="mod:a",
            target_id="mod:b",
            kind=EdgeKind.CALLS,
        ),
    ]
    graph = CodeGraph(nodes=nodes, edges=edges)
    return GraphStore(graph)


class TestCalleesNonexistent:
    def test_callees_of_missing_node(self) -> None:
        store = _build_store()
        assert store.callees_of("nonexistent") == []


class TestPathsBetweenNonexistent:
    def test_paths_missing_src(self) -> None:
        store = _build_store()
        assert store.paths_between("zzz", "mod:b") == []

    def test_paths_missing_dst(self) -> None:
        store = _build_store()
        assert store.paths_between("mod:a", "zzz") == []


class TestReachableFromNonexistent:
    def test_reachable_missing_node(self) -> None:
        store = _build_store()
        assert store.reachable_from("zzz") == set()


class TestFindNodeMethod:
    def test_find_by_method_name(self) -> None:
        store = _build_store()
        node = store.find_node("method")
        assert node is not None
        assert node.id == "mod:Cls.method"

    def test_find_returns_none(self) -> None:
        store = _build_store()
        assert store.find_node("nonexistent") is None
