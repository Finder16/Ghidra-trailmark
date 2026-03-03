"""Tests for QueryEngine edge cases."""

from __future__ import annotations

import pytest

from trailmark.models import (
    CodeEdge,
    CodeGraph,
    CodeUnit,
    EdgeKind,
    NodeKind,
    SourceLocation,
)
from trailmark.query.api import QueryEngine

_LOC = SourceLocation(file_path="test.py", start_line=1, end_line=10)


def _make_node(node_id: str, name: str) -> CodeUnit:
    return CodeUnit(
        id=node_id,
        name=name,
        kind=NodeKind.FUNCTION,
        location=_LOC,
    )


def _simple_engine() -> QueryEngine:
    nodes = {
        "a": _make_node("a", "a"),
        "b": _make_node("b", "b"),
    }
    edges = [
        CodeEdge(
            source_id="a",
            target_id="b",
            kind=EdgeKind.CALLS,
        ),
    ]
    graph = CodeGraph(nodes=nodes, edges=edges)
    return QueryEngine.from_graph(graph)


class TestUnsupportedLanguage:
    def test_from_directory_bad_language(self) -> None:
        with pytest.raises(ValueError, match="Unsupported language"):
            QueryEngine.from_directory(".", language="cobol")


class TestCalleesOfMissing:
    def test_callees_of_nonexistent(self) -> None:
        engine = _simple_engine()
        assert engine.callees_of("nonexistent") == []


class TestPathsBetweenMissing:
    def test_paths_with_missing_src(self) -> None:
        engine = _simple_engine()
        assert engine.paths_between("zzz", "b") == []

    def test_paths_with_missing_dst(self) -> None:
        engine = _simple_engine()
        assert engine.paths_between("a", "zzz") == []
