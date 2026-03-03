"""Property-based tests for Trailmark core invariants.

Uses Hypothesis to verify structural properties that example-based
tests cannot cover exhaustively: index bijections, merge monotonicity,
annotation round-trips, graph traversal duality, and diagram safety.
"""

from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from trailmark.diagram import sanitize_id
from trailmark.models.annotations import Annotation, AnnotationKind
from trailmark.models.edges import CodeEdge, EdgeKind
from trailmark.models.graph import CodeGraph
from trailmark.models.nodes import CodeUnit, NodeKind, SourceLocation
from trailmark.storage.graph_store import GraphStore

# ── Shared strategies ────────────────────────────────────────────

_MERMAID_ID_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

_LOC = SourceLocation("test.py", 1, 10)

_node_id_st = st.text(
    st.characters(whitelist_categories=("L", "N"), whitelist_characters="_:"),
    min_size=1,
    max_size=20,
)


def _make_unit(nid: str) -> CodeUnit:
    return CodeUnit(id=nid, name=nid, kind=NodeKind.FUNCTION, location=_LOC)


@st.composite
def _graph_st(
    draw: st.DrawFn,
    max_nodes: int = 15,
    max_edges: int = 25,
) -> CodeGraph:
    """Generate a random CodeGraph with unique node IDs."""
    ids = draw(
        st.lists(_node_id_st, min_size=0, max_size=max_nodes, unique=True),
    )
    nodes = {nid: _make_unit(nid) for nid in ids}
    edges: list[CodeEdge] = []
    if len(ids) >= 2:
        raw = draw(
            st.lists(
                st.tuples(
                    st.sampled_from(ids),
                    st.sampled_from(ids),
                    st.sampled_from(list(EdgeKind)),
                ),
                max_size=max_edges,
            ),
        )
        edges = [CodeEdge(source_id=s, target_id=t, kind=k) for s, t, k in raw if s != t]
    deps = draw(
        st.lists(st.text(min_size=1, max_size=10), max_size=5, unique=True),
    )
    return CodeGraph(nodes=nodes, edges=edges, dependencies=deps)


_annotation_kind_st = st.sampled_from(list(AnnotationKind))

_annotation_st = st.builds(
    Annotation,
    kind=_annotation_kind_st,
    description=st.text(min_size=1, max_size=30),
    source=st.text(min_size=1, max_size=10),
)


# ── 1. GraphStore index bijection ────────────────────────────────


@given(graph=_graph_st())  # type: ignore[misc]  # st.composite ParamSpec
@settings(max_examples=200)
def test_index_bijection(graph: CodeGraph) -> None:
    """_id_to_idx and _idx_to_id form a perfect bijection over nodes."""
    store = GraphStore(graph)
    assert set(store._id_to_idx.keys()) == set(graph.nodes.keys())
    assert len(store._id_to_idx) == len(store._idx_to_id)
    for nid, idx in store._id_to_idx.items():
        assert store._idx_to_id[idx] == nid
    for idx, nid in store._idx_to_id.items():
        assert store._id_to_idx[nid] == idx


# ── 2. CodeGraph.merge monotonicity ─────────────────────────────


@given(g1=_graph_st(), g2=_graph_st())  # type: ignore[misc]  # st.composite ParamSpec
@settings(max_examples=200)
def test_merge_monotonic(g1: CodeGraph, g2: CodeGraph) -> None:
    """Merging never loses nodes, edges, or dependencies."""
    orig_nodes = len(g1.nodes)
    orig_edges = len(g1.edges)
    orig_deps = len(g1.dependencies)
    g2_node_ids = set(g2.nodes.keys())
    g2_dep_set = set(g2.dependencies)

    g1.merge(g2)

    assert len(g1.nodes) >= orig_nodes
    assert len(g1.edges) >= orig_edges
    assert len(g1.dependencies) >= orig_deps
    # All of g2's nodes are present after merge
    for nid in g2_node_ids:
        assert nid in g1.nodes
    # All of g2's deps are present, and no duplicates
    for dep in g2_dep_set:
        assert dep in g1.dependencies
    assert len(g1.dependencies) == len(set(g1.dependencies))


# ── 3. Annotation add/clear round-trip ──────────────────────────


@given(
    annotations=st.lists(_annotation_st, min_size=1, max_size=15),
    clear_kind=st.one_of(st.none(), _annotation_kind_st),
)
@settings(max_examples=200)
def test_annotation_add_clear_roundtrip(
    annotations: list[Annotation],
    clear_kind: AnnotationKind | None,
) -> None:
    """Adding then clearing annotations preserves correct state."""
    graph = CodeGraph(nodes={"n": _make_unit("n")})
    store = GraphStore(graph)

    for ann in annotations:
        assert store.add_annotation("n", ann) is True

    assert len(store.annotations_for("n")) == len(annotations)

    store.clear_annotations("n", clear_kind)

    if clear_kind is None:
        assert store.annotations_for("n") == []
    else:
        remaining = store.annotations_for("n")
        expected_count = sum(1 for a in annotations if a.kind != clear_kind)
        assert len(remaining) == expected_count
        for r in remaining:
            assert r.kind != clear_kind


# ── 4. reachable_from / ancestors_of duality ─────────────────────


@given(graph=_graph_st(max_nodes=10, max_edges=15))  # type: ignore[misc]  # st.composite ParamSpec
@settings(max_examples=100)
def test_reachable_ancestors_duality(graph: CodeGraph) -> None:
    """If B is reachable from A, then A is an ancestor of B."""
    store = GraphStore(graph)
    for node_id in graph.nodes:
        reachable = store.reachable_from(node_id)
        for r_id in reachable:
            ancestors = store.ancestors_of(r_id)
            assert node_id in ancestors, f"{node_id} reaches {r_id} but not in ancestors_of({r_id})"


@given(graph=_graph_st(max_nodes=10, max_edges=15))  # type: ignore[misc]  # st.composite ParamSpec
@settings(max_examples=100)
def test_reachable_transitive_closure(graph: CodeGraph) -> None:
    """reachable_from is transitively closed (modulo start node).

    rx.descendants excludes the starting node, so in a cycle A→B→A,
    reachable_from(A) = {B} and reachable_from(B) = {A}. The property
    holds when we account for the excluded start node.
    """
    store = GraphStore(graph)
    for node_id in graph.nodes:
        reachable = store.reachable_from(node_id)
        for r_id in reachable:
            sub_reachable = store.reachable_from(r_id)
            # Everything reachable from r_id (except node_id itself,
            # which is excluded by rx.descendants) must be in reachable
            assert sub_reachable - {node_id} <= reachable, (
                f"reachable_from({node_id}) is not transitively closed: "
                f"{r_id} reaches {sub_reachable - reachable - {node_id}}"
            )


# ── 5. sanitize_id idempotency and output validity ──────────────


@given(node_id=st.text(min_size=1, max_size=80))
@settings(max_examples=500)
def test_sanitize_id_idempotent(node_id: str) -> None:
    """Applying sanitize_id twice gives the same result as once."""
    once = sanitize_id(node_id)
    twice = sanitize_id(once)
    assert once == twice


@given(node_id=st.text(min_size=1, max_size=80))
@settings(max_examples=500)
def test_sanitize_id_produces_valid_mermaid_id(node_id: str) -> None:
    """sanitize_id always produces a valid Mermaid identifier."""
    result = sanitize_id(node_id)
    assert len(result) > 0
    assert _MERMAID_ID_RE.match(result), f"Invalid Mermaid ID: {result!r}"


def test_sanitize_id_empty_input() -> None:
    """Empty input produces a non-empty fallback identifier."""
    assert sanitize_id("") == "n_empty"
    assert _MERMAID_ID_RE.match(sanitize_id(""))
