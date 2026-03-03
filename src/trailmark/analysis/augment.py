"""Augment code graphs with external findings from SARIF and weAudit files.

Parses SARIF 2.1.0 static analysis results and weAudit audit annotations,
matches findings to graph nodes by file path and line range overlap, and
stores them as annotations and named subgraphs.
"""

from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import unquote, urlparse

from trailmark.models.annotations import Annotation, AnnotationKind
from trailmark.models.graph import CodeGraph
from trailmark.storage.graph_store import GraphStore

_AUGMENT_SUBGRAPH_PREFIXES = ("sarif:", "weaudit:")


def augment_from_sarif(
    store: GraphStore,
    sarif_path: str,
) -> dict[str, Any]:
    """Parse a SARIF file and augment the graph with findings.

    Reads SARIF 2.1.0 JSON, maps results to graph nodes by file/line
    overlap, creates annotations and subgraphs by severity and tool.

    Returns a summary dict with match statistics.
    """
    clear_augmented(store, "sarif")
    with open(sarif_path) as f:
        sarif = json.load(f)

    graph = store._graph  # noqa: SLF001
    matched = 0
    unmatched = 0
    subgraph_sets: dict[str, set[str]] = {}

    for run in sarif.get("runs", []):
        tool_name = _sarif_tool_name(run)
        for result in run.get("results", []):
            node_ids = _process_sarif_result(
                result,
                tool_name,
                graph,
            )
            if node_ids:
                matched += 1
                _add_to_subgraphs(
                    subgraph_sets,
                    node_ids,
                    result,
                    tool_name,
                )
            else:
                unmatched += 1

    for name, ids in subgraph_sets.items():
        store.add_subgraph(name, ids)

    return {
        "matched_findings": matched,
        "unmatched_findings": unmatched,
        "subgraphs_created": sorted(subgraph_sets.keys()),
    }


def augment_from_weaudit(
    store: GraphStore,
    weaudit_path: str,
) -> dict[str, Any]:
    """Parse a weAudit file and augment the graph with findings.

    Reads weAudit JSON, maps entries to graph nodes by file/line
    overlap (converting 0-indexed to 1-indexed lines), creates
    annotations and subgraphs by severity and entry type.

    Returns a summary dict with match statistics.
    """
    clear_augmented(store, "weaudit")
    with open(weaudit_path) as f:
        data = json.load(f)

    graph = store._graph  # noqa: SLF001
    matched = 0
    unmatched = 0
    subgraph_sets: dict[str, set[str]] = {}

    entries = data.get("treeEntries", [])
    entries += data.get("resolvedEntries", [])

    for entry in entries:
        node_ids = _process_weaudit_entry(entry, data, graph)
        if node_ids:
            matched += 1
            _add_weaudit_to_subgraphs(subgraph_sets, node_ids, entry)
        else:
            unmatched += 1

    for name, ids in subgraph_sets.items():
        store.add_subgraph(name, ids)

    return {
        "matched_findings": matched,
        "unmatched_findings": unmatched,
        "subgraphs_created": sorted(subgraph_sets.keys()),
    }


def clear_augmented(store: GraphStore, source_prefix: str) -> None:
    """Remove annotations and subgraphs from a prior augmentation run.

    Filters annotations whose source starts with the given prefix
    and deletes subgraphs whose name starts with that prefix followed
    by a colon.
    """
    graph = store._graph  # noqa: SLF001
    for node_id in list(graph.annotations):
        graph.annotations[node_id] = [
            a for a in graph.annotations[node_id] if not a.source.startswith(source_prefix)
        ]
        if not graph.annotations[node_id]:
            del graph.annotations[node_id]

    sg_prefix = f"{source_prefix}:"
    for name in list(graph.subgraphs):
        if name.startswith(sg_prefix):
            del graph.subgraphs[name]


# ── Path matching ────────────────────────────────────────────────────


def _normalize_path(uri: str, root_path: str) -> str | None:
    """Normalize a URI or file path to be relative to root_path.

    Handles file:// URIs, absolute paths, and relative paths.
    Returns None if the path cannot be resolved under root_path.
    """
    path = uri
    parsed = urlparse(uri)
    if parsed.scheme == "file":
        path = unquote(parsed.path)
    elif parsed.scheme and parsed.scheme != "":
        return None

    if os.path.isabs(path):
        try:
            return os.path.relpath(path, root_path)
        except ValueError:
            return None

    return path


def _find_overlapping_nodes(
    graph: CodeGraph,
    rel_path: str,
    start_line: int,
    end_line: int,
) -> list[str]:
    """Find graph nodes whose source location overlaps the given range.

    Returns node IDs sorted by span size (tightest match first).
    """
    root = graph.root_path
    matches: list[tuple[int, str]] = []

    for node_id, node in graph.nodes.items():
        loc = node.location
        node_rel = _normalize_path(loc.file_path, root)
        if node_rel is None or node_rel != rel_path:
            continue
        if loc.start_line <= end_line and loc.end_line >= start_line:
            span = loc.end_line - loc.start_line
            matches.append((span, node_id))

    matches.sort(key=lambda m: m[0])
    return [node_id for _, node_id in matches]


# ── SARIF processing ────────────────────────────────────────────────


def _sarif_tool_name(run: dict[str, Any]) -> str:
    """Extract the tool name from a SARIF run object."""
    tool = run.get("tool", {})
    driver = tool.get("driver", {})
    return driver.get("name", "unknown")


def _sarif_level(result: dict[str, Any]) -> str:
    """Extract severity level from a SARIF result."""
    return result.get("level", "warning")


def _format_sarif_description(
    result: dict[str, Any],
    tool_name: str,
) -> str:
    """Build a compact single-line description from a SARIF result."""
    level = _sarif_level(result).upper()
    rule_id = result.get("ruleId", "unknown")
    message = result.get("message", {}).get("text", "")
    return f"[{level}] {rule_id}: {message} ({tool_name})"


def _process_sarif_result(
    result: dict[str, Any],
    tool_name: str,
    graph: CodeGraph,
) -> set[str]:
    """Map a single SARIF result to graph nodes and annotate them.

    Returns the set of node IDs that were annotated.
    """
    description = _format_sarif_description(result, tool_name)
    source = f"sarif:{tool_name}"
    all_node_ids: set[str] = set()
    locations = result.get("locations", [])

    for loc in locations:
        phys = loc.get("physicalLocation", {})
        node_ids = _nodes_from_physical_location(phys, graph)
        all_node_ids.update(node_ids)

    _annotate_nodes(graph, all_node_ids, description, source)
    return all_node_ids


def _nodes_from_physical_location(
    phys: dict[str, Any],
    graph: CodeGraph,
) -> list[str]:
    """Resolve a SARIF physicalLocation to overlapping graph nodes."""
    artifact = phys.get("artifactLocation", {})
    uri = artifact.get("uri", "")
    if not uri:
        return []

    region = phys.get("region", {})
    start_line = region.get("startLine", 1)
    end_line = region.get("endLine", start_line)

    rel_path = _normalize_path(uri, graph.root_path)
    if rel_path is None:
        return []

    return _find_overlapping_nodes(graph, rel_path, start_line, end_line)


def _add_to_subgraphs(
    subgraph_sets: dict[str, set[str]],
    node_ids: set[str],
    result: dict[str, Any],
    tool_name: str,
) -> None:
    """Add node IDs to SARIF-derived subgraphs by level and tool."""
    level = _sarif_level(result)
    level_key = f"sarif:{level}"
    subgraph_sets.setdefault(level_key, set()).update(node_ids)

    tool_key = f"sarif:{tool_name}"
    subgraph_sets.setdefault(tool_key, set()).update(node_ids)


# ── weAudit processing ──────────────────────────────────────────────


def _weaudit_author(data: dict[str, Any]) -> str:
    """Extract a default author from the weAudit file metadata."""
    remote = data.get("clientRemote", "")
    if "/" in remote:
        return remote.rsplit("/", 1)[-1]
    return "unknown"


def _format_weaudit_description(
    entry: dict[str, Any],
    author: str,
) -> str:
    """Build a compact single-line description from a weAudit entry."""
    details = entry.get("details", {})
    severity = details.get("severity", "").upper() or "UNSET"
    label = entry.get("label", "untitled")
    finding_type = details.get("type", "")
    desc = details.get("description", "")

    parts = [f"[{severity}] {label}"]
    if finding_type:
        parts.append(f"({finding_type})")
    if desc:
        first_line = desc.split("\n", 1)[0]
        parts.append(f"- {first_line}")
    parts.append(f"[{author}]")
    return " ".join(parts)


def _process_weaudit_entry(
    entry: dict[str, Any],
    data: dict[str, Any],
    graph: CodeGraph,
) -> set[str]:
    """Map a single weAudit entry to graph nodes and annotate them.

    Returns the set of node IDs that were annotated.
    """
    author = entry.get("author", _weaudit_author(data))
    description = _format_weaudit_description(entry, author)
    entry_type = entry.get("entryType", 0)
    kind = AnnotationKind.AUDIT_NOTE if entry_type == 1 else AnnotationKind.FINDING
    source = f"weaudit:{author}"
    all_node_ids: set[str] = set()

    for loc in entry.get("locations", []):
        node_ids = _nodes_from_weaudit_location(loc, graph)
        all_node_ids.update(node_ids)

    _annotate_nodes(
        graph,
        all_node_ids,
        description,
        source,
        kind=kind,
    )
    return all_node_ids


def _nodes_from_weaudit_location(
    loc: dict[str, Any],
    graph: CodeGraph,
) -> list[str]:
    """Resolve a weAudit location to overlapping graph nodes.

    Converts 0-indexed weAudit lines to 1-indexed Trailmark lines.
    """
    path = loc.get("path", "")
    if not path:
        return []

    start_line = loc.get("startLine", 0) + 1
    end_line = loc.get("endLine", 0) + 1

    rel_path = _normalize_path(path, graph.root_path)
    if rel_path is None:
        return []

    return _find_overlapping_nodes(graph, rel_path, start_line, end_line)


def _add_weaudit_to_subgraphs(
    subgraph_sets: dict[str, set[str]],
    node_ids: set[str],
    entry: dict[str, Any],
) -> None:
    """Add node IDs to weAudit-derived subgraphs."""
    entry_type = entry.get("entryType", 0)
    type_key = "weaudit:findings" if entry_type == 0 else "weaudit:notes"
    subgraph_sets.setdefault(type_key, set()).update(node_ids)

    details = entry.get("details", {})
    severity = details.get("severity", "").lower()
    if severity:
        sev_key = f"weaudit:{severity}"
        subgraph_sets.setdefault(sev_key, set()).update(node_ids)


# ── Shared helpers ───────────────────────────────────────────────────


def _annotate_nodes(
    graph: CodeGraph,
    node_ids: set[str],
    description: str,
    source: str,
    kind: AnnotationKind = AnnotationKind.FINDING,
) -> None:
    """Add an annotation to each node in the set."""
    ann = Annotation(kind=kind, description=description, source=source)
    for node_id in node_ids:
        graph.add_annotation(node_id, ann)
