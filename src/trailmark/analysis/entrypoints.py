"""Automatic entrypoint detection.

Populates ``CodeGraph.entrypoints`` so that ``attack_surface()``, taint
propagation, entrypoint enumeration, and privilege-boundary crossing
produce meaningful results.

Detection layers (later layers override earlier ones):
1. Universal heuristics — functions named ``main``, ``[project.scripts]``
   entries in pyproject.toml.
2. Repo-local override file — ``.trailmark/entrypoints.toml`` at the
   repository root.

Framework-specific detection (Flask ``@app.route``, FastAPI, Django URL
patterns, Solidity ``external``/``public``, etc.) requires per-language
parser support for decorators/visibility and is planned for a follow-up.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from trailmark.models.annotations import (
    AssetValue,
    EntrypointKind,
    EntrypointTag,
    TrustLevel,
)
from trailmark.models.graph import CodeGraph

OVERRIDE_FILE = ".trailmark/entrypoints.toml"

_KIND_BY_NAME = {k.value: k for k in EntrypointKind}
_TRUST_BY_NAME = {t.value: t for t in TrustLevel}
_ASSET_BY_NAME = {a.value: a for a in AssetValue}


def detect_entrypoints(graph: CodeGraph, root_path: str) -> dict[str, EntrypointTag]:
    """Return detected entrypoints for ``graph`` rooted at ``root_path``.

    Callers typically merge the result into ``graph.entrypoints``:

        graph.entrypoints.update(detect_entrypoints(graph, path))

    Args:
        graph: The parsed code graph.
        root_path: Absolute or repository-relative path the parser walked.

    Returns:
        Mapping of node id -> EntrypointTag. Empty dict if no entrypoints
        are detected.
    """
    root = Path(root_path).resolve()
    repo_root = _find_repo_root(root)

    # Priority (least to most specific, later layers override earlier):
    #   1. Generic `main` functions — fallback heuristic.
    #   2. pyproject.toml [project.scripts] — explicitly-declared CLI targets.
    #   3. Override file — hand-curated, authoritative.
    detected: dict[str, EntrypointTag] = {}
    detected.update(_detect_main_functions(graph))
    detected.update(_detect_pyproject_scripts(graph, repo_root))
    detected.update(_load_override_file(graph, repo_root))
    return detected


def _find_repo_root(start: Path) -> Path:
    """Walk up until we find a directory with pyproject.toml, or give up.

    Falls back to ``start`` if nothing is found so the caller still has a
    sensible base path for the override file lookup.
    """
    for candidate in (start, *start.parents):
        if (candidate / "pyproject.toml").exists():
            return candidate
        if (candidate / OVERRIDE_FILE).exists():
            return candidate
    return start


def _detect_main_functions(graph: CodeGraph) -> dict[str, EntrypointTag]:
    """Mark any top-level function named ``main`` as a CLI entrypoint.

    Uses TRUSTED_INTERNAL because the developer explicitly invoked it —
    it's an API boundary but not an external attacker surface by default.
    Users who want a stricter posture can override via the override file.
    """
    result: dict[str, EntrypointTag] = {}
    for node_id, unit in graph.nodes.items():
        if unit.name != "main":
            continue
        if unit.kind.value not in {"function", "method"}:
            continue
        result[node_id] = EntrypointTag(
            kind=EntrypointKind.USER_INPUT,
            trust_level=TrustLevel.TRUSTED_INTERNAL,
            description="CLI main() entrypoint",
            asset_value=AssetValue.LOW,
        )
    return result


def _detect_pyproject_scripts(
    graph: CodeGraph,
    repo_root: Path,
) -> dict[str, EntrypointTag]:
    """Read ``[project.scripts]`` from pyproject.toml and tag each target.

    Entries take the form ``name = "module.path:function"``. We locate the
    matching node by (file path suffix, function name) because Trailmark's
    node IDs use file basenames rather than full module paths.
    """
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.exists():
        return {}

    try:
        data = tomllib.loads(pyproject.read_text())
    except (OSError, ValueError):
        return {}

    project = data.get("project")
    if not isinstance(project, dict):
        return {}
    scripts_raw = project.get("scripts")
    if not isinstance(scripts_raw, dict):
        return {}

    result: dict[str, EntrypointTag] = {}
    for _script_name, target in scripts_raw.items():
        if not isinstance(target, str) or ":" not in target:
            continue
        module_path, func_name = target.rsplit(":", 1)
        node_id = _resolve_script_target(graph, module_path, func_name)
        if node_id is None:
            continue
        result[node_id] = EntrypointTag(
            kind=EntrypointKind.USER_INPUT,
            trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
            description=f"pyproject.toml [project.scripts] entry ({target})",
            asset_value=AssetValue.MEDIUM,
        )
    return result


def _resolve_script_target(
    graph: CodeGraph,
    module_path: str,
    func_name: str,
) -> str | None:
    """Find the node id matching a ``module.path:function`` script target."""
    suffix = module_path.replace(".", "/") + ".py"
    for node_id, unit in graph.nodes.items():
        if unit.name != func_name:
            continue
        if unit.location.file_path.endswith(suffix):
            return node_id
    return None


def _load_override_file(
    graph: CodeGraph,
    repo_root: Path,
) -> dict[str, EntrypointTag]:
    """Parse ``.trailmark/entrypoints.toml`` into EntrypointTag entries.

    Expected schema:

        [[entrypoint]]
        node = "cli:main"          # node id OR "module.path:function"
        kind = "api"               # EntrypointKind value
        trust = "untrusted_external"  # TrustLevel value (optional)
        asset_value = "high"       # AssetValue value (optional)
        description = "HTTP handler"  # optional
    """
    path = repo_root / OVERRIDE_FILE
    if not path.exists():
        return {}

    try:
        data = tomllib.loads(path.read_text())
    except (OSError, ValueError):
        return {}

    entries = data.get("entrypoint")
    if not isinstance(entries, list):
        return {}

    result: dict[str, EntrypointTag] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        tag_and_id = _entry_to_tag(graph, entry)
        if tag_and_id is None:
            continue
        node_id, tag = tag_and_id
        result[node_id] = tag
    return result


def _entry_to_tag(
    graph: CodeGraph,
    entry: dict[str, Any],
) -> tuple[str, EntrypointTag] | None:
    node_ref = entry.get("node")
    if not isinstance(node_ref, str):
        return None
    node_id = _resolve_override_node(graph, node_ref)
    if node_id is None:
        return None

    kind_name = entry.get("kind", "user_input")
    trust_name = entry.get("trust", "untrusted_external")
    asset_name = entry.get("asset_value", "medium")
    description = entry.get("description")

    kind = _KIND_BY_NAME.get(kind_name)
    trust = _TRUST_BY_NAME.get(trust_name)
    asset = _ASSET_BY_NAME.get(asset_name)
    if kind is None or trust is None or asset is None:
        return None

    return node_id, EntrypointTag(
        kind=kind,
        trust_level=trust,
        description=description if isinstance(description, str) else None,
        asset_value=asset,
    )


def _resolve_override_node(graph: CodeGraph, reference: str) -> str | None:
    """Resolve an override reference to a concrete node id.

    Accepts either a literal node id (``cli:main``) or a Python-style
    ``module.path:function`` reference, which we resolve the same way
    pyproject.toml scripts are resolved.
    """
    if reference in graph.nodes:
        return reference
    if ":" in reference:
        module_path, func_name = reference.rsplit(":", 1)
        return _resolve_script_target(graph, module_path, func_name)
    return None


