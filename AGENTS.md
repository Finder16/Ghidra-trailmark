# Agents

Development context for AI agents working on this codebase.

## Project Overview

Trailmark parses source code into directed graphs of functions, classes,
calls, and semantic metadata for security analysis. It supports 16
languages via tree-sitter (plus a bundled Circom grammar) and uses
rustworkx for graph traversal.

## Architecture

```
CodeGraph (data) -> GraphStore (indexed storage) -> QueryEngine (facade)
```

- **CodeGraph** holds raw nodes, edges, annotations, entrypoints. Mutable.
- **GraphStore** wraps CodeGraph in a rustworkx PyDiGraph. Validates
  node existence. Returns model objects.
- **QueryEngine** resolves names to node IDs, delegates to GraphStore,
  returns plain dicts for JSON serialization.

## Key Conventions

- All public methods return `False` or `[]` for missing nodes. Never raise.
- QueryEngine returns dicts; GraphStore returns model objects.
- Node IDs follow `module:function`, `module:Class`, `module:Class.method`.
- Edge confidence: `certain`, `inferred`, `uncertain`.
- Annotation sources: `"llm"`, `"docstring"`, `"manual"`.
- Frozen dataclasses for immutable data. `CodeGraph` is mutable.
- No relative (`..`) imports. Use `from trailmark.*`.

## File Layout

```
src/trailmark/
  models/          # Data classes: CodeUnit, CodeEdge, Annotation, CodeGraph
    graph.py       # CodeGraph with add_annotation, clear_annotations, merge
    nodes.py       # CodeUnit, Parameter, TypeRef, BranchInfo
    edges.py       # CodeEdge, EdgeKind, EdgeConfidence
    annotations.py # Annotation, AnnotationKind, EntrypointTag
  parsers/         # Language-specific tree-sitter parsers
    base.py        # BaseParser protocol
    _common.py     # Shared parser utilities
    python/        # One subpackage per language
    javascript/
    ...
  storage/
    graph_store.py # GraphStore: rustworkx-backed indexed storage
  query/
    api.py         # QueryEngine: high-level facade
  cli.py           # CLI entry point
tests/             # pytest test suite
```

## Running Checks

```bash
uv run ruff check --fix src/ tests/
uv run ruff format src/ tests/
uv run ty check
pytest -q
```

## Mutation Testing

```bash
uv run mutmut run
uv run mutmut results
```

### macOS Fork Safety

mutmut uses `fork()` which segfaults with rustworkx on macOS. Set:

```bash
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```

This is not needed on Linux/CI (Ubuntu).

## Adding Features

- Follow the three-layer pattern: add to CodeGraph first, then GraphStore
  (with validation), then QueryEngine (with name resolution and dict
  conversion).
- Add tests at each layer: `test_models.py`, `test_storage.py`,
  `test_query.py`.
- Update `README.md` if adding user-facing API.
