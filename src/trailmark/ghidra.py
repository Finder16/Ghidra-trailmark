"""Ghidra headless harness integration for Trailmark."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from trailmark.models.annotations import EntrypointKind, EntrypointTag, TrustLevel
from trailmark.models.edges import CodeEdge, EdgeConfidence, EdgeKind
from trailmark.models.graph import CodeGraph
from trailmark.models.nodes import CodeUnit, NodeKind, Parameter, SourceLocation, TypeRef

_EXPORT_SCHEMA_VERSION = 1
_EXPORT_SCRIPT_NAME = "trailmark_ghidra_export.py"
_EXPORT_JSON_NAME = "trailmark_ghidra_export.json"

_EXPORT_SCRIPT = """#@category Trailmark

from __future__ import print_function

import json


def _hex_addr(addr):
    if addr is None:
        return None
    return "0x%x" % int(addr.getOffset())


def _prototype(function):
    try:
        return function.getPrototypeString(True, True)
    except Exception:
        return function.getName()


def _qualified_name(function):
    try:
        return function.getName(True)
    except Exception:
        return function.getName()


def _namespace(function):
    namespace = function.getParentNamespace()
    if namespace is None:
        return None
    try:
        return namespace.getName(True)
    except Exception:
        return namespace.getName()


def _type_name(data_type):
    if data_type is None:
        return None
    try:
        return data_type.getDisplayName()
    except Exception:
        return str(data_type)


def _parameter_dict(parameter):
    return {
        "name": parameter.getName(),
        "type": _type_name(parameter.getDataType()),
    }


def _function_dict(function):
    body = function.getBody()
    end_address = None
    if body is not None and not body.isEmpty():
        end_address = _hex_addr(body.getMaxAddress())

    return {
        "name": function.getName(),
        "qualified_name": _qualified_name(function),
        "namespace": _namespace(function),
        "entry_address": _hex_addr(function.getEntryPoint()),
        "end_address": end_address or _hex_addr(function.getEntryPoint()),
        "signature": _prototype(function),
        "calling_convention": function.getCallingConventionName(),
        "return_type": _type_name(function.getReturnType()),
        "parameters": [_parameter_dict(param) for param in function.getParameters()],
        "is_external": bool(function.isExternal()),
        "is_thunk": bool(function.isThunk()),
    }


def _function_map(function_manager):
    mapping = {}
    iterator = function_manager.getFunctions(True)
    while iterator.hasNext():
        function = iterator.next()
        mapping[_hex_addr(function.getEntryPoint())] = function
    return mapping


def _functions(function_manager):
    functions = []
    iterator = function_manager.getFunctions(True)
    while iterator.hasNext():
        functions.append(_function_dict(iterator.next()))
    return functions


def _entry_points(function_manager):
    mapping = _function_map(function_manager)
    points = []
    seen = set()
    iterator = currentProgram.getSymbolTable().getExternalEntryPointIterator()
    while iterator.hasNext():
        address = iterator.next()
        function = function_manager.getFunctionContaining(address)
        if function is not None:
            address_text = _hex_addr(function.getEntryPoint())
        else:
            address_text = _hex_addr(address)
        if address_text and address_text not in seen:
            points.append(address_text)
            seen.add(address_text)
    return points


def _call_edges(function_manager):
    edges = []
    seen = set()
    listing = currentProgram.getListing()
    functions = function_manager.getFunctions(True)
    while functions.hasNext():
        function = functions.next()
        body = function.getBody()
        if body is None or body.isEmpty():
            continue

        instructions = listing.getInstructions(body, True)
        while instructions.hasNext():
            instruction = instructions.next()
            references = instruction.getReferencesFrom()
            for reference in references:
                ref_type = reference.getReferenceType()
                if not ref_type.isCall():
                    continue
                target = function_manager.getFunctionAt(reference.getToAddress())
                if target is None:
                    target = function_manager.getFunctionContaining(reference.getToAddress())
                if target is None:
                    continue

                source_address = _hex_addr(function.getEntryPoint())
                target_address = _hex_addr(target.getEntryPoint())
                callsite = _hex_addr(reference.getFromAddress())
                key = (source_address, target_address, callsite)
                if key in seen:
                    continue
                seen.add(key)
                edges.append(
                    {
                        "source_address": source_address,
                        "target_address": target_address,
                        "callsite_address": callsite,
                        "confidence": "certain",
                    }
                )
    return edges


def main():
    args = getScriptArgs()
    if len(args) != 1:
        raise Exception("Expected exactly one argument: output JSON path")

    function_manager = currentProgram.getFunctionManager()
    document = {
        "schema_version": 1,
        "binary": {
            "name": currentProgram.getName(),
            "path": currentProgram.getExecutablePath(),
            "language_id": str(currentProgram.getLanguageID()),
            "compiler": str(currentProgram.getCompilerSpec().getCompilerSpecID()),
            "image_base": _hex_addr(currentProgram.getImageBase()),
        },
        "functions": _functions(function_manager),
        "calls": _call_edges(function_manager),
        "entry_points": _entry_points(function_manager),
    }

    output_path = args[0]
    with open(output_path, "w") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)

    print("Trailmark export written to %s" % output_path)


main()
"""


def analyze_binary(
    binary_path: str,
    *,
    ghidra_install_dir: str | None = None,
) -> CodeGraph:
    """Analyze ``binary_path`` with Ghidra headless and return a ``CodeGraph``."""
    binary = Path(binary_path).expanduser().resolve()
    if not binary.exists():
        msg = f"Binary does not exist: {binary}"
        raise ValueError(msg)

    analyze_headless = resolve_analyze_headless(ghidra_install_dir)
    project_name = _project_name(binary)

    with tempfile.TemporaryDirectory(prefix="trailmark-ghidra-") as temp_dir:
        scratch = Path(temp_dir)
        project_dir = scratch / "project"
        project_dir.mkdir()
        user_home = scratch / "home"
        user_home.mkdir()
        xdg_config_home = user_home / ".config"
        xdg_cache_home = user_home / ".cache"
        xdg_config_home.mkdir()
        xdg_cache_home.mkdir()
        export_path = scratch / _EXPORT_JSON_NAME
        script_path = scratch / _EXPORT_SCRIPT_NAME
        script_path.write_text(_EXPORT_SCRIPT)
        env = os.environ.copy()
        env["HOME"] = str(user_home)
        env["USER_HOME"] = str(user_home)
        env["XDG_CONFIG_HOME"] = str(xdg_config_home)
        env["XDG_CACHE_HOME"] = str(xdg_cache_home)

        cmd = [
            str(analyze_headless),
            str(project_dir),
            project_name,
            "-import",
            str(binary),
            "-scriptPath",
            str(scratch),
            "-postScript",
            _EXPORT_SCRIPT_NAME,
            str(export_path),
            "-deleteProject",
        ]

        try:
            result = subprocess.run(  # noqa: S603
                cmd,
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
        except subprocess.CalledProcessError as exc:  # pragma: no cover - exercised via tests
            details = exc.stderr.strip() or exc.stdout.strip() or str(exc)
            msg = f"Ghidra headless analysis failed: {details}"
            raise RuntimeError(msg) from exc

        if not export_path.exists():
            details = "\n".join(
                text.strip() for text in (result.stdout, result.stderr) if text and text.strip()
            )
            msg = "Ghidra headless finished without producing an export JSON file."
            if details:
                msg = f"{msg} {details}"
            raise RuntimeError(msg)

        return load_ghidra_export(str(export_path))


def load_ghidra_export(path: str) -> CodeGraph:
    """Load a Trailmark-compatible graph from a Ghidra export JSON file."""
    export_path = Path(path)
    with export_path.open() as handle:
        document = json.load(handle)
    return _graph_from_export(document, export_path)


def resolve_analyze_headless(ghidra_install_dir: str | None = None) -> Path:
    """Resolve the ``analyzeHeadless`` executable from a Ghidra install root."""
    install_root = _resolve_install_root(ghidra_install_dir)
    candidates = [install_root / "support" / "analyzeHeadless"]
    dist_root = install_root / "build" / "dist"
    if dist_root.exists():
        candidates.extend(sorted(dist_root.glob("*/support/analyzeHeadless"), reverse=True))
    candidates.append(
        install_root / "Ghidra" / "RuntimeScripts" / "Linux" / "support" / "analyzeHeadless"
    )

    for candidate in candidates:
        if candidate.exists():
            return candidate

    msg = (
        f"Could not locate analyzeHeadless under {install_root}. "
        "Set GHIDRA_INSTALL_DIR or pass --ghidra-install-dir."
    )
    raise ValueError(msg)


def _resolve_install_root(ghidra_install_dir: str | None) -> Path:
    configured = ghidra_install_dir or os.environ.get("GHIDRA_INSTALL_DIR")
    if not configured:
        msg = "Ghidra install dir is required. Set GHIDRA_INSTALL_DIR or pass one explicitly."
        raise ValueError(msg)
    return Path(configured).expanduser().resolve()


def _graph_from_export(document: dict[str, Any], export_path: Path) -> CodeGraph:
    schema_version = document.get("schema_version")
    if schema_version != _EXPORT_SCHEMA_VERSION:
        msg = (
            f"Unsupported Ghidra export schema version: {schema_version!r}. "
            f"Expected {_EXPORT_SCHEMA_VERSION}."
        )
        raise ValueError(msg)

    binary_info = document.get("binary", {})
    raw_binary_path = binary_info.get("path")
    if raw_binary_path:
        binary_path = str(Path(raw_binary_path).resolve())
    else:
        binary_path = str(export_path.resolve())
    program_name = str(binary_info.get("name") or Path(binary_path).name)
    image_base = _text_or_none(binary_info.get("image_base"))
    language_id = _text_or_none(binary_info.get("language_id"))
    module_id = _module_id(binary_path, program_name)

    nodes: dict[str, CodeUnit] = {}
    edges: list[CodeEdge] = []
    addr_to_id: dict[str, str] = {}

    module_location = _binary_location(binary_path, image_base, image_base)
    nodes[module_id] = CodeUnit(
        id=module_id,
        name=program_name,
        kind=NodeKind.MODULE,
        location=module_location,
        docstring="Imported from a Ghidra headless export.",
    )

    dependencies: set[str] = set()

    for raw_function in document.get("functions", []):
        entry_address = _text_or_none(raw_function.get("entry_address"))
        if entry_address is None:
            continue
        node_id = _function_id(module_id, raw_function, entry_address)
        addr_to_id[entry_address] = node_id

        namespace = _text_or_none(raw_function.get("namespace"))
        if raw_function.get("is_external") and namespace not in {None, "", "Global"}:
            dependencies.add(namespace)

        nodes[node_id] = CodeUnit(
            id=node_id,
            name=str(raw_function.get("name") or entry_address),
            kind=NodeKind.FUNCTION,
            location=_binary_location(
                binary_path,
                entry_address,
                _text_or_none(raw_function.get("end_address")) or entry_address,
            ),
            parameters=_parameters(raw_function.get("parameters", [])),
            return_type=_type_ref(raw_function.get("return_type")),
            docstring=_text_or_none(raw_function.get("signature")),
        )
        edges.append(
            CodeEdge(
                source_id=module_id,
                target_id=node_id,
                kind=EdgeKind.CONTAINS,
            )
        )

    for raw_call in document.get("calls", []):
        source_id = addr_to_id.get(_text_or_none(raw_call.get("source_address")) or "")
        target_id = addr_to_id.get(_text_or_none(raw_call.get("target_address")) or "")
        if source_id is None or target_id is None:
            continue
        callsite = _text_or_none(raw_call.get("callsite_address"))
        edges.append(
            CodeEdge(
                source_id=source_id,
                target_id=target_id,
                kind=EdgeKind.CALLS,
                confidence=_confidence(raw_call.get("confidence")),
                location=_binary_location(binary_path, callsite, callsite) if callsite else None,
            )
        )

    entrypoints: dict[str, EntrypointTag] = {}
    for entry_address in document.get("entry_points", []):
        node_id = addr_to_id.get(_text_or_none(entry_address) or "")
        if node_id is None:
            continue
        entrypoints[node_id] = EntrypointTag(
            kind=EntrypointKind.API,
            trust_level=TrustLevel.TRUSTED_INTERNAL,
            description="Ghidra-reported binary entry point",
        )

    graph_language = f"ghidra:{language_id}" if language_id else "ghidra"
    return CodeGraph(
        nodes=nodes,
        edges=edges,
        entrypoints=entrypoints,
        dependencies=sorted(dependencies),
        language=graph_language,
        root_path=binary_path,
    )


def _binary_location(
    binary_path: str,
    start_address: str | None,
    end_address: str | None,
) -> SourceLocation:
    return SourceLocation(
        file_path=binary_path,
        start_line=1,
        end_line=1,
        start_address=start_address,
        end_address=end_address,
    )


def _confidence(raw: object | None) -> EdgeConfidence:
    if isinstance(raw, str):
        for confidence in EdgeConfidence:
            if confidence.value == raw:
                return confidence
    return EdgeConfidence.CERTAIN


def _function_id(module_id: str, raw_function: dict[str, Any], entry_address: str) -> str:
    qualified_name = _text_or_none(raw_function.get("qualified_name"))
    name = qualified_name or _text_or_none(raw_function.get("name")) or "sub"
    return f"{module_id}:{name}@{entry_address}"


def _module_id(binary_path: str, program_name: str) -> str:
    stem = Path(binary_path).stem or program_name or "binary"
    return stem.replace(" ", "_")


def _parameters(raw_parameters: list[dict[str, Any]]) -> tuple[Parameter, ...]:
    params: list[Parameter] = []
    for raw in raw_parameters:
        params.append(
            Parameter(
                name=str(raw.get("name") or "param"),
                type_ref=_type_ref(raw.get("type")),
            )
        )
    return tuple(params)


def _project_name(binary: Path) -> str:
    return f"trailmark_{binary.stem}"


def _text_or_none(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _type_ref(type_name: object | None) -> TypeRef | None:
    text = _text_or_none(type_name)
    if text is None:
        return None
    return TypeRef(name=text)


__all__ = [
    "analyze_binary",
    "load_ghidra_export",
    "resolve_analyze_headless",
]
