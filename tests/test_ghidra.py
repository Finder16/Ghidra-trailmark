"""Tests for Ghidra headless integration."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from trailmark.ghidra import analyze_binary, load_ghidra_export, resolve_analyze_headless
from trailmark.query.api import QueryEngine


def _export_doc(binary_path: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "binary": {
            "name": "sample.bin",
            "path": binary_path,
            "language_id": "x86:LE:64:default",
            "compiler": "gcc",
            "image_base": "0x401000",
        },
        "functions": [
            {
                "name": "main",
                "qualified_name": "main",
                "namespace": "Global",
                "entry_address": "0x401000",
                "end_address": "0x40101f",
                "signature": "int main(void)",
                "calling_convention": "__cdecl",
                "return_type": "int",
                "parameters": [],
                "is_external": False,
                "is_thunk": False,
            },
            {
                "name": "helper",
                "qualified_name": "helper",
                "namespace": "Global",
                "entry_address": "0x401050",
                "end_address": "0x40107f",
                "signature": "void helper(void)",
                "calling_convention": "__cdecl",
                "return_type": "void",
                "parameters": [],
                "is_external": False,
                "is_thunk": False,
            },
            {
                "name": "puts",
                "qualified_name": "puts",
                "namespace": "libc",
                "entry_address": "0x500000",
                "end_address": "0x500000",
                "signature": "int puts(char * s)",
                "calling_convention": "__cdecl",
                "return_type": "int",
                "parameters": [{"name": "s", "type": "char *"}],
                "is_external": True,
                "is_thunk": False,
            },
        ],
        "calls": [
            {
                "source_address": "0x401000",
                "target_address": "0x401050",
                "callsite_address": "0x401010",
                "confidence": "certain",
            },
            {
                "source_address": "0x401050",
                "target_address": "0x500000",
                "callsite_address": "0x401060",
                "confidence": "certain",
            },
        ],
        "entry_points": ["0x401000"],
    }


class TestResolveAnalyzeHeadless:
    def test_resolves_standard_install_layout(self, tmp_path: Path) -> None:
        analyze = tmp_path / "support" / "analyzeHeadless"
        analyze.parent.mkdir(parents=True)
        analyze.write_text("#!/bin/sh\n")

        resolved = resolve_analyze_headless(str(tmp_path))

        assert resolved == analyze

    def test_resolves_built_source_tree_layout(self, tmp_path: Path) -> None:
        analyze = tmp_path / "build" / "dist" / "ghidra_dev" / "support" / "analyzeHeadless"
        analyze.parent.mkdir(parents=True)
        analyze.write_text("#!/bin/sh\n")

        resolved = resolve_analyze_headless(str(tmp_path))

        assert resolved == analyze

    def test_rejects_missing_install(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="Could not locate analyzeHeadless"):
            resolve_analyze_headless(str(tmp_path))


class TestLoadGhidraExport:
    def test_load_ghidra_export_builds_queryable_graph(self, tmp_path: Path) -> None:
        binary = tmp_path / "sample.bin"
        export = tmp_path / "export.json"
        export.write_text(json.dumps(_export_doc(str(binary))))

        graph = load_ghidra_export(str(export))
        engine = QueryEngine.from_graph(graph)

        assert graph.language == "ghidra:x86:LE:64:default"
        assert graph.root_path == str(binary.resolve())
        assert graph.dependencies == ["libc"]
        assert "sample" in graph.nodes
        assert "sample:main@0x401000" in graph.nodes
        assert graph.nodes["sample:main@0x401000"].location.start_address == "0x401000"
        assert graph.nodes["sample:helper@0x401050"].location.end_address == "0x40107f"
        assert [node["name"] for node in engine.callees_of("main")] == ["helper"]
        assert [node["name"] for node in engine.callees_of("helper")] == ["puts"]
        assert engine.attack_surface()[0]["node_id"] == "sample:main@0x401000"

    def test_query_engine_from_ghidra_export(self, tmp_path: Path) -> None:
        binary = tmp_path / "sample.bin"
        export = tmp_path / "export.json"
        export.write_text(json.dumps(_export_doc(str(binary))))

        engine = QueryEngine.from_ghidra_export(str(export))

        assert [node["name"] for node in engine.callers_of("puts")] == ["helper"]

    def test_rejects_unknown_schema_version(self, tmp_path: Path) -> None:
        export = tmp_path / "export.json"
        export.write_text(json.dumps({"schema_version": 99}))

        with pytest.raises(ValueError, match="Unsupported Ghidra export schema version"):
            load_ghidra_export(str(export))


class TestAnalyzeBinary:
    def test_analyze_binary_runs_headless_and_imports_export(self, tmp_path: Path) -> None:
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x7fELF")

        def _fake_run(
            cmd: list[str],
            *,
            check: bool,
            capture_output: bool,
            text: bool,
            env: dict[str, str],
        ) -> subprocess.CompletedProcess[str]:
            assert check is True
            assert capture_output is True
            assert text is True
            assert env["HOME"] == env["USER_HOME"]
            assert env["XDG_CONFIG_HOME"].endswith("/.config")
            assert env["XDG_CACHE_HOME"].endswith("/.cache")
            assert "-postScript" in cmd
            assert "-import" in cmd
            export_path = Path(cmd[-2])
            export_path.write_text(json.dumps(_export_doc(str(binary))))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with (
            patch(
                "trailmark.ghidra.resolve_analyze_headless",
                return_value=Path("/ghidra/analyzeHeadless"),
            ),
            patch("trailmark.ghidra.subprocess.run", side_effect=_fake_run) as mock_run,
        ):
            graph = analyze_binary(str(binary), ghidra_install_dir="/ghidra")

        assert mock_run.called
        assert "sample:main@0x401000" in graph.nodes
        assert graph.root_path == str(binary.resolve())

    def test_query_engine_from_binary_uses_ghidra_backend(self, tmp_path: Path) -> None:
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x7fELF")

        def _fake_run(
            cmd: list[str],
            *,
            check: bool,
            capture_output: bool,
            text: bool,
            env: dict[str, str],
        ) -> subprocess.CompletedProcess[str]:
            export_path = Path(cmd[-2])
            export_path.write_text(json.dumps(_export_doc(str(binary))))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with (
            patch(
                "trailmark.ghidra.resolve_analyze_headless",
                return_value=Path("/ghidra/analyzeHeadless"),
            ),
            patch("trailmark.ghidra.subprocess.run", side_effect=_fake_run),
        ):
            engine = QueryEngine.from_binary(str(binary), ghidra_install_dir="/ghidra")

        assert [node["name"] for node in engine.callees_of("main")] == ["helper"]
