"""Tests for automatic entrypoint detection.

Regression guard: an earlier version of Trailmark silently returned no
entrypoints because no parser populated ``graph.entrypoints``. These
tests lock in that entrypoint detection runs automatically and that the
three detection layers (main heuristic, pyproject scripts, override
file) have the intended precedence.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trailmark.analysis.entrypoints import detect_entrypoints
from trailmark.models.annotations import AssetValue, EntrypointKind, TrustLevel
from trailmark.query.api import QueryEngine

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"


class TestSelfAnalysis:
    """Running Trailmark on its own source must produce entrypoints.

    This is the regression test for the Codex-discovered bug where
    ``graph.entrypoints`` was never populated and ``attack_surface()``
    silently returned an empty list.
    """

    def test_self_analysis_has_entrypoints(self) -> None:
        engine = QueryEngine.from_directory(str(SRC), language="python")
        summary = engine.summary()
        assert summary["entrypoints"] > 0, (
            "Running Trailmark on its own src/ must detect at least one "
            "entrypoint (the pyproject [project.scripts] target)."
        )

    def test_self_analysis_attack_surface_nonempty(self) -> None:
        engine = QueryEngine.from_directory(str(SRC), language="python")
        surface = engine.attack_surface()
        assert surface, "attack_surface() returned empty on trailmark's own source"

    def test_self_analysis_finds_pyproject_script(self) -> None:
        engine = QueryEngine.from_directory(str(SRC), language="python")
        surface = engine.attack_surface()
        node_ids = {ep["node_id"] for ep in surface}
        assert "cli:main" in node_ids, (
            f"Expected cli:main (the pyproject.toml script target) in {node_ids}"
        )


class TestMainHeuristic:
    def test_bare_main_function_detected(self, tmp_path: Path) -> None:
        sample = tmp_path / "tool.py"
        sample.write_text("def main():\n    return 0\n")
        engine = QueryEngine.from_directory(str(tmp_path))
        surface = engine.attack_surface()
        ids = {ep["node_id"] for ep in surface}
        assert "tool:main" in ids

    def test_main_gets_trusted_internal_by_default(self, tmp_path: Path) -> None:
        sample = tmp_path / "tool.py"
        sample.write_text("def main():\n    pass\n")
        engine = QueryEngine.from_directory(str(tmp_path))
        (ep,) = engine.attack_surface()
        assert ep["trust_level"] == "trusted_internal"

    def test_non_main_function_not_detected(self, tmp_path: Path) -> None:
        sample = tmp_path / "tool.py"
        sample.write_text("def helper():\n    pass\n")
        engine = QueryEngine.from_directory(str(tmp_path))
        assert engine.attack_surface() == []


class TestPyprojectScripts:
    def test_pyproject_script_overrides_main_heuristic(self, tmp_path: Path) -> None:
        """A pyproject.toml script target beats the generic main heuristic."""
        (tmp_path / "pyproject.toml").write_text(
            '[project]\n'
            'name = "demo"\n'
            'version = "0.0.0"\n'
            '[project.scripts]\n'
            'demo = "demo:main"\n',
        )
        src = tmp_path / "demo.py"
        src.write_text("def main():\n    pass\n")

        engine = QueryEngine.from_directory(str(tmp_path))
        (ep,) = engine.attack_surface()
        assert ep["node_id"] == "demo:main"
        assert ep["trust_level"] == "untrusted_external"
        assert ep["asset_value"] == "medium"

    def test_pyproject_script_in_parent_is_discovered(self, tmp_path: Path) -> None:
        """Detection walks up from the parse path to find pyproject.toml."""
        (tmp_path / "pyproject.toml").write_text(
            '[project]\n'
            'name = "demo"\n'
            'version = "0.0.0"\n'
            '[project.scripts]\n'
            'demo = "pkg.app:main"\n',
        )
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "app.py").write_text("def main():\n    pass\n")

        engine = QueryEngine.from_directory(str(pkg))
        ids = {ep["node_id"] for ep in engine.attack_surface()}
        assert "app:main" in ids

    def test_malformed_pyproject_is_tolerated(self, tmp_path: Path) -> None:
        """A broken pyproject.toml must not crash detection."""
        (tmp_path / "pyproject.toml").write_text("this is not valid toml = [")
        (tmp_path / "tool.py").write_text("def main():\n    pass\n")
        engine = QueryEngine.from_directory(str(tmp_path))
        # main heuristic still fires
        assert engine.attack_surface()


class TestOverrideFile:
    def _write_override(self, tmp_path: Path, body: str) -> None:
        (tmp_path / ".trailmark").mkdir()
        (tmp_path / ".trailmark" / "entrypoints.toml").write_text(body)

    def test_override_adds_entrypoint(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("def handle_request(req):\n    pass\n")
        self._write_override(
            tmp_path,
            '[[entrypoint]]\n'
            'node = "app:handle_request"\n'
            'kind = "api"\n'
            'trust = "untrusted_external"\n'
            'asset_value = "high"\n'
            'description = "HTTP handler"\n',
        )
        engine = QueryEngine.from_directory(str(tmp_path))
        (ep,) = engine.attack_surface()
        assert ep["node_id"] == "app:handle_request"
        assert ep["kind"] == "api"
        assert ep["trust_level"] == "untrusted_external"
        assert ep["asset_value"] == "high"
        assert ep["description"] == "HTTP handler"

    def test_override_beats_pyproject_and_main(self, tmp_path: Path) -> None:
        """Override file is the final word."""
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\nversion = "0"\n'
            '[project.scripts]\nx = "app:main"\n',
        )
        (tmp_path / "app.py").write_text("def main():\n    pass\n")
        self._write_override(
            tmp_path,
            '[[entrypoint]]\n'
            'node = "app:main"\n'
            'kind = "api"\n'
            'trust = "untrusted_external"\n'
            'asset_value = "high"\n',
        )
        engine = QueryEngine.from_directory(str(tmp_path))
        (ep,) = engine.attack_surface()
        assert ep["kind"] == "api"  # override, not user_input
        assert ep["asset_value"] == "high"  # override, not medium

    def test_override_accepts_module_reference(self, tmp_path: Path) -> None:
        """Override `node = "module.path:func"` resolves like pyproject scripts."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "app.py").write_text("def serve():\n    pass\n")
        self._write_override(
            tmp_path,
            '[[entrypoint]]\n'
            'node = "pkg.app:serve"\n'
            'kind = "api"\n',
        )
        engine = QueryEngine.from_directory(str(tmp_path))
        ids = {ep["node_id"] for ep in engine.attack_surface()}
        assert "app:serve" in ids

    def test_override_unknown_node_is_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("def real():\n    pass\n")
        self._write_override(
            tmp_path,
            '[[entrypoint]]\nnode = "nonexistent:func"\nkind = "api"\n',
        )
        engine = QueryEngine.from_directory(str(tmp_path))
        # Nothing matched, no main heuristic trigger either
        assert engine.attack_surface() == []

    def test_override_invalid_enum_is_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("def main():\n    pass\n")
        self._write_override(
            tmp_path,
            '[[entrypoint]]\nnode = "app:main"\nkind = "not-a-real-kind"\n',
        )
        engine = QueryEngine.from_directory(str(tmp_path))
        # Override is skipped, main heuristic still applies
        (ep,) = engine.attack_surface()
        assert ep["trust_level"] == "trusted_internal"

    def test_malformed_override_toml_is_tolerated(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("def main():\n    pass\n")
        self._write_override(tmp_path, "this is not valid toml = [")
        engine = QueryEngine.from_directory(str(tmp_path))
        # Heuristic still runs
        assert engine.attack_surface()


class TestOptOut:
    def test_detection_can_be_disabled(self, tmp_path: Path) -> None:
        """``detect_entrypoints_=False`` skips automatic detection."""
        (tmp_path / "tool.py").write_text("def main():\n    pass\n")
        engine = QueryEngine.from_directory(
            str(tmp_path),
            detect_entrypoints_=False,
        )
        assert engine.attack_surface() == []


class TestDirectAPI:
    """``detect_entrypoints`` can be called directly on a prebuilt graph."""

    def test_returns_mapping_of_node_id_to_tag(self, tmp_path: Path) -> None:
        from trailmark.parsers.python import PythonParser

        (tmp_path / "tool.py").write_text("def main():\n    pass\n")
        graph = PythonParser().parse_directory(str(tmp_path))
        detected = detect_entrypoints(graph, str(tmp_path))

        assert "tool:main" in detected
        tag = detected["tool:main"]
        assert tag.kind == EntrypointKind.USER_INPUT
        assert tag.trust_level == TrustLevel.TRUSTED_INTERNAL
        assert tag.asset_value == AssetValue.LOW


@pytest.fixture(autouse=True)
def _isolate_cwd(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Some tests create pyproject.toml in tmp_path; make sure detection does
    not accidentally pick up Trailmark's own pyproject.toml by walking up
    past tmp_path when the parse path is inside tmp_path.

    This fixture is a no-op for tests that don't rely on tmp_path; it just
    ensures a deterministic cwd.
    """
    monkeypatch.chdir(tmp_path)
