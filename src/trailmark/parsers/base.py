"""Base protocol for language parsers."""

from __future__ import annotations

from typing import Protocol

from trailmark.models.graph import CodeGraph


class LanguageParser(Protocol):
    """Interface that all language parsers must implement."""

    @property
    def language(self) -> str:
        """The language this parser handles (e.g., 'python')."""
        ...

    def parse_file(self, file_path: str) -> CodeGraph:
        """Parse a single source file into a code graph."""
        ...

    def parse_directory(self, dir_path: str) -> CodeGraph:
        """Parse all source files in a directory into a merged graph."""
        ...
