"""Tests for the C++ language parser."""

from __future__ import annotations

import os
import tempfile

from trailmark.models.edges import EdgeConfidence, EdgeKind
from trailmark.models.graph import CodeGraph
from trailmark.models.nodes import NodeKind
from trailmark.parsers.cpp.parser import CppParser

SAMPLE_CODE = """\
#include <iostream>
#include "utils.hpp"

namespace geometry {

struct Point {
    double x;
    double y;
};

enum Shape {
    CIRCLE,
    SQUARE,
    TRIANGLE
};

/** Base class for all animals. */
class Animal {
public:
    virtual void speak() {
        return;
    }

    int age() {
        return 0;
    }
};

class Dog : public Animal {
public:
    void speak() {
        return;
    }

    bool fetch(int item) {
        if (item <= 0) {
            throw std::invalid_argument("bad item");
        }
        return true;
    }
};

}

int compute(int a, int b) {
    int result = a + b;
    if (result > 100) {
        result = 100;
    }
    for (int i = 0; i < b; i++) {
        if (a > i) {
            result += i;
        }
    }
    while (result < 0) {
        result += 10;
    }
    return result;
}

void run_all(void) {
    int val = compute(10, 20);
    std::cout << val << std::endl;
}
"""


def _parse_sample() -> tuple[CppParser, CodeGraph]:
    parser = CppParser()
    with tempfile.NamedTemporaryFile(
        suffix=".cpp",
        mode="w",
        delete=False,
    ) as f:
        f.write(SAMPLE_CODE)
        f.flush()
        graph = parser.parse_file(f.name)
    os.unlink(f.name)
    return parser, graph


class TestCppParserNodes:
    def test_finds_module(self) -> None:
        _, graph = _parse_sample()
        modules = [n for n in graph.nodes.values() if n.kind == NodeKind.MODULE]
        assert len(modules) == 1

    def test_finds_namespace(self) -> None:
        _, graph = _parse_sample()
        nss = [n for n in graph.nodes.values() if n.kind == NodeKind.NAMESPACE]
        names = {n.name for n in nss}
        assert "geometry" in names

    def test_finds_classes(self) -> None:
        _, graph = _parse_sample()
        classes = [n for n in graph.nodes.values() if n.kind == NodeKind.CLASS]
        names = {c.name for c in classes}
        assert "Animal" in names
        assert "Dog" in names

    def test_finds_struct(self) -> None:
        _, graph = _parse_sample()
        structs = [n for n in graph.nodes.values() if n.kind == NodeKind.STRUCT]
        names = {s.name for s in structs}
        assert "Point" in names

    def test_finds_enum(self) -> None:
        _, graph = _parse_sample()
        enums = [n for n in graph.nodes.values() if n.kind == NodeKind.ENUM]
        names = {e.name for e in enums}
        assert "Shape" in names

    def test_finds_functions(self) -> None:
        _, graph = _parse_sample()
        funcs = [n for n in graph.nodes.values() if n.kind == NodeKind.FUNCTION]
        names = {f.name for f in funcs}
        assert "compute" in names
        assert "run_all" in names

    def test_finds_methods(self) -> None:
        _, graph = _parse_sample()
        methods = [n for n in graph.nodes.values() if n.kind == NodeKind.METHOD]
        names = {m.name for m in methods}
        assert "speak" in names
        assert "fetch" in names

    def test_class_docstring(self) -> None:
        _, graph = _parse_sample()
        animal = next(n for n in graph.nodes.values() if n.name == "Animal")
        assert animal.docstring is not None
        assert "animal" in animal.docstring.lower()


class TestCppParserParameters:
    def test_function_parameters(self) -> None:
        _, graph = _parse_sample()
        comp = next(n for n in graph.nodes.values() if n.name == "compute")
        assert len(comp.parameters) == 2
        names = {p.name for p in comp.parameters}
        assert "a" in names
        assert "b" in names

    def test_parameter_types(self) -> None:
        _, graph = _parse_sample()
        comp = next(n for n in graph.nodes.values() if n.name == "compute")
        for p in comp.parameters:
            assert p.type_ref is not None
            assert p.type_ref.name == "int"

    def test_return_type(self) -> None:
        _, graph = _parse_sample()
        comp = next(n for n in graph.nodes.values() if n.name == "compute")
        assert comp.return_type is not None
        assert comp.return_type.name == "int"

    def test_method_parameters(self) -> None:
        _, graph = _parse_sample()
        fetch = next(n for n in graph.nodes.values() if n.name == "fetch")
        assert len(fetch.parameters) == 1
        assert fetch.parameters[0].name == "item"


class TestCppParserComplexity:
    def test_simple_function_complexity(self) -> None:
        _, graph = _parse_sample()
        run_fn = next(n for n in graph.nodes.values() if n.name == "run_all")
        assert run_fn.cyclomatic_complexity == 1

    def test_branching_function_complexity(self) -> None:
        _, graph = _parse_sample()
        comp = next(n for n in graph.nodes.values() if n.name == "compute")
        assert comp.cyclomatic_complexity is not None
        assert comp.cyclomatic_complexity >= 4

    def test_branches_tracked(self) -> None:
        _, graph = _parse_sample()
        comp = next(n for n in graph.nodes.values() if n.name == "compute")
        assert len(comp.branches) > 0


class TestCppParserEdges:
    def test_contains_edges(self) -> None:
        _, graph = _parse_sample()
        contains = [e for e in graph.edges if e.kind == EdgeKind.CONTAINS]
        assert len(contains) > 0

    def test_inherits_edge(self) -> None:
        _, graph = _parse_sample()
        inherits = [e for e in graph.edges if e.kind == EdgeKind.INHERITS]
        assert len(inherits) >= 1
        targets = {e.target_id for e in inherits}
        has_animal = any("Animal" in t for t in targets)
        assert has_animal

    def test_call_edges(self) -> None:
        _, graph = _parse_sample()
        calls = [e for e in graph.edges if e.kind == EdgeKind.CALLS]
        assert len(calls) > 0

    def test_exception_type_from_throw(self) -> None:
        _, graph = _parse_sample()
        fetch = next(n for n in graph.nodes.values() if n.name == "fetch")
        assert len(fetch.exception_types) >= 1

    def test_edge_confidence(self) -> None:
        _, graph = _parse_sample()
        calls = [e for e in graph.edges if e.kind == EdgeKind.CALLS]
        certain = [e for e in calls if e.confidence == EdgeConfidence.CERTAIN]
        inferred = [e for e in calls if e.confidence == EdgeConfidence.INFERRED]
        assert len(certain) > 0 or len(inferred) > 0


class TestCppParserDependencies:
    def test_includes_tracked(self) -> None:
        _, graph = _parse_sample()
        assert "iostream" in graph.dependencies
        assert "utils.hpp" in graph.dependencies


EXTRA_CPP_CODE = """\
template<typename T>
T identity(T x) {
    return x;
}

template<typename T>
class Box {
public:
    T value;
    T get() { return value; }
};

typedef struct TypedefPoint {
    int x;
    int y;
} TypedefPoint;

typedef enum TypedefColor {
    RED,
    GREEN,
    BLUE
} TypedefColor;

class WithInline {
public:
    static void staticHelper() { return; }
};
"""


def _parse_extra() -> CodeGraph:
    parser = CppParser()
    with tempfile.NamedTemporaryFile(
        suffix=".cpp",
        mode="w",
        delete=False,
    ) as f:
        f.write(EXTRA_CPP_CODE)
        f.flush()
        graph = parser.parse_file(f.name)
    os.unlink(f.name)
    return graph


class TestCppExtraFeatures:
    def test_template_function_extracted(self) -> None:
        graph = _parse_extra()
        names = {n.name for n in graph.nodes.values()}
        assert "identity" in names

    def test_template_class_extracted(self) -> None:
        graph = _parse_extra()
        names = {n.name for n in graph.nodes.values()}
        assert "Box" in names

    def test_template_class_method(self) -> None:
        graph = _parse_extra()
        names = {n.name for n in graph.nodes.values()}
        assert "get" in names

    def test_typedef_struct_extracted(self) -> None:
        graph = _parse_extra()
        structs = [n for n in graph.nodes.values() if n.kind == NodeKind.STRUCT]
        names = {s.name for s in structs}
        assert "TypedefPoint" in names

    def test_typedef_enum_extracted(self) -> None:
        graph = _parse_extra()
        enums = [n for n in graph.nodes.values() if n.kind == NodeKind.ENUM]
        names = {e.name for e in enums}
        assert "TypedefColor" in names

    def test_inline_declaration_method(self) -> None:
        graph = _parse_extra()
        names = {n.name for n in graph.nodes.values()}
        assert "WithInline" in names


class TestCppParseDirectory:
    def test_parses_multiple_files(self) -> None:
        parser = CppParser()
        code_a = "void fromA() {}\n"
        code_b = "void fromB() {}\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            for name, code in [("a.cpp", code_a), ("b.cpp", code_b)]:
                path = os.path.join(tmpdir, name)
                with open(path, "w") as f:
                    f.write(code)
            graph = parser.parse_directory(tmpdir)
        assert graph.language == "cpp"
        assert graph.root_path == tmpdir
        names = {n.name for n in graph.nodes.values()}
        assert "fromA" in names
        assert "fromB" in names

    def test_ignores_wrong_extensions(self) -> None:
        parser = CppParser()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "skip.txt")
            with open(path, "w") as f:
                f.write("not source code")
            graph = parser.parse_directory(tmpdir)
        assert len(graph.nodes) == 0
