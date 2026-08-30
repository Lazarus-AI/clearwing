from clearwing.sourcehunt.callgraph import CallGraph, FunctionInfo
from clearwing.ui.commands.visualize import _render_html


def _callgraph(file_name: str = "src/main.c", function_name: str = "main") -> CallGraph:
    graph = CallGraph()
    graph.functions[file_name].add(function_name)
    graph.defined_in[function_name].add(file_name)
    graph.function_info[file_name].append(FunctionInfo(function_name, 1, 3))
    graph.func_calls_out[file_name][function_name].add("external")
    return graph


def test_callgraph_json_round_trip() -> None:
    original = _callgraph()

    restored = CallGraph.from_json(original.to_json())

    assert restored.functions == original.functions
    assert restored.defined_in == original.defined_in
    assert restored.function_info == original.function_info
    assert restored.func_calls_out == original.func_calls_out


def test_render_html_escapes_repository_controlled_script_markup() -> None:
    graph = _callgraph("src/</script><script>alert(1)</script>.c", "danger")

    html = _render_html(graph)

    assert "</script><script>alert(1)</script>" not in html
    assert r"\u003c/script\u003e\u003cscript\u003ealert(1)" in html
