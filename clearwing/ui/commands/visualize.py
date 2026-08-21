"""Visualize callgraph in browser."""

import tempfile
import webbrowser
from pathlib import Path


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "visualize", help="Open interactive callgraph visualization in browser"
    )
    parser.add_argument(
        "path",
        help="Path to repository OR checkpoint.json file",
    )
    parser.add_argument("--output", help="Output HTML file path (default: temp file)")
    parser.add_argument("--no-open", action="store_true", help="Do not open in browser")
    parser.add_argument(
        "--max-nodes",
        type=int,
        default=500,
        help="Max nodes to render (default 500, 0=unlimited)",
    )
    return parser


def handle(cli, args):
    """Build callgraph from repo or load from checkpoint, render in browser."""
    from ...sourcehunt.callgraph import CallGraph, CallGraphBuilder

    target = Path(args.path).resolve()

    if target.is_file() and target.suffix == ".json":
        # Load from checkpoint
        cli.console.print(f"[dim]Loading callgraph from checkpoint {target}...[/dim]")
        from ...sourcehunt.checkpoints import SourceHuntCheckpoint

        ckpt = SourceHuntCheckpoint.from_file(target)
        if ckpt.preprocess is None or ckpt.preprocess.result is None:
            cli.console.print("[red]Checkpoint has no preprocess result[/red]")
            return
        cg_data = ckpt.preprocess.result.get("callgraph")
        if not cg_data:
            cli.console.print("[red]Checkpoint has no callgraph data[/red]")
            return
        cg = CallGraph.from_json(cg_data)
    else:
        # Build from source
        repo_path = str(target)
        cli.console.print(f"[dim]Building callgraph for {repo_path}...[/dim]")
        builder = CallGraphBuilder()
        cg = builder.build(repo_path)

    n_files = len(cg.functions)
    n_funcs = sum(len(fns) for fns in cg.functions.values())
    n_edges = sum(
        len(callees)
        for func_map in cg.func_calls_out.values()
        for callees in func_map.values()
    )

    cli.console.print(
        f"[green]Callgraph:[/green] {n_files} files, {n_funcs} functions, {n_edges} call edges"
    )

    html = _render_html(cg, max_nodes=args.max_nodes)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        cli.console.print(f"[green]Saved to {output_path}[/green]")
    else:
        with tempfile.NamedTemporaryFile(
            "w", delete=False, suffix=".html", encoding="utf-8"
        ) as f:
            f.write(html)
            output_path = Path(f.name)
        cli.console.print(f"[green]Rendered to {output_path}[/green]")

    if not args.no_open:
        webbrowser.open(f"file://{output_path.absolute()}")


def _render_html(cg, max_nodes: int = 500) -> str:
    """Build a self-contained HTML page with vis-network graph."""
    # Collect nodes and edges
    nodes = []
    edges = []
    node_ids: dict[str, int] = {}  # "file::func" → id
    next_id = 0

    # Assign colors per file (cycle through palette)
    palette = [
        "#4fc3f7", "#81c784", "#ffb74d", "#e57373", "#ba68c8",
        "#4dd0e1", "#aed581", "#ff8a65", "#f06292", "#7986cb",
    ]
    file_color: dict[str, str] = {}
    color_idx = 0

    for file_path, func_map in cg.func_calls_out.items():
        if file_path not in file_color:
            file_color[file_path] = palette[color_idx % len(palette)]
            color_idx += 1

        for caller, callees in func_map.items():
            caller_key = f"{file_path}::{caller}"
            if caller_key not in node_ids:
                node_ids[caller_key] = next_id
                nodes.append({
                    "id": next_id,
                    "label": caller,
                    "title": f"{file_path}:{caller}",
                    "color": file_color[file_path],
                    "file": file_path,
                })
                next_id += 1

            for callee in callees:
                # Find where callee is defined
                callee_files = cg.defined_in.get(callee, set())
                if not callee_files:
                    # External / unresolved — create a gray node
                    callee_key = f"?::{callee}"
                    if callee_key not in node_ids:
                        node_ids[callee_key] = next_id
                        nodes.append({
                            "id": next_id,
                            "label": callee,
                            "title": f"(unresolved) {callee}",
                            "color": "#616161",
                            "file": "",
                        })
                        next_id += 1
                    edges.append({"from": node_ids[caller_key], "to": node_ids[callee_key]})
                else:
                    for cf in callee_files:
                        callee_key = f"{cf}::{callee}"
                        if callee_key not in node_ids:
                            if cf not in file_color:
                                file_color[cf] = palette[color_idx % len(palette)]
                                color_idx += 1
                            node_ids[callee_key] = next_id
                            nodes.append({
                                "id": next_id,
                                "label": callee,
                                "title": f"{cf}:{callee}",
                                "color": file_color[cf],
                                "file": cf,
                            })
                            next_id += 1
                        edges.append({"from": node_ids[caller_key], "to": node_ids[callee_key]})

            if max_nodes and next_id >= max_nodes:
                break
        if max_nodes and next_id >= max_nodes:
            break

    import json

    nodes_json = json.dumps(nodes)
    edges_json = json.dumps(edges)
    truncated = max_nodes and next_id >= max_nodes

    return f"""\
<!DOCTYPE html>
<html>
<head>
<title>Callgraph Visualization</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
  body {{ margin: 0; background: #1e1e1e; color: #eee; font-family: monospace; }}
  #graph {{ width: 100vw; height: 100vh; }}
  #info {{ position: fixed; top: 10px; left: 10px; background: rgba(30,30,30,0.9);
           padding: 10px 15px; border-radius: 6px; font-size: 13px; z-index: 10; }}
  #info span {{ color: #4fc3f7; }}
  #search {{ position: fixed; top: 10px; right: 10px; background: rgba(30,30,30,0.9);
             padding: 8px 12px; border-radius: 6px; z-index: 10; }}
  #search input {{ background: #333; border: 1px solid #555; color: #eee; padding: 4px 8px;
                   border-radius: 3px; font-family: monospace; width: 200px; }}
</style>
</head>
<body>
<div id="info">
  <span>{len(nodes)}</span> nodes &middot; <span>{len(edges)}</span> edges
  {"&middot; <span style='color:#ffb74d'>truncated to " + str(max_nodes) + "</span>" if truncated else ""}
</div>
<div id="search"><input type="text" id="filter" placeholder="filter functions..."></div>
<div id="graph"></div>
<script>
var nodes = new vis.DataSet({nodes_json});
var edges = new vis.DataSet({edges_json});
var container = document.getElementById('graph');
var data = {{ nodes: nodes, edges: edges }};
var options = {{
  nodes: {{ shape: 'dot', size: 8, font: {{ size: 11, color: '#ccc' }} }},
  edges: {{ arrows: 'to', color: {{ color: '#555', highlight: '#4fc3f7' }}, smooth: {{ type: 'continuous' }} }},
  physics: {{ solver: 'forceAtlas2Based', forceAtlas2Based: {{ gravitationalConstant: -30, springLength: 80 }} }},
  interaction: {{ hover: true, tooltipDelay: 100 }},
  layout: {{ improvedLayout: false }}
}};
var network = new vis.Network(container, data, options);

document.getElementById('filter').addEventListener('input', function(e) {{
  var q = e.target.value.toLowerCase();
  if (!q) {{
    nodes.forEach(function(n) {{ nodes.update({{id: n.id, hidden: false}}); }});
    return;
  }}
  nodes.forEach(function(n) {{
    var match = n.label.toLowerCase().includes(q) || (n.file || '').toLowerCase().includes(q);
    nodes.update({{id: n.id, hidden: !match}});
  }});
}});
</script>
</body>
</html>"""
