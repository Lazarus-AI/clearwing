"""Attack graph subcommand."""


def add_parser(subparsers):
    parser = subparsers.add_parser('graph', help='Show interactive attack graph')
    parser.add_argument('--path', help='Path to knowledge graph JSON file')
    parser.add_argument('--output', help='Output HTML file path')
    parser.add_argument('--no-open', action='store_true', help='Do not open in browser')
    return parser


def handle(cli, args):
    """Show the interactive attack graph in the browser."""
    import tempfile
    import webbrowser
    from pathlib import Path
    import networkx as nx
    from ...data.knowledge.graph import KnowledgeGraph
    from ...reporting.report_generator import ReportGenerator

    persist_path = args.path or "~/.clearwing/knowledge_graph.json"
    kg = KnowledgeGraph(persist_path=persist_path)

    if kg._graph.number_of_nodes() == 0:
        cli.console.print(f"[yellow]Knowledge graph at {persist_path} is empty.[/yellow]")
        return

    graph_data = nx.node_link_data(kg._graph)

    generator = ReportGenerator()
    html = generator.generate_attack_graph(graph_data)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding='utf-8')
        cli.console.print(f"[green]Graph saved to {output_path}[/green]")
        if not args.no_open:
            webbrowser.open(f"file://{output_path.absolute()}")
    else:
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html', encoding='utf-8') as f:
            f.write(html)
            temp_path = Path(f.name)

        cli.console.print(f"[green]Temporary graph generated at {temp_path}[/green]")
        if not args.no_open:
            webbrowser.open(f"file://{temp_path.absolute()}")
