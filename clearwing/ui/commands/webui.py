"""Web UI subcommand."""


def add_parser(subparsers):
    parser = subparsers.add_parser('webui', help='Start the web UI server')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=8899, help='Port to bind (default: 8899)')
    parser.add_argument('--reload', action='store_true', help='Enable auto-reload for development')
    return parser


def handle(cli, args):
    """Start the FastAPI web UI server."""
    try:
        import uvicorn
    except ImportError:
        cli.console.print(
            "[red]uvicorn is required for the web UI. "
            "Install with: pip install 'clearwing[web]'[/red]"
        )
        return

    from ..web import create_app
    app = create_app()

    cli.console.print(
        f"[bold cyan]Clearwing Web UI[/bold cyan]\n"
        f"Starting server at http://{args.host}:{args.port}\n"
        f"API docs at http://{args.host}:{args.port}/docs"
    )

    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload)
