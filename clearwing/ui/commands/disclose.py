"""Disclosure workflow CLI — clearwing disclose (spec 011, 014).

Subcommands:
    queue       Show pending findings awaiting review
    review      Display full context for a finding
    validate    Mark a finding as human-validated
    reject      Reject a finding with reason
    send        Generate disclosure and start 90-day CVD timeline
    status      Dashboard of disclosure states
    timeline    Show findings with approaching deadlines
    verify      Verify a cryptographic commitment against a document
    commitments Show or export the commitment log
"""

from __future__ import annotations

from datetime import datetime, timezone

from rich.table import Table

from clearwing.core.event_payloads import DisclosureUpdatePayload
from clearwing.core.events import EventBus


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "disclose",
        help="Human validation and coordinated disclosure workflow",
    )
    sub = parser.add_subparsers(dest="disclose_action")

    # queue
    q = sub.add_parser("queue", help="Show pending findings awaiting review")
    q.add_argument("--state", help="Filter by disclosure state")
    q.add_argument("--repo", help="Filter by repository URL")

    # review
    r = sub.add_parser("review", help="Show full review context for a finding")
    r.add_argument("finding_id", help="Finding ID to review")

    # validate
    v = sub.add_parser("validate", help="Mark a finding as validated")
    v.add_argument("finding_id", help="Finding ID to validate")
    v.add_argument("--notes", default="", help="Review notes")
    v.add_argument("--reviewer", default="cli", help="Reviewer name")

    # reject
    rj = sub.add_parser("reject", help="Reject a finding")
    rj.add_argument("finding_id", help="Finding ID to reject")
    rj.add_argument("--reason", required=True, help="Rejection reason")
    rj.add_argument("--reviewer", default="cli", help="Reviewer name")

    # send
    s = sub.add_parser("send", help="Generate disclosure and start CVD timeline")
    s.add_argument("finding_id", help="Finding ID to disclose")
    s.add_argument("--reviewer", default="cli", help="Reviewer name")
    s.add_argument("--reporter-name", default="(your name)")
    s.add_argument("--reporter-affiliation", default="(your affiliation)")
    s.add_argument("--reporter-email", default="(your email)")

    # status
    sub.add_parser("status", help="Dashboard of disclosure workflow states")

    # timeline
    tl = sub.add_parser("timeline", help="Show findings with approaching deadlines")
    tl.add_argument("--days", type=int, default=30, help="Deadline threshold in days")

    # verify (spec 014)
    vr = sub.add_parser("verify", help="Verify a commitment against a document")
    vr.add_argument("finding_id", help="Finding ID to verify")
    vr.add_argument("--document", required=True, help="Path to original document JSON")

    # commitments (spec 014)
    cm = sub.add_parser("commitments", help="Show or export commitment log")
    cm.add_argument(
        "--format", choices=["markdown", "json"], default="markdown",
        dest="commitment_format",
        help="Output format (default: markdown)",
    )

    return parser


def handle(cli, args):
    """Dispatch to the appropriate disclose subcommand."""
    action = getattr(args, "disclose_action", None)
    if not action:
        cli.console.print(
            "[yellow]Usage: clearwing disclose "
            "<queue|review|validate|reject|send|status|timeline|verify|commitments>[/yellow]"
        )
        return

    from clearwing.sourcehunt.disclosure_db import DisclosureDB
    from clearwing.sourcehunt.disclosure_workflow import DisclosureWorkflow

    db = DisclosureDB()
    try:
        workflow = DisclosureWorkflow(db)
        handlers = {
            "queue": _handle_queue,
            "review": _handle_review,
            "validate": _handle_validate,
            "reject": _handle_reject,
            "send": _handle_send,
            "status": _handle_status,
            "timeline": _handle_timeline,
            "verify": _handle_verify,
            "commitments": _handle_commitments,
        }
        handler = handlers.get(action)
        if handler:
            handler(cli, args, db, workflow)
        else:
            cli.console.print(f"[red]Unknown action: {action}[/red]")
    finally:
        db.close()


def _handle_queue(cli, args, db, workflow):
    state = getattr(args, "state", None)
    repo = getattr(args, "repo", None)
    findings = db.get_queue(state=state, repo_url=repo)

    if not findings:
        cli.console.print("[yellow]No findings in queue.[/yellow]")
        return

    table = Table(title="Disclosure Queue")
    table.add_column("ID", style="cyan", max_width=20)
    table.add_column("Severity", style="red")
    table.add_column("File", style="magenta")
    table.add_column("CWE", style="blue")
    table.add_column("Stability", style="green")
    table.add_column("State", style="yellow")
    table.add_column("Priority", style="bold")

    for f in findings:
        sev = f.get("severity_verified") or f.get("severity") or "?"
        table.add_row(
            f["id"][:20],
            sev.upper(),
            f"{f.get('file', '?')}:{f.get('line_number', '?')}",
            f.get("cwe", ""),
            f.get("stability_classification", ""),
            f["state"],
            f"{f['priority_score']:.0f}",
        )

    cli.console.print(table)


def _handle_review(cli, args, db, workflow):
    from clearwing.sourcehunt.state import DisclosureState

    context = workflow.format_review_context(args.finding_id)
    cli.console.print(context)

    finding = db.get_finding(args.finding_id)
    if finding and finding["state"] == DisclosureState.PENDING_REVIEW.value:
        try:
            db.transition(
                args.finding_id, DisclosureState.IN_REVIEW, "cli", "opened for review",
            )
            cli.console.print("[green]Status: moved to in_review[/green]")
        except ValueError:
            pass


def _handle_validate(cli, args, db, workflow):
    try:
        finding = db.get_finding(args.finding_id)
        if not finding:
            cli.console.print(f"[red]Finding {args.finding_id} not found.[/red]")
            return
        if finding["state"] == "pending_review":
            from clearwing.sourcehunt.state import DisclosureState
            db.transition(args.finding_id, DisclosureState.IN_REVIEW, args.reviewer, "auto-claim for validate")
        workflow.validate(args.finding_id, args.reviewer, args.notes)
        EventBus().emit_disclosure_update(DisclosureUpdatePayload(
            finding_id=args.finding_id, action="validated",
            reviewer=args.reviewer, days_remaining=None, detail=args.notes or "",
        ))
        cli.console.print(f"[green]Finding {args.finding_id} validated.[/green]")
    except ValueError as e:
        cli.console.print(f"[red]{e}[/red]")


def _handle_reject(cli, args, db, workflow):
    try:
        finding = db.get_finding(args.finding_id)
        if not finding:
            cli.console.print(f"[red]Finding {args.finding_id} not found.[/red]")
            return
        workflow.reject(args.finding_id, args.reviewer, args.reason)
        EventBus().emit_disclosure_update(DisclosureUpdatePayload(
            finding_id=args.finding_id, action="rejected",
            reviewer=args.reviewer, days_remaining=None, detail=args.reason,
        ))
        cli.console.print(f"[green]Finding {args.finding_id} rejected.[/green]")
    except ValueError as e:
        cli.console.print(f"[red]{e}[/red]")


def _handle_send(cli, args, db, workflow):
    try:
        finding = db.get_finding(args.finding_id)
        if not finding:
            cli.console.print(f"[red]Finding {args.finding_id} not found.[/red]")
            return
        if finding["state"] == "validated":
            pass  # send_disclosure handles the transitions
        templates = workflow.send_disclosure(
            args.finding_id,
            reviewer=args.reviewer,
            reporter_name=args.reporter_name,
            reporter_affiliation=args.reporter_affiliation,
            reporter_email=args.reporter_email,
        )
        EventBus().emit_disclosure_update(DisclosureUpdatePayload(
            finding_id=args.finding_id, action="sent",
            reviewer=args.reviewer, days_remaining=90,
            detail="CVD 90-day timeline started",
        ))
        cli.console.print(f"[green]Disclosure sent for {args.finding_id}. 90-day CVD clock started.[/green]")
        for fmt, body in templates.items():
            cli.console.print(f"\n[bold]--- {fmt.upper()} Template ---[/bold]")
            cli.console.print(body[:3000])
    except ValueError as e:
        cli.console.print(f"[red]{e}[/red]")


def _handle_status(cli, args, db, workflow):
    stats = workflow.get_dashboard()

    table = Table(title="Disclosure Dashboard")
    table.add_column("State", style="cyan")
    table.add_column("Count", style="bold")

    for state, count in sorted(stats.get("by_state", {}).items()):
        table.add_row(state, str(count))

    cli.console.print(table)
    cli.console.print(f"\n[bold]Total:[/bold] {stats.get('total', 0)}")
    cli.console.print(
        f"[bold]Approaching deadlines:[/bold] {stats.get('approaching_deadlines', 0)}"
    )

    if stats.get("by_repo"):
        repo_table = Table(title="By Repository")
        repo_table.add_column("Repo", style="magenta")
        repo_table.add_column("Count", style="bold")
        for repo, count in sorted(stats["by_repo"].items()):
            repo_table.add_row(repo, str(count))
        cli.console.print(repo_table)


def _handle_timeline(cli, args, db, workflow):
    alerts = workflow.check_timeline_alerts()

    if not alerts:
        cli.console.print("[green]No approaching deadlines.[/green]")
        return

    table = Table(title="Timeline Alerts")
    table.add_column("Finding", style="cyan", max_width=20)
    table.add_column("Repo", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Days Elapsed", style="yellow")
    table.add_column("Days Remaining", style="bold")
    table.add_column("Deadline", style="blue")
    table.add_column("State", style="green")

    for a in alerts:
        remaining = a["days_remaining"]
        style = "bold red" if remaining <= 0 else ("yellow" if remaining <= 15 else "")
        table.add_row(
            a["finding_id"][:20],
            a["repo_url"],
            (a.get("severity") or "?").upper(),
            str(a["days_elapsed"]),
            str(remaining),
            a["deadline"],
            a["state"],
        )

    cli.console.print(table)


def _handle_verify(cli, args, db, workflow):
    from pathlib import Path

    from clearwing.sourcehunt.commitment import CommitmentLog, verify_commitment

    log = CommitmentLog()
    commitments = log.get_commitments(finding_id=args.finding_id)
    if not commitments:
        cli.console.print(
            f"[yellow]No commitments found for {args.finding_id}[/yellow]",
        )
        return

    doc_path = Path(args.document)
    if not doc_path.exists():
        cli.console.print(f"[red]Document not found: {args.document}[/red]")
        return
    document = doc_path.read_text(encoding="utf-8")

    cli.console.print(
        f"[bold]Verifying {len(commitments)} commitment(s) "
        f"for {args.finding_id}:[/bold]",
    )
    for c in commitments:
        match = verify_commitment(document, c)
        status = "[green]MATCH[/green]" if match else "[red]MISMATCH[/red]"
        cli.console.print(
            f"  {c.commitment_type}: {c.digest[:16]}... {status}",
        )


def _handle_commitments(cli, args, db, workflow):
    from clearwing.sourcehunt.commitment import CommitmentLog

    log = CommitmentLog()
    fmt = getattr(args, "commitment_format", "markdown")
    output = log.format_public_table(fmt=fmt)
    cli.console.print(output)
