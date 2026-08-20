#!/usr/bin/env python3
"""Detect Git conflicts and overlapping changes across active branches and PRs."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = 1
SEVERITY_ORDER = {"none": 0, "medium": 1, "high": 2, "blocker": 3, "unknown": 4}
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
OID_RE = re.compile(r"^[0-9a-f]{40,64}$")


class CheckError(RuntimeError):
    """An error that makes the scan incomplete."""


@dataclass
class Candidate:
    label: str
    ref: str
    kind: str
    commit: str | None = None
    title: str = ""
    url: str = ""
    pr_number: int | None = None
    base_name: str = ""
    base_commit: str | None = None
    is_draft: bool = False
    fetch_source: str = ""
    error: str = ""


@dataclass
class Finding:
    candidate: Candidate
    severity: str = "unknown"
    merge_status: str = "unknown"
    common_base: str = ""
    candidate_base_status: str = "unknown"
    transplant_status: str = "not-needed"
    candidate_changed_files: list[str] = field(default_factory=list)
    shared_files: list[str] = field(default_factory=list)
    overlapping_hunks: list[dict[str, Any]] = field(default_factory=list)
    overlap_count: int = 0
    candidate_base_messages: list[str] = field(default_factory=list)
    merge_messages: list[str] = field(default_factory=list)
    error: str = ""


def run(
    command: Sequence[str],
    *,
    check: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess[Any]:
    process = subprocess.run(
        command,
        capture_output=True,
        text=text,
        check=False,
    )
    if check and process.returncode != 0:
        stderr = process.stderr.strip() if text else process.stderr.decode(errors="replace").strip()
        raise CheckError(f"{' '.join(command)} failed: {stderr or f'exit {process.returncode}'}")
    return process


def git(
    args: Sequence[str],
    *,
    check: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess[Any]:
    return run(["git", *args], check=check, text=text)


def require_tools(open_prs: bool) -> None:
    if shutil.which("git") is None:
        raise CheckError("git is required")
    if open_prs and shutil.which("gh") is None:
        raise CheckError("gh is required for open-PR discovery; install it or use --no-open-prs")


def resolve_commit(ref: str) -> str:
    process = git(["rev-parse", "--verify", f"{ref}^{{commit}}"], check=False)
    if process.returncode != 0:
        raise CheckError(f"cannot resolve commit ref {ref!r}")
    return process.stdout.strip()


def first_resolved(refs: Iterable[str]) -> tuple[str, str] | None:
    for ref in refs:
        if not ref:
            continue
        try:
            return ref, resolve_commit(ref)
        except CheckError:
            pass
    return None


def has_commit(oid: str) -> bool:
    return git(["cat-file", "-e", f"{oid}^{{commit}}"], check=False).returncode == 0


def current_branch() -> str:
    process = git(["symbolic-ref", "--quiet", "--short", "HEAD"], check=False)
    return process.stdout.strip() if process.returncode == 0 else ""


def discover_open_prs(repo: str, limit: int) -> list[dict[str, Any]]:
    command = [
        "gh",
        "pr",
        "list",
        "--state",
        "open",
        "--limit",
        str(limit),
        "--json",
        "number,title,url,headRefName,headRefOid,baseRefName,isDraft",
    ]
    if repo:
        command.extend(["--repo", repo])
    process = run(command, check=False)
    if process.returncode == 0:
        try:
            value = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            raise CheckError(f"gh returned invalid PR JSON: {exc}") from exc
        if not isinstance(value, list):
            raise CheckError("gh PR discovery returned an unexpected response")
        return value

    primary_error = process.stderr.strip() or f"exit {process.returncode}"
    if not repo:
        raise CheckError(f"{' '.join(command)} failed: {primary_error}")

    fallback = run(
        [
            "gh",
            "api",
            f"repos/{repo}/pulls?state=open&per_page=100",
            "--paginate",
            "--slurp",
        ],
        check=False,
    )
    if fallback.returncode != 0:
        fallback_error = fallback.stderr.strip() or f"exit {fallback.returncode}"
        raise CheckError(
            f"GitHub PR discovery failed via GraphQL ({primary_error}) and REST ({fallback_error})"
        )
    try:
        pages = json.loads(fallback.stdout)
        if not isinstance(pages, list) or not all(isinstance(page, list) for page in pages):
            raise TypeError("REST response is not a list of pages")
        values = [item for page in pages for item in page]
        return [
            {
                "number": item["number"],
                "title": item.get("title") or "",
                "url": item.get("html_url") or "",
                "headRefName": item["head"]["ref"],
                "headRefOid": item["head"]["sha"],
                "baseRefName": item["base"]["ref"],
                "isDraft": bool(item.get("draft")),
            }
            for item in values[:limit]
        ]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise CheckError(f"GitHub REST PR discovery returned invalid JSON: {exc}") from exc


def default_branch_name(repo: str) -> str:
    command = ["gh", "repo", "view"]
    if repo:
        command.append(repo)
    command.extend(["--json", "defaultBranchRef"])
    process = run(command, check=False)
    name: Any = None
    if process.returncode == 0:
        try:
            value = json.loads(process.stdout)
            name = value["defaultBranchRef"]["name"]
        except (json.JSONDecodeError, KeyError, TypeError):
            name = None
    if not name and repo:
        fallback = run(["gh", "api", f"repos/{repo}"], check=False)
        if fallback.returncode == 0:
            try:
                name = json.loads(fallback.stdout)["default_branch"]
            except (json.JSONDecodeError, KeyError, TypeError):
                name = None
    if not isinstance(name, str) or not name:
        primary_error = process.stderr.strip() or "invalid GraphQL response"
        raise CheckError(f"could not determine the GitHub default branch: {primary_error}")
    return name


def resolve_remote_branch(remote: str, branch: str, fetch: bool) -> str:
    if not fetch:
        resolved = first_resolved((f"refs/remotes/{remote}/{branch}", f"{remote}/{branch}", branch))
        if resolved:
            return resolved[1]
        raise CheckError(f"cannot resolve remote branch {remote}/{branch} without fetching")

    process = git(["ls-remote", "--refs", remote, f"refs/heads/{branch}"])
    lines = [line for line in process.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise CheckError(f"remote branch {remote}/{branch} was not found unambiguously")
    oid = lines[0].split()[0]
    git(
        [
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-write-fetch-head",
            remote,
            f"refs/heads/{branch}",
        ]
    )
    if not has_commit(oid):
        raise CheckError(
            f"fetched remote branch {remote}/{branch}, but commit {oid} is unavailable"
        )
    return oid


def fetch_candidate(candidate: Candidate, remote: str, fetch: bool) -> None:
    if candidate.commit and has_commit(candidate.commit):
        return
    if not fetch:
        candidate.error = f"commit for {candidate.label} is unavailable and --no-fetch was used"
        return
    if not candidate.fetch_source:
        candidate.error = f"no fetch source is known for {candidate.label}"
        return
    process = git(
        [
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-write-fetch-head",
            remote,
            candidate.fetch_source,
        ],
        check=False,
    )
    if process.returncode != 0:
        candidate.error = process.stderr.strip() or f"fetch failed with exit {process.returncode}"
        return
    if not candidate.commit or not has_commit(candidate.commit):
        candidate.error = (
            f"fetched {candidate.fetch_source}, but its expected commit is unavailable"
        )


def ref_candidates(namespace: str, kind: str) -> list[Candidate]:
    process = git(
        [
            "for-each-ref",
            "--format=%(refname)%09%(objectname)%09%(symref)",
            namespace,
        ]
    )
    candidates: list[Candidate] = []
    for line in process.stdout.splitlines():
        values = line.split("\t", 2)
        values.extend([""] * (3 - len(values)))
        ref, oid, symref = values
        if not ref or symref:
            continue
        short_ref = ref.removeprefix("refs/heads/").removeprefix("refs/remotes/")
        candidates.append(Candidate(label=short_ref, ref=ref, kind=kind, commit=oid))
    return candidates


def changed_files(base: str, head: str) -> list[str]:
    process = git(
        ["diff", "--name-only", "-z", "--no-renames", f"{base}..{head}", "--"],
        text=False,
    )
    return sorted(
        item.decode(errors="surrogateescape") for item in process.stdout.split(b"\0") if item
    )


def hunk_ranges(base: str, head: str, path: str) -> list[tuple[int, int]]:
    process = git(
        [
            "diff",
            "--no-ext-diff",
            "--no-color",
            "--unified=0",
            "--no-renames",
            f"{base}..{head}",
            "--",
            path,
        ]
    )
    ranges: list[tuple[int, int]] = []
    for line in process.stdout.splitlines():
        match = HUNK_RE.match(line)
        if not match:
            continue
        start = int(match.group(1))
        length = int(match.group(2) or "1")
        end = start if length == 0 else start + length - 1
        ranges.append((start, end))
    return ranges


def overlaps(
    base: str,
    head: str,
    candidate: str,
    shared_files: Iterable[str],
) -> tuple[list[dict[str, Any]], int]:
    recorded: list[dict[str, Any]] = []
    total = 0
    for path in shared_files:
        head_ranges = hunk_ranges(base, head, path)
        candidate_ranges = hunk_ranges(base, candidate, path)
        for head_range in head_ranges:
            for candidate_range in candidate_ranges:
                if max(head_range[0], candidate_range[0]) <= min(head_range[1], candidate_range[1]):
                    total += 1
                    if len(recorded) < 100:
                        recorded.append(
                            {
                                "path": path,
                                "head": list(head_range),
                                "candidate": list(candidate_range),
                            }
                        )
    return recorded, total


def tree_oid(treeish: str) -> str:
    process = git(["rev-parse", "--verify", f"{treeish}^{{tree}}"], check=False)
    if process.returncode != 0:
        raise CheckError(f"cannot resolve tree for {treeish!r}")
    return process.stdout.strip()


def merge_trees(
    left: str,
    right: str,
    *,
    merge_base: str | None = None,
) -> tuple[str, str, list[str], str]:
    arguments = ["merge-tree", "--write-tree", "--name-only", "--messages"]
    if merge_base:
        arguments.extend(["--merge-base", merge_base])
    arguments.extend([left, right])
    process = git(arguments, check=False)
    output_lines = [line.strip() for line in process.stdout.splitlines() if line.strip()]
    merged_tree = next((line for line in output_lines if OID_RE.fullmatch(line)), "")
    messages = [line for line in output_lines if not OID_RE.fullmatch(line)][:50]
    if process.returncode == 0:
        if not merged_tree:
            return "unknown", "", messages, "git merge-tree returned no merged tree"
        return "clean", merged_tree, messages, ""
    if process.returncode == 1:
        return "conflict", merged_tree, messages, ""
    error = process.stderr.strip() or f"git merge-tree failed with exit {process.returncode}"
    return "unknown", merged_tree, messages, error


def analyze_candidate(
    *,
    current_base: str,
    current_base_tree: str,
    head_tree: str,
    head_changed_files: list[str],
    candidate: Candidate,
) -> Finding:
    finding = Finding(candidate=candidate)
    finding.common_base = current_base
    if candidate.error or not candidate.commit or not candidate.base_commit:
        finding.error = candidate.error or "candidate commit or base is unavailable"
        return finding

    try:
        candidate_fork = git(["merge-base", candidate.base_commit, candidate.commit], check=False)
        if candidate_fork.returncode != 0:
            finding.error = (
                candidate_fork.stderr.strip()
                or "candidate branch has no usable merge base with its target"
            )
            return finding
        finding.candidate_changed_files = changed_files(
            candidate_fork.stdout.strip(), candidate.commit
        )
        finding.shared_files = sorted(
            set(head_changed_files) & set(finding.candidate_changed_files)
        )

        (
            finding.candidate_base_status,
            candidate_tree,
            finding.candidate_base_messages,
            finding.error,
        ) = merge_trees(candidate.base_commit, candidate.commit)
        if finding.error or finding.candidate_base_status == "unknown":
            return finding
        if finding.candidate_base_status == "conflict":
            finding.merge_status = "candidate-base-conflict"
            finding.severity = "medium" if finding.shared_files else "none"
            return finding

        if candidate.base_commit != current_base:
            candidate_base_tree = tree_oid(candidate.base_commit)
            (
                finding.transplant_status,
                candidate_tree,
                finding.merge_messages,
                finding.error,
            ) = merge_trees(
                current_base_tree,
                candidate_tree,
                merge_base=candidate_base_tree,
            )
            if finding.error or finding.transplant_status == "unknown":
                return finding
            if finding.transplant_status == "conflict":
                finding.merge_status = "cross-base-conflict"
                finding.severity = "medium"
                return finding

        finding.candidate_changed_files = changed_files(current_base_tree, candidate_tree)
        finding.shared_files = sorted(
            set(head_changed_files) & set(finding.candidate_changed_files)
        )
        finding.overlapping_hunks, finding.overlap_count = overlaps(
            current_base_tree,
            head_tree,
            candidate_tree,
            finding.shared_files,
        )
        (
            finding.merge_status,
            _,
            finding.merge_messages,
            finding.error,
        ) = merge_trees(
            head_tree,
            candidate_tree,
            merge_base=current_base_tree,
        )
    except CheckError as exc:
        finding.error = str(exc)
        return finding

    if finding.error or finding.merge_status == "unknown":
        finding.severity = "unknown"
    elif finding.merge_status == "conflict":
        finding.severity = "blocker"
    elif finding.overlap_count:
        finding.severity = "high"
    elif finding.shared_files:
        finding.severity = "medium"
    else:
        finding.severity = "none"
    return finding


def clean_label(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def abbreviated(oid: str) -> str:
    return oid[:12] if oid else "unknown"


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    candidate = finding.candidate
    return {
        "candidate": {
            "label": candidate.label,
            "kind": candidate.kind,
            "ref": candidate.ref,
            "commit": candidate.commit,
            "title": candidate.title,
            "url": candidate.url,
            "pr_number": candidate.pr_number,
            "base": candidate.base_name,
            "base_commit": candidate.base_commit,
            "draft": candidate.is_draft,
        },
        "severity": finding.severity,
        "merge_status": finding.merge_status,
        "common_base": finding.common_base,
        "candidate_base_status": finding.candidate_base_status,
        "transplant_status": finding.transplant_status,
        "candidate_changed_files": finding.candidate_changed_files,
        "shared_files": finding.shared_files,
        "overlapping_hunks": finding.overlapping_hunks,
        "overlap_count": finding.overlap_count,
        "candidate_base_messages": finding.candidate_base_messages,
        "merge_messages": finding.merge_messages,
        "error": finding.error,
    }


def print_markdown(  # noqa: C901
    *,
    head_ref: str,
    head: str,
    base_ref: str,
    base: str,
    head_files: list[str],
    findings: list[Finding],
    warnings: list[str],
) -> None:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    print("# PR conflict check")
    print()
    print(f"- Head: `{head_ref}` (`{abbreviated(head)}`)")
    print(f"- Base: `{base_ref}` (`{abbreviated(base)}`)")
    print(f"- Head changed files: {len(head_files)}")
    print(f"- Candidates: {len(findings)}")
    print(
        "- Summary: "
        + ", ".join(
            f"{counts[name]} {name.upper()}"
            for name in ("blocker", "high", "medium", "none", "unknown")
        )
    )
    if warnings:
        print("- Scan warnings: " + "; ".join(clean_label(item) for item in warnings))
    print()
    if not findings:
        print("No candidate branches or pull requests were found in the requested scope.")
        return
    print("| Severity | Candidate | Merge | Candidate files | Shared files | Hunk overlaps |")
    print("| --- | --- | --- | ---: | ---: | ---: |")
    for finding in sorted(
        findings,
        key=lambda item: (-SEVERITY_ORDER[item.severity], item.candidate.label),
    ):
        print(
            f"| {finding.severity.upper()} | {clean_label(finding.candidate.label)} | "
            f"{finding.merge_status} | {len(finding.candidate_changed_files)} | "
            f"{len(finding.shared_files)} | {finding.overlap_count} |"
        )
    for finding in sorted(
        findings,
        key=lambda item: (-SEVERITY_ORDER[item.severity], item.candidate.label),
    ):
        if finding.severity == "none":
            continue
        print()
        print(f"## {finding.severity.upper()}: {clean_label(finding.candidate.label)}")
        candidate = finding.candidate
        metadata = []
        if candidate.url:
            metadata.append(candidate.url)
        if candidate.base_name:
            metadata.append(f"targets `{candidate.base_name}`")
        if candidate.is_draft:
            metadata.append("draft")
        if metadata:
            print()
            print("; ".join(metadata))
        if finding.error:
            print()
            print(f"- Incomplete: {clean_label(finding.error)}")
        if finding.candidate_base_status != "clean":
            print()
            print(f"- Candidate vs its target base: {clean_label(finding.candidate_base_status)}")
        if finding.transplant_status not in ("not-needed", "clean"):
            print()
            print(f"- Candidate delta vs this PR base: {clean_label(finding.transplant_status)}")
        if finding.candidate_changed_files:
            print()
            print(
                "- Candidate changed files: "
                + ", ".join(f"`{path}`" for path in finding.candidate_changed_files[:20])
            )
            if len(finding.candidate_changed_files) > 20:
                print(
                    "- Additional candidate changed files: "
                    f"{len(finding.candidate_changed_files) - 20}"
                )
        if finding.shared_files:
            print()
            print("- Shared files: " + ", ".join(f"`{path}`" for path in finding.shared_files[:20]))
            if len(finding.shared_files) > 20:
                print(f"- Additional shared files: {len(finding.shared_files) - 20}")
        if finding.overlapping_hunks:
            print("- Overlapping base-line hunks:")
            for item in finding.overlapping_hunks[:20]:
                print(
                    f"  - `{item['path']}`: head {item['head'][0]}-{item['head'][1]}, "
                    f"candidate {item['candidate'][0]}-{item['candidate'][1]}"
                )
            if finding.overlap_count > 20:
                print(f"  - Additional overlaps: {finding.overlap_count - 20}")
        if finding.merge_messages:
            print("- Git merge evidence:")
            for message in finding.merge_messages[:20]:
                print(f"  - {clean_label(message)}")
        if finding.candidate_base_messages:
            print("- Candidate/base merge evidence:")
            for message in finding.candidate_base_messages[:20]:
                print(f"  - {clean_label(message)}")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare a branch with open GitHub PRs and active Git refs without checking them out."
        )
    )
    parser.add_argument("--head", default="HEAD", help="Head ref to analyze (default: HEAD)")
    parser.add_argument("--base", help="PR base ref; auto-detected when omitted")
    parser.add_argument(
        "--remote", default="origin", help="Remote for GitHub PR refs (default: origin)"
    )
    parser.add_argument("--repo", help="GitHub OWNER/REPO override passed to gh")
    parser.add_argument(
        "--ref", action="append", default=[], help="Existing Git ref to compare; repeatable"
    )
    parser.add_argument(
        "--branch",
        action="append",
        default=[],
        help="Branch tip to discover on --remote without updating local refs; repeatable",
    )
    parser.add_argument(
        "--include-local-branches",
        action="store_true",
        help="Compare all existing refs/heads branches",
    )
    parser.add_argument(
        "--include-remote-branches",
        action="store_true",
        help="Compare existing refs/remotes/<remote> branches without refreshing them",
    )
    parser.add_argument(
        "--no-open-prs",
        action="store_true",
        help="Skip GitHub open-PR discovery",
    )
    parser.add_argument(
        "--exclude-drafts",
        action="store_true",
        help="Exclude draft PRs (drafts are included by default)",
    )
    parser.add_argument(
        "--limit", type=int, default=100, help="Maximum open PRs to query (default: 100)"
    )
    parser.add_argument(
        "--no-fetch",
        action="store_true",
        help="Do not fetch Git objects; resolve only existing refs/objects",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Analyze committed HEAD despite current uncommitted/untracked changes",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument(
        "--fail-on",
        choices=("conflict", "high", "medium", "never"),
        default="high",
        help="Finding threshold for exit 1 (default: high)",
    )
    return parser.parse_args(argv)


def should_fail(findings: list[Finding], threshold: str) -> bool:
    if threshold == "never":
        return False
    minimum = {"conflict": 3, "high": 2, "medium": 1}[threshold]
    return any(
        finding.severity != "unknown" and SEVERITY_ORDER[finding.severity] >= minimum
        for finding in findings
    )


def main(argv: Sequence[str] | None = None) -> int:  # noqa: C901
    args = parse_args(argv or sys.argv[1:])
    open_prs_enabled = not args.no_open_prs
    try:
        require_tools(open_prs_enabled)
        git(["rev-parse", "--show-toplevel"])
        head = resolve_commit(args.head)
        head_ref = args.head if args.head != "HEAD" else current_branch() or "HEAD"
        warnings: list[str] = []

        if args.head == "HEAD" and not args.allow_dirty:
            dirty = git(["status", "--porcelain", "--untracked-files=normal"]).stdout.strip()
            if dirty:
                raise CheckError(
                    "current worktree is dirty; commit intended PR changes or explicitly "
                    "use --allow-dirty"
                )

        pr_values = discover_open_prs(args.repo or "", args.limit) if open_prs_enabled else []
        if open_prs_enabled and len(pr_values) == args.limit:
            warnings.append(
                f"the open-PR query reached --limit {args.limit}; additional PRs may exist"
            )
        current_pr = next(
            (
                item
                for item in pr_values
                if item.get("headRefOid") == head
                or (head_ref != "HEAD" and item.get("headRefName") == head_ref)
            ),
            None,
        )

        if args.base:
            base_ref = args.base
            base = resolve_commit(base_ref)
            current_base_name = base_ref.rsplit("/", 1)[-1]
        elif open_prs_enabled:
            current_base_name = (
                current_pr.get("baseRefName")
                if current_pr
                else default_branch_name(args.repo or "")
            )
            base_ref = f"{args.remote}/{current_base_name}"
            base = resolve_remote_branch(args.remote, current_base_name, not args.no_fetch)
        else:
            symbolic = git(
                [
                    "symbolic-ref",
                    "--quiet",
                    "--short",
                    f"refs/remotes/{args.remote}/HEAD",
                ],
                check=False,
            )
            resolved = first_resolved(
                (
                    symbolic.stdout.strip(),
                    f"{args.remote}/main",
                    f"{args.remote}/master",
                    "main",
                    "master",
                )
            )
            if not resolved:
                raise CheckError("could not infer a base; pass --base REF")
            base_ref, base = resolved
            current_base_name = base_ref.rsplit("/", 1)[-1]

        base_tree = tree_oid(base)
        head_base_status, head_tree, head_base_messages, head_base_error = merge_trees(base, head)
        if head_base_error or head_base_status == "unknown":
            raise CheckError(head_base_error or f"could not normalize {head_ref} onto {base_ref}")
        if head_base_status == "conflict":
            evidence = "; ".join(head_base_messages[:5])
            raise CheckError(
                f"head {head_ref} already conflicts with {base_ref}"
                + (f": {evidence}" if evidence else "")
            )
        head_files = changed_files(base_tree, head_tree)

        base_cache = {current_base_name: base}

        def get_candidate_base(name: str) -> str:
            candidate_base_name = name or current_base_name
            if candidate_base_name not in base_cache:
                base_cache[candidate_base_name] = resolve_remote_branch(
                    args.remote,
                    candidate_base_name,
                    not args.no_fetch,
                )
            return base_cache[candidate_base_name]

        candidates: list[Candidate] = []
        for item in pr_values:
            if item is current_pr or item.get("headRefOid") == head:
                continue
            if args.exclude_drafts and item.get("isDraft"):
                continue
            number = int(item["number"])
            title = str(item.get("title") or "")
            candidate = Candidate(
                label=f"PR #{number}: {title}",
                ref=f"refs/pull/{number}/head",
                kind="pull-request",
                commit=item.get("headRefOid") or None,
                title=title,
                url=str(item.get("url") or ""),
                pr_number=number,
                base_name=str(item.get("baseRefName") or ""),
                is_draft=bool(item.get("isDraft")),
                fetch_source=f"refs/pull/{number}/head",
            )
            try:
                candidate.base_commit = get_candidate_base(candidate.base_name)
            except CheckError as exc:
                candidate.error = str(exc)
            candidates.append(candidate)

        for branch in args.branch:
            candidate = Candidate(
                label=f"branch {args.remote}/{branch}",
                ref=f"refs/heads/{branch}",
                kind="remote-branch",
                base_name=current_base_name,
                base_commit=base,
                fetch_source=f"refs/heads/{branch}",
            )
            try:
                candidate.commit = resolve_remote_branch(args.remote, branch, not args.no_fetch)
            except CheckError as exc:
                candidate.error = str(exc)
            candidates.append(candidate)

        for ref in args.ref:
            candidate = Candidate(
                label=f"ref {ref}",
                ref=ref,
                kind="explicit-ref",
                base_name=current_base_name,
                base_commit=base,
            )
            try:
                candidate.commit = resolve_commit(ref)
            except CheckError as exc:
                candidate.error = str(exc)
            candidates.append(candidate)

        if args.include_local_branches:
            candidates.extend(ref_candidates("refs/heads", "local-branch"))
        if args.include_remote_branches:
            candidates.extend(ref_candidates(f"refs/remotes/{args.remote}", "existing-remote-ref"))

        for candidate in candidates:
            if not candidate.base_commit:
                candidate.base_name = candidate.base_name or current_base_name
                candidate.base_commit = base

        unique: list[Candidate] = []
        seen_commits = {head}
        seen_errors: set[tuple[str, str]] = set()
        for candidate in candidates:
            fetch_candidate(candidate, args.remote, not args.no_fetch)
            if candidate.commit and candidate.commit in seen_commits:
                continue
            if candidate.commit:
                seen_commits.add(candidate.commit)
            elif (candidate.label, candidate.error) in seen_errors:
                continue
            else:
                seen_errors.add((candidate.label, candidate.error))
            unique.append(candidate)

        findings = [
            analyze_candidate(
                current_base=base,
                current_base_tree=base_tree,
                head_tree=head_tree,
                head_changed_files=head_files,
                candidate=candidate,
            )
            for candidate in unique
        ]
        incomplete = [finding for finding in findings if finding.severity == "unknown"]

        if args.json:
            counts = {severity: 0 for severity in SEVERITY_ORDER}
            for finding in findings:
                counts[finding.severity] += 1
            print(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "head": {
                            "ref": head_ref,
                            "commit": head,
                            "changed_files": head_files,
                        },
                        "base": {"ref": base_ref, "commit": base},
                        "summary": {"candidates": len(findings), "counts": counts},
                        "warnings": warnings,
                        "findings": [finding_to_dict(finding) for finding in findings],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print_markdown(
                head_ref=head_ref,
                head=head,
                base_ref=base_ref,
                base=base,
                head_files=head_files,
                findings=findings,
                warnings=warnings,
            )

        if incomplete:
            return 2
        return 1 if should_fail(findings, args.fail_on) else 0
    except CheckError as exc:
        if args.json:
            print(json.dumps({"schema_version": SCHEMA_VERSION, "error": str(exc)}, indent=2))
        else:
            print(f"INCOMPLETE: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
