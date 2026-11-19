#!/usr/bin/env python3
"""Zero-dependency GitHub Actions workflow security linter (Lite).

Python 3.9+ stdlib only. Scans .github/workflows/*.yml and *.yaml files for
common CI/CD supply-chain and security misconfigurations.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

VERSION = "0.1.0"

SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"\s#]+)['\"]?")
RUN_START_RE = re.compile(r"^\s*(?:-\s*)?run:\s*(.*)$")
KEY_VALUE_RE = re.compile(r"^\s*(?:-\s*)?([A-Za-z0-9_-]+)\s*:\s*(.*)$")

UNTRUSTED_CONTEXT_RE = re.compile(
    r"\$\{\{\s*github\.event\.(?:"
    r"issue\.(?:title|body)|"
    r"pull_request\.(?:title|body|head\.ref|head\.label)|"
    r"comment\.body|"
    r"review\.body|"
    r"review_comment\.body|"
    r"discussion\.(?:title|body)|"
    r"head_commit\.message|"
    r"commits\[[^\]]+\]\.message|"
    r"workflow_run\.head_branch"
    r")\s*\}\}"
)

INLINE_SECRET_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("GitHub classic PAT", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Generic API/Secret token", re.compile(r"(?i)\b(?:api_key|secret_key|access_token|password|passwd)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]")),
)

SAMPLE_VULNERABLE_WORKFLOW = """name: PR Preview & Deploy
on:
  pull_request_target:
    types: [opened, synchronize]

permissions: write-all

jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Greet PR author
        env:
          GH_TOKEN_FALLBACK: "ghp_1234567890abcdef1234567890abcdef1234"
        run: |
          echo "Reviewing: ${{ github.event.pull_request.title }}"
"""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    file: str
    line: int
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _strip_quotes(val: str) -> str:
    val = val.strip()
    if len(val) >= 2 and ((val[0] == val[-1] == '"') or (val[0] == val[-1] == "'")):
        return val[1:-1]
    return val


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_comment_or_empty(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def lint_workflow_text(content: str, filename: str = "workflow.yml") -> List[Finding]:
    """Lint a single GitHub Actions workflow YAML string and return findings."""
    findings: List[Finding] = []
    lines = content.splitlines()

    has_top_permissions = False
    has_top_concurrency = False
    has_pull_request_target = False
    prt_line = 1

    in_jobs = False
    jobs_indent = 0
    current_job: Optional[str] = None
    current_job_line = 1
    current_job_indent = 0
    job_has_timeout: Dict[str, bool] = {}
    job_lines: Dict[str, int] = {}

    in_run_block = False
    run_block_indent = 0

    for idx, raw_line in enumerate(lines, start=1):
        if _is_comment_or_empty(raw_line):
            continue

        indent = _indent_of(raw_line)
        stripped = raw_line.strip()

        if in_run_block:
            if indent > run_block_indent:
                _check_run_line(raw_line, idx, filename, findings)
                _check_inline_secrets(raw_line, idx, filename, findings)
                continue
            in_run_block = False

        # Top-level keys
        if indent == 0:
            kv = KEY_VALUE_RE.match(raw_line)
            if kv:
                key = kv.group(1)
                val = kv.group(2).strip()
                if key == "permissions":
                    has_top_permissions = True
                    if _strip_quotes(val) == "write-all":
                        findings.append(
                            Finding(
                                rule_id="GHA003",
                                severity="HIGH",
                                title="Excessive workflow permissions (write-all)",
                                message="Top-level 'permissions: write-all' grants broad write access to GITHUB_TOKEN.",
                                file=filename,
                                line=idx,
                                remediation="Use least-privilege permissions (e.g., 'permissions: { contents: read }').",
                            )
                        )
                elif key == "concurrency":
                    has_top_concurrency = True
                elif key == "jobs":
                    in_jobs = True
                    jobs_indent = indent
                else:
                    if key != "jobs":
                        in_jobs = False

        # Detect pull_request_target trigger
        if re.match(r"^\s*pull_request_target\s*:", raw_line) or re.match(
            r"^\s*on\s*:\s*.*pull_request_target", raw_line
        ):
            has_pull_request_target = True
            prt_line = idx

        # Track jobs
        if in_jobs and indent > jobs_indent:
            kv = KEY_VALUE_RE.match(raw_line)
            if kv and not raw_line.lstrip().startswith("-"):
                key = kv.group(1)
                if current_job is None or indent == current_job_indent:
                    if key not in ("steps", "runs-on", "needs", "if", "env", "permissions", "strategy", "outputs", "timeout-minutes", "concurrency"):
                        current_job = key
                        current_job_indent = indent
                        current_job_line = idx
                        job_has_timeout.setdefault(current_job, False)
                        job_lines.setdefault(current_job, idx)
                elif indent > current_job_indent and current_job is not None:
                    if key == "timeout-minutes":
                        job_has_timeout[current_job] = True
                    elif key == "permissions" and _strip_quotes(kv.group(2)) == "write-all":
                        findings.append(
                            Finding(
                                rule_id="GHA003",
                                severity="HIGH",
                                title="Excessive job permissions (write-all)",
                                message=f"Job '{current_job}' sets 'permissions: write-all'.",
                                file=filename,
                                line=idx,
                                remediation="Scope job permissions to only the required read/write scopes.",
                            )
                        )

        # Check uses: for unpinned third-party actions
        uses_match = USES_RE.match(raw_line)
        if uses_match:
            action_ref = uses_match.group(1)
            if not action_ref.startswith("./") and not action_ref.startswith("docker://"):
                if "@" in action_ref:
                    action_name, ref = action_ref.rsplit("@", 1)
                    if not SHA40_RE.match(ref):
                        findings.append(
                            Finding(
                                rule_id="GHA001",
                                severity="HIGH",
                                title="Unpinned third-party GitHub Action",
                                message=f"Action '{action_name}@{ref}' is not pinned to a 40-character commit SHA.",
                                file=filename,
                                line=idx,
                                remediation=f"Pin '{action_name}' to a full 40-char commit SHA (e.g., {action_name}@<40-char-sha> # {ref}).",
                            )
                        )

        # Check pull_request_target + head checkout
        if has_pull_request_target and "pull_request.head" in raw_line and "ref:" in raw_line:
            findings.append(
                Finding(
                    rule_id="GHA002",
                    severity="CRITICAL",
                    title="pull_request_target untrusted head checkout",
                    message="Checking out 'pull_request.head' inside 'pull_request_target' executes untrusted fork code with base repo secrets.",
                    file=filename,
                    line=idx,
                    remediation="Use 'pull_request' trigger instead, or never check out / execute untrusted PR head code in 'pull_request_target'.",
                )
            )

        # Check run: lines (single-line or block)
        run_match = RUN_START_RE.match(raw_line)
        if run_match:
            rest = run_match.group(1).strip()
            if rest in ("|", "|-", "|+", ">", ">-", ">+"):
                in_run_block = True
                run_block_indent = indent
            else:
                _check_run_line(rest, idx, filename, findings)

        # Check inline secrets on any line
        _check_inline_secrets(raw_line, idx, filename, findings)

    # Post-pass workflow checks
    if has_pull_request_target and not any(f.rule_id == "GHA002" for f in findings):
        findings.append(
            Finding(
                rule_id="GHA002",
                severity="MEDIUM",
                title="pull_request_target trigger used",
                message="Workflow uses 'pull_request_target', which runs with base repository privileges and secrets.",
                file=filename,
                line=prt_line,
                remediation="Prefer 'pull_request' unless base-repo write access is strictly required and no untrusted code is executed.",
            )
        )

    if not has_top_permissions:
        findings.append(
            Finding(
                rule_id="GHA004",
                severity="MEDIUM",
                title="Missing top-level permissions block",
                message="Workflow does not declare top-level 'permissions:', which may default to broad read-write token scopes.",
                file=filename,
                line=1,
                remediation="Add 'permissions: read-all' or 'permissions: {}' at the top level and grant scopes per job.",
            )
        )

    if not has_top_concurrency:
        findings.append(
            Finding(
                rule_id="GHA008",
                severity="LOW",
                title="Missing workflow concurrency group",
                message="Workflow lacks a top-level 'concurrency:' block, risking wasted CI minutes on superseded runs.",
                file=filename,
                line=1,
                remediation="Add 'concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }'.",
            )
        )

    for job_name, has_timeout in job_has_timeout.items():
        if not has_timeout:
            findings.append(
                Finding(
                    rule_id="GHA007",
                    severity="LOW",
                    title="Missing job timeout-minutes",
                    message=f"Job '{job_name}' does not set 'timeout-minutes', defaulting to 360 minutes (6 hours).",
                    file=filename,
                    line=job_lines.get(job_name, 1),
                    remediation="Set 'timeout-minutes: 15' (or appropriate limit) on every job.",
                )
            )

    return findings


def _check_run_line(line: str, line_no: int, filename: str, findings: List[Finding]) -> None:
    match = UNTRUSTED_CONTEXT_RE.search(line)
    if match:
        findings.append(
            Finding(
                rule_id="GHA006",
                severity="CRITICAL",
                title="Script injection via untrusted GitHub context",
                message=f"Untrusted expression '{match.group(0)}' interpolated directly inside 'run:'.",
                file=filename,
                line=line_no,
                remediation="Pass untrusted values through an 'env:' variable and quote it in shell (e.g. \"$PR_TITLE\").",
            )
        )


def _check_inline_secrets(line: str, line_no: int, filename: str, findings: List[Finding]) -> None:
    if "${{ secrets." in line:
        return
    for label, pattern in INLINE_SECRET_PATTERNS:
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="GHA005",
                    severity="CRITICAL",
                    title=f"Hardcoded secret detected ({label})",
                    message=f"Potential {label} found inline in workflow file.",
                    file=filename,
                    line=line_no,
                    remediation="Move credentials to GitHub Actions Secrets and reference via '${{ secrets.NAME }}'.",
                )
            )
            break


def discover_workflow_files(target: Path) -> List[Path]:
    """Find .yml/.yaml workflow files from a file or directory path."""
    if target.is_file():
        return [target]
    if not target.exists():
        return []

    workflows_dir = target / ".github" / "workflows"
    search_root = workflows_dir if workflows_dir.is_dir() else target
    files = sorted(
        p for p in search_root.rglob("*") if p.is_file() and p.suffix.lower() in (".yml", ".yaml")
    )
    return files


def scan_path(target: Path) -> Tuple[List[Path], List[Finding]]:
    """Scan a file or repository path and return (scanned_files, findings)."""
    files = discover_workflow_files(target)
    all_findings: List[Finding] = []
    for wf in files:
        text = wf.read_text(encoding="utf-8", errors="replace")
        all_findings.extend(lint_workflow_text(text, filename=str(wf)))
    return files, all_findings


def format_text(files: Sequence[Path], findings: Sequence[Finding]) -> str:
    if not files:
        return "No workflow files found."
    lines = [f"Scanned {len(files)} workflow file(s). Found {len(findings)} issue(s):"]
    for f in findings:
        lines.append(f"  [{f.severity}] {f.rule_id} {f.file}:{f.line} - {f.title}")
        lines.append(f"    {f.message}")
        lines.append(f"    Fix: {f.remediation}")
    return "\n".join(lines)


def format_json(files: Sequence[Path], findings: Sequence[Finding]) -> str:
    payload = {
        "tool": "gha-lint-lite",
        "version": VERSION,
        "scanned_files": [str(p) for p in files],
        "issue_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def format_sarif(files: Sequence[Path], findings: Sequence[Finding]) -> str:
    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }
    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "level": level_map.get(f.severity, "warning"),
                "message": {"text": f"{f.title}: {f.message} Fix: {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file.replace("\\", "/")},
                            "region": {"startLine": f.line},
                        }
                    }
                ],
            }
        )
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "gha-lint-lite",
                        "version": VERSION,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gha_lint.py",
        description="Zero-dependency GitHub Actions workflow security linter (Lite).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser("scan", help="Scan a workflow file or repository directory.")
    scan_cmd.add_argument("path", nargs="?", default=".", help="Path to repo, .github/workflows, or .yml file.")
    scan_cmd.add_argument("--format", choices=("text", "json", "sarif"), default="text")

    demo_cmd = sub.add_parser("demo", help="Run linter against a built-in vulnerable workflow sample.")
    demo_cmd.add_argument("--format", choices=("text", "json", "sarif"), default="text")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "demo":
        files = [Path(".github/workflows/pr-preview.yml")]
        findings = lint_workflow_text(SAMPLE_VULNERABLE_WORKFLOW, filename=str(files[0]))
    else:
        target = Path(args.path)
        files, findings = scan_path(target)

    if args.format == "json":
        print(format_json(files, findings))
    elif args.format == "sarif":
        print(format_sarif(files, findings))
    else:
        print(format_text(files, findings))

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
