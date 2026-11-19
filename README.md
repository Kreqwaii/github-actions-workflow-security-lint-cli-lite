# GitHub Actions Workflow Security Lint CLI (Lite)

A **zero-dependency Python 3.9+ CLI linter** for `.github/workflows/*.yml` and `*.yaml` files. Catch supply-chain, privilege-escalation, and CI/CD security misconfigurations before they reach `main`.

## The Problem

GitHub Actions workflows frequently ship with silent security risks:
- **Unpinned third-party actions** (`@v4`, `@main`) vulnerable to tag-hijacking supply-chain attacks.
- **`pull_request_target` + head checkout** executing untrusted fork code with base-repository secrets.
- **Over-privileged `GITHUB_TOKEN`** (`permissions: write-all` or missing `permissions:` blocks).
- **Script injection** via `${{ github.event.pull_request.title }}` inside `run:` blocks.
- **Hardcoded secrets** or missing `timeout-minutes` / `concurrency` guards.

## Features

- **100% Python 3.9+ stdlib only** — zero `pip install` dependencies, instant CI drop-in.
- **Multiple output formats** — `text`, `json`, and `sarif` (2.1.0 for GitHub Code Scanning).
- **Deterministic exit codes** — `0` when clean, `1` when findings are detected.
- **Built-in `demo` mode** — test the linter immediately without a target repo.

## Quickstart

```bash
# Run built-in vulnerable workflow demo
python gha_lint.py demo

# Scan current repository (.github/workflows/*.yml)
python gha_lint.py scan .

# Output SARIF for GitHub Code Scanning
python gha_lint.py scan . --format sarif > gha-lint.sarif

# Output JSON for CI pipelines
python gha_lint.py scan .github/workflows/ci.yml --format json
```

## Sample CLI Output

```text
Scanned 1 workflow file(s). Found 8 issue(s):
  [HIGH] GHA003 .github/workflows/pr-preview.yml:6 - Excessive workflow permissions (write-all)
    Top-level 'permissions: write-all' grants broad write access to GITHUB_TOKEN.
    Fix: Use least-privilege permissions (e.g., 'permissions: { contents: read }').
  [HIGH] GHA001 .github/workflows/pr-preview.yml:12 - Unpinned third-party GitHub Action
    Action 'actions/checkout@v4' is not pinned to a 40-character commit SHA.
    Fix: Pin 'actions/checkout' to a full 40-char commit SHA (e.g., actions/checkout@<40-char-sha> # v4).
  [CRITICAL] GHA002 .github/workflows/pr-preview.yml:14 - pull_request_target untrusted head checkout
    Checking out 'pull_request.head' inside 'pull_request_target' executes untrusted fork code with base repo secrets.
    Fix: Use 'pull_request' trigger instead, or never check out / execute untrusted PR head code in 'pull_request_target'.
```

## Rule Table

| Rule ID | Severity | Description |
| --- | --- | --- |
| `GHA001` | HIGH | Unpinned third-party GitHub Action (not pinned to a 40-char commit SHA) |
| `GHA002` | CRITICAL / MEDIUM | `pull_request_target` trigger or untrusted `pull_request.head` checkout |
| `GHA003` | HIGH | Excessive `permissions: write-all` at workflow or job level |
| `GHA004` | MEDIUM | Missing top-level `permissions:` block |
| `GHA005` | CRITICAL | Hardcoded inline secret or token (`ghp_`, `github_pat_`, `AKIA...`, etc.) |
| `GHA006` | CRITICAL | Script injection via untrusted `${{ github.event.* }}` inside `run:` |
| `GHA007` | LOW | Missing `timeout-minutes` on job |
| `GHA008` | LOW | Missing top-level `concurrency:` group |

## Running Tests

```bash
python -m unittest discover -s tests -v
```

---

### Need Web Dashboard, Team Policy Bundles & HTML Executive Reports?

Upgrade to **Pro Studio** for multi-repo organization scanning, custom Rego/YAML policy bundles, interactive web dashboards, and client-ready HTML executive reports:

👉 **[Pro Studio on FunPay](https://funpay.com/users/20096179/)**
