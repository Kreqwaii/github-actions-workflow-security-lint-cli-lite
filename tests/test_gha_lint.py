import json
import tempfile
import unittest
from pathlib import Path

import gha_lint


CLEAN_WORKFLOW = """name: CI
on: [push, pull_request]
permissions:
  contents: read
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: echo "clean"
"""


class TestGhaLint(unittest.TestCase):
    def test_clean_workflow_has_zero_findings(self) -> None:
        findings = gha_lint.lint_workflow_text(CLEAN_WORKFLOW, "ci.yml")
        self.assertEqual(findings, [])

    def test_unpinned_action_tag_flagged(self) -> None:
        wf = CLEAN_WORKFLOW.replace(
            "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
            "actions/checkout@v4",
        )
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertTrue(any(f.rule_id == "GHA001" for f in findings))

    def test_unpinned_action_branch_flagged(self) -> None:
        wf = CLEAN_WORKFLOW.replace(
            "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
            "some-org/some-action@main",
        )
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertTrue(any(f.rule_id == "GHA001" for f in findings))

    def test_local_action_not_flagged_for_sha(self) -> None:
        wf = CLEAN_WORKFLOW.replace(
            "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
            "./.github/actions/build",
        )
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertFalse(any(f.rule_id == "GHA001" for f in findings))

    def test_docker_action_not_flagged_for_sha(self) -> None:
        wf = CLEAN_WORKFLOW.replace(
            "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
            "docker://alpine:3.19",
        )
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertFalse(any(f.rule_id == "GHA001" for f in findings))

    def test_pull_request_target_head_checkout_critical(self) -> None:
        wf = """name: PRT
on:
  pull_request_target:
permissions: read-all
concurrency:
  group: g
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
        findings = gha_lint.lint_workflow_text(wf, "prt.yml")
        gha002 = [f for f in findings if f.rule_id == "GHA002"]
        self.assertEqual(len(gha002), 1)
        self.assertEqual(gha002[0].severity, "CRITICAL")

    def test_pull_request_target_without_head_checkout_medium(self) -> None:
        wf = """name: PRT
on:
  pull_request_target:
permissions: read-all
concurrency:
  group: g
jobs:
  label:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: echo "ok"
"""
        findings = gha_lint.lint_workflow_text(wf, "prt.yml")
        gha002 = [f for f in findings if f.rule_id == "GHA002"]
        self.assertEqual(len(gha002), 1)
        self.assertEqual(gha002[0].severity, "MEDIUM")

    def test_top_level_write_all_flagged(self) -> None:
        wf = CLEAN_WORKFLOW.replace("permissions:\n  contents: read", "permissions: write-all")
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertTrue(any(f.rule_id == "GHA003" for f in findings))

    def test_job_level_write_all_flagged(self) -> None:
        wf = CLEAN_WORKFLOW.replace(
            "    timeout-minutes: 15",
            "    timeout-minutes: 15\n    permissions: write-all",
        )
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertTrue(any(f.rule_id == "GHA003" for f in findings))

    def test_missing_top_level_permissions_flagged(self) -> None:
        wf = CLEAN_WORKFLOW.replace("permissions:\n  contents: read\n", "")
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertTrue(any(f.rule_id == "GHA004" for f in findings))

    def test_inline_github_pat_flagged(self) -> None:
        wf = CLEAN_WORKFLOW + '      - run: echo "ghp_1234567890abcdef1234567890abcdef1234"\n'
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertTrue(any(f.rule_id == "GHA005" for f in findings))

    def test_inline_aws_key_flagged(self) -> None:
        wf = CLEAN_WORKFLOW + '      - run: echo "AKIAIOSFODNN7EXAMPLE"\n'
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertTrue(any(f.rule_id == "GHA005" for f in findings))

    def test_secrets_context_not_flagged_as_inline_secret(self) -> None:
        wf = CLEAN_WORKFLOW + '      - run: echo "${{ secrets.MY_TOKEN }}"\n'
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertFalse(any(f.rule_id == "GHA005" for f in findings))

    def test_script_injection_single_line_run(self) -> None:
        wf = CLEAN_WORKFLOW + '      - run: echo "${{ github.event.issue.title }}"\n'
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertTrue(any(f.rule_id == "GHA006" for f in findings))

    def test_script_injection_multiline_run(self) -> None:
        wf = CLEAN_WORKFLOW + "      - run: |\n          echo \"${{ github.event.comment.body }}\"\n"
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertTrue(any(f.rule_id == "GHA006" for f in findings))

    def test_missing_timeout_minutes_flagged(self) -> None:
        wf = CLEAN_WORKFLOW.replace("    timeout-minutes: 15\n", "")
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertTrue(any(f.rule_id == "GHA007" for f in findings))

    def test_missing_concurrency_flagged(self) -> None:
        wf = CLEAN_WORKFLOW.replace(
            "concurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: true\n",
            "",
        )
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertTrue(any(f.rule_id == "GHA008" for f in findings))

    def test_comments_ignored(self) -> None:
        wf = CLEAN_WORKFLOW + "      # - uses: actions/checkout@v4\n"
        findings = gha_lint.lint_workflow_text(wf, "ci.yml")
        self.assertEqual(findings, [])

    def test_demo_sample_has_multiple_findings(self) -> None:
        findings = gha_lint.lint_workflow_text(gha_lint.SAMPLE_VULNERABLE_WORKFLOW, "demo.yml")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("GHA001", rule_ids)
        self.assertIn("GHA002", rule_ids)
        self.assertIn("GHA003", rule_ids)
        self.assertIn("GHA005", rule_ids)
        self.assertIn("GHA006", rule_ids)

    def test_discover_workflow_files_in_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wf_dir = root / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "ci.yml").write_text(CLEAN_WORKFLOW, encoding="utf-8")
            (root / "README.md").write_text("hi", encoding="utf-8")
            found = gha_lint.discover_workflow_files(root)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].name, "ci.yml")

    def test_discover_nonexistent_path_returns_empty(self) -> None:
        found = gha_lint.discover_workflow_files(Path("/nonexistent/path/12345"))
        self.assertEqual(found, [])

    def test_scan_path_returns_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wf = Path(tmp) / "bad.yaml"
            wf.write_text(gha_lint.SAMPLE_VULNERABLE_WORKFLOW, encoding="utf-8")
            files, findings = gha_lint.scan_path(wf)
            self.assertEqual(len(files), 1)
            self.assertGreater(len(findings), 0)

    def test_format_text_output(self) -> None:
        findings = gha_lint.lint_workflow_text(gha_lint.SAMPLE_VULNERABLE_WORKFLOW, "demo.yml")
        out = gha_lint.format_text([Path("demo.yml")], findings)
        self.assertIn("Scanned 1 workflow file(s).", out)
        self.assertIn("GHA001", out)

    def test_format_json_valid(self) -> None:
        findings = gha_lint.lint_workflow_text(gha_lint.SAMPLE_VULNERABLE_WORKFLOW, "demo.yml")
        out = gha_lint.format_json([Path("demo.yml")], findings)
        data = json.loads(out)
        self.assertEqual(data["tool"], "gha-lint-lite")
        self.assertEqual(data["issue_count"], len(findings))

    def test_format_sarif_valid(self) -> None:
        findings = gha_lint.lint_workflow_text(gha_lint.SAMPLE_VULNERABLE_WORKFLOW, "demo.yml")
        out = gha_lint.format_sarif([Path("demo.yml")], findings)
        data = json.loads(out)
        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(len(data["runs"][0]["results"]), len(findings))

    def test_cli_demo_exit_code_1(self) -> None:
        code = gha_lint.main(["demo", "--format", "json"])
        self.assertEqual(code, 1)

    def test_cli_scan_clean_exit_code_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wf = Path(tmp) / "ci.yml"
            wf.write_text(CLEAN_WORKFLOW, encoding="utf-8")
            code = gha_lint.main(["scan", str(wf), "--format", "text"])
            self.assertEqual(code, 0)

    def test_cli_scan_sarif_exit_code_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wf = Path(tmp) / "bad.yml"
            wf.write_text(gha_lint.SAMPLE_VULNERABLE_WORKFLOW, encoding="utf-8")
            code = gha_lint.main(["scan", str(wf), "--format", "sarif"])
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
