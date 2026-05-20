"""S7 DoD #3 — end-to-end full pipeline on `symfony_minimal`.

Wires together every stage that `/fr-security-review:security-project` runs in
a real review:

    recon_inventory → plan_waves → (worker output is seeded by hand) → dedupe

The worker step is **simulated**: spawning a Claude subagent inside `python3
-m unittest` is out of scope, and the worker's only contract is the markdown
shape its agent emits into `<review_root>/waves/<slice_id>.md`. We hand-write
exactly that shape — including the seeded IDOR finding from
`fixtures/symfony_minimal/src/Controller/PostController.php:39` — and verify
that dedupe groups it correctly into the split-report layout
(`REPORT.md` + `REPORT/<root_cause_family>.md`).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent
RECON = BIN_DIR / "recon_inventory.py"
PLAN_WAVES = BIN_DIR / "plan_waves.py"
DEDUPE = BIN_DIR / "dedupe_findings.py"

FIX_SYMFONY_MINIMAL = THIS_DIR / "fixtures" / "symfony_minimal"


def _run(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True, text=True, timeout=timeout,
    )


# -----------------------------------------------------------------------------
# Worker output simulator: emits one wave's SECURITY_REVIEW_RESULTS file with
# the seeded IDOR finding. Schema matches agents/security.md output spec.
# -----------------------------------------------------------------------------

SEEDED_IDOR_MD = """# Vulnerability 1: [missing_authz]: `src/Controller/PostController.php:39`

* **Severity**: High
* **Confidence**: 9/10
* **Category**: missing_authz
* **sink_kind**: idor_lookup
* **root_cause_family**: authz
* **enclosing_symbol**: PostController::show
* **sink_snippet**: |
    $post = $repo->find($request->get('id'));
* **Description**: GET /posts/show reads `id` from request and returns the post
    body without any authorization check on ownership/role.
* **Data path**: $request->get('id') -> PostRepository::find -> response body
* **Exploitation scenario**: GET /posts/show?id=42 returns any post.
* **Impact**: IDOR -- disclosure of any Post by guessable id.
* **Recommendation**: add `denyAccessUnlessGranted(PostVoter::VIEW, $post)`
    or scope query by current user.
* **Discovered via**: checklist:stacks/symfony/auth.md
"""


class FullPipelineOnSymfonyMinimal(unittest.TestCase):
    """Recon → plan → seeded worker output → dedupe."""

    @classmethod
    def setUpClass(cls):
        if not shutil.which("php"):
            raise unittest.SkipTest("php not on PATH (recipe needs the PHP extractor)")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.review_root = Path(cls.tmp.name) / "review"

        # Stage 1 — recon (no console, ceiling=medium is fine for E2E).
        recon = _run(
            str(RECON), str(FIX_SYMFONY_MINIMAL),
            "--recipe", "symfony",
            "--review-root", str(cls.review_root),
            "--no-console",
        )
        # bare `assert` here would be stripped under `python -O`; use a real
        # exception so a CI run with optimisation flags still reports the
        # underlying recipe failure rather than passing an empty fixture
        # downstream.
        if recon.returncode != 0:
            raise RuntimeError(f"recon failed: {recon.stderr}")
        cls.recon = recon

        # Stage 2 — plan_waves on the resulting CONTEXT.md.
        plan = _run(
            str(PLAN_WAVES), str(cls.review_root / "CONTEXT.md"),
            "--exploratory",
        )
        if plan.returncode != 0:
            raise RuntimeError(f"plan_waves failed: {plan.stderr}")
        cls.plan_stdout = plan.stdout
        cls.plan = json.loads(plan.stdout)

        # Stage 3 — simulate worker output for W1 (auth wave).
        waves_dir = cls.review_root / "waves"
        waves_dir.mkdir(parents=True, exist_ok=True)
        cls.wave_md = waves_dir / "W1_PART1.md"
        cls.wave_md.write_text(SEEDED_IDOR_MD, encoding="utf-8")

        # Stage 4 — dedupe split report.
        cls.report = cls.review_root / "REPORT.md"
        cls.details = cls.review_root / "REPORT"
        dd = _run(
            str(DEDUPE),
            "--input-glob", str(cls.review_root / "waves" / "*.md"),
            "--output", str(cls.report),
            "--details-dir", str(cls.details),
        )
        if dd.returncode != 0:
            raise RuntimeError(f"dedupe failed: {dd.stderr}")
        cls.dedupe = dd

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "tmp"):
            cls.tmp.cleanup()

    # -- recon ----

    def test_recon_emitted_review_root(self):
        self.assertTrue((self.review_root / "CONTEXT.md").is_file())
        self.assertTrue((self.review_root / ".gitignore").is_file())

    # -- plan ----

    def test_plan_includes_w1_auth_wave(self):
        # symfony fixture has http_route + voter triggers for the auth wave,
        # so the parsed plan must contain a W1_PART1 slice.
        slice_ids = [s["slice_id"] for s in self.plan]
        self.assertIn("W1_PART1", slice_ids,
                      msg=f"slice_ids in plan: {slice_ids}")

    def test_plan_resolves_symfony_auth_checklist(self):
        # Stack=symfony → stacks/symfony/auth.md must be in the plan
        # for any wave that includes the `auth` theme.
        all_checklists = {c for s in self.plan for c in s.get("checklists", [])}
        self.assertTrue(
            any("stacks/symfony/auth.md" in c for c in all_checklists),
            msg=f"no symfony auth checklist resolved; checklists={all_checklists}",
        )
        self.assertTrue(
            any(c.endswith("core/auth.md") for c in all_checklists),
            msg=f"no core auth checklist resolved; checklists={all_checklists}",
        )

    def test_plan_uses_post_controller_as_target(self):
        # PostController is in the http_route attack_surface, so it must
        # land in some wave's target_files.
        all_targets = {t for s in self.plan for t in s.get("target_files", [])}
        self.assertIn("src/Controller/PostController.php", all_targets)

    # -- dedupe ----

    def test_dedupe_split_report_written(self):
        self.assertTrue(self.report.is_file())
        self.assertTrue(self.details.is_dir())

    def test_index_lists_seeded_finding(self):
        idx = self.report.read_text(encoding="utf-8")
        self.assertIn("PostController.php:39", idx)
        # Index links to the per-family detail file by relative path; assert
        # the full link target so a future change to `details_dirname` is
        # caught instead of silently passing on the substring "authz.md".
        self.assertIn("REPORT/authz.md", idx)
        # Severity/sink_kind surface in the index table.
        self.assertIn("idor_lookup", idx)

    def test_authz_family_detail_contains_full_finding(self):
        authz = self.details / "authz.md"
        self.assertTrue(authz.is_file(),
                        msg=f"missing detail file; details/={list(self.details.iterdir())}")
        body = authz.read_text(encoding="utf-8")
        self.assertIn("PostController::show", body)
        self.assertIn("idor_lookup", body)
        # confidence ≥ 8 must survive end-to-end (worker output had 9/10).
        self.assertIn("9/10", body)

    def test_no_manual_review_for_clean_input(self):
        # The seeded finding has a known symbol + sink_file:line + standard
        # sink_kind, so it must not land in manual_review.
        manual = self.details / "manual_review.md"
        self.assertFalse(manual.is_file(),
                         msg="seeded clean finding leaked into manual_review")


if __name__ == "__main__":
    unittest.main()
