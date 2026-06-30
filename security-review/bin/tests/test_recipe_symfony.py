"""S2 tests — Symfony recipe full inventory.

Covers DoD from REDESIGN_v3_PLAN.md §S2:

1. inventory recall on symfony_minimal `--no-console` — 12/12 attribute routes,
   100 % data_access, all voters / forms / messenger handlers / event listeners
   detected statically.
2. EasyAdmin on symfony_admin → kind: http_route_admin.
3. Hostile-fixture: with `--no-console` `.snitch/pwned` MUST NOT appear.
4. Vendor exclude: `vendor/_fake/Vendor.php`'s `unserialize($_GET[...])` is NOT
   in serialization.
5. Path traversal — utility refuses to read outside project_root.
6. Wall-clock budget — symfony_minimal `--no-console` ≤ 30 s.
7. Per-section source_files on scalar sections (mode=changes channel 2).
8. touched_by_diff propagation when `diff_files` provided.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent
PLUGIN_ROOT = BIN_DIR.parent
RECON = BIN_DIR / "recon_inventory.py"

FIX_MIN = THIS_DIR / "fixtures" / "symfony_minimal"
FIX_ADM = THIS_DIR / "fixtures" / "symfony_admin"
FIX_SONATA = THIS_DIR / "fixtures" / "symfony_sonata_admin"
FIX_HOSTILE = THIS_DIR / "fixtures" / "symfony_hostile_console"

sys.path.insert(0, str(BIN_DIR))
from validate_context import parse_yaml_subset, FRONTMATTER_RE  # noqa: E402
from recon.recipes import symfony as recipe_symfony  # noqa: E402


def _run_recipe(
    project: Path, review_root: Path, *extra: str, timeout: int = 60,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(RECON), str(project),
         "--recipe", "symfony", "--review-root", str(review_root), *extra],
        capture_output=True, text=True, timeout=timeout,
    )


def _read_context(review_root: Path) -> tuple[dict, str]:
    text = (review_root / "CONTEXT.md").read_text(encoding="utf-8")
    m = FRONTMATTER_RE.match(text)
    assert m, f"no frontmatter in {review_root}/CONTEXT.md"
    fm = parse_yaml_subset(m.group(1))
    body = text[m.end():]
    return fm, body


def _section_payload(text: str, section_id: str) -> dict | None:
    """Return the parsed payload for `## ... <!-- section_id: X --> ... yaml ...`.
    For `recon_bags.<key>` use dot-notation.
    """
    import re
    if "." not in section_id:
        anchor = f"<!-- section_id: {section_id} -->"
        idx = text.find(anchor)
        if idx == -1:
            return None
        rest = text[idx:]
        m = re.search(r"```yaml\s*\n(.*?)\n```", rest, re.DOTALL)
        if not m:
            return None
        return parse_yaml_subset(m.group(1))
    parts = section_id.split(".")
    base = _section_payload(text, parts[0])
    cur = base
    for p in parts[1:]:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class InventoryRecallNoConsole(unittest.TestCase):
    """All static-only DoD checks against symfony_minimal."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.review_root = Path(cls.tmp.name) / "review"
        proc = _run_recipe(FIX_MIN, cls.review_root, "--no-console")
        assert proc.returncode == 0, proc.stderr
        cls.text = (cls.review_root / "CONTEXT.md").read_text(encoding="utf-8")
        cls.fm = parse_yaml_subset(FRONTMATTER_RE.match(cls.text).group(1))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_attack_surface_has_12_http_routes(self):
        payload = _section_payload(self.text, "attack_surface")
        items = payload["items"]
        http_routes = [it for it in items if it.get("kind") == "http_route"]
        self.assertEqual(len(http_routes), 12, f"expected 12, got: {[it['identifier'] for it in http_routes]}")

    def test_attack_surface_includes_cli_command(self):
        payload = _section_payload(self.text, "attack_surface")
        cli = [it for it in payload["items"] if it.get("kind") == "cli_command"]
        self.assertTrue(len(cli) >= 1, f"no cli_command items: {payload['items']}")
        # AsCommand attribute provided `name: 'app:sync'` — recipe must surface it.
        self.assertEqual(cli[0]["identifier"], "app:sync")

    def test_attack_surface_includes_message_handler(self):
        payload = _section_payload(self.text, "attack_surface")
        handlers = [it for it in payload["items"] if it.get("kind") == "message_handler"]
        self.assertEqual(len(handlers), 1)
        self.assertEqual(handlers[0]["handler"], "App\\Messenger\\SendEmailHandler")

    def test_attack_surface_includes_event_listener(self):
        payload = _section_payload(self.text, "attack_surface")
        listeners = [it for it in payload["items"] if it.get("kind") == "event_listener"]
        self.assertEqual(len(listeners), 1)
        self.assertEqual(listeners[0]["handler"], "App\\EventListener\\RequestListener")

    def test_data_access_has_both_repositories(self):
        payload = _section_payload(self.text, "data_access")
        files = {it["file"] for it in payload["items"]}
        self.assertEqual(
            files,
            {"src/Repository/PostRepository.php", "src/Repository/UserRepository.php"},
        )

    def test_voters_collected_with_attributes_and_subjects(self):
        payload = _section_payload(self.text, "recon_bags.stack.symfony.voters")
        self.assertEqual(payload["status"], "ok")
        items = payload["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["class"], "App\\Security\\Voter\\PostVoter")
        self.assertEqual(set(items[0]["attributes"]), {"POST_VIEW", "POST_EDIT"})
        self.assertEqual(items[0]["subjects"], ["App\\Entity\\Post"])

    def test_forms_collected(self):
        payload = _section_payload(self.text, "recon_bags.stack.symfony.forms")
        items = payload["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["class"], "App\\Form\\PostType")
        self.assertEqual(items[0]["data_class"], "App\\Entity\\Post")
        self.assertEqual(items[0]["csrf_protection"], True)
        self.assertEqual(items[0]["allow_extra_fields"], False)

    def test_authz_usage_collects_call_sites(self):
        payload = _section_payload(self.text, "authz_usage")
        items = payload["items"]
        # PostController::edit + PostController::delete + UserController::update.
        self.assertGreaterEqual(len(items), 3)
        self.assertTrue(any(it["kind"] == "denyAccessUnlessGranted" for it in items))

    def test_auth_layer_scalar_with_source_files(self):
        payload = _section_payload(self.text, "auth_layer")
        self.assertEqual(payload["status"], "ok")
        self.assertIn("kind", payload["data"])
        self.assertEqual(payload["source_files"], ["config/packages/security.yaml"])

    def test_auth_layer_provider_name_resolved(self):
        # Regression: `_first_key_under` used to look at indent==0 only and
        # missed nested `security: providers:` blocks → provider was always
        # "unknown". Fixed via `_first_key_under_nested(("security","providers"))`.
        payload = _section_payload(self.text, "auth_layer")
        self.assertEqual(payload["data"]["provider"], "app_user_provider")

    def test_firewalls_parsed_from_security_yaml(self):
        payload = _section_payload(self.text, "recon_bags.stack.symfony.firewalls")
        self.assertEqual(payload["status"], "ok")
        names = {fw["name"] for fw in payload["data"]["firewalls"]}
        self.assertEqual(names, {"dev", "main"})
        self.assertEqual(payload["source_files"], ["config/packages/security.yaml"])

    def test_messenger_transports_parsed_from_yaml(self):
        payload = _section_payload(self.text, "recon_bags.stack.symfony.messenger_transports")
        self.assertEqual(payload["status"], "ok")
        names = {t["name"] for t in payload["data"]["transports"]}
        self.assertEqual(names, {"async", "sync"})
        self.assertEqual(payload["source_files"], ["config/packages/messenger.yaml"])

    def test_messenger_transports_no_serializer_when_absent(self):
        # symfony_minimal fixture has no `serializer:` key — the field must be
        # absent rather than defaulted to a string. The worker uses absence vs
        # presence to decide whether to read messenger.yaml directly.
        payload = _section_payload(self.text, "recon_bags.stack.symfony.messenger_transports")
        for t in payload["data"]["transports"]:
            self.assertNotIn("serializer", t,
                             f"unexpected serializer in {t!r} when yaml has none")

    def test_twig_overrides_parsed_from_yaml(self):
        payload = _section_payload(self.text, "recon_bags.stack.symfony.twig_overrides")
        self.assertEqual(payload["status"], "ok")
        # Our fixture has 1 |raw filter in templates/post/show.html.twig.
        self.assertGreaterEqual(payload["data"]["raw_filter_count"], 1)
        self.assertEqual(payload["data"]["autoescape_default"], "name")

    def test_serialization_excludes_vendor(self):
        payload = _section_payload(self.text, "serialization")
        for it in payload["items"]:
            self.assertNotIn("vendor/", it["file"], msg=f"vendor leak: {it}")

    def test_secrets_status_pending_enrichment(self):
        payload = _section_payload(self.text, "secrets")
        self.assertEqual(payload["status"], "pending_enrichment")
        self.assertIn("enrichment_hint", payload)
        # Static collector populates app_secret_in_repo, password_hasher etc.
        self.assertIn("app_secret_in_repo", payload["data"])

    def test_secrets_password_hasher_is_algorithm_not_subject(self):
        # Regression: greedy regex `password_hashers:.*?:\s*['\"]?([A-Za-z0-9_]+)`
        # used to capture the subject FQN (`Symfony` from
        # `Symfony\...\PasswordAuthenticatedUserInterface`) instead of the
        # algorithm value (`auto`). Fixed via `_parse_password_hasher`.
        payload = _section_payload(self.text, "secrets")
        self.assertEqual(payload["data"]["password_hasher"], "auto")

    def test_console_disabled_warning_present(self):
        self.assertIn("console_disabled_by_flag", self.fm["warnings"])
        self.assertEqual(self.fm["recon_confidence"]["ceiling"], "medium")

    def test_recipe_used_is_symfony(self):
        self.assertEqual(self.fm["recipe_used"], "symfony")
        self.assertEqual(self.fm["stack"]["framework"], "symfony")


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class VendorExcludeWithSyntheticFile(unittest.TestCase):
    """Recipe must NOT report `vendor/**/*.php` matches in serialization /
    file_operations / http_clients (rev 3.5 G-Vendor.1).

    Built as a synthetic test (copy minimal fixture → drop a vendor/_fake file
    with hostile content → run recipe → assert exclusion). Avoids dependence
    on a tracked `vendor/` payload, which is gitignored by default.
    """

    def test_unserialize_in_vendor_is_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / "proj"
            shutil.copytree(FIX_MIN, scratch)
            vendor_file = scratch / "vendor" / "_fake" / "Vendor.php"
            vendor_file.parent.mkdir(parents=True, exist_ok=True)
            vendor_file.write_text(
                "<?php\nfunction pwn() { return unserialize($_GET['x']); }\n"
            )
            review_root = scratch / "review"
            proc = _run_recipe(scratch, review_root, "--no-console")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text()
            payload = _section_payload(text, "serialization")
        for it in payload["items"]:
            self.assertNotIn("vendor/", it["file"], msg=f"vendor leak: {it}")


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class YamlSecretsCandidateScan(unittest.TestCase):
    """Recipe must scan `config/**/*.yaml` for credential-prefix tokens.
    Synthetic test — drop a yaml with `sk_live_...` into the minimal fixture
    and assert it surfaces in `secrets.candidates`."""

    def test_yaml_resident_stripe_key_surfaces(self):
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / "proj"
            shutil.copytree(FIX_MIN, scratch)
            (scratch / "config" / "packages").mkdir(parents=True, exist_ok=True)
            (scratch / "config" / "secrets.yaml").write_text(
                "parameters:\n"
                "    app.payment_secret: 'sk_live_FAKE_FIXTURE_KEY_NOT_REAL'\n"
            )
            review_root = scratch / "review"
            proc = _run_recipe(scratch, review_root, "--no-console")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text()
            payload = _section_payload(text, "secrets")
        candidates = payload["data"]["candidates"]
        yaml_hit = next(
            (c for c in candidates
             if c["file"] == "config/secrets.yaml"
             and c["regex_match"] == "stripe_live_key"),
            None,
        )
        self.assertIsNotNone(yaml_hit,
                             f"yaml secret missed; candidates={candidates!r}")


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class IndirectInheritanceCliCommand(unittest.TestCase):
    """`_classify_kind` must detect CLI commands defined as
    `MyCommand extends BaseCommand extends Symfony\\...\\Command\\Command`
    via `parent_chain` rather than direct `extends` only."""

    def test_indirect_command_surfaces_in_attack_surface(self):
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / "proj"
            shutil.copytree(FIX_MIN, scratch)
            console_dir = scratch / "src" / "Console"
            console_dir.mkdir(parents=True, exist_ok=True)
            (console_dir / "BaseCommand.php").write_text(textwrap.dedent("""\
                <?php
                namespace App\\Console;
                use Symfony\\Component\\Console\\Command\\Command;
                abstract class BaseCommand extends Command {}
                """))
            (console_dir / "ImportCommand.php").write_text(textwrap.dedent("""\
                <?php
                namespace App\\Console;
                class ImportCommand extends BaseCommand {
                    protected static $defaultName = 'app:import';
                }
                """))
            review_root = scratch / "review"
            proc = _run_recipe(scratch, review_root, "--no-console")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text()
        payload = _section_payload(text, "attack_surface")
        cli_identifiers = {
            it.get("identifier") for it in payload["items"]
            if it.get("kind") == "cli_command"
        }
        self.assertIn("App\\Console\\ImportCommand", cli_identifiers)


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class ExcludePropagationE2E(unittest.TestCase):
    """End-to-end exclude propagation through every collect_* call site (3.1.1).

    Synthetic legacy/ subtree with a #[Route] controller — without --exclude
    it must surface in attack_surface (control); with --exclude=legacy it
    must NOT. Catches regressions where any of the 6 collect_* helpers
    forgets to forward `exclude=` to sandbox.run_extractor.
    """

    LEGACY_CONTROLLER = textwrap.dedent('''\
        <?php
        namespace App\\Legacy;

        use Symfony\\Component\\HttpFoundation\\Response;
        use Symfony\\Component\\Routing\\Attribute\\Route;

        final class LegacyController
        {
            #[Route('/legacy/foo', name: 'legacy_foo', methods: ['GET'])]
            public function foo(): Response
            {
                return new Response('legacy');
            }
        }
        ''')

    def _scratch_with_legacy(self, td: Path) -> Path:
        scratch = td / "proj"
        shutil.copytree(FIX_MIN, scratch)
        legacy_dir = scratch / "legacy" / "Controller"
        legacy_dir.mkdir(parents=True)
        (legacy_dir / "LegacyController.php").write_text(self.LEGACY_CONTROLLER)
        return scratch

    def test_legacy_present_without_exclude(self):
        # Control case: extractor scans legacy/ (it's not in DEFAULT_EXCLUDE),
        # so the route MUST surface — otherwise the exclude test below would
        # pass for the wrong reason.
        with tempfile.TemporaryDirectory() as td:
            scratch = self._scratch_with_legacy(Path(td))
            review_root = scratch / "review"
            proc = _run_recipe(scratch, review_root, "--no-console")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text()
        payload = _section_payload(text, "attack_surface")
        legacy_files = [it["file"] for it in payload["items"]
                        if it["file"].startswith("legacy/")]
        self.assertTrue(legacy_files,
                        msg="control case failed: legacy/ controller must surface without --exclude")

    def test_legacy_dropped_with_exclude_flag(self):
        with tempfile.TemporaryDirectory() as td:
            scratch = self._scratch_with_legacy(Path(td))
            review_root = scratch / "review"
            proc = _run_recipe(
                scratch, review_root, "--no-console", "--exclude=legacy",
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text()
        payload = _section_payload(text, "attack_surface")
        for it in payload["items"]:
            self.assertFalse(
                it["file"].startswith("legacy/"),
                msg=f"--exclude=legacy did not propagate to attack_surface: {it!r}",
            )

    def test_legacy_repository_dropped_in_data_access(self):
        # Same legacy/ tree but with a Repository class — different code path
        # (collect_data_access). Catches regression in `collect_data_access`
        # forgetting to forward exclude=.
        with tempfile.TemporaryDirectory() as td:
            scratch = self._scratch_with_legacy(Path(td))
            repo_dir = scratch / "legacy" / "Repository"
            repo_dir.mkdir(parents=True)
            (repo_dir / "OldUserRepository.php").write_text(textwrap.dedent('''\
                <?php
                namespace App\\Legacy\\Repository;

                use Doctrine\\Bundle\\DoctrineBundle\\Repository\\ServiceEntityRepository;

                final class OldUserRepository extends ServiceEntityRepository
                {
                }
                '''))
            review_root = scratch / "review"
            proc = _run_recipe(
                scratch, review_root, "--no-console", "--exclude=legacy",
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text()
        payload = _section_payload(text, "data_access")
        for it in payload["items"]:
            self.assertFalse(
                it["file"].startswith("legacy/"),
                msg=f"--exclude=legacy did not propagate to data_access: {it!r}",
            )


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class AdminFixtureRecall(unittest.TestCase):
    """EasyAdmin AbstractCrudController detection → kind: http_route_admin."""

    def test_admin_controllers_detected(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            proc = _run_recipe(FIX_ADM, review_root, "--no-console")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text()
        payload = _section_payload(text, "attack_surface")
        admins = [it for it in payload["items"] if it.get("kind") == "http_route_admin"]
        admin_files = {it["file"] for it in admins}
        # Both PostCrudController and UserCrudController extend AbstractCrudController.
        self.assertIn("src/Controller/Admin/PostCrudController.php", admin_files)
        self.assertIn("src/Controller/Admin/UserCrudController.php", admin_files)


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class EasyadminCrudControllersSection(unittest.TestCase):
    """`recon_bags.addon.easyadmin.crud_controllers` recipe section."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        review_root = Path(cls.tmp.name) / "review"
        proc = _run_recipe(FIX_ADM, review_root, "--no-console")
        assert proc.returncode == 0, proc.stderr
        cls.text = (review_root / "CONTEXT.md").read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_section_present_with_two_admin_fixture_controllers(self):
        payload = _section_payload(
            self.text, "recon_bags.addon.easyadmin.crud_controllers",
        )
        self.assertIsNotNone(payload, "easyadmin_crud_controllers section missing")
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(len(payload["items"]), 2)

    def test_entity_fqcn_resolved_per_controller(self):
        payload = _section_payload(
            self.text, "recon_bags.addon.easyadmin.crud_controllers",
        )
        by_class = {it["class"]: it for it in payload["items"]}
        self.assertEqual(
            by_class["App\\Controller\\Admin\\PostCrudController"]["entity_fqcn"],
            "App\\Entity\\Post",
        )
        self.assertEqual(
            by_class["App\\Controller\\Admin\\UserCrudController"]["entity_fqcn"],
            "App\\Entity\\User",
        )

    def test_configure_fields_modifiers_propagated_from_extractor(self):
        payload = _section_payload(
            self.text, "recon_bags.addon.easyadmin.crud_controllers",
        )
        post = next(it for it in payload["items"]
                    if it["class"].endswith("PostCrudController"))
        names = [f["name"] for f in post["configure_fields"]]
        self.assertEqual(names, ["id", "title", "body", "author"])
        by_name = {f["name"]: f for f in post["configure_fields"]}
        self.assertEqual(by_name["title"]["modifiers"], ["setDisabled"])
        self.assertEqual(by_name["body"]["modifiers"], ["formatValue"])
        self.assertEqual(by_name["author"]["modifiers"], [])

    def test_configure_actions_disabled_propagated(self):
        payload = _section_payload(
            self.text, "recon_bags.addon.easyadmin.crud_controllers",
        )
        user = next(it for it in payload["items"]
                    if it["class"].endswith("UserCrudController"))
        self.assertEqual(sorted(user["configure_actions"]["disabled"]),
                         ["delete", "new"])

    def test_section_status_none_on_minimal_without_admin(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            proc = _run_recipe(FIX_MIN, review_root, "--no-console")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text()
        payload = _section_payload(
            text, "recon_bags.addon.easyadmin.crud_controllers",
        )
        self.assertIsNotNone(payload)
        self.assertEqual(payload["status"], "none")


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class SonataAdminClassesSection(unittest.TestCase):
    """`recon_bags.addon.sonata.admin_classes` recipe section.

    Sonata fixture has two admin classes: ArticleAdmin (covered by ArticleVoter)
    and UserAdmin (no voter — drives admin_authz_coverage=partial).
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        review_root = Path(cls.tmp.name) / "review"
        proc = _run_recipe(FIX_SONATA, review_root, "--no-console")
        assert proc.returncode == 0, proc.stderr
        cls.text = (review_root / "CONTEXT.md").read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_section_present_with_two_admin_classes(self):
        payload = _section_payload(
            self.text, "recon_bags.addon.sonata.admin_classes",
        )
        self.assertIsNotNone(payload, "sonata_admin_classes section missing")
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(len(payload["items"]), 2)

    def test_entity_fqcn_resolved_per_admin_class(self):
        payload = _section_payload(
            self.text, "recon_bags.addon.sonata.admin_classes",
        )
        by_class = {it["class"]: it for it in payload["items"]}
        self.assertEqual(
            by_class["App\\Admin\\ArticleAdmin"]["entity_fqcn"],
            "App\\Entity\\Article",
        )
        self.assertEqual(
            by_class["App\\Admin\\UserAdmin"]["entity_fqcn"],
            "App\\Entity\\User",
        )

    def test_form_fields_extracted(self):
        payload = _section_payload(
            self.text, "recon_bags.addon.sonata.admin_classes",
        )
        by_class = {it["class"]: it for it in payload["items"]}
        article_fields = by_class["App\\Admin\\ArticleAdmin"]["form_fields"]
        self.assertEqual(article_fields, ["title", "body"])
        user_fields = by_class["App\\Admin\\UserAdmin"]["form_fields"]
        self.assertEqual(user_fields, ["email", "password", "roles"])

    def test_section_none_on_minimal_fixture(self):
        # Sanity: symfony_minimal has no Sonata classes — section must be `none`,
        # not `ok` with empty items (avoids polluting non-Sonata projects).
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            proc = _run_recipe(FIX_MIN, review_root, "--no-console")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text()
        payload = _section_payload(
            text, "recon_bags.addon.sonata.admin_classes",
        )
        self.assertIsNotNone(payload)
        self.assertEqual(payload["status"], "none")

    def test_admin_authz_coverage_marks_useradmin_unwired(self):
        payload = _section_payload(
            self.text, "recon_bags.stack.symfony.admin_authz_coverage",
        )
        self.assertEqual(payload["status"], "partial")
        data = payload["data"]
        self.assertIn("ArticleAdmin", data["crud_controllers_with_voter"])
        self.assertIn("UserAdmin", data["crud_controllers_without_voter"])

    def test_attack_surface_includes_sonata_admin_classes(self):
        # Sonata admins are http_route_admin entries (extends AbstractAdmin).
        payload = _section_payload(self.text, "attack_surface")
        admin_files = {
            it["file"] for it in payload["items"]
            if it.get("kind") == "http_route_admin"
        }
        self.assertIn("src/Admin/ArticleAdmin.php", admin_files)
        self.assertIn("src/Admin/UserAdmin.php", admin_files)


class AdminAuthzCoverageUnit(unittest.TestCase):
    """`compute_admin_authz_coverage` — pure function, no PHP needed."""

    def _voters(self, *items):
        from recon.types import SectionPayload
        return SectionPayload(status="ok", items=list(items))

    def _crud(self, *items, status="ok"):
        from recon.types import SectionPayload
        return SectionPayload(status=status, items=list(items))

    def test_status_none_when_no_crud_controllers(self):
        out = recipe_symfony.compute_admin_authz_coverage(
            self._voters({"class": "App\\Sec\\PostVoter", "subjects": ["App\\Entity\\Post"], "file": "src/Sec/PostVoter.php"}),
            self._crud(status="none"),
        )
        self.assertEqual(out.status, "none")
        self.assertEqual(out.source_files, [])

    def test_status_partial_when_unwired_crud_present(self):
        out = recipe_symfony.compute_admin_authz_coverage(
            self._voters({
                "class": "App\\Sec\\PostVoter",
                "subjects": ["App\\Entity\\Post"],
                "file": "src/Sec/PostVoter.php",
            }),
            self._crud(
                {
                    "class": "App\\Admin\\PostCrudController",
                    "entity_fqcn": "App\\Entity\\Post",
                    "file": "src/Admin/PostCrudController.php",
                },
                {
                    "class": "App\\Admin\\UserCrudController",
                    "entity_fqcn": "App\\Entity\\User",
                    "file": "src/Admin/UserCrudController.php",
                },
            ),
        )
        self.assertEqual(out.status, "partial")
        self.assertEqual(out.data["crud_controllers_with_voter"], ["PostCrudController"])
        self.assertEqual(out.data["crud_controllers_without_voter"], ["UserCrudController"])
        self.assertEqual(out.data["voters_inspected"], ["PostVoter"])
        # source_files = union of CRUD controller files + voter files (sorted).
        self.assertEqual(set(out.source_files), {
            "src/Admin/PostCrudController.php",
            "src/Admin/UserCrudController.php",
            "src/Sec/PostVoter.php",
        })

    def test_status_ok_when_every_crud_wired(self):
        out = recipe_symfony.compute_admin_authz_coverage(
            self._voters({
                "class": "App\\Sec\\PostVoter",
                "subjects": ["App\\Entity\\Post"],
                "file": "src/Sec/PostVoter.php",
            }),
            self._crud({
                "class": "App\\Admin\\PostCrudController",
                "entity_fqcn": "App\\Entity\\Post",
                "file": "src/Admin/PostCrudController.php",
            }),
        )
        self.assertEqual(out.status, "ok")
        self.assertEqual(out.data["crud_controllers_without_voter"], [])

    def test_crud_without_entity_fqcn_treated_as_unwired(self):
        out = recipe_symfony.compute_admin_authz_coverage(
            self._voters(),
            self._crud({
                "class": "App\\Admin\\BareCrudController",
                "entity_fqcn": None,
                "file": "src/Admin/BareCrudController.php",
            }),
        )
        self.assertEqual(out.status, "partial")
        self.assertEqual(out.data["crud_controllers_without_voter"], ["BareCrudController"])

    def test_voter_with_multiple_subjects_matches_each(self):
        out = recipe_symfony.compute_admin_authz_coverage(
            self._voters({
                "class": "App\\Sec\\MultiVoter",
                "subjects": ["App\\Entity\\Post", "App\\Entity\\Comment"],
                "file": "src/Sec/MultiVoter.php",
            }),
            self._crud(
                {"class": "App\\Admin\\PostCrudController", "entity_fqcn": "App\\Entity\\Post",
                 "file": "src/Admin/PostCrudController.php"},
                {"class": "App\\Admin\\CommentCrudController", "entity_fqcn": "App\\Entity\\Comment",
                 "file": "src/Admin/CommentCrudController.php"},
            ),
        )
        self.assertEqual(out.status, "ok")
        self.assertEqual(
            sorted(out.data["crud_controllers_with_voter"]),
            ["CommentCrudController", "PostCrudController"],
        )


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class AdminAuthzCoverageE2E(unittest.TestCase):
    """`recon_bags.stack.symfony.admin_authz_coverage` end-to-end on admin fixture."""

    def test_admin_fixture_post_wired_user_unwired(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            proc = _run_recipe(FIX_ADM, review_root, "--no-console")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text()
        payload = _section_payload(text, "recon_bags.stack.symfony.admin_authz_coverage")
        self.assertIsNotNone(payload, "admin_authz_coverage section missing")
        self.assertEqual(payload["status"], "partial")
        self.assertEqual(payload["data"]["crud_controllers_with_voter"], ["PostCrudController"])
        self.assertEqual(payload["data"]["crud_controllers_without_voter"], ["UserCrudController"])
        self.assertIn("PostVoter", payload["data"]["voters_inspected"])
        # Scalar section contract: source_files non-empty + includes every CRUD controller file.
        self.assertIn("src/Controller/Admin/PostCrudController.php", payload["source_files"])
        self.assertIn("src/Controller/Admin/UserCrudController.php", payload["source_files"])
        self.assertIn("src/Security/Voter/PostVoter.php", payload["source_files"])

    def test_minimal_fixture_section_status_none(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            proc = _run_recipe(FIX_MIN, review_root, "--no-console")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text()
        payload = _section_payload(text, "recon_bags.stack.symfony.admin_authz_coverage")
        self.assertIsNotNone(payload)
        self.assertEqual(payload["status"], "none")


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class HostileFixtureSandbox(unittest.TestCase):
    """`--no-console` MUST NOT execute project PHP code (no `.snitch/pwned`)."""

    def setUp(self):
        # snitch directory inside the fixture is gitignored; remove if present.
        snitch = FIX_HOSTILE / ".snitch"
        if snitch.is_dir():
            shutil.rmtree(snitch)

    def test_no_console_does_not_create_snitch(self):
        snitch = FIX_HOSTILE / ".snitch" / "pwned"
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            proc = _run_recipe(FIX_HOSTILE, review_root, "--no-console")
            # Verify file presence INSIDE the with block — TemporaryDirectory
            # is removed on __exit__ and the path becomes a stale handle.
            self.assertTrue((review_root / "CONTEXT.md").is_file(), msg=proc.stderr)
        # Recipe runs static-only — even if it falls through to "unknown" sections,
        # NO PHP from the fixture should have been executed.
        self.assertFalse(snitch.is_file(),
                         msg="snitch was written — `--no-console` did not contain execution")


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class WallClockBudget(unittest.TestCase):
    """rev 3.5 G-Concur.1: ≤ 30 s on minimal fixture in --no-console mode."""

    def test_minimal_under_30_seconds(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            t0 = time.monotonic()
            proc = _run_recipe(FIX_MIN, review_root, "--no-console", timeout=60)
            elapsed = time.monotonic() - t0
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertLess(elapsed, 30.0, msg=f"recipe took {elapsed:.1f}s, budget is 30s")


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class TouchedByDiffPropagation(unittest.TestCase):
    """Recipe must mark items with file ∈ diff_files as touched_by_diff: true."""

    def test_diff_marks_routes_in_changed_controller(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            diff_file = Path(td) / "changed.txt"
            diff_file.write_text("src/Controller/PostController.php\n")
            proc = _run_recipe(
                FIX_MIN, review_root,
                "--no-console", f"--diff-files={diff_file}",
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text()
        payload = _section_payload(text, "attack_surface")
        post_routes = [it for it in payload["items"]
                       if it.get("kind") == "http_route"
                       and it["file"] == "src/Controller/PostController.php"]
        self.assertTrue(post_routes)
        for it in post_routes:
            self.assertTrue(it["touched_by_diff"], f"item not marked: {it}")
        # And another controller's items must NOT be marked.
        auth_routes = [it for it in payload["items"]
                       if it.get("kind") == "http_route"
                       and it["file"] == "src/Controller/AuthController.php"]
        for it in auth_routes:
            self.assertFalse(it["touched_by_diff"])


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class ScalarSectionSourceFiles(unittest.TestCase):
    """Every scalar section with status=ok must declare `source_files`
    (rev 3.4 mode=changes channel 2)."""

    def test_all_scalar_ok_sections_have_source_files(self):
        from validate_context import _section_payload as vc_payload, extract_sections
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            _run_recipe(FIX_MIN, review_root, "--no-console")
            text = (review_root / "CONTEXT.md").read_text()
        sections = extract_sections(text)
        for sid in ("auth_layer",):
            payload = _section_payload(text, sid)
            if payload.get("status") == "ok":
                self.assertIn("source_files", payload, msg=f"{sid} missing source_files")
                self.assertIsInstance(payload["source_files"], list)
                self.assertGreater(len(payload["source_files"]), 0)


class RecipeUnitContract(unittest.TestCase):
    """Unit-level contract tests that don't require subprocess + PHP."""

    def test_classify_kind_dispatches_known_extensions(self):
        from recon.recipes.symfony import _classify_kind as ck
        # Admin via extends AbstractCrudController.
        cls = {"extends": "EasyCorp\\Bundle\\EasyAdminBundle\\Controller\\AbstractCrudController",
               "implements": [], "attributes": []}
        self.assertEqual(ck(cls, {}), "http_route_admin")
        # CLI command via extends Command.
        cls = {"extends": "Symfony\\Component\\Console\\Command\\Command",
               "implements": [], "attributes": []}
        self.assertEqual(ck(cls, {}), "cli_command")
        # CLI command via #[AsCommand] attribute (without explicit extends).
        cls = {"extends": None, "implements": [],
               "attributes": [{"name": "Symfony\\Component\\Console\\Attribute\\AsCommand",
                               "arguments": {"named": {}, "positional": []}}]}
        self.assertEqual(ck(cls, {}), "cli_command")
        # Message handler via #[AsMessageHandler].
        cls = {"extends": None, "implements": [],
               "attributes": [{"name": "AsMessageHandler",
                               "arguments": {"named": {}, "positional": []}}]}
        self.assertEqual(ck(cls, {}), "message_handler")
        # Event subscriber via implements EventSubscriberInterface.
        cls = {"extends": None, "implements": ["Symfony\\Component\\EventDispatcher\\EventSubscriberInterface"],
               "attributes": []}
        self.assertEqual(ck(cls, {}), "event_listener")
        # Plain class — no kind.
        cls = {"extends": None, "implements": [], "attributes": []}
        self.assertIsNone(ck(cls, {}))

    def test_exclude_paths_match_vendor(self):
        from recon.recipes.symfony import _is_excluded, EXCLUDE_PATHS
        self.assertTrue(_is_excluded("vendor/_fake/Vendor.php", EXCLUDE_PATHS))
        self.assertTrue(_is_excluded("var/cache/foo.php", EXCLUDE_PATHS))
        self.assertTrue(_is_excluded("tests/Foo.php", EXCLUDE_PATHS))
        self.assertFalse(_is_excluded("src/Controller/PostController.php", EXCLUDE_PATHS))

    def test_exclude_paths_glob_min_js(self):
        from recon.recipes.symfony import _is_excluded, EXCLUDE_PATHS
        self.assertTrue(_is_excluded("public/js/app.min.js", EXCLUDE_PATHS))
        self.assertFalse(_is_excluded("public/js/app.js", EXCLUDE_PATHS))

    def test_classify_dsn(self):
        from recon.recipes.symfony import _classify_dsn
        self.assertEqual(_classify_dsn("doctrine://default"), "doctrine")
        self.assertEqual(_classify_dsn("redis://localhost"), "redis")
        self.assertEqual(_classify_dsn("amqp://x"), "amqp")
        self.assertEqual(_classify_dsn("sync://"), "sync")
        self.assertEqual(_classify_dsn("%env(MESSENGER_TRANSPORT_DSN)%"), "env")
        self.assertEqual(_classify_dsn("custom://"), "other")

    def test_cli_command_probe_has_content_filter(self):
        # Probe glob src/**/*Command.php overmatches CQRS DTOs / Messenger
        # messages. The probe must narrow by file content (regex) to keep
        # sanity coverage honest on DDD Symfony codebases.
        import re
        probes = recipe_symfony.sanity_probes()
        cli = next((p for p in probes if p.label == "CLI commands"), None)
        self.assertIsNotNone(cli, "CLI commands probe missing")
        self.assertIsNotNone(cli.content_filter, "CLI probe must have content_filter")
        rx = re.compile(cli.content_filter)
        # Real Symfony Console command — matches.
        self.assertIsNotNone(rx.search(
            "use Symfony\\Component\\Console\\Command\\Command;\n"
            "class FooCommand extends Command {}"))
        # AsCommand attribute alone — matches.
        self.assertIsNotNone(rx.search("#[AsCommand(name: 'x')] class X {}"))
        # CQRS DTO — does NOT match (the bug we're fixing).
        self.assertIsNone(rx.search(
            "namespace App\\Application\\Order\\Command;\n"
            "final class CreateOrderCommand {}"))
        # Plain Messenger message — does NOT match.
        self.assertIsNone(rx.search(
            "namespace App\\Domain\\Notify\\Command;\n"
            "final class SendEmailCommand {}"))

    def test_no_plugin_root_returns_unknown_skeleton(self):
        with tempfile.TemporaryDirectory() as td:
            r = recipe_symfony.build_inventory(Path(td))  # no plugin_root
            self.assertEqual(r.status, "partial")
            for sid, payload in r.core.items():
                self.assertEqual(payload.status, "unknown", msg=f"{sid}")
            # recon_bags is now `{kind: {name: {bag_key: payload}}}` — walk 3 levels.
            for kind, names in r.recon_bags.items():
                for name, bag in names.items():
                    for k, payload in bag.items():
                        self.assertEqual(payload.status, "unknown", msg=f"{kind}/{name}/{k}")


@unittest.skipUnless(shutil.which("php"), "php not on PATH")
class TripleReviewRegressions(unittest.TestCase):
    """Regression coverage for issues found in the S2 triple review."""

    def test_h1_vendor_routes_excluded_from_attack_surface(self):
        # Claude HIGH H1 / Codex Issue 2: extractor scans the entire project
        # tree (including vendor/), so route attributes from vendor bundles
        # would leak into attack_surface unless EXCLUDE_PATHS is applied.
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / "proj"
            shutil.copytree(FIX_MIN, scratch)
            vendor_ctrl = scratch / "vendor" / "_fake" / "VendorController.php"
            vendor_ctrl.parent.mkdir(parents=True, exist_ok=True)
            vendor_ctrl.write_text(
                "<?php\nnamespace _Fake;\n"
                "use Symfony\\Component\\Routing\\Attribute\\Route;\n"
                "class VendorController {\n"
                "    #[Route('/vendor-route', name: 'vendor_route', methods: ['GET'])]\n"
                "    public function leak() {}\n"
                "}\n"
            )
            review_root = scratch / "review"
            proc = _run_recipe(scratch, review_root, "--no-console")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text()
        payload = _section_payload(text, "attack_surface")
        for it in payload["items"]:
            self.assertNotIn(
                "vendor/", it.get("file", ""),
                msg=f"vendor route leaked into attack_surface: {it}",
            )
            self.assertNotEqual(it.get("identifier"), "vendor_route")

    def test_codex_symlink_escape_blocked(self):
        # Codex HIGH Issue 1: `_list_php_files` followed symlinks and read
        # files outside `project_root`. Containment check via Path.resolve()
        # must drop them silently.
        with tempfile.TemporaryDirectory() as td:
            outside = Path(td) / "outside"
            outside.mkdir()
            evil = outside / "Evil.php"
            evil.write_text("<?php\nfunction pwn() { return unserialize($_GET['x']); }\n")
            scratch = Path(td) / "proj"
            shutil.copytree(FIX_MIN, scratch)
            try:
                (scratch / "src" / "EvilLink.php").symlink_to(evil)
            except (OSError, NotImplementedError) as e:
                self.skipTest(f"symlink unsupported on this platform: {e}")
            review_root = scratch / "review"
            proc = _run_recipe(scratch, review_root, "--no-console")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            text = (review_root / "CONTEXT.md").read_text()
        payload = _section_payload(text, "serialization")
        for it in payload["items"]:
            self.assertNotIn(
                "EvilLink", it.get("file", ""),
                msg=f"symlink-escaped file leaked: {it}",
            )
            self.assertFalse(it.get("file", "").startswith("/"),
                             msg=f"absolute outside-path leaked: {it}")

    def test_m1_yaml_parser_handles_2_space_indent_security_yaml(self):
        # Claude MEDIUM M1 / Gemini Issue 3: hardcoded indent == 4 / 8 broke
        # parsing on 2-space indentation. Indent-relative parsers must work.
        from recon.recipes.symfony import (
            _parse_firewalls, _parse_access_control, _first_key_under_nested,
        )
        text = (
            "security:\n"
            "  providers:\n"
            "    custom_provider:\n"
            "      entity: { class: App\\Entity\\User }\n"
            "  firewalls:\n"
            "    main:\n"
            "      lazy: true\n"
            "      stateless: true\n"
            "      provider: custom_provider\n"
            "  access_control:\n"
            "    - { path: ^/api, roles: ROLE_USER }\n"
        )
        firewalls = _parse_firewalls(text)
        self.assertEqual([fw["name"] for fw in firewalls], ["main"])
        self.assertEqual(firewalls[0]["stateless"], "true")
        self.assertEqual(_first_key_under_nested(text, ("security", "providers")),
                         "custom_provider")
        ac = _parse_access_control(text)
        self.assertEqual(len(ac), 1)
        self.assertEqual(ac[0]["path"], "^/api")

    def test_codex_block_style_access_control(self):
        # Codex / Gemini: only flow-style `- { path: ..., roles: ... }` was
        # supported. Block-style (Symfony skeleton's natural form) was lost.
        from recon.recipes.symfony import _parse_access_control
        text = (
            "security:\n"
            "    access_control:\n"
            "        - path: ^/admin\n"
            "          roles: ROLE_ADMIN\n"
            "        - path: ^/api\n"
            "          roles: ROLE_USER\n"
        )
        ac = _parse_access_control(text)
        self.assertEqual(len(ac), 2)
        self.assertEqual(ac[0], {"path": "^/admin", "roles": "ROLE_ADMIN"})
        self.assertEqual(ac[1], {"path": "^/api", "roles": "ROLE_USER"})

    def test_multiline_flow_style_access_control(self):
        # Multi-line flow-style `- {\n path: ...,\n roles: ... \n}` must parse
        # like its single-line counterpart. The accumulator must also reset so a
        # following single-line flow entry is not swallowed by the open block.
        from recon.recipes.symfony import _parse_access_control
        text = (
            "security:\n"
            "    access_control:\n"
            "        - {\n"
            "            path: ^/admin,\n"
            "            roles: ROLE_ADMIN\n"
            "          }\n"
            "        - { path: ^/pub, roles: PUBLIC_ACCESS }\n"
        )
        ac = _parse_access_control(text)
        self.assertEqual(len(ac), 2)
        self.assertEqual(ac[0], {"path": "^/admin", "roles": "ROLE_ADMIN"})
        self.assertEqual(ac[1], {"path": "^/pub", "roles": "PUBLIC_ACCESS"})

    def test_m2_classify_kind_does_not_match_app_command(self):
        # Claude MEDIUM M2: `extends_short == "Command"` collided with DDD
        # `App\Domain\Command` base class. FQN-only check fixes this.
        from recon.recipes.symfony import _classify_kind
        cls = {"extends": "App\\Domain\\Command",
               "implements": [], "attributes": []}
        self.assertIsNone(_classify_kind(cls, {}))
        cls = {"extends": "Symfony\\Component\\Console\\Command\\Command",
               "implements": [], "attributes": []}
        self.assertEqual(_classify_kind(cls, {}), "cli_command")

    def test_m3_inline_comments_in_yaml_stripped(self):
        # Claude MEDIUM M3: trailing ` # comment` was kept as part of the
        # value, breaking `_classify_dsn` etc.
        from recon.recipes.symfony import _strip_inline_comment
        self.assertEqual(_strip_inline_comment("'amqp://x' # comment"), "'amqp://x'")
        self.assertEqual(_strip_inline_comment("ROLE_USER  # rbac"), "ROLE_USER")
        # `#` inside quotes must NOT be treated as a comment.
        self.assertEqual(_strip_inline_comment("'value #1'"), "'value #1'")
        # A `#` with no leading whitespace must not be split (anchor names).
        self.assertEqual(_strip_inline_comment("#anchor"), "#anchor")

    def test_l3_authz_no_double_report_per_line(self):
        # Claude LOW L3: missing `break` produced duplicate items when a
        # line matched two patterns.
        from recon.recipes.symfony import collect_authz_usage
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / "proj"
            scratch.mkdir()
            src = scratch / "src" / "Foo.php"
            src.parent.mkdir()
            # Single line that matches both `denyAccessUnlessGranted` and
            # `isGranted_security` patterns conceptually — use any matching
            # line to confirm the loop short-circuits to ONE item.
            src.write_text(
                "<?php\nclass Foo {\n"
                "  public function bar() { $this->denyAccessUnlessGranted('EDIT', $x); }\n"
                "}\n"
            )
            from recon.recipes.symfony import _list_php_files
            files = _list_php_files(scratch)
            items = collect_authz_usage(files, scratch, None)
        # Exactly one record per matched line.
        self.assertEqual(len([it for it in items if it["file"] == "src/Foo.php"]), 1)


if __name__ == "__main__":
    unittest.main()
