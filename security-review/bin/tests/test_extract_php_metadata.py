"""End-to-end tests for extract_php_metadata.php.

Drives the PHP extractor via subprocess, parses JSON, asserts on key facts
from the symfony_minimal / symfony_admin fixtures plus inline-temp test files
for multi-line attributes, serializer groups, and edge cases.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent
PLUGIN_ROOT = BIN_DIR.parent
EXTRACTOR = BIN_DIR / "recon" / "extract_php_metadata.php"
FIX_MIN = THIS_DIR / "fixtures" / "symfony_minimal"
FIX_ADM = THIS_DIR / "fixtures" / "symfony_admin"
FIX_GEN = THIS_DIR / "fixtures" / "generic_php"


def _have_php():
    return shutil.which("php") is not None


def _run(kind: str, path: Path, timeout: int = 30) -> tuple[int, dict | None, str]:
    """Run extractor; return (rc, parsed_json_or_None, stderr)."""
    proc = subprocess.run(
        ["php", "-d", "memory_limit=256M", str(EXTRACTOR), f"--kind={kind}", str(path)],
        capture_output=True, text=True, timeout=timeout,
    )
    parsed = None
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError:
            pass
    return proc.returncode, parsed, proc.stderr


@unittest.skipUnless(_have_php(), "php not on PATH")
class Routes(unittest.TestCase):
    def test_collects_all_attribute_routes_in_minimal_fixture(self):
        rc, out, err = _run("routes", FIX_MIN / "src" / "Controller")
        self.assertEqual(rc, 0, msg=err)
        self.assertEqual(out["kind"], "routes")
        names = {it["route_name"] for it in out["items"]}
        # symfony_minimal fixture: 4 auth + 5 post + 3 user = 12 attribute routes.
        self.assertEqual(names, {
            "auth_login", "auth_logout", "auth_register", "auth_refresh",
            "post_list", "post_show", "post_create", "post_edit", "post_delete",
            "user_me", "user_profile", "user_update",
        })
        self.assertEqual(len(out["items"]), 12)

    def test_combines_class_prefix_with_method_path(self):
        rc, out, _ = _run("routes", FIX_MIN / "src" / "Controller" / "PostController.php")
        self.assertEqual(rc, 0)
        by_name = {it["route_name"]: it for it in out["items"]}
        # post_list is at `/posts` (empty method path → class prefix only).
        self.assertEqual(by_name["post_list"]["path"], "/posts")
        self.assertEqual(by_name["post_list"]["class_path_prefix"], "/posts")
        self.assertEqual(by_name["post_show"]["path"], "/posts/show")
        self.assertEqual(by_name["post_edit"]["path"], "/posts/{id}/edit")

    def test_methods_array_parsed_to_list(self):
        rc, out, _ = _run("routes", FIX_MIN / "src" / "Controller")
        self.assertEqual(rc, 0)
        by_name = {it["route_name"]: it for it in out["items"]}
        self.assertEqual(by_name["post_show"]["methods"], ["GET"])
        self.assertEqual(by_name["post_edit"]["methods"], ["POST"])
        self.assertEqual(by_name["auth_login"]["methods"], ["POST"])
        self.assertEqual(by_name["post_delete"]["methods"], ["DELETE"])

    def test_controller_fqn_uses_namespace(self):
        rc, out, _ = _run("routes", FIX_MIN / "src" / "Controller" / "UserController.php")
        self.assertEqual(rc, 0)
        self.assertEqual(out["items"][0]["controller"], "App\\Controller\\UserController::me")

    def test_multiline_route_attribute(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Foo.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Controller;
                use Symfony\\Component\\Routing\\Attribute\\Route;
                class FooController {
                    #[Route(
                        '/api/users',
                        name: 'foo_users',
                        methods: ['GET', 'POST'],
                    )]
                    public function list(): void {}
                }
                """))
            rc, out, err = _run("routes", f)
            self.assertEqual(rc, 0, msg=err)
            self.assertEqual(len(out["items"]), 1)
            it = out["items"][0]
            self.assertEqual(it["route_name"], "foo_users")
            self.assertEqual(it["path"], "/api/users")
            self.assertEqual(set(it["methods"]), {"GET", "POST"})


@unittest.skipUnless(_have_php(), "php not on PATH")
class Voters(unittest.TestCase):
    def test_post_voter_attributes_resolved_from_constants(self):
        rc, out, err = _run("voters", FIX_MIN / "src" / "Security" / "Voter")
        self.assertEqual(rc, 0, msg=err)
        self.assertEqual(len(out["items"]), 1)
        it = out["items"][0]
        self.assertEqual(it["class"], "App\\Security\\Voter\\PostVoter")
        self.assertEqual(set(it["attributes"]), {"POST_VIEW", "POST_EDIT"})

    def test_post_voter_subject_resolved_from_instanceof(self):
        rc, out, _ = _run("voters", FIX_MIN / "src" / "Security" / "Voter")
        self.assertEqual(rc, 0)
        it = out["items"][0]
        self.assertIn("App\\Entity\\Post", it["subjects"])

    def test_indirect_inheritance_via_project_base_voter(self):
        # `OrderVoter extends BaseVoter extends Voter` — without inheritance-graph
        # lookup the direct-extends check would skip it (and the suffix fallback
        # only catches names ending with "Voter").
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "BaseVoter.php"
            base.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Security;
                use Symfony\\Component\\Security\\Core\\Authorization\\Voter\\Voter;
                abstract class BaseVoter extends Voter {}
                """))
            child = Path(td) / "OrderAuthz.php"
            child.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Security;
                use App\\Entity\\Order;
                use Symfony\\Component\\Security\\Core\\Authentication\\Token\\TokenInterface;
                class OrderAuthz extends BaseVoter {
                    public const VIEW = 'ORDER_VIEW';
                    protected function supports(string $attribute, mixed $subject): bool {
                        return $attribute === self::VIEW && $subject instanceof Order;
                    }
                    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool {
                        return false;
                    }
                }
                """))
            rc, out, err = _run("voters", Path(td))
            self.assertEqual(rc, 0, msg=err)
            classes = {it["class"] for it in out["items"]}
            self.assertIn("App\\Security\\OrderAuthz", classes,
                          "indirect Voter inheritance missed by recipe")


@unittest.skipUnless(_have_php(), "php not on PATH")
class Forms(unittest.TestCase):
    def test_post_type_options(self):
        rc, out, err = _run("forms", FIX_MIN / "src" / "Form")
        self.assertEqual(rc, 0, msg=err)
        self.assertEqual(len(out["items"]), 1)
        it = out["items"][0]
        self.assertEqual(it["class"], "App\\Form\\PostType")
        self.assertEqual(it["data_class"], "App\\Entity\\Post")
        self.assertTrue(it["csrf_protection"])
        self.assertFalse(it["allow_extra_fields"])

    def test_indirect_inheritance_via_project_base_type(self):
        # `MyType extends AppFormType extends AbstractType` — recipe must
        # surface MyType via inheritance-graph lookup.
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "AppFormType.php"
            base.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Form;
                use Symfony\\Component\\Form\\AbstractType;
                abstract class AppFormType extends AbstractType {}
                """))
            child = Path(td) / "ProfileType.php"
            child.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Form;
                use Symfony\\Component\\OptionsResolver\\OptionsResolver;
                class ProfileType extends AppFormType {
                    public function configureOptions(OptionsResolver $resolver): void {
                        $resolver->setDefaults(['csrf_protection' => true]);
                    }
                }
                """))
            rc, out, err = _run("forms", Path(td))
            self.assertEqual(rc, 0, msg=err)
            classes = {it["class"] for it in out["items"]}
            self.assertIn("App\\Form\\ProfileType", classes,
                          "indirect AbstractType inheritance missed by recipe")


@unittest.skipUnless(_have_php(), "php not on PATH")
class ClassMetadata(unittest.TestCase):
    def test_extends_resolved_against_uses(self):
        rc, out, err = _run("class", FIX_MIN / "src" / "Controller" / "PostController.php")
        self.assertEqual(rc, 0, msg=err)
        cls = next(it for it in out["items"] if it["fqn"].endswith("PostController"))
        self.assertEqual(cls["extends"], "Symfony\\Bundle\\FrameworkBundle\\Controller\\AbstractController")

    def test_class_attribute_named_args(self):
        rc, out, _ = _run("class", FIX_ADM / "src" / "Controller" / "Admin" / "DashboardController.php")
        self.assertEqual(rc, 0)
        cls = out["items"][0]
        attrs = {a["name"]: a for a in cls["attributes"]}
        # H1: attribute names are resolved to FQN via use-clauses.
        adm_fqn = "EasyCorp\\Bundle\\EasyAdminBundle\\Attribute\\AdminDashboard"
        self.assertIn(adm_fqn, attrs)
        named = attrs[adm_fqn]["arguments"]["named"]
        self.assertEqual(named["routePath"]["value"], "/admin")
        self.assertEqual(named["routeName"]["value"], "admin")

    def test_use_alias_resolved(self):
        rc, out, _ = _run("class", FIX_MIN / "src" / "Entity" / "Post.php")
        self.assertEqual(rc, 0)
        cls = out["items"][0]
        attrs = {a["name"] for a in cls["attributes"]}
        # `use Doctrine\\ORM\\Mapping as ORM` + `#[ORM\\Entity(...)]` →
        # full FQN after H1 post-process resolution.
        self.assertIn("Doctrine\\ORM\\Mapping\\Entity", attrs)

    def test_message_handler_attribute_no_args(self):
        rc, out, _ = _run("class", FIX_MIN / "src" / "Messenger" / "SendEmailHandler.php")
        self.assertEqual(rc, 0)
        handler = next(it for it in out["items"] if it["fqn"].endswith("SendEmailHandler"))
        attrs = {a["name"] for a in handler["attributes"]}
        # H1: attribute name resolved to FQN.
        self.assertIn("Symfony\\Component\\Messenger\\Attribute\\AsMessageHandler", attrs)

    def test_parent_chain_traverses_project_local_base_class(self):
        # `MyCommand extends BaseCommand extends Symfony\\...\\Command` — recipe
        # must surface `parent_chain` so CLI-command detection sees the symfony
        # base across one project hop.
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "BaseCommand.php"
            base.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Console;
                use Symfony\\Component\\Console\\Command\\Command;
                abstract class BaseCommand extends Command {}
                """))
            child = Path(td) / "MyCommand.php"
            child.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Console;
                class MyCommand extends BaseCommand {}
                """))
            rc, out, err = _run("class", Path(td))
            self.assertEqual(rc, 0, msg=err)
            mine = next(it for it in out["items"] if it["fqn"].endswith("MyCommand"))
            self.assertEqual(mine["extends"], "App\\Console\\BaseCommand")
            self.assertEqual(
                mine["parent_chain"],
                ["App\\Console\\BaseCommand", "Symfony\\Component\\Console\\Command\\Command"],
            )

    def test_parent_chain_empty_when_no_extends(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Plain.php"
            f.write_text("<?php\nnamespace App;\nclass Plain {}\n")
            rc, out, err = _run("class", Path(td))
            self.assertEqual(rc, 0, msg=err)
            self.assertEqual(out["items"][0]["parent_chain"], [])


@unittest.skipUnless(_have_php(), "php not on PATH")
class SerializerGroups(unittest.TestCase):
    def test_property_groups_extracted(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "User.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Dto;
                use Symfony\\Component\\Serializer\\Attribute\\Groups;
                class UserDto {
                    #[Groups(['public', 'admin'])]
                    public string $email;

                    #[Groups(['admin'])]
                    public string $internalToken;
                }
                """))
            rc, out, err = _run("serializer-groups", f)
            self.assertEqual(rc, 0, msg=err)
            by_member = {it["member"]: it for it in out["items"]}
            self.assertEqual(by_member["email"]["groups"], ["public", "admin"])
            self.assertEqual(by_member["internalToken"]["groups"], ["admin"])


@unittest.skipUnless(_have_php(), "php not on PATH")
class CliErrors(unittest.TestCase):
    def test_unknown_kind_exits_2(self):
        rc, out, err = _run("nope", FIX_MIN)
        self.assertEqual(rc, 2)
        self.assertIn("unknown kind", err)

    def test_missing_path_exits_2(self):
        proc = subprocess.run(
            ["php", str(EXTRACTOR), "--kind=routes"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("usage", proc.stderr.lower())

    def test_nonexistent_path_exits_2(self):
        proc = subprocess.run(
            ["php", str(EXTRACTOR), "--kind=routes", "/nonexistent/path/xyz"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proc.returncode, 2)

    def test_empty_dir_returns_empty_items(self):
        with tempfile.TemporaryDirectory() as td:
            rc, out, _ = _run("routes", Path(td))
            self.assertEqual(rc, 0)
            self.assertEqual(out["items"], [])

    def test_generic_php_no_attributes_yields_empty_routes(self):
        rc, out, err = _run("routes", FIX_GEN / "src")
        self.assertEqual(rc, 0, msg=err)
        self.assertEqual(out["items"], [])


@unittest.skipUnless(_have_php(), "php not on PATH")
class Symbols(unittest.TestCase):
    def test_symbols_collects_namespace_and_kind(self):
        rc, out, err = _run("symbols", FIX_MIN / "src" / "Messenger" / "SendEmailHandler.php")
        self.assertEqual(rc, 0, msg=err)
        by_fqn = {it["fqn"]: it for it in out["items"]}
        self.assertEqual(by_fqn["App\\Messenger\\SendEmailMessage"]["kind"], "class")
        self.assertEqual(by_fqn["App\\Messenger\\SendEmailMessage"]["namespace"], "App\\Messenger")


@unittest.skipUnless(_have_php(), "php not on PATH")
class EdgeCases(unittest.TestCase):
    """Regression tests for review-issue fixes (L8, plus H1/H2/H3/H7)."""

    def test_anonymous_class_skipped(self):
        # H3: `new class { ... }` is an expression, must not appear as a class entry.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Foo.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App;
                class Real {
                    public function make() {
                        return new class {
                            public function inside() {}
                        };
                    }
                }
                """))
            rc, out, _ = _run("class", f)
            self.assertEqual(rc, 0)
            self.assertEqual(len(out["items"]), 1)
            self.assertEqual(out["items"][0]["fqn"], "App\\Real")

    def test_group_use_attribute_resolved(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Entity.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Entity;
                use Doctrine\\ORM\\Mapping\\{Entity, Column, Id};
                #[Entity]
                class Foo {
                    #[Id]
                    #[Column]
                    private ?int $id = null;
                }
                """))
            rc, out, _ = _run("class", f)
            self.assertEqual(rc, 0)
            attrs = {a["name"] for a in out["items"][0]["attributes"]}
            self.assertIn("Doctrine\\ORM\\Mapping\\Entity", attrs)

    def test_broken_php_does_not_crash(self):
        # H2 + general robustness: malformed file should produce stderr warning,
        # not a crash. Empty/garbage stdout fine; rc must be 0.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Broken.php"
            f.write_text("<?php\nclass\n{ this is not valid PHP }")
            rc, out, _ = _run("class", f)
            self.assertEqual(rc, 0)
            self.assertIsInstance(out, dict)

    def test_invalid_utf8_does_not_silent_drop(self):
        # H2: invalid UTF-8 should not produce silent empty stdout (json_encode
        # was returning false → printed nothing). Now it emits FFFD substitutes.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Bad.php"
            # Write a byte sequence that isn't valid UTF-8 inside a string literal.
            f.write_bytes(
                b"<?php\nnamespace App;\nclass Bad { const X = \"a\xc3\x28b\"; }\n"
            )
            rc, out, _ = _run("class", f)
            self.assertEqual(rc, 0)
            self.assertEqual(len(out["items"]), 1)

    def test_voter_constants_no_plain_string_false_positive(self):
        # M3: only self::CONST and resolved values should appear; plain
        # 'EUR'/'AES_GCM' string literals should not leak as attributes.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "PaymentVoter.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Security;
                use Symfony\\Component\\Security\\Core\\Authorization\\Voter\\Voter;
                class PaymentVoter extends Voter {
                    public const PAY = 'PAY_ACTION';
                    protected function supports(string $a, mixed $s): bool {
                        return $a === self::PAY && in_array('EUR', ['EUR', 'USD'], true);
                    }
                    protected function voteOnAttribute(string $a, mixed $s, $t): bool {
                        $algo = 'AES_GCM';
                        return true;
                    }
                }
                """))
            rc, out, _ = _run("voters", f)
            self.assertEqual(rc, 0)
            attrs = set(out["items"][0]["attributes"])
            self.assertEqual(attrs, {"PAY_ACTION"})
            self.assertNotIn("EUR", attrs)
            self.assertNotIn("USD", attrs)
            self.assertNotIn("AES_GCM", attrs)

    def test_form_strict_extends_abstract_type_only(self):
        # M6: classes named *Type but not extending AbstractType should not be
        # picked up as Symfony Form types.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Stuff.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Lib;
                class CurrencyType {
                    public function name(): string { return 'eur'; }
                }
                class MimeType {}
                """))
            rc, out, _ = _run("forms", f)
            self.assertEqual(rc, 0)
            self.assertEqual(out["items"], [])

    def test_class_const_fqn_resolved_in_attribute_args(self):
        # H1: `Post::class` inside attribute args resolves via use-clauses.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Foo.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App;
                use App\\Entity\\Post;
                #[\\App\\Custom\\AsResource(class: Post::class)]
                class FooThing {}
                """))
            rc, out, _ = _run("class", f)
            self.assertEqual(rc, 0)
            attr = out["items"][0]["attributes"][0]
            self.assertEqual(attr["arguments"]["named"]["class"]["value"], "App\\Entity\\Post")

    def test_unicode_escape_sequence_in_string(self):
        # H7: \\u{1F600} should decode into the actual codepoint (here used as a
        # Voter attribute string — which we don't pick up directly, but should
        # round-trip via stripQuotes for class constants).
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Constants.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App;
                class C {
                    public const SMILE = "\\u{1F600}";
                }
                """).replace("\\\\", "\\"))
            rc, out, _ = _run("class", f)
            self.assertEqual(rc, 0)
            # Sanity: the run should not have crashed; class is present.
            self.assertEqual(out["items"][0]["fqn"], "App\\C")

    def test_symlink_outside_project_skipped(self):
        # C1: symlinks resolving outside project_root are not read.
        with tempfile.TemporaryDirectory() as td:
            project = Path(td) / "proj"
            outside = Path(td) / "outside"
            project.mkdir()
            outside.mkdir()
            (project / "real.php").write_text("<?php\nnamespace App;\nclass Real {}\n")
            (outside / "leak.php").write_text("<?php\nnamespace Outside;\nclass Secret {}\n")
            os.symlink(outside / "leak.php", project / "leak.php")
            rc, out, _ = _run("class", project)
            self.assertEqual(rc, 0)
            fqns = {i["fqn"] for i in out["items"]}
            self.assertIn("App\\Real", fqns)
            self.assertNotIn("Outside\\Secret", fqns)


def _run_with_args(extra_args: list[str], path: Path, kind: str = "class",
                   project_root: Path | None = None,
                   timeout: int = 30) -> tuple[int, dict | None, str]:
    """Variant of _run that lets the caller pass arbitrary extra CLI args.

    Used by ExcludeAndSizeCap to drive --exclude / --max-file-size /
    --project-root combos without polluting the canonical _run helper.
    """
    cmd = ["php", "-d", "memory_limit=256M", str(EXTRACTOR), f"--kind={kind}"]
    if project_root is not None:
        cmd.append(f"--project-root={project_root}")
    cmd.extend(extra_args)
    cmd.append(str(path))
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    parsed = None
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError:
            pass
    return proc.returncode, parsed, proc.stderr


@unittest.skipUnless(_have_php(), "php not on PATH")
class ExcludeAndSizeCap(unittest.TestCase):
    """Pre-parse exclude prefixes + per-file size cap (3.1.1).

    Regression target: a vendored vimeo/psalm CallMap_*.php blew memory_limit
    when extractor scanned project_root indiscriminately. Now vendor/ subtrees
    are skipped before parsing, and oversized files are dropped with a stderr
    warning instead of OOM-ing the whole process.
    """

    def _make_project(self, td: Path, *, oversize_in_app: bool = False) -> Path:
        """Fixture: app/ with one real class + vendor/ and var/cache/ that
        MUST NOT be parsed. Returns the project root.
        """
        proj = td / "proj"
        (proj / "app").mkdir(parents=True)
        (proj / "app" / "Real.php").write_text(
            "<?php\nnamespace App;\nclass Real {}\n"
        )
        # vendor/ giant file — would OOM if parsed (we make it small but rely
        # on the exclude-prefix skip; OOM is impractical to assert in CI).
        (proj / "vendor" / "psalm" / "dictionaries").mkdir(parents=True)
        (proj / "vendor" / "psalm" / "dictionaries" / "CallMap.php").write_text(
            "<?php\nnamespace Vendor\\Psalm;\nclass CallMap {}\n"
        )
        # var/cache/ Symfony container dump — same story.
        (proj / "var" / "cache" / "dev").mkdir(parents=True)
        (proj / "var" / "cache" / "dev" / "Container.php").write_text(
            "<?php\nnamespace VarCache;\nclass Container {}\n"
        )
        if oversize_in_app:
            # An auto-generated giant in app/ should still be skipped at the
            # file-level cap, even though its directory is not in default
            # exclude. 3 MiB of comments — safely above 2 MiB cap.
            big = "<?php\nnamespace App;\n// " + ("x" * (3 * 1024 * 1024)) + "\nclass Huge {}\n"
            (proj / "app" / "Huge.php").write_text(big)
        return proj

    def test_default_exclude_skips_vendor_and_var_cache(self):
        with tempfile.TemporaryDirectory() as td:
            proj = self._make_project(Path(td))
            # Pass project-root so relative-prefix matching works against it.
            rc, out, err = _run_with_args(
                [], proj, kind="class", project_root=proj,
            )
            self.assertEqual(rc, 0, msg=err)
            fqns = {i["fqn"] for i in out["items"]}
            self.assertIn("App\\Real", fqns)
            self.assertNotIn("Vendor\\Psalm\\CallMap", fqns)
            self.assertNotIn("VarCache\\Container", fqns)

    def test_explicit_exclude_replaces_defaults(self):
        # When --exclude= is passed explicitly, defaults are NOT layered on
        # at the PHP level — sandbox.py is responsible for merging them in.
        # So passing --exclude=app/ alone means vendor/ files ARE parsed.
        with tempfile.TemporaryDirectory() as td:
            proj = self._make_project(Path(td))
            rc, out, err = _run_with_args(
                ["--exclude=app"], proj, kind="class", project_root=proj,
            )
            self.assertEqual(rc, 0, msg=err)
            fqns = {i["fqn"] for i in out["items"]}
            self.assertNotIn("App\\Real", fqns)
            self.assertIn("Vendor\\Psalm\\CallMap", fqns)

    def test_oversize_file_skipped_with_warning(self):
        with tempfile.TemporaryDirectory() as td:
            proj = self._make_project(Path(td), oversize_in_app=True)
            rc, out, err = _run_with_args(
                ["--max-file-size=2097152"], proj, kind="class", project_root=proj,
            )
            self.assertEqual(rc, 0, msg=err)
            fqns = {i["fqn"] for i in out["items"]}
            self.assertIn("App\\Real", fqns)
            self.assertNotIn("App\\Huge", fqns)
            self.assertIn("exceeds --max-file-size", err)

    def test_disabling_size_cap_includes_large_file(self):
        with tempfile.TemporaryDirectory() as td:
            proj = self._make_project(Path(td), oversize_in_app=True)
            rc, out, err = _run_with_args(
                ["--max-file-size=0"], proj, kind="class", project_root=proj,
            )
            self.assertEqual(rc, 0, msg=err)
            fqns = {i["fqn"] for i in out["items"]}
            self.assertIn("App\\Huge", fqns)

    def test_invalid_max_file_size_exits_2(self):
        with tempfile.TemporaryDirectory() as td:
            proj = self._make_project(Path(td))
            rc, _out, err = _run_with_args(
                ["--max-file-size=not-a-number"], proj,
                kind="class", project_root=proj,
            )
            self.assertEqual(rc, 2)
            self.assertIn("--max-file-size", err)

    def test_single_file_oversize_skipped_with_warning(self):
        # Regression for the is_file branch (extract_php_metadata.php :95-110):
        # when caller points the extractor at one file directly (not a dir),
        # the size cap must still apply. Without this guard, a single-file
        # invocation against a giant auto-generated PHP would still OOM.
        with tempfile.TemporaryDirectory() as td:
            project = Path(td) / "p"
            project.mkdir()
            big = project / "Huge.php"
            # 3 MiB > default cap (2 MiB) — comment body keeps it parseable PHP.
            big.write_text(
                "<?php\nnamespace App;\n// "
                + ("z" * (3 * 1024 * 1024))
                + "\nclass Huge {}\n"
            )
            rc, out, err = _run_with_args(
                [], big, kind="class", project_root=project,
            )
            self.assertEqual(rc, 0, msg=err)
            # Empty stdout is allowed (the extractor exits 0 with empty
            # `items` when all files were filtered). Check explicitly.
            if out is not None:
                self.assertEqual(out.get("items"), [])
            self.assertIn("exceeds --max-file-size", err)

    def test_single_file_under_cap_parsed(self):
        # Counterpart to the test above: a small single file IS parsed.
        with tempfile.TemporaryDirectory() as td:
            project = Path(td) / "p"
            project.mkdir()
            small = project / "Small.php"
            small.write_text("<?php\nnamespace App;\nclass Small {}\n")
            rc, out, err = _run_with_args(
                [], small, kind="class", project_root=project,
            )
            self.assertEqual(rc, 0, msg=err)
            self.assertEqual({i["fqn"] for i in out["items"]}, {"App\\Small"})

    def test_user_extra_csv_appended_to_defaults_via_sandbox(self):
        # sandbox.run_extractor merges DEFAULT_EXCLUDE with caller extras and
        # forwards a single combined --exclude= to the PHP extractor. We
        # simulate that merge here (vendor + legacy) and assert both subtrees
        # are dropped while app/ survives.
        with tempfile.TemporaryDirectory() as td:
            proj = self._make_project(Path(td))
            (proj / "legacy").mkdir()
            (proj / "legacy" / "Old.php").write_text(
                "<?php\nnamespace Legacy;\nclass Old {}\n"
            )
            rc, out, err = _run_with_args(
                ["--exclude=vendor,var/cache,legacy"], proj,
                kind="class", project_root=proj,
            )
            self.assertEqual(rc, 0, msg=err)
            fqns = {i["fqn"] for i in out["items"]}
            self.assertIn("App\\Real", fqns)
            self.assertNotIn("Vendor\\Psalm\\CallMap", fqns)
            self.assertNotIn("VarCache\\Container", fqns)
            self.assertNotIn("Legacy\\Old", fqns)


@unittest.skipUnless(_have_php(), "php not on PATH")
class EasyadminCrud(unittest.TestCase):
    def test_collects_both_admin_fixture_crud_controllers(self):
        rc, out, err = _run("easyadmin-crud", FIX_ADM / "src")
        self.assertEqual(rc, 0, msg=err)
        self.assertEqual(out["kind"], "easyadmin-crud")
        classes = {it["class"]: it for it in out["items"]}
        self.assertIn("App\\Controller\\Admin\\PostCrudController", classes)
        self.assertIn("App\\Controller\\Admin\\UserCrudController", classes)
        # DashboardController extends AbstractDashboardController, not CRUD — skipped.
        self.assertEqual(len(out["items"]), 2)

    def test_entity_fqcn_resolved_against_uses(self):
        rc, out, _ = _run("easyadmin-crud", FIX_ADM / "src")
        self.assertEqual(rc, 0)
        by_class = {it["class"]: it for it in out["items"]}
        self.assertEqual(
            by_class["App\\Controller\\Admin\\PostCrudController"]["entity_fqcn"],
            "App\\Entity\\Post",
        )
        self.assertEqual(
            by_class["App\\Controller\\Admin\\UserCrudController"]["entity_fqcn"],
            "App\\Entity\\User",
        )

    def test_configure_fields_post_crud_with_modifiers(self):
        rc, out, _ = _run("easyadmin-crud", FIX_ADM / "src")
        self.assertEqual(rc, 0)
        post = next(it for it in out["items"]
                    if it["class"] == "App\\Controller\\Admin\\PostCrudController")
        names = [f["name"] for f in post["configure_fields"]]
        self.assertEqual(names, ["id", "title", "body", "author"])
        by_name = {f["name"]: f for f in post["configure_fields"]}
        self.assertEqual(by_name["id"]["field_type"], "IdField")
        self.assertEqual(by_name["id"]["modifiers"], ["hideOnForm"])
        self.assertEqual(by_name["title"]["modifiers"], ["setDisabled"])
        self.assertEqual(by_name["body"]["modifiers"], ["formatValue"])
        self.assertEqual(by_name["author"]["modifiers"], [])

    def test_configure_fields_yield_with_conditional_block(self):
        # UserCrudController uses `yield ...` (not array) and a conditional
        # `if ($pageName === ...) yield ...`. Extractor must produce the union of all
        # yielded fields — in declaration order, including conditional ones.
        rc, out, _ = _run("easyadmin-crud", FIX_ADM / "src")
        self.assertEqual(rc, 0)
        user = next(it for it in out["items"]
                    if it["class"] == "App\\Controller\\Admin\\UserCrudController")
        names = [f["name"] for f in user["configure_fields"]]
        self.assertEqual(names, ["id", "email", "password", "roles"])
        by_name = {f["name"]: f for f in user["configure_fields"]}
        self.assertEqual(by_name["password"]["modifiers"], ["onlyOnForms"])
        self.assertEqual(by_name["roles"]["field_type"], "ArrayField")

    def test_configure_actions_disable_collected(self):
        rc, out, _ = _run("easyadmin-crud", FIX_ADM / "src")
        self.assertEqual(rc, 0)
        user = next(it for it in out["items"]
                    if it["class"] == "App\\Controller\\Admin\\UserCrudController")
        self.assertEqual(sorted(user["configure_actions"]["disabled"]), ["delete", "new"])
        post = next(it for it in out["items"]
                    if it["class"] == "App\\Controller\\Admin\\PostCrudController")
        self.assertEqual(post["configure_actions"]["disabled"], [])

    def test_page_titles_collected_from_configure_crud(self):
        rc, out, _ = _run("easyadmin-crud", FIX_ADM / "src")
        self.assertEqual(rc, 0)
        post = next(it for it in out["items"]
                    if it["class"] == "App\\Controller\\Admin\\PostCrudController")
        self.assertEqual(post["page_titles"], {"index": "Posts", "new": "Create post"})
        # No configureCrud → empty dict (object shape, not list).
        user = next(it for it in out["items"]
                    if it["class"] == "App\\Controller\\Admin\\UserCrudController")
        self.assertEqual(user["page_titles"], {})

    def test_unresolved_fields_when_delegated_to_parent(self):
        # MVP limitation marker: if configureFields delegates to parent::configureFields()
        # or `yield from parent::...`, we cannot statically resolve the field set.
        # Recipe should mark such CRUD as `partial`.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "ExtendedCrudController.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Controller\\Admin;
                use App\\Entity\\Order;
                use EasyCorp\\Bundle\\EasyAdminBundle\\Controller\\AbstractCrudController;
                use EasyCorp\\Bundle\\EasyAdminBundle\\Field\\TextField;
                class ExtendedCrudController extends AbstractCrudController {
                    public static function getEntityFqcn(): string { return Order::class; }
                    public function configureFields(string $pageName): iterable {
                        yield from parent::configureFields($pageName);
                        yield TextField::new('comment');
                    }
                }
                """))
            rc, out, err = _run("easyadmin-crud", f)
            self.assertEqual(rc, 0, msg=err)
            self.assertEqual(len(out["items"]), 1)
            it = out["items"][0]
            self.assertTrue(it["unresolved_fields"])
            # Statically visible fields are still emitted (best-effort).
            self.assertEqual([f["name"] for f in it["configure_fields"]], ["comment"])

    def test_skips_classes_not_extending_abstract_crud_controller(self):
        # Like collectForms's strict extends check: a random class is not an EasyAdmin
        # CRUD even if its name ends with CrudController.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "FakeCrudController.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Controller\\Admin;
                class FakeCrudController {
                    public static function getEntityFqcn(): string { return ''; }
                }
                """))
            rc, out, _ = _run("easyadmin-crud", f)
            self.assertEqual(rc, 0)
            self.assertEqual(out["items"], [])

    def test_no_configure_fields_method_yields_empty_fields(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "BareCrudController.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Controller\\Admin;
                use App\\Entity\\Tag;
                use EasyCorp\\Bundle\\EasyAdminBundle\\Controller\\AbstractCrudController;
                class BareCrudController extends AbstractCrudController {
                    public static function getEntityFqcn(): string { return Tag::class; }
                }
                """))
            rc, out, err = _run("easyadmin-crud", f)
            self.assertEqual(rc, 0, msg=err)
            self.assertEqual(len(out["items"]), 1)
            it = out["items"][0]
            self.assertEqual(it["configure_fields"], [])
            self.assertEqual(it["entity_fqcn"], "App\\Entity\\Tag")
            self.assertFalse(it["unresolved_fields"])

    def test_modifier_extraction_skips_calls_inside_lambdas(self):
        # Regression: regex-based modifier scan used to flag `->getInner()` as a
        # modifier when nested inside `formatValue(fn($v) => $v->getInner())`.
        # Paren-depth-aware scanner must report only top-level chain calls.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "LambdaCrudController.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Controller\\Admin;
                use App\\Entity\\Item;
                use EasyCorp\\Bundle\\EasyAdminBundle\\Controller\\AbstractCrudController;
                use EasyCorp\\Bundle\\EasyAdminBundle\\Field\\TextField;
                class LambdaCrudController extends AbstractCrudController {
                    public static function getEntityFqcn(): string { return Item::class; }
                    public function configureFields(string $pageName): iterable {
                        yield TextField::new('title')
                            ->formatValue(fn($v, $entity) => $entity->getInner()->toString())
                            ->onlyOnForms();
                    }
                }
                """))
            rc, out, err = _run("easyadmin-crud", f)
            self.assertEqual(rc, 0, msg=err)
            it = out["items"][0]
            field = it["configure_fields"][0]
            self.assertEqual(field["name"], "title")
            self.assertEqual(field["modifiers"], ["formatValue", "onlyOnForms"])

    def test_abstract_base_class_filtered_from_items(self):
        # Regression: BaseCrudController extends AbstractCrudController itself
        # used to leak into items, drove ghost `admin_authz_coverage` gaps.
        # `abstract class` modifier must be parsed and the class skipped.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "BaseCrud.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Controller\\Admin;
                use EasyCorp\\Bundle\\EasyAdminBundle\\Controller\\AbstractCrudController;
                abstract class BaseCrud extends AbstractCrudController {}
                """))
            rc, out, err = _run("easyadmin-crud", f)
            self.assertEqual(rc, 0, msg=err)
            self.assertEqual(out["items"], [])

    def test_collect_classes_marks_abstract(self):
        # `is_abstract` must propagate through `--kind=class` so downstream
        # consumers (`_classify_kind`) can filter base classes.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Base.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App;
                abstract class Base {}
                final class Concrete extends Base {}
                """))
            rc, out, err = _run("class", f)
            self.assertEqual(rc, 0, msg=err)
            by_fqn = {it["fqn"]: it for it in out["items"]}
            self.assertTrue(by_fqn["App\\Base"]["is_abstract"])
            self.assertFalse(by_fqn["App\\Concrete"]["is_abstract"])

    def test_short_name_collision_does_not_match(self):
        # `App\\Local\\AbstractCrudController` — same short name but unrelated
        # to EasyAdmin. FQN-first matching must reject it.
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "AbstractCrudController.php"
            base.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Local;
                abstract class AbstractCrudController {}
                """))
            child = Path(td) / "FakeCrud.php"
            child.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Controller;
                use App\\Local\\AbstractCrudController;
                class FakeCrud extends AbstractCrudController {}
                """))
            rc, out, err = _run("easyadmin-crud", Path(td))
            self.assertEqual(rc, 0, msg=err)
            self.assertEqual(
                out["items"], [],
                f"non-EasyAdmin AbstractCrudController matched: {out['items']!r}",
            )

    def test_sonata_get_class_string_literal_with_escaped_namespace(self):
        # `return 'App\\Entity\\User';` source keeps double-backslashes in the
        # captured token text. Recipe must normalise to the resolved FQN form
        # so admin_authz_coverage cross-check matches voter subjects.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "UserAdmin.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Admin;
                use Sonata\\AdminBundle\\Admin\\AbstractAdmin;
                class UserAdmin extends AbstractAdmin {
                    public function getClass(): string { return 'App\\\\Entity\\\\User'; }
                }
                """))
            rc, out, err = _run("sonata-admin", f)
            self.assertEqual(rc, 0, msg=err)
            self.assertEqual(len(out["items"]), 1)
            self.assertEqual(out["items"][0]["entity_fqcn"], "App\\Entity\\User")

    def test_indirect_inheritance_via_project_base_class(self):
        # `IntegrationCrud extends BaseCrudController extends AbstractCrudController`.
        # Strict-extends only would skip IntegrationCrud — recipe must surface
        # both via inheritance-graph lookup.
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "BaseCrudController.php"
            base.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Controller\\Admin;
                use EasyCorp\\Bundle\\EasyAdminBundle\\Controller\\AbstractCrudController;
                abstract class BaseCrudController extends AbstractCrudController {}
                """))
            child = Path(td) / "IntegrationCrudController.php"
            child.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Controller\\Admin;
                use App\\Entity\\Integration;
                use EasyCorp\\Bundle\\EasyAdminBundle\\Field\\TextField;
                class IntegrationCrudController extends BaseCrudController {
                    public static function getEntityFqcn(): string { return Integration::class; }
                    public function configureFields(string $pageName): iterable {
                        yield TextField::new('name');
                    }
                }
                """))
            rc, out, err = _run("easyadmin-crud", Path(td))
            self.assertEqual(rc, 0, msg=err)
            classes = {it["class"] for it in out["items"]}
            self.assertIn("App\\Controller\\Admin\\IntegrationCrudController", classes)
            # Abstract base class is filtered out — surfacing it would create
            # ghost authz-coverage gaps (no entity_fqcn, no concrete fields).
            self.assertNotIn("App\\Controller\\Admin\\BaseCrudController", classes)
            integration = next(it for it in out["items"]
                               if it["class"].endswith("IntegrationCrudController"))
            self.assertEqual(integration["entity_fqcn"], "App\\Entity\\Integration")

    def test_modifier_extraction_skips_arrow_inside_comments(self):
        # `body_text` is raw token concatenation — comments are preserved.
        # Scanner must not treat `// ->oldModifier()` as a real modifier.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "CommentsCrudController.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Controller\\Admin;
                use App\\Entity\\Item;
                use EasyCorp\\Bundle\\EasyAdminBundle\\Controller\\AbstractCrudController;
                use EasyCorp\\Bundle\\EasyAdminBundle\\Field\\TextField;
                class CommentsCrudController extends AbstractCrudController {
                    public static function getEntityFqcn(): string { return Item::class; }
                    public function configureFields(string $pageName): iterable {
                        yield TextField::new('label')
                            // ->oldDisable()
                            # deprecated: ->legacyName()
                            /* multi-line: ->blockHidden() */
                            ->setLabel('X');
                    }
                }
                """))
            rc, out, err = _run("easyadmin-crud", f)
            self.assertEqual(rc, 0, msg=err)
            field = out["items"][0]["configure_fields"][0]
            self.assertEqual(field["modifiers"], ["setLabel"],
                             f"modifiers leaked from comments: {field['modifiers']!r}")

    def test_modifier_extraction_skips_arrow_inside_string_literal(self):
        # `'foo->bar'` inside a modifier arg must not become a modifier name.
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "StringArrowCrudController.php"
            f.write_text(textwrap.dedent("""\
                <?php
                namespace App\\Controller\\Admin;
                use App\\Entity\\Item;
                use EasyCorp\\Bundle\\EasyAdminBundle\\Controller\\AbstractCrudController;
                use EasyCorp\\Bundle\\EasyAdminBundle\\Field\\TextField;
                class StringArrowCrudController extends AbstractCrudController {
                    public static function getEntityFqcn(): string { return Item::class; }
                    public function configureFields(string $pageName): iterable {
                        yield TextField::new('label')
                            ->setHelp('see field->bar reference')
                            ->setLabel("alias->thing");
                    }
                }
                """))
            rc, out, err = _run("easyadmin-crud", f)
            self.assertEqual(rc, 0, msg=err)
            field = out["items"][0]["configure_fields"][0]
            self.assertEqual(sorted(field["modifiers"]), ["setHelp", "setLabel"])


if __name__ == "__main__":
    unittest.main()
