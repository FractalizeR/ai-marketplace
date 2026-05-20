"""Wave 2-D (3.4.0) — `framework_specific.symfony.sensitive_columns` emitter.

Pure-Python emitter (no PHP runtime needed) — uses regex-based scanning of
Doctrine entity files. Tests are NOT skip-gated on `php` availability.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent.parent
sys.path.insert(0, str(BIN_DIR))

from recon.recipes import symfony as recipe_symfony  # noqa: E402

FIX = THIS_DIR.parent / "fixtures" / "symfony_sensitive_columns"


class SensitiveColumnsEmitter(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = recipe_symfony._build_sensitive_columns(FIX)

    def _items_by_field(self) -> dict:
        return {(it["entity_class"], it["field_name"]): it
                for it in (self.payload.items or [])}

    def test_status_ok(self) -> None:
        self.assertEqual(self.payload.status, "ok")
        self.assertTrue(self.payload.items)

    def test_password_field_detected_as_plaintext(self) -> None:
        items = self._items_by_field()
        key = ("App\\Entity\\User", "password")
        self.assertIn(key, items)
        item = items[key]
        self.assertEqual(item["column_type"], "string")
        self.assertEqual(item["encryption_status"], "plaintext")
        self.assertEqual(item["encryption_evidence"], [])

    def test_apikey_field_detected_as_plaintext(self) -> None:
        items = self._items_by_field()
        key = ("App\\Entity\\User", "apiKey")
        self.assertIn(key, items)
        self.assertEqual(items[key]["encryption_status"], "plaintext")

    def test_encrypted_string_type_recognized(self) -> None:
        items = self._items_by_field()
        key = ("App\\Entity\\OAuthAccount", "accessToken")
        self.assertIn(key, items)
        item = items[key]
        self.assertEqual(item["encryption_status"], "encrypted")
        self.assertEqual(item["column_type"], "encrypted_string")
        self.assertTrue(item["encryption_evidence"])
        ev = item["encryption_evidence"][0]
        self.assertEqual(ev["kind"], "doctrine_type_whitelist")
        self.assertEqual(ev["identifier"], "encrypted_string")

    def test_encrypted_attribute_recognized(self) -> None:
        items = self._items_by_field()
        key = ("App\\Entity\\OAuthAccount", "refreshToken")
        self.assertIn(key, items)
        item = items[key]
        self.assertEqual(item["encryption_status"], "encrypted")
        self.assertEqual(item["column_type"], "string")
        ev_kinds = {ev["kind"] for ev in item["encryption_evidence"]}
        self.assertIn("column_attribute", ev_kinds)

    def test_non_sensitive_field_not_emitted(self) -> None:
        items = self._items_by_field()
        # `email` and `amount` on Order — not sensitive.
        self.assertNotIn(("App\\Entity\\Order", "email"), items)
        self.assertNotIn(("App\\Entity\\Order", "amount"), items)
        # `id` on every entity — not sensitive.
        for entity in ("App\\Entity\\User", "App\\Entity\\OAuthAccount",
                       "App\\Entity\\Order"):
            self.assertNotIn((entity, "id"), items)

    def test_no_entity_dir_returns_none(self) -> None:
        # Project without src/Entity must report `none`, not crash.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            payload = recipe_symfony._build_sensitive_columns(Path(td))
            self.assertEqual(payload.status, "none")


class SensitiveColumnsSchemaInvariants(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = recipe_symfony._build_sensitive_columns(FIX)

    def test_each_item_has_contract_keys(self) -> None:
        spec = recipe_symfony.FRAMEWORK_SPECIFIC_SCHEMA["sensitive_columns"]
        expected = spec.item_keys or frozenset()
        for item in (self.payload.items or []):
            self.assertEqual(
                set(item.keys()), set(expected),
                msg=f"item key drift: {set(item.keys())} vs {set(expected)}",
            )

    def test_encrypted_items_have_evidence(self) -> None:
        for item in (self.payload.items or []):
            if item["encryption_status"] == "encrypted":
                self.assertTrue(
                    item["encryption_evidence"],
                    msg=f"encrypted item must have evidence: {item}",
                )
                for ev in item["encryption_evidence"]:
                    for key in ("kind", "identifier", "file", "line"):
                        self.assertIn(key, ev)
                    self.assertIn(ev["kind"], {
                        "doctrine_type_whitelist",
                        "column_attribute",
                        "manual_pattern",
                    })

    def test_plaintext_items_have_empty_or_no_evidence(self) -> None:
        for item in (self.payload.items or []):
            if item["encryption_status"] == "plaintext":
                self.assertEqual(item["encryption_evidence"], [])


if __name__ == "__main__":
    unittest.main()
