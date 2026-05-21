"""Tests for `recon_bags.stack.laravel.sensitive_columns` emitter.

Coverage:
  * $casts entries with name patterns matching credentials.
    - 'string'/'hashed'/explicit class — plaintext / encrypted classification.
  * $fillable entries (no cast) — plaintext, no evidence required.
  * Migration Blueprint::* columns (string/text/encryptedText) — separate
    file-anchored items so they don't collide with model rows.
  * Non-credential field names (`name`, `email`, `description`) — never emit.
  * encrypted ↔ non-empty evidence invariant.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

PLUGIN_BIN = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PLUGIN_BIN))

from recon.recipes import laravel  # noqa: E402

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "laravel_sensitive_columns"


class SensitiveColumnsBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = laravel._build_sensitive_columns(FIX)
        cls.items = cls.payload.items or []

    def _items_for_field(self, field_name: str, *, entity_substr: str = "") -> list[dict]:
        return [
            it for it in self.items
            if it["field_name"] == field_name
            and entity_substr in it["entity_class"]
        ]

    def test_status_ok(self):
        self.assertEqual(self.payload.status, "ok")

    def test_token_field_in_casts_plaintext_when_string(self):
        # User: 'api_token' => 'string' → plaintext, no encryption_evidence.
        rows = self._items_for_field("api_token", entity_substr="User")
        self.assertEqual(len(rows), 1, msg=f"got {self.items!r}")
        row = rows[0]
        self.assertEqual(row["encryption_status"], "plaintext")
        self.assertEqual(row["encryption_evidence"], [])
        self.assertEqual(row["column_type"], "string")

    def test_token_field_in_casts_encrypted_emits_evidence(self):
        # OAuthAccount: 'access_token' => 'encrypted' → encrypted + evidence.
        rows = self._items_for_field("access_token", entity_substr="OAuthAccount")
        self.assertEqual(len(rows), 1, msg=f"got {self.items!r}")
        row = rows[0]
        self.assertEqual(row["encryption_status"], "encrypted")
        self.assertEqual(len(row["encryption_evidence"]), 1)
        ev = row["encryption_evidence"][0]
        self.assertEqual(ev["kind"], "eloquent_cast_whitelist")
        self.assertEqual(ev["identifier"], "encrypted")

    def test_encrypted_with_qualifier_recognised(self):
        # OAuthAccount: 'refresh_token' => 'encrypted:json' → encrypted.
        rows = self._items_for_field("refresh_token", entity_substr="OAuthAccount")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["encryption_status"], "encrypted")
        self.assertEqual(rows[0]["encryption_evidence"][0]["identifier"], "encrypted:json")

    def test_password_field_emitted_with_hashed_status(self):
        # User: 'password' => 'hashed' → encrypted (hashed counts as one-way encryption-at-rest).
        rows = self._items_for_field("password", entity_substr="User")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["encryption_status"], "encrypted")
        self.assertEqual(rows[0]["column_type"], "hashed")

    def test_migration_blueprint_string_emitted(self):
        # Webhooks migration: $table->string('webhook_secret', 64) → plaintext, column_type=string.
        rows = [
            it for it in self.items
            if it["field_name"] == "webhook_secret"
        ]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["column_type"], "string")
        self.assertEqual(row["encryption_status"], "plaintext")
        self.assertTrue(row["entity_class"].startswith("migration:"))

    def test_migration_encrypted_text_classified_encrypted(self):
        # $table->encryptedText('private_key') → encrypted via blueprint method allowlist.
        rows = [
            it for it in self.items
            if it["field_name"] == "private_key"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["encryption_status"], "encrypted")
        self.assertEqual(rows[0]["column_type"], "encryptedText")
        self.assertEqual(rows[0]["encryption_evidence"][0]["identifier"], "encryptedText")

    def test_no_match_no_emit(self):
        # `name`, `email`, `description` must NOT appear.
        for benign in ("name", "email", "description"):
            self.assertEqual(
                self._items_for_field(benign), [],
                msg=f"benign field '{benign}' should not be emitted",
            )

    def test_encrypted_status_requires_evidence(self):
        # Schema invariant: every encrypted item has non-empty encryption_evidence.
        for row in self.items:
            if row["encryption_status"] == "encrypted":
                self.assertGreater(
                    len(row["encryption_evidence"]), 0,
                    msg=f"encrypted row missing evidence: {row!r}",
                )

    def test_plaintext_evidence_is_empty_list(self):
        for row in self.items:
            if row["encryption_status"] == "plaintext":
                self.assertEqual(
                    row["encryption_evidence"], [],
                    msg=f"plaintext row carries stray evidence: {row!r}",
                )

    def test_source_files_includes_emitting_files(self):
        sources = self.payload.source_files or []
        self.assertIn("app/Models/User.php", sources)
        self.assertIn("app/Models/OAuthAccount.php", sources)
        self.assertIn(
            "database/migrations/2024_01_01_000000_create_webhooks_table.php",
            sources,
        )

    def test_pattern_label_canonical(self):
        rows = self._items_for_field("api_token", entity_substr="User")
        self.assertEqual(rows[0]["name_pattern_matched"], "api_token")

    def test_empty_project_emits_none(self):
        with tempfile.TemporaryDirectory() as td:
            payload = laravel._build_sensitive_columns(Path(td))
            self.assertEqual(payload.status, "none")
            self.assertEqual(payload.items, [])

    def test_item_keys_match_schema(self):
        spec_keys = laravel.RECON_BAGS_SCHEMA["stack"]["laravel"]["sensitive_columns"].item_keys
        for row in self.items:
            self.assertEqual(
                set(row.keys()), set(spec_keys),
                msg=f"row keys diverge from schema: {row!r}",
            )


if __name__ == "__main__":
    unittest.main()
