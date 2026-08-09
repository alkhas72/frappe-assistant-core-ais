"""Regression tests for legacy_tool_test_support exact snapshot cleanup."""

from __future__ import annotations

from unittest.mock import patch

import frappe

from frappe_assistant_core.tests.base_test import BaseAssistantTest
from frappe_assistant_core.tests.legacy_tool_test_support import (
    LegacyToolRegistryAccess,
    capture_tool_configs_snapshot,
    legacy_tool_registry_access,
    tool_configs_snapshot_hash,
)


class TestLegacyToolTestSupportRegression(BaseAssistantTest):
    """RED→GREEN guards: exact config restore and disposable user cleanup."""

    probe_tool = "get_document"

    def setUp(self):
        super().setUp()
        if not frappe.db.exists("FAC Tool Configuration", self.probe_tool):
            self.skipTest(f"{self.probe_tool} FAC Tool Configuration missing")

    def test_exact_snapshot_restored_after_successful_context(self):
        before = capture_tool_configs_snapshot([self.probe_tool])
        before_hash = tool_configs_snapshot_hash(before)

        with legacy_tool_registry_access([self.probe_tool]) as ctx:
            self.assertTrue(frappe.db.exists("User", ctx.email))

        after = capture_tool_configs_snapshot([self.probe_tool])
        self.assertEqual(before, after)
        self.assertEqual(before_hash, tool_configs_snapshot_hash(after))
        self.assertFalse(frappe.db.exists("User", ctx.email))

    def test_exact_snapshot_restored_after_setup_failure(self):
        run_id = "setup-failure-regression"
        email = f"fac-legacy-{run_id}@example.com"
        before = capture_tool_configs_snapshot([self.probe_tool])

        ctx = LegacyToolRegistryAccess([self.probe_tool], run_id=run_id)
        with patch(
            "frappe_assistant_core.tests.legacy_tool_test_support.create_disposable_system_manager_user",
            side_effect=RuntimeError("forced setup failure"),
        ):
            with self.assertRaises(RuntimeError):
                ctx.__enter__()

        after = capture_tool_configs_snapshot([self.probe_tool])
        self.assertEqual(before, after)
        self.assertFalse(frappe.db.exists("User", email))

    def test_configs_restored_when_disposable_user_delete_fails(self):
        run_id = "user-delete-failure-regression"
        email = f"fac-legacy-{run_id}@example.com"
        before = capture_tool_configs_snapshot([self.probe_tool])

        original_delete = frappe.delete_doc

        def failing_user_delete(doctype, name, *args, **kwargs):
            if doctype == "User" and name == email:
                raise RuntimeError("forced user delete failure")
            return original_delete(doctype, name, *args, **kwargs)

        with patch.object(frappe, "delete_doc", side_effect=failing_user_delete):
            with legacy_tool_registry_access([self.probe_tool], run_id=run_id):
                self.assertTrue(frappe.db.exists("User", email))

        after = capture_tool_configs_snapshot([self.probe_tool])
        self.assertEqual(before, after)
        # User may remain when delete is forced to fail; configs must still match.
        self.assertTrue(frappe.db.exists("User", email))

        frappe.set_user("Administrator")
        if frappe.db.exists("User", email):
            frappe.delete_doc("User", email, force=True)
            frappe.db.commit()
