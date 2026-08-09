"""Regression tests for plugin-management API endpoints."""

import frappe
from frappe.tests.utils import FrappeTestCase


class TestPluginAPI(FrappeTestCase):
    def test_refresh_tool_registry_uses_current_registry_contract(self):
        """The public refresh endpoint must work with the canonical registry."""
        from frappe_assistant_core.api.plugin_api import refresh_tool_registry

        previous_user = frappe.session.user
        frappe.set_user("Administrator")
        self.addCleanup(frappe.set_user, previous_user)

        try:
            result = refresh_tool_registry()
        except Exception as exc:
            self.fail(f"refresh_tool_registry raised {type(exc).__name__}")

        self.assertTrue(result.get("success"), result)
        self.assertEqual(result.get("message"), "Tool registry refreshed")
        self.assertIn("total_tools", result.get("stats", {}))
