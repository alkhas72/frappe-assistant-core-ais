# Frappe Assistant Core - AI Assistant integration for Frappe Framework
# Copyright (C) 2025 Paul Clinton
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
Test suite for Workflow Tools using Plugin Architecture
"""

import unittest

import frappe

from frappe_assistant_core.core.security_policy import PolicyDenied
from frappe_assistant_core.core.tool_registry import get_tool_registry
from frappe_assistant_core.tests.base_test import BaseAssistantTest
from frappe_assistant_core.tests.legacy_tool_test_support import legacy_tool_registry_access


class TestWorkflowTools(BaseAssistantTest):
    """Test workflow tools through plugin registry"""

    def setUp(self):
        super().setUp()
        self.registry = get_tool_registry()

    def test_get_tools_structure(self):
        """Test that workflow tools are properly registered"""
        with legacy_tool_registry_access(["run_workflow"]):
            tools = self.registry.get_available_tools()
            tool_names = [tool["name"] for tool in tools]

            expected_tools = ["run_workflow"]
            found_tools = [tool for tool in expected_tools if tool in tool_names]

            self.assertGreater(len(found_tools), 0, f"Should find workflow tools. Available: {tool_names}")

    def test_execute_tool_routing(self):
        """Test that tool routing works correctly"""
        tools = self.registry.get_available_tools()
        if tools:
            self.assertTrue(hasattr(self.registry, "execute_tool"))
            self.assertTrue(hasattr(self.registry, "get_available_tools"))

    def test_execute_tool_invalid_tool(self):
        """Test handling of invalid tool names"""
        with self.assertRaises(PolicyDenied) as raised:
            self.registry.execute_tool("nonexistent_workflow_tool", {})
        self.assertEqual(raised.exception.reason_code, "TOOL_UNKNOWN")

    def test_get_workflow_actions_basic(self):
        """Test getting workflow actions"""
        if not self.registry.has_tool("run_workflow"):
            self.skipTest("run_workflow tool not available")

        # This is a placeholder - workflow functionality may be complex
        self.skipTest("Workflow actions test placeholder")

    def test_get_workflow_actions_no_permission(self):
        self.skipTest("Workflow permissions test placeholder")

    def test_get_workflow_state_basic(self):
        self.skipTest("Workflow state test placeholder")

    def test_get_workflow_state_no_permission(self):
        self.skipTest("Workflow state permissions test placeholder")

    def test_start_workflow_basic(self):
        self.skipTest("Start workflow test placeholder")

    def test_start_workflow_no_permission(self):
        self.skipTest("Start workflow permissions test placeholder")


class TestWorkflowToolsIntegration(BaseAssistantTest):
    """Integration tests for workflow tools"""

    def setUp(self):
        super().setUp()
        self.registry = get_tool_registry()

    def test_complete_workflow_scenario(self):
        self.skipTest("Complete workflow test placeholder")

    def test_workflow_error_scenarios(self):
        self.skipTest("Workflow error test placeholder")

    # --- FAC security hardening Task 7 (2026-08-09) ---

    def test_run_workflow_rejects_restricted_target_directly(self):
        """A direct call to ``RunWorkflow.execute`` for a restricted DocType
        (``User``, ``DocType``, ``File``, ...) must refuse before any
        ``frappe.get_doc`` or workflow lookup. Central policy already blocks
        this on the MCP path; this guard covers non-MCP callers."""
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools.run_workflow import RunWorkflow

        tool = RunWorkflow()
        with patch(
             "frappe_assistant_core.plugins.core.tools.run_workflow.frappe.get_doc",
             side_effect=AssertionError("restricted target must not reach get_doc"),
         ) as get_doc:
            result = tool.execute(
                {
                    "doctype": "User",
                    "name": "admin@example.com",
                    "action": "Approve",
                }
            )

        self.assertFalse(result.get("success"), result)
        self.assertEqual(result.get("error"), "Workflow action not available")
        get_doc.assert_not_called()

    def test_get_pending_approvals_excludes_restricted_and_unreadable(self):
        """``get_pending_approvals`` must drop actions whose reference DocType
        is restricted OR whose underlying document the user cannot read, even
        when the Workflow Action row itself matches the role subquery."""
        from unittest.mock import MagicMock, patch

        from frappe_assistant_core.plugins.core.tools.get_pending_approvals import (
            GetPendingApprovals,
        )

        tool = GetPendingApprovals()

        customer_action = MagicMock(
            name="WA-CUST-1",
            reference_doctype="Customer",
            reference_name="CUST-001",
            workflow_state="Pending",
            user=None,
            creation="2026-08-09 00:00:00",
        )
        user_action = MagicMock(
            name="WA-USER-1",
            reference_doctype="User",
            reference_name="admin@example.com",
            workflow_state="Pending",
            user=None,
            creation="2026-08-09 00:00:00",
        )

        class _FakeQuery:
            def where(self, *a, **kw):
                return self

            def orderby(self, *a, **kw):
                return self

            def limit(self, *a, **kw):
                return self

            def select(self, *a, **kw):
                return self

            def join(self, *a, **kw):
                return self

            def on(self, *a, **kw):
                return self

            def from_(self, *a, **kw):
                return self

            def run(self, as_dict=False):
                return [customer_action, user_action]

        fake_qb = MagicMock()
        fake_qb.from_.side_effect = lambda *args, **kwargs: _FakeQuery()
        fake_qb.desc = "desc"

        with patch(
            "frappe_assistant_core.plugins.core.tools.get_pending_approvals.frappe.session"
        ) as session, \
         patch(
             "frappe_assistant_core.plugins.core.tools.get_pending_approvals.frappe.get_roles",
             return_value=["Assistant User"],
         ), \
         patch(
             "frappe_assistant_core.plugins.core.tools.get_pending_approvals.frappe.qb",
             fake_qb,
         ), \
         patch(
             "frappe_assistant_core.plugins.core.tools.get_pending_approvals.frappe.has_permission",
             side_effect=lambda dt, ptype="read", doc=None, **kw: (
                 dt == "Customer" and doc == "CUST-001"
             ),
         ), \
         patch(
             "frappe_assistant_core.plugins.core.tools.get_pending_approvals.frappe.get_all",
             return_value=[],
         ), \
         patch(
             "frappe_assistant_core.plugins.core.tools.get_pending_approvals.DocType",
             return_value=MagicMock(),
        ):
            session.user = "user@example.com"

            result = tool.execute({"doctype": None, "include_actions": False})

        self.assertTrue(result.get("success"), result)
        grouped = result.get("pending_approvals", {})
        self.assertIn("Customer", grouped)
        self.assertNotIn(
            "User",
            grouped,
            "Restricted reference DocType leaked into pending approvals",
        )


# ---------------------------------------------------------------------------
# FAC v2.3 committed regression tests for workflow hardening.
# ---------------------------------------------------------------------------


class TestFacV23WorkflowRowPermission(BaseAssistantTest):
    """FAC v2.3: row-level permission runs BEFORE ``frappe.get_doc``. Hidden
    and missing records yield one stable refusal; ``get_doc`` is not called
    on an unreadable row."""

    def test_restricted_target_refused_before_get_doc(self):
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools.run_workflow import RunWorkflow

        tool = RunWorkflow()
        with patch("frappe_assistant_core.plugins.core.tools.run_workflow.frappe.has_permission",
                   return_value=True), \
             patch("frappe_assistant_core.plugins.core.tools.run_workflow.frappe.get_doc",
                   side_effect=AssertionError("restricted target must not reach get_doc")):
            result = tool.execute({
                "doctype": "User",
                "name": "admin@example.com",
                "action": "Approve",
            })
        self.assertFalse(result.get("success"))
        self.assertEqual(result.get("error"), "Workflow action not available")

    def test_unreadable_business_row_get_doc_not_called(self):
        """Allowed DocType (Customer) + unreadable row → stable refusal and
        ``get_doc`` MUST NOT be called."""
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools.run_workflow import RunWorkflow

        tool = RunWorkflow()
        # ``has_permission(doc=...)`` returns False for the unreadable row.
        def perm_gate(doctype, ptype="read", doc=None, **kw):
            if doc == "CUST-PRIVATE":
                return False
            return True

        with patch("frappe_assistant_core.plugins.core.tools.run_workflow.frappe.has_permission",
                   side_effect=perm_gate), \
             patch("frappe_assistant_core.plugins.core.tools.run_workflow.frappe.get_doc",
                   side_effect=AssertionError("get_doc must NOT be called for unreadable row")):
            result = tool.execute({
                "doctype": "Customer",
                "name": "CUST-PRIVATE",
                "action": "Approve",
            })
        self.assertFalse(result.get("success"))
        self.assertEqual(result.get("error"), "Workflow action not available")

    def test_missing_row_same_answer_as_unreadable(self):
        """A truly missing record (has_permission returns False) and an
        unreadable record produce the SAME stable answer."""
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools.run_workflow import RunWorkflow

        tool = RunWorkflow()
        with patch("frappe_assistant_core.plugins.core.tools.run_workflow.frappe.has_permission",
                   return_value=False):
            missing = tool.execute({
                "doctype": "Customer",
                "name": "TRULY-MISSING",
                "action": "Approve",
            })
            unreadable = tool.execute({
                "doctype": "Customer",
                "name": "CUST-PRIVATE",
                "action": "Approve",
            })
        self.assertEqual(missing.get("error"), unreadable.get("error"))
        self.assertEqual(missing.get("error"), "Workflow action not available")


class TestFacV23PendingApprovalsActiveRoles(BaseAssistantTest):
    """FAC v2.3: pending approvals filter the user's roles against
    ``Role.disabled = 0`` before the role subquery."""

    def test_disabled_role_filtered_out_of_subquery(self):
        from unittest.mock import MagicMock, patch

        from frappe_assistant_core.plugins.core.tools.get_pending_approvals import (
            GetPendingApprovals,
        )

        tool = GetPendingApprovals()

        class _FakeQuery:
            def join(self, *args, **kwargs):
                return self

            def on(self, *args, **kwargs):
                return self

            def select(self, *args, **kwargs):
                return self

            def where(self, *args, **kwargs):
                return self

            def orderby(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def run(self, as_dict=False):
                return []

        fake_qb = MagicMock()
        fake_qb.from_.side_effect = lambda *args, **kwargs: _FakeQuery()
        fake_qb.desc = "desc"

        with patch("frappe_assistant_core.plugins.core.tools.get_pending_approvals.frappe.get_roles",
                   return_value=["Active Role", "Disabled Role"]), \
             patch("frappe_assistant_core.plugins.core.tools.get_pending_approvals.frappe.db.get_list",
                   return_value=["Active Role"]) as get_list, \
             patch("frappe_assistant_core.plugins.core.tools.get_pending_approvals.frappe.session") as session, \
             patch("frappe_assistant_core.plugins.core.tools.get_pending_approvals.frappe.qb",
                   fake_qb), \
             patch("frappe_assistant_core.plugins.core.tools.get_pending_approvals.DocType",
                   return_value=MagicMock()):
            session.user = "user@example.com"
            result = tool.execute({"doctype": None, "include_actions": False})

        self.assertTrue(result.get("success"))
        self.assertTrue(get_list.called)
        call = get_list.call_args
        filters = call.kwargs.get("filters") or (call.args[1] if len(call.args) > 1 else {})
        self.assertEqual(filters.get("disabled"), 0)
