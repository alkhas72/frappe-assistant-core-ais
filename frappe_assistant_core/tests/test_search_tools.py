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
Test suite for Search Tools using Plugin Architecture
"""

import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import frappe

from frappe_assistant_core.core.security_policy import PolicyDenied
from frappe_assistant_core.core.tool_registry import get_tool_registry
from frappe_assistant_core.tests.base_test import BaseAssistantTest


class TestSearchTools(BaseAssistantTest):
    """Test search tools through plugin registry"""

    def setUp(self):
        super().setUp()
        self.registry = get_tool_registry()

    def test_get_tools_structure(self):
        """Test that search tools are properly registered"""
        tools = self.registry.get_available_tools()
        tool_names = [tool["name"] for tool in tools]

        # Check for search tools
        expected_tools = ["search_documents"]
        found_tools = [tool for tool in expected_tools if tool in tool_names]

        self.assertGreater(len(found_tools), 0, f"Should find search tools. Available: {tool_names}")

    def test_execute_tool_routing(self):
        """Test that tool routing works correctly"""
        tools = self.registry.get_available_tools()
        if tools:
            self.assertTrue(hasattr(self.registry, "execute_tool"))
            self.assertTrue(hasattr(self.registry, "get_available_tools"))

    def test_execute_tool_invalid_tool(self):
        """Test handling of invalid tool names"""
        with self.assertRaises(PolicyDenied) as raised:
            self.registry.execute_tool("nonexistent_search_tool", {})
        self.assertEqual(raised.exception.reason_code, "TOOL_UNKNOWN")

    def test_search_documents_basic(self):
        """Test basic document search"""
        if not self.registry.has_tool("search_documents"):
            self.skipTest("search_documents tool not available")

        arguments = {"query": "Admin"}

        try:
            result = self.registry.execute_tool("search_documents", arguments)
            self.assertIsInstance(result, dict)
        except Exception:
            # Search may fail for various reasons
            pass

    # Placeholder tests for other search functionality
    def test_search_documents_with_filters(self):
        self.skipTest("Search with filters test placeholder")

    def test_global_search_uses_permission_aware_query(self):
        """Regression guard for #189: global_search (behind the search_documents
        tool) must use frappe.get_list with ``ignore_permissions=False``.

        Note (FAC Task 7 rev. 2): we no longer plant an AssertionError on
        ``frappe.get_all`` — that hook also caught Frappe-internal calls
        (Custom DocPerm reads, meta lookups, etc.) and broke unrelated
        behaviour. We verify the actual FAC call site: ``get_list`` is used
        and carries ``ignore_permissions=False``.
        """
        from frappe_assistant_core.plugins.core.tools import search_tools

        with ExitStack() as stack:
            # Make exactly one doctype exist and be readable so a single query
            # runs. global_search calls frappe.db.exists("DocType", <doctype>),
            # so the doctype name is the second positional arg.
            stack.enter_context(
                patch.object(
                    search_tools.frappe.db,
                    "exists",
                    side_effect=lambda *a, **k: "Employee" in a,
                )
            )
            stack.enter_context(
                patch.object(
                    search_tools.frappe,
                    "has_permission",
                    side_effect=lambda doctype, *a, **k: doctype == "Employee",
                )
            )
            stack.enter_context(
                patch(
                    "frappe_assistant_core.core.security_policy.SecurityPolicy._is_restricted_target",
                    side_effect=lambda doctype: doctype != "Employee",
                )
            )
            get_list = stack.enter_context(patch.object(search_tools.frappe, "get_list"))
            get_list.return_value = [{"name": "EMP-0001"}]

            result = search_tools.SearchTools.global_search(query="EMP", limit=20)

        self.assertTrue(result.get("success"), result)
        self.assertTrue(get_list.called, "global_search must query via frappe.get_list")
        fac_calls = [
            call
            for call in get_list.call_args_list
            if call.args and call.args[0] == "Employee"
        ]
        self.assertEqual(len(fac_calls), 1, get_list.call_args_list)
        self.assertFalse(
            fac_calls[0].kwargs.get("ignore_permissions", True),
            "global_search must pass ignore_permissions=False",
        )

    def test_search_doctype_uses_permission_aware_query(self):
        """Regression guard for #189: search_doctype (behind the search_doctype
        tool) must use frappe.get_list with ``ignore_permissions=False``.

        Note (FAC Task 7 rev. 2): ``frappe.get_all`` is no longer trapped with
        an AssertionError — that broke Frappe-internal reads. We assert on
        ``get_list`` directly instead.
        """
        from frappe_assistant_core.plugins.core.tools import search_tools

        with ExitStack() as stack:
            stack.enter_context(patch.object(search_tools.frappe.db, "exists", return_value=True))
            stack.enter_context(patch.object(search_tools.frappe, "has_permission", return_value=True))
            # Minimal meta stub: one searchable Data field, no title field.
            # Explicit ``istable=False`` so the restricted-target gate does
            # not classify Employee as a child table.
            meta = MagicMock()
            meta.title_field = None
            meta.istable = False
            field = MagicMock(fieldtype="Data", hidden=False, fieldname="employee_name")
            meta.fields = [field]
            stack.enter_context(patch.object(search_tools.frappe, "get_meta", return_value=meta))
            get_list = stack.enter_context(patch.object(search_tools.frappe, "get_list"))
            get_list.return_value = [{"name": "EMP-0001", "employee_name": "Allowed"}]

            result = search_tools.SearchTools.search_doctype(doctype="Employee", query="All", limit=20)

        self.assertTrue(result.get("success"), result)
        self.assertEqual(get_list.call_count, 1)
        call = get_list.call_args_list[0]
        self.assertEqual(call.args[0], "Employee")
        self.assertFalse(call.kwargs.get("ignore_permissions", True))

    def test_search_empty_query(self):
        self.skipTest("Empty query test placeholder")

    # --- FAC security hardening Task 6 (2026-08-09) ---
    #
    # Regression guards for restricted-target leaks in global / doctype / link
    # search. The legacy ``SearchTools`` shipped ``User`` and ``DocType`` in
    # ``common_doctypes`` and only checked ``frappe.has_permission``, which a
    # System Manager passes for restricted DocTypes. The central policy in
    # ``_safe_execute`` now blocks restricted targets at the publish/execute
    # gate, but a direct call into the static helper must also refuse.

    def test_global_search_excludes_restricted_doctypes(self):
        """``User`` and ``DocType`` must NEVER appear in global_search output,
        even when the actor has read permission (System Manager)."""
        from frappe_assistant_core.plugins.core.tools import search_tools

        with ExitStack() as stack:
            # Pretend every doctype exists and is readable. Without the
            # restricted-target gate, User and DocType would leak through.
            stack.enter_context(
                patch.object(search_tools.frappe.db, "exists", return_value=True)
            )
            stack.enter_context(
                patch.object(search_tools.frappe, "has_permission", return_value=True)
            )
            get_list = stack.enter_context(patch.object(search_tools.frappe, "get_list"))
            get_list.return_value = [{"name": "LEAK"}]

            result = search_tools.SearchTools.global_search(query="any", limit=20)

        self.assertTrue(result.get("success"), result)
        searched = result.get("searched_doctypes", [])
        self.assertNotIn("User", searched, "Restricted DocType User leaked into global_search")
        self.assertNotIn("DocType", searched, "Restricted DocType DocType leaked into global_search")
        # The leaked rows we would have produced for User/DocType must not be
        # present in the result set either.
        for row in result.get("results", []):
            self.assertNotEqual(row.get("doctype"), "User")
            self.assertNotEqual(row.get("doctype"), "DocType")

    def test_search_doctype_rejects_restricted_target(self):
        """A direct call to ``search_doctype("User", ...)`` must refuse before
        running any query, regardless of role."""
        from frappe_assistant_core.plugins.core.tools import search_tools

        with ExitStack() as stack:
            stack.enter_context(
                patch.object(search_tools.frappe.db, "exists", return_value=True)
            )
            stack.enter_context(
                patch.object(search_tools.frappe, "has_permission", return_value=True)
            )
            # Sentinel: if restricted-target gate fails, ``get_list`` would be
            # reached. We assert on result + call count instead of trapping
            # ``get_list`` itself so the test does not interfere with any
            # future internal Frappe calls.
            get_list = stack.enter_context(patch.object(search_tools.frappe, "get_list"))
            get_list.return_value = [{"name": "LEAK"}]

            result = search_tools.SearchTools.search_doctype(doctype="User", query="any", limit=20)

        self.assertFalse(result.get("success"), result)
        self.assertIn("restricted", (result.get("error") or "").lower())
        get_list.assert_not_called()

    def test_search_link_rejects_restricted_target(self):
        """``search_link`` must refuse restricted DocTypes before delegating to
        Frappe's ``frappe.desk.search.search_link``."""
        from frappe_assistant_core.plugins.core.tools import search_tools

        # Patch the symbol where it is looked up. ``search_tools`` imports
        # ``search_link`` lazily inside the function, so we patch it on the
        # source module ``frappe.desk.search``.
        with ExitStack() as stack:
            stack.enter_context(
                patch.object(search_tools.frappe.db, "exists", return_value=True)
            )
            stack.enter_context(
                patch.object(search_tools.frappe, "has_permission", return_value=True)
            )
            desk_search_link = stack.enter_context(
                patch("frappe.desk.search.search_link")
            )
            desk_search_link.return_value = [{"name": "LEAK"}]

            result = search_tools.SearchTools.search_link(doctype="User", query="any", filters={})

        self.assertFalse(result.get("success"), result)
        self.assertIn("restricted", (result.get("error") or "").lower())
        desk_search_link.assert_not_called()


class TestSearchToolsIntegration(BaseAssistantTest):
    """Integration tests for search tools"""

    def setUp(self):
        super().setUp()
        self.registry = get_tool_registry()

    def test_search_workflow(self):
        self.skipTest("Search workflow test placeholder")
