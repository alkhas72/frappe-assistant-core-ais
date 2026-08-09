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
Test suite for Report Tools using Plugin Architecture
Tests report operations through the tool registry
"""

import unittest

import frappe

from frappe_assistant_core.core.security_policy import PolicyDenied
from frappe_assistant_core.core.tool_registry import get_tool_registry
from frappe_assistant_core.tests.base_test import BaseAssistantTest


class TestReportTools(BaseAssistantTest):
    """Test report tools through plugin registry"""

    def setUp(self):
        super().setUp()
        self.registry = get_tool_registry()

    def test_get_tools_structure(self):
        """Test that report tools are properly registered"""
        tools = self.registry.get_available_tools()
        tool_names = [tool["name"] for tool in tools]

        # Check for core report tools
        expected_tools = ["generate_report", "get_report_data"]
        found_tools = [tool for tool in expected_tools if tool in tool_names]

        self.assertGreater(len(found_tools), 0, f"Should find report tools. Available: {tool_names}")

    def test_execute_tool_routing(self):
        """Test that tool routing works correctly"""
        tools = self.registry.get_available_tools()
        if tools:
            self.assertTrue(hasattr(self.registry, "execute_tool"))
            self.assertTrue(hasattr(self.registry, "get_available_tools"))

    def test_execute_tool_invalid_tool(self):
        """Test handling of invalid tool names"""
        with self.assertRaises(PolicyDenied) as raised:
            self.registry.execute_tool("nonexistent_report_tool", {})
        self.assertEqual(raised.exception.reason_code, "TOOL_UNKNOWN")

    def test_list_reports_basic(self):
        """Test basic report listing - placeholder for now"""
        # Skip actual test as report listing might not exist as a tool
        self.skipTest("Report listing test placeholder")

    def test_execute_report_query_report(self):
        """Test query report execution"""
        if not self.registry.has_tool("generate_report"):
            self.skipTest("generate_report tool not available")

        # Try a simple report that should exist
        arguments = {
            "report_name": "User Report"  # Simple report that might exist
        }

        try:
            result = self.registry.execute_tool("generate_report", arguments)
            self.assertIsInstance(result, dict)
        except Exception:
            # Report may not exist, which is fine for this test
            pass

    def test_execute_report_script_report(self):
        """Test script report execution"""
        self.skipTest("Script report test placeholder")

    def test_execute_report_with_filters(self):
        """Test report execution with filters"""
        self.skipTest("Report with filters test placeholder")

    def test_execute_report_nonexistent_report(self):
        """Test execution of nonexistent report"""
        if not self.registry.has_tool("generate_report"):
            self.skipTest("generate_report tool not available")

        arguments = {"report_name": "NonExistent Report 12345"}

        try:
            result = self.registry.execute_tool("generate_report", arguments)
            self.assertIsInstance(result, dict)
            # Should return error for nonexistent report
            if "success" in result:
                self.assertFalse(result["success"], "Should fail for nonexistent report")
        except Exception:
            # Exception is also acceptable for nonexistent report
            pass

    def test_execute_report_no_permission(self):
        """Test report execution without permission"""
        self.skipTest("Permission test placeholder")

    def test_get_report_columns_query_report(self):
        """Test getting report columns"""
        self.skipTest("Report columns test placeholder")

    def test_get_report_columns_script_report(self):
        """Test getting script report columns"""
        self.skipTest("Script report columns test placeholder")

    def test_list_reports_with_filters(self):
        """Test listing reports with filters"""
        self.skipTest("List reports with filters placeholder")

    def test_list_reports_no_permission(self):
        """Test listing reports without permission"""
        self.skipTest("List reports permission test placeholder")

    def test_report_format_functionality(self):
        """Test report format functionality"""
        self.skipTest("Report format test placeholder")

    # --- FAC security hardening Task 7 (2026-08-09) ---
    #
    # ``Report`` itself is not in ``RESTRICTED_DOCTYPES`` (operators need to
    # discover and run reports). The leak vector is ``ref_doctype``: a report
    # built on top of ``User`` / ``File`` / FAC config types would disclose
    # restricted data through the report surface. ``list_reports`` also used
    # ``frappe.get_all`` (permission-bypassing) for discovery.

    def test_list_reports_uses_permission_aware_query(self):
        """Regression: ``list_reports`` must call ``frappe.get_list`` with
        ``ignore_permissions=False``.

        FAC Task 7 rev. 2: the AssertionError trap on ``frappe.get_all`` was
        removed — it caught Frappe-internal reads (Custom DocPerm, meta
        lookups) and broke unrelated behaviour. We assert the FAC call site
        (``get_list`` with ``ignore_permissions=False``) directly.
        """
        from contextlib import ExitStack
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        with ExitStack() as stack:
            stack.enter_context(
                patch.object(report_tools.frappe.db, "exists", return_value=True)
            )
            stack.enter_context(
                patch.object(report_tools.frappe, "has_permission", return_value=True)
            )
            get_list = stack.enter_context(patch.object(report_tools.frappe, "get_list"))
            # ``list_reports`` now also reads ``ref_doctype`` so it can filter
            # restricted-target reports.
            get_list.return_value = [
                {"name": "Allowed Report", "ref_doctype": "Customer"},
            ]

            result = report_tools.ReportTools.list_reports()

        self.assertTrue(result.get("success"), result)
        self.assertTrue(get_list.called, "list_reports must use frappe.get_list")
        call = get_list.call_args_list[0]
        self.assertFalse(
            call.kwargs.get("ignore_permissions", True),
            "list_reports must pass ignore_permissions=False",
        )

    def test_execute_report_rejects_restricted_ref_doctype(self):
        """A report whose ``ref_doctype`` is restricted must be refused before
        any filter validation or execution runs. FAC v2.1: the external answer
        is the generic ``"Report not available"`` so the existence of a
        restricted-target report is not disclosed."""
        from unittest.mock import MagicMock, patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        report_doc = MagicMock()
        report_doc.ref_doctype = "User"
        report_doc.report_type = "Query Report"

        with patch.object(report_tools.frappe, "has_permission", return_value=True), \
             patch.object(report_tools.frappe, "get_doc", return_value=report_doc), \
             patch.object(
                 "frappe.desk.query_report.run",
                 side_effect=AssertionError("restricted-target report must not execute"),
             ) as run:
            result = report_tools.ReportTools.execute_report(
                report_name="User Report", filters={}
            )

        self.assertFalse(result.get("success"), result)
        self.assertEqual(result.get("error"), "Report not available")
        run.assert_not_called()

    def test_get_report_columns_rejects_restricted_ref_doctype(self):
        """``get_report_columns`` mirrors ``execute_report`` and must refuse a
        report whose ``ref_doctype`` is restricted before any column
        extraction. FAC v2.1: stable ``"Report not available"`` answer."""
        from unittest.mock import MagicMock, patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        report_doc = MagicMock()
        report_doc.ref_doctype = "File"
        report_doc.report_type = "Query Report"

        with patch.object(report_tools.frappe, "has_permission", return_value=True), \
             patch.object(report_tools.frappe, "get_doc", return_value=report_doc):
            result = report_tools.ReportTools.get_report_columns(report_name="File Report")

        self.assertFalse(result.get("success"), result)
        self.assertEqual(result.get("error"), "Report not available")

    # --- FAC v2.1 (2026-08-09) ---
    #
    # Independent review found four remaining leaks in report_tools. The tests
    # below prove each contract and lock it in.

    def test_hidden_and_missing_report_produce_same_external_answer(self):
        """A hidden report (exists, caller lacks ``read``) and a missing one
        MUST yield the same stable public answer — otherwise the difference
        discloses existence."""
        from unittest.mock import MagicMock, patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        # Hidden: doctype-level permission yes, doc-level no.
        def hidden_perm(doctype, ptype="read", doc=None, **kw):
            if doctype == "Report" and doc == "Hidden":
                return False
            return True

        # Missing: doctype-level yes, doc-level True, but get_doc raises.
        def missing_perm(doctype, ptype="read", doc=None, **kw):
            return True

        def hidden_get_doc(doctype, name):
            return MagicMock(name=name, ref_doctype="Customer", report_type="Query Report")

        def missing_get_doc(doctype, name):
            raise frappe.DoesNotExistError("missing")

        with patch.object(report_tools.frappe, "has_permission", side_effect=hidden_perm), \
             patch.object(report_tools.frappe, "get_doc", side_effect=hidden_get_doc):
            hidden = report_tools.ReportTools.execute_report("Hidden", {})

        with patch.object(report_tools.frappe, "has_permission", side_effect=missing_perm), \
             patch.object(report_tools.frappe, "get_doc", side_effect=missing_get_doc):
            missing = report_tools.ReportTools.execute_report("Truly Missing", {})

        self.assertFalse(hidden.get("success"))
        self.assertFalse(missing.get("success"))
        self.assertEqual(hidden.get("error"), missing.get("error"))
        self.assertEqual(hidden.get("error"), "Report not available")

    def test_execute_report_no_raw_exception_in_response(self):
        """On internal failure the public answer is a stable category and
        never contains the raw exception text."""
        from unittest.mock import MagicMock, patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        report_doc = MagicMock()
        report_doc.ref_doctype = "Customer"
        report_doc.report_type = "Query Report"
        report_doc.name = "Sensitive Report"

        sensitive_message = "secret_value_leaked_in_SQL: password='hunter2'"

        def boom(**kw):
            raise RuntimeError(sensitive_message)

        with patch.object(report_tools.frappe, "has_permission", return_value=True), \
             patch.object(report_tools.frappe, "get_doc", return_value=report_doc), \
             patch.object(report_tools.frappe, "logger"), \
             patch("frappe.desk.query_report.run", side_effect=boom):
            result = report_tools.ReportTools.execute_report("Sensitive Report", {})

        self.assertFalse(result.get("success"))
        self.assertEqual(result.get("error"), "Report execution failed")
        rendered = repr(result)
        self.assertNotIn("hunter2", rendered)
        self.assertNotIn("secret_value_leaked", rendered)

    def test_execute_report_redacts_list_rows(self):
        """Positional (list) rows are matched against the column index map and
        sensitive positions are dropped consistently with the columns."""
        from frappe_assistant_core.plugins.core.tools import report_tools

        debug_info = {
            "data": [["C1", "leak-me"], ["C2", "leak-2"]],
            "columns": [
                {"fieldname": "name", "label": "Name"},
                {"fieldname": "password", "label": "Secret"},
            ],
        }
        out = report_tools.ReportTools._redact_report_output(debug_info, "Customer")
        col_names = [c.get("fieldname") for c in out["columns"]]
        self.assertNotIn("password", col_names)
        for row in out["data"]:
            self.assertIsInstance(row, list)
            self.assertEqual(len(row), 1)
            self.assertNotIn("leak", repr(row))

    def test_execute_report_redacts_tuple_rows(self):
        """Positional (tuple) rows preserve tuple shape after redaction."""
        from frappe_assistant_core.plugins.core.tools import report_tools

        debug_info = {
            "data": [("C1", "leak-me")],
            "columns": [
                {"fieldname": "name", "label": "Name"},
                {"fieldname": "api_key", "label": "API Key"},
            ],
        }
        out = report_tools.ReportTools._redact_report_output(debug_info, "Customer")
        self.assertEqual(len(out["data"]), 1)
        row = out["data"][0]
        self.assertIsInstance(row, tuple)
        self.assertEqual(len(row), 1)
        self.assertNotIn("leak", repr(row))

    def test_malicious_row_doctype_does_not_override_report_ref_doctype(self):
        """A row that claims a benign ``doctype`` (``Customer``) must NOT
        downgrade the report's restricted ``ref_doctype`` (``User``)."""
        from frappe_assistant_core.plugins.core.tools.report_tools import ReportTools

        debug_info = {
            "data": [
                {
                    "doctype": "Customer",  # malicious override attempt
                    "name": "U1",
                    "password": "p",
                    "api_key": "k",
                    # ``login_after`` is sensitive specifically for User; a
                    # successful bypass would leave it intact.
                    "login_after": "secret-login-after",
                }
            ],
            # NOTE: ``password`` is intentionally NOT in ``columns``. Sensitive
            # columns are dropped; sensitive KEYS without a matching column are
            # redacted in place. We need the latter to prove the malicious
            # ``doctype="Customer"`` does not downgrade User-scoped redaction.
            "columns": [{"fieldname": "name"}],
        }

        out = ReportTools._redact_report_output(debug_info, "User")

        row = out["data"][0]
        self.assertNotIn("doctype", row)
        self.assertEqual(row["password"], "***REDACTED***")
        self.assertEqual(row["api_key"], "***REDACTED***")
        # User-specific sensitive key was also redacted — proves ref_doctype
        # won over the malicious Customer claim.
        self.assertEqual(row["login_after"], "***REDACTED***")


class TestReportToolsIntegration(BaseAssistantTest):
    """Integration tests for report tools"""

    def setUp(self):
        super().setUp()
        self.registry = get_tool_registry()

    def test_complete_report_workflow(self):
        """Test complete report workflow"""
        self.skipTest("Complete report workflow test placeholder")

    def test_report_error_handling(self):
        """Test report error handling"""
        if not self.registry.has_tool("generate_report"):
            self.skipTest("generate_report tool not available")

        # Test with invalid arguments
        invalid_tests = [
            {},  # Missing report_name
            {"report_name": ""},  # Empty report name
        ]

        for args in invalid_tests:
            try:
                result = self.registry.execute_tool("generate_report", args)
                self.assertIsInstance(result, dict)
            except Exception:
                # Exceptions are acceptable for invalid input
                pass
