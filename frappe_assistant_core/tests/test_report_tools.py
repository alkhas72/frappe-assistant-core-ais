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
            stack.enter_context(patch.object(report_tools.frappe.db, "exists", return_value=True))
            stack.enter_context(patch.object(report_tools.frappe, "has_permission", return_value=True))
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

    def test_list_reports_ignores_malformed_permission_rows(self):
        """A malformed row from the permission layer must fail closed without
        aborting the complete report discovery response."""
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        with patch.object(report_tools.frappe, "get_list", return_value=[object()]):
            result = report_tools.ReportTools.list_reports()

        self.assertTrue(result.get("success"), result)
        self.assertEqual(result.get("reports"), [])
        self.assertEqual(result.get("count"), 0)

    def test_list_reports_skips_row_when_native_permission_check_errors(self):
        """A row-specific Frappe error fails closed for that report only."""
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        row = {
            "name": "Broken Permission Report",
            "disabled": 0,
            "ref_doctype": "Customer",
        }
        with patch.object(report_tools.frappe, "get_list", return_value=[row]), patch.object(
            report_tools.frappe,
            "has_permission",
            side_effect=AttributeError("test-only permission failure"),
        ):
            result = report_tools.ReportTools.list_reports()

        self.assertTrue(result.get("success"), result)
        self.assertEqual(result.get("reports"), [])
        self.assertEqual(result.get("count"), 0)

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
        report_doc.disabled = 0

        with patch.object(report_tools.frappe, "has_permission", return_value=True), patch(
            "frappe.desk.query_report.get_report_doc", return_value=report_doc
        ), patch(
            "frappe.desk.query_report.run",
            side_effect=AssertionError("restricted-target report must not execute"),
        ) as run:
            result = report_tools.ReportTools.execute_report(report_name="User Report", filters={})

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
        report_doc.disabled = 0

        with patch.object(report_tools.frappe, "has_permission", return_value=True), patch(
            "frappe.desk.query_report.get_report_doc", return_value=report_doc
        ):
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
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        def hidden_get_report_doc(name):
            raise frappe.PermissionError("hidden")

        def missing_get_report_doc(name):
            raise frappe.DoesNotExistError("missing")

        with patch("frappe.desk.query_report.get_report_doc", side_effect=hidden_get_report_doc):
            hidden = report_tools.ReportTools.execute_report("Hidden", {})

        with patch("frappe.desk.query_report.get_report_doc", side_effect=missing_get_report_doc):
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
        report_doc.disabled = 0

        sensitive_message = "secret_value_leaked_in_SQL: password='hunter2'"

        def boom(**kw):
            raise RuntimeError(sensitive_message)

        with patch.object(report_tools.frappe, "has_permission", return_value=True), patch(
            "frappe.desk.query_report.get_report_doc", return_value=report_doc
        ), patch.object(report_tools.frappe, "logger"), patch(
            "frappe.desk.query_report.run", side_effect=boom
        ):
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


# ---------------------------------------------------------------------------
# FAC v2.3 committed regression tests for Task 6/7 hardening.
#
# These tests are bench-runnable (use ``unittest.mock.patch`` against real
# Frappe entry points). Each test is self-contained and does not require a
# live site beyond the BaseAssistantTest bootstrap. When run under
# ``bench run-tests`` they prove the v2.2/v2.3 contracts:
#   * report authorization parity (missing/hidden/disabled/restricted);
#   * prepared-report binding runs BEFORE retrieval on both cached and
#     polling paths;
#   * one safe log record per prepared failure (no exc_info, no secret);
#   * column descriptors in string form classify as sensitive;
#   * nested positional ``doctype`` override cannot downgrade redaction.
# ---------------------------------------------------------------------------


class TestFacV23ReportAuthorization(BaseAssistantTest):
    """Missing, hidden, disabled and restricted-target reports all produce
    the same stable public answer ``"Report not available"``."""

    def _report_doc(self, name="R", ref_doctype="Customer", disabled=0):
        from unittest.mock import MagicMock

        rd = MagicMock()
        rd.name = name
        rd.ref_doctype = ref_doctype
        rd.report_type = "Query Report"
        rd.disabled = disabled
        rd.prepared_report = False
        rd.timeout = 30
        return rd

    def test_missing_report_stable_answer(self):
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        def raises_missing(name):
            raise frappe.DoesNotExistError("missing")

        with patch("frappe.desk.query_report.get_report_doc", side_effect=raises_missing):
            result = report_tools.ReportTools.execute_report("Truly Missing", {})
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Report not available")

    def test_hidden_report_same_answer_as_missing(self):
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        def raises_hidden(name):
            raise frappe.PermissionError("role-hidden")

        def raises_missing(name):
            raise frappe.DoesNotExistError("missing")

        with patch("frappe.desk.query_report.get_report_doc", side_effect=raises_hidden):
            hidden = report_tools.ReportTools.execute_report("Hidden", {})
        with patch("frappe.desk.query_report.get_report_doc", side_effect=raises_missing):
            missing = report_tools.ReportTools.execute_report("Missing", {})

        self.assertEqual(hidden["error"], missing["error"])
        self.assertEqual(hidden["error"], "Report not available")

    def test_disabled_report_same_answer(self):
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        rd = self._report_doc(disabled=1)
        with patch("frappe.desk.query_report.get_report_doc", return_value=rd):
            result = report_tools.ReportTools.execute_report("Disabled", {})
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Report not available")

    def test_restricted_ref_doctype_same_answer_and_no_run(self):
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        rd = self._report_doc(ref_doctype="User")  # restricted
        with patch("frappe.desk.query_report.get_report_doc", return_value=rd), patch(
            "frappe.desk.query_report.run", side_effect=AssertionError("must not execute")
        ) as run:
            result = report_tools.ReportTools.execute_report("R", {})
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Report not available")
        run.assert_not_called()


class TestFacV23PreparedBindingOrder(BaseAssistantTest):
    """FAC v2.3: binding check runs BEFORE retrieval on both cached and
    polling paths. ``get_prepared_report_result`` MUST NOT be called when
    owner or report_name does not match."""

    def _setup_prepared(self, owner_mismatch=True, report_mismatch=False, status="Completed"):
        from unittest.mock import MagicMock

        from frappe_assistant_core.plugins.core.tools import report_tools

        rd = MagicMock()
        rd.name = "Allowed"
        rd.ref_doctype = "Customer"
        rd.report_type = "Query Report"
        rd.disabled = 0
        rd.prepared_report = True
        rd.disable_prepared_report = False
        rd.timeout = 30

        session_user = frappe.session.user
        prepared_doc = MagicMock(
            owner=("someone-else@example.com" if owner_mismatch else session_user),
            report_name=("Other Report" if report_mismatch else "Allowed"),
            status=status,
            modified="2026-08-09",
        )
        return rd, prepared_doc

    def test_cached_path_retrieval_not_called_on_owner_mismatch(self):
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        rd, prepared_doc = self._setup_prepared(owner_mismatch=True)

        with patch.object(report_tools.frappe, "get_doc", return_value=prepared_doc), patch(
            "frappe.core.doctype.prepared_report.prepared_report.get_completed_prepared_report",
            return_value="PR-001",
        ), patch(
            "frappe.desk.query_report.get_prepared_report_result",
            side_effect=AssertionError("get_prepared_report_result must NOT be called on owner mismatch"),
        ) as retrieval:
            result = report_tools.ReportTools._handle_prepared_report_execution(rd, {})

        self.assertFalse(result.get("success"))
        self.assertEqual(result.get("error"), "Prepared report not available")
        retrieval.assert_not_called()

    def test_polling_path_retrieval_not_called_on_report_mismatch(self):
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        rd, prepared_doc = self._setup_prepared(
            owner_mismatch=False,
            report_mismatch=True,
            status="Completed",
        )

        with patch(
            "frappe.core.doctype.prepared_report.prepared_report.get_completed_prepared_report",
            return_value=None,
        ), patch(
            "frappe.core.doctype.prepared_report.prepared_report.make_prepared_report",
            return_value={"name": "PR-POLL"},
        ), patch(
            "frappe.desk.query_report.get_prepared_report_result",
            side_effect=AssertionError("get_prepared_report_result must NOT be called on report mismatch"),
        ) as retrieval, patch.object(report_tools.frappe, "get_value", return_value=60), patch.object(
            report_tools.frappe, "get_doc", return_value=prepared_doc
        ), patch("time.sleep", return_value=None):
            result = report_tools.ReportTools._handle_prepared_report_execution(rd, {})

        self.assertFalse(result.get("success"))
        self.assertEqual(result.get("error"), "Prepared report not available")
        retrieval.assert_not_called()

    def test_outer_execute_preserves_prepared_failure(self):
        """If the prepared helper returns ``{"success": False, ...}`` the
        outer ``execute_report`` MUST propagate it, not re-wrap as success."""
        from unittest.mock import MagicMock, patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        rd = MagicMock()
        rd.name = "Allowed"
        rd.ref_doctype = "Customer"
        rd.report_type = "Query Report"
        rd.disabled = 0
        rd.prepared_report = True
        rd.disable_prepared_report = False
        rd.timeout = 30

        prepared_doc = MagicMock(
            owner="someone-else@example.com",
            report_name="Allowed",
            status="Completed",
            modified="2026-08-09",
        )

        with patch("frappe.desk.query_report.get_report_doc", return_value=rd), patch.object(
            report_tools.frappe, "get_doc", return_value=prepared_doc
        ):
            # Force cached-path entry; prepared_report True routes through
            # the prepared handler.
            from frappe.core.doctype.prepared_report import prepared_report as pr_module

            with patch.object(pr_module, "get_completed_prepared_report", return_value="PR-001"):
                result = report_tools.ReportTools.execute_report("Allowed", {})

        self.assertFalse(result.get("success"))
        self.assertEqual(result.get("error"), "Prepared report not available")


class TestFacV23SingleSafeLogOnPreparedFailure(BaseAssistantTest):
    """One safe log record per prepared failure: helper does NOT log, outer
    ``execute_report`` logs exactly once with no exc_info and no secret."""

    def test_logger_called_once_no_secret_no_exc_info(self):
        from unittest.mock import MagicMock, patch

        from frappe_assistant_core.plugins.core.tools import report_tools

        rd = MagicMock()
        rd.name = "Allowed"
        rd.ref_doctype = "Customer"
        rd.report_type = "Query Report"
        rd.disabled = 0
        rd.prepared_report = True
        rd.disable_prepared_report = False
        rd.timeout = 30

        prepared_doc = MagicMock(
            owner=frappe.session.user,
            report_name="Allowed",
            status="Completed",
            modified="2026-08-09",
        )

        secret = "password='hunter2' in traceback"
        capturing_logger = MagicMock()
        with patch("frappe.desk.query_report.get_report_doc", return_value=rd), patch(
            "frappe.desk.query_report.get_prepared_report_result", side_effect=RuntimeError(secret)
        ), patch.object(report_tools.frappe, "get_doc", return_value=prepared_doc), patch.object(
            report_tools.frappe, "has_permission", return_value=True
        ), patch.object(report_tools.frappe, "logger", return_value=capturing_logger):
            from frappe.core.doctype.prepared_report import prepared_report as pr_module

            with patch.object(pr_module, "get_completed_prepared_report", return_value="PR-001"):
                result = report_tools.ReportTools.execute_report("Allowed", {})

        self.assertFalse(result.get("success"))
        self.assertEqual(result.get("error"), "Report execution failed")
        self.assertEqual(capturing_logger.warning.call_count, 1)
        for call in capturing_logger.warning.call_args_list:
            args, kwargs = call
            self.assertNotIn("exc_info", kwargs)
            joined = " ".join(str(a) for a in args)
            self.assertNotIn("hunter2", joined)


class TestFacV23ColumnDescriptors(BaseAssistantTest):
    """FAC v2.3: string-form column descriptors classify as sensitive."""

    def _redact(self, columns, ref_doctype="Customer"):
        from frappe_assistant_core.plugins.core.tools.report_tools import ReportTools

        debug = {"data": [["x"]], "columns": columns}
        return ReportTools._redact_report_output(debug, ref_doctype)

    def test_password_string_descriptor(self):
        out = self._redact(["password:Data:120"])
        self.assertEqual(out["columns"], [])

    def test_api_key_string_descriptor(self):
        out = self._redact(["api_key:Data:120"])
        self.assertEqual(out["columns"], [])

    def test_encryption_key_string_descriptor(self):
        out = self._redact(["encryption_key:Data:120"])
        self.assertEqual(out["columns"], [])

    def test_api_key_with_spaces_string_descriptor(self):
        # "API Key:Data:120" → label "API Key" → "api_key"
        out = self._redact(["API Key:Data:120"])
        self.assertEqual(out["columns"], [])

    def test_login_after_string_descriptor_for_user(self):
        # login_after is sensitive specifically for User
        out = self._redact(["login_after:Data:120"], ref_doctype="User")
        self.assertEqual(out["columns"], [])

    def test_non_sensitive_string_descriptor_kept(self):
        out = self._redact(["customer_name:Data:120"])
        self.assertEqual(out["columns"], ["customer_name:Data:120"])


class TestFacV23NestedPositionalDoctype(BaseAssistantTest):
    """FAC v2.3: positional cells (list/tuple) cannot carry a malicious
    nested ``doctype`` to downgrade ref_doctype redaction."""

    def test_list_cell_with_nested_doctype_stripped(self):
        from frappe_assistant_core.plugins.core.tools.report_tools import ReportTools

        debug = {
            "data": [
                [
                    "C1",
                    {"doctype": "Customer", "connected_user": "secret-leak"},
                ]
            ],
            "columns": [
                {"fieldname": "name"},
                {"fieldname": "metadata"},
            ],
        }
        out = ReportTools._redact_report_output(debug, "Email Account")
        # Email Account: connected_user is sensitive → redacted in nested cell.
        nested = out["data"][0][1]
        self.assertNotIn("doctype", nested)
        self.assertEqual(nested["connected_user"], "***REDACTED***")

    def test_tuple_cell_with_nested_doctype_stripped(self):
        from frappe_assistant_core.plugins.core.tools.report_tools import ReportTools

        debug = {
            "data": [
                (
                    "C1",
                    {"doctype": "Customer", "auth_method": "Bearer secret"},
                )
            ],
            "columns": [
                {"fieldname": "name"},
                {"fieldname": "metadata"},
            ],
        }
        out = ReportTools._redact_report_output(debug, "Email Account")
        row = out["data"][0]
        self.assertIsInstance(row, tuple)
        nested = row[1]
        self.assertNotIn("doctype", nested)
        self.assertEqual(nested["auth_method"], "***REDACTED***")
