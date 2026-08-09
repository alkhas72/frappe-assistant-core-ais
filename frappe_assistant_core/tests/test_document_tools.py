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
Test suite for Document Tools using Plugin Architecture
Tests document operations through the tool registry
"""

import json
import sys
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import frappe

from frappe_assistant_core.core.security_policy import PolicyDenied
from frappe_assistant_core.core.tool_registry import get_tool_registry
from frappe_assistant_core.tests.base_test import BaseAssistantTest
from frappe_assistant_core.tests.legacy_tool_test_support import legacy_tool_registry_access


class TestDocumentTools(BaseAssistantTest):
    """Test document tools through plugin registry"""

    def setUp(self):
        super().setUp()
        self.registry = get_tool_registry()
        self.test_doctype = "ToDo"  # Safe test doctype that always exists

    def test_get_tools_structure(self):
        """Test that document tools are properly registered"""
        document_tools = [
            "create_document",
            "get_document",
            "update_document",
            "list_documents",
        ]
        with legacy_tool_registry_access(document_tools):
            tools = self.registry.get_available_tools()
            tool_names = [tool["name"] for tool in tools]

            expected_tools = [
                "create_document",
                "get_document",
                "update_document",
                "list_documents",
                "delete_document",
            ]
            found_tools = [tool for tool in expected_tools if tool in tool_names]

            self.assertGreater(len(found_tools), 0, f"Should find document tools. Available: {tool_names}")

    def test_create_document_basic(self):
        """Test basic document creation"""
        with legacy_tool_registry_access(["create_document"]):
            if not self.registry.has_tool("create_document"):
                self.skipTest("create_document tool not available")

            # Test with minimal valid data
            arguments = {
                "doctype": self.test_doctype,
                "data": {"description": "Test ToDo created by test suite"},
            }

            try:
                result = self.registry.execute_tool("create_document", arguments)
                self.assertIsInstance(result, dict)

                # Should have success status
                if "success" in result:
                    if result.get("success"):
                        # New format: name is directly in result, not nested under "data"
                        self.assertIn("name", result)
                    else:
                        # Failed creation should have error message
                        self.assertIn("error", result)
            except Exception as e:
                # Tool execution should not raise unhandled exceptions
                self.fail(f"Tool execution raised exception: {str(e)}")

    def test_get_document_basic(self):
        """Test basic document retrieval"""
        with legacy_tool_registry_access(["get_document"]):
            if not self.registry.has_tool("get_document"):
                self.skipTest("get_document tool not available")

            test_doc = frappe.get_doc(
                {"doctype": self.test_doctype, "description": "Safe get_document test"}
            ).insert(ignore_permissions=True)
            arguments = {"doctype": self.test_doctype, "name": test_doc.name}

            try:
                result = self.registry.execute_tool("get_document", arguments)
                self.assertIsInstance(result, dict)

                if "success" in result and result.get("success"):
                    # Document data is directly in result for successful gets
                    self.assertIn("name", result)
                    self.assertEqual(result["name"], test_doc.name)
            except Exception as e:
                self.fail(f"Tool execution raised exception: {str(e)}")
            finally:
                frappe.delete_doc(self.test_doctype, test_doc.name, force=True)

    def test_list_documents_via_execute_tool(self):
        """Test document listing"""
        with legacy_tool_registry_access(["list_documents"]):
            if not self.registry.has_tool("list_documents"):
                self.skipTest("list_documents tool not available")

            arguments = {
                "doctype": self.test_doctype,
                "limit": 5,
                "fields": ["name", "description"],
            }

            try:
                result = self.registry.execute_tool("list_documents", arguments)
                self.assertIsInstance(result, dict)

                if "success" in result and result.get("success"):
                    # For list_documents, check if we have documents or results key
                    if "documents" in result:
                        self.assertIsInstance(result["documents"], list)
                        if result["documents"]:
                            for doc in result["documents"]:
                                self.assertIn("name", doc)
                    elif "results" in result:
                        self.assertIsInstance(result["results"], list)
                        if result["results"]:
                            for doc in result["results"]:
                                self.assertIn("name", doc)
            except Exception as e:
                self.fail(f"Tool execution raised exception: {str(e)}")

    def test_list_documents_uses_permission_aware_queries_for_data_and_count(self):
        """Regression guard for #189: list_documents must not use permission-bypassing APIs."""
        from frappe_assistant_core.plugins.core.tools.list_documents import DocumentList

        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "frappe_assistant_core.core.security_config.validate_document_access",
                    return_value={"success": True, "role": "Default"},
                )
            )
            stack.enter_context(
                patch(
                    "frappe_assistant_core.core.security_config.filter_sensitive_fields",
                    side_effect=lambda doc, _doctype, _role: doc,
                )
            )
            stack.enter_context(
                patch(
                    "frappe_assistant_core.plugins.core.tools.list_documents.frappe.session",
                    MagicMock(user="restricted@example.com"),
                )
            )
            get_all = stack.enter_context(
                patch(
                    "frappe_assistant_core.plugins.core.tools.list_documents.frappe.get_all",
                    side_effect=AssertionError("frappe.get_all bypasses DocType permissions"),
                )
            )
            db_count = stack.enter_context(
                patch(
                    "frappe_assistant_core.plugins.core.tools.list_documents.frappe.db.count",
                    side_effect=AssertionError("frappe.db.count bypasses DocType permissions"),
                )
            )
            get_list = stack.enter_context(
                patch("frappe_assistant_core.plugins.core.tools.list_documents.frappe.get_list")
            )
            get_list.side_effect = [
                [{"name": "EMP-0001", "employee_name": "Allowed Employee"}],
                [{"count": 1}],
            ]

            result = DocumentList().execute(
                {
                    "doctype": "Employee",
                    "filters": {},
                    "fields": ["name", "employee_name"],
                    "limit": 20,
                }
            )

        self.assertTrue(result.get("success"), result)
        self.assertEqual(result.get("count"), 1)
        self.assertEqual(result.get("total_count"), 1)
        get_all.assert_not_called()
        db_count.assert_not_called()
        self.assertEqual(get_list.call_count, 2)

        data_call = get_list.call_args_list[0]
        self.assertEqual(data_call.args[0], "Employee")
        self.assertEqual(data_call.kwargs["fields"], ["name", "employee_name"])
        self.assertEqual(data_call.kwargs["limit"], 20)
        self.assertFalse(data_call.kwargs["ignore_permissions"])

        count_call = get_list.call_args_list[1]
        self.assertEqual(count_call.args[0], "Employee")
        self.assertEqual(count_call.kwargs["fields"], [{"COUNT": "name", "as": "count"}])
        self.assertEqual(count_call.kwargs["limit"], 1)
        self.assertFalse(count_call.kwargs["ignore_permissions"])

    def test_list_documents_count_falls_back_to_legacy_aggregate_syntax(self):
        """Frappe 15 does not support dict aggregate fields."""
        from frappe_assistant_core.plugins.core.tools.list_documents import DocumentList

        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "frappe_assistant_core.core.security_config.validate_document_access",
                    return_value={"success": True, "role": "Default"},
                )
            )
            stack.enter_context(
                patch(
                    "frappe_assistant_core.core.security_config.filter_sensitive_fields",
                    side_effect=lambda doc, _doctype, _role: doc,
                )
            )
            stack.enter_context(
                patch(
                    "frappe_assistant_core.plugins.core.tools.list_documents.frappe.session",
                    MagicMock(user="restricted@example.com"),
                )
            )
            get_list = stack.enter_context(
                patch("frappe_assistant_core.plugins.core.tools.list_documents.frappe.get_list")
            )
            get_list.side_effect = [
                [{"name": "EMP-0001", "employee_name": "Allowed Employee"}],
                AttributeError("'dict' object has no attribute 'lower'"),
                [{"count": 1}],
            ]

            result = DocumentList().execute(
                {
                    "doctype": "Employee",
                    "filters": {},
                    "fields": ["name", "employee_name"],
                    "limit": 20,
                }
            )

        self.assertTrue(result.get("success"), result)
        self.assertEqual(result.get("total_count"), 1)
        self.assertEqual(get_list.call_count, 3)

        fallback_count_call = get_list.call_args_list[2]
        self.assertEqual(fallback_count_call.args[0], "Employee")
        self.assertEqual(fallback_count_call.kwargs["fields"], ["count(name) as count"])
        self.assertEqual(fallback_count_call.kwargs["limit"], 1)
        self.assertFalse(fallback_count_call.kwargs["ignore_permissions"])

    def test_update_document_basic(self):
        """Test basic document update"""
        with legacy_tool_registry_access(["create_document", "update_document"]):
            if not self.registry.has_tool("update_document"):
                self.skipTest("update_document tool not available")

            # Create a test document first
            if self.registry.has_tool("create_document"):
                create_args = {"doctype": self.test_doctype, "data": {"description": "Test ToDo for update"}}
                create_result = self.registry.execute_tool("create_document", create_args)

                if create_result.get("success") and "name" in create_result:
                    doc_name = create_result["name"]

                    # Now update it
                    update_args = {
                        "doctype": self.test_doctype,
                        "name": doc_name,
                        "data": {"description": "Updated description"},
                    }

                    try:
                        result = self.registry.execute_tool("update_document", update_args)
                        self.assertIsInstance(result, dict)
                    except Exception as e:
                        self.fail(f"Update tool execution raised exception: {str(e)}")

    def test_execute_tool_routing(self):
        """Test that tool routing works correctly"""
        # This should pass for any available tool
        tools = self.registry.get_available_tools()
        if tools:
            # Just test that we can call the registry without errors
            self.assertTrue(hasattr(self.registry, "execute_tool"))
            self.assertTrue(hasattr(self.registry, "get_available_tools"))

    def test_execute_tool_invalid_tool(self):
        """Test handling of invalid tool names"""
        with self.assertRaises(PolicyDenied) as raised:
            self.registry.execute_tool("nonexistent_tool", {})
        self.assertEqual(raised.exception.reason_code, "TOOL_UNKNOWN")

    def test_create_document_with_submit(self):
        """Test document creation with submission"""
        with legacy_tool_registry_access(["create_document"]):
            if not self.registry.has_tool("create_document"):
                self.skipTest("create_document tool not available")

            # Use a simple doctype for testing
            arguments = {
                "doctype": self.test_doctype,
                "data": {"description": "Test ToDo with submit"},
                "submit": False,  # Don't actually submit, just test the parameter
            }

            try:
                result = self.registry.execute_tool("create_document", arguments)
                self.assertIsInstance(result, dict)
            except Exception as e:
                self.fail(f"Tool execution with submit raised exception: {str(e)}")

    def test_create_document_no_permission(self):
        """Test document creation without permission"""
        if not self.registry.has_tool("create_document"):
            self.skipTest("create_document tool not available")

        # Try to create document in a restricted doctype
        with patch("frappe.set_user") as mock_set_user:
            mock_set_user.return_value = None
            frappe.session.user = "Guest"  # Guest has limited permissions

            arguments = {
                "doctype": "User",  # Restricted doctype
                "data": {"email": "test@example.com"},
            }

            try:
                result = self.registry.execute_tool("create_document", arguments)
                self.assertIsInstance(result, dict)
                # Should fail with permission error
                if "success" in result:
                    self.assertFalse(result["success"], "Should fail due to permissions")
            except Exception:
                # Permission exceptions are acceptable
                pass

    def test_get_document_no_permission(self):
        """Test document retrieval without permission"""
        if not self.registry.has_tool("get_document"):
            self.skipTest("get_document tool not available")

        # This test might not be meaningful if Guest can read basic doctypes
        # But we test the error handling path
        arguments = {"doctype": "User", "name": "Administrator"}

        try:
            result = self.registry.execute_tool("get_document", arguments)
            self.assertIsInstance(result, dict)
        except Exception:
            # Permission exceptions are acceptable in tests
            pass

    def test_get_document_nonexistent(self):
        """Test getting a nonexistent document"""
        if not self.registry.has_tool("get_document"):
            self.skipTest("get_document tool not available")

        arguments = {"doctype": self.test_doctype, "name": "NONEXISTENT-DOC-12345"}

        try:
            result = self.registry.execute_tool("get_document", arguments)
            self.assertIsInstance(result, dict)
            # Should return error, not crash
            if "success" in result:
                self.assertFalse(result["success"], "Should fail for nonexistent document")
        except Exception:
            # DoesNotExistError is acceptable
            pass

    def test_update_document_no_permission(self):
        """Test document update without permission"""
        if not self.registry.has_tool("update_document"):
            self.skipTest("update_document tool not available")

        arguments = {
            "doctype": "User",  # Restricted doctype
            "name": "Administrator",
            "data": {"full_name": "Should Not Update"},
        }

        try:
            result = self.registry.execute_tool("update_document", arguments)
            self.assertIsInstance(result, dict)
        except Exception:
            # Permission exceptions are acceptable
            pass

    def test_create_document_no_false_positive_for_set_missing_values_fields(self):
        """Issue #165 follow-up: fields populated by Frappe's set_missing_values()
        during validate() must not be flagged as missing.

        Quotation has reqd fields (conversion_rate, price_list_currency,
        plc_conversion_rate) that new_doc() does NOT populate — they're filled
        by the doctype controller's set_missing_values() during validate(),
        which runs inside doc.insert(). A pre-flight check that inspects
        doc.get(f) before insert() returns false positives for these.
        """
        from frappe_assistant_core.plugins.core.tools.create_document import DocumentCreate

        if not frappe.db.exists("DocType", "Quotation"):
            self.skipTest("Quotation doctype not available (ERPNext not installed)")

        cust = frappe.get_all("Customer", limit=1, pluck="name")
        item = frappe.get_all("Item", filters={"is_sales_item": 1, "disabled": 0}, limit=1, pluck="name")
        if not (cust and item):
            self.skipTest("No Customer/Item available for test")

        result = DocumentCreate().execute(
            {
                "doctype": "Quotation",
                "data": {
                    "quotation_to": "Customer",
                    "party_name": cust[0],
                    "transaction_date": frappe.utils.nowdate(),
                    "items": [{"item_code": item[0], "qty": 1, "rate": 100}],
                },
            }
        )

        # Whichever way it lands (success, or genuine missing field like
        # enquiry_reference per site config), it must NOT report any of the
        # set_missing_values()-populated fields as missing.
        false_positives = {"conversion_rate", "price_list_currency", "plc_conversion_rate"}
        if not result.get("success"):
            missing = set(result.get("missing_fields") or [])
            leaked = missing & false_positives
            self.assertFalse(
                leaked,
                f"set_missing_values() fields incorrectly reported as missing: {leaked}. "
                f"Full error: {result.get('error')}",
            )
            # If it failed, it must be for a different (genuine) reason.
            if missing:
                # Genuine missing field is fine — the structured error shape
                # is the contract here.
                self.assertEqual(result.get("error_type"), "missing_required_field")
                self.assertIn("provided_fields", result)
                self.assertIn("suggestion", result)
        else:
            # Cleanup if the create actually succeeded.
            try:
                frappe.delete_doc("Quotation", result["name"], ignore_permissions=True, force=True)
                frappe.db.commit()
            except Exception:
                pass

    def test_create_document_mandatory_error_returns_structured_response(self):
        """When Frappe raises MandatoryError, the tool returns the structured
        missing-fields response (not a raw error string).

        ToDo has a single mandatory field (`description`) that is NOT populated
        by set_missing_values, so omitting it reliably triggers MandatoryError
        across sites.
        """
        from frappe_assistant_core.plugins.core.tools.create_document import DocumentCreate

        result = DocumentCreate().execute(
            {
                "doctype": "ToDo",
                "data": {"date": frappe.utils.nowdate()},
            }
        )

        self.assertIsInstance(result, dict)
        self.assertFalse(result.get("success"), f"ToDo create with no description should fail: {result}")
        self.assertEqual(result.get("error_type"), "missing_required_field")
        self.assertIn("description", result.get("missing_fields") or [])
        self.assertEqual(result.get("provided_fields"), ["date"])
        self.assertIn("suggestion", result)

    def test_create_document_generic_exception_does_not_crash_on_translation(self):
        """Regression guard: the local `_, _, fields_part = ...` shadow bug.

        `_` is the translation function imported at module scope. Any local
        `_ = ...` inside execute() makes Python treat `_` as a function-local
        for the entire body, so the later `_("Document Creation Error")` call
        inside frappe.log_error raised UnboundLocalError on paths that didn't
        reach the local assignment first (e.g. the generic Exception branch
        triggered by an invalid Link reference, not by MandatoryError).

        Triggering: pass an invalid `reference_type` link value to ToDo. This
        raises a LinkValidationError (subclass of ValidationError, not
        MandatoryError), routes through the generic `except Exception`, and
        attempts to call `_(\"...\")` for log_error. The test asserts the call
        completes and returns a structured dict, never an UnboundLocalError.
        """
        from frappe_assistant_core.plugins.core.tools.create_document import DocumentCreate

        result = DocumentCreate().execute(
            {
                "doctype": "ToDo",
                "data": {
                    "description": "regression probe",
                    "reference_type": "User",
                    "reference_name": "this-user-definitely-does-not-exist@nowhere.invalid",
                },
            }
        )

        self.assertIsInstance(result, dict)
        # The call must NOT crash with UnboundLocalError no matter what error
        # path is taken. If the create somehow succeeded, that's also fine —
        # the test exists to guard the error path, not to assert a specific
        # validation outcome.
        if not result.get("success"):
            error_msg = str(result.get("error") or "")
            self.assertNotIn("referenced before assignment", error_msg)
            self.assertNotIn("UnboundLocalError", error_msg)
            self.assertIn("error_type", result)
        else:
            # Cleanup if create unexpectedly succeeded.
            try:
                frappe.delete_doc("ToDo", result["name"], ignore_permissions=True, force=True)
                frappe.db.commit()
            except Exception:
                pass

    def test_update_document_rejects_child_doctype(self):
        """Direct updates to a child-table doctype must be rejected with a clear suggestion.

        Saving a child row in isolation bypasses the parent's validate() pipeline,
        leaving parent totals (grand_total, total_qty, etc.) stale. The tool should
        refuse and point the caller at the parent doc.

        The tool registry raises on success=False results, so we exercise the tool
        class directly to inspect the structured error payload.
        """
        from frappe_assistant_core.plugins.core.tools.update_document import DocumentUpdate

        # "DocField" is a built-in child of "DocType" — guaranteed to exist.
        if not frappe.db.exists("DocType", "DocField"):
            self.skipTest("DocField doctype not available in this site")

        existing = frappe.db.get_all("DocField", limit=1, fields=["name"])
        row_name = existing[0].name if existing else "nonexistent-row"

        result = DocumentUpdate().execute(
            {
                "doctype": "DocField",
                "name": row_name,
                "data": {"label": "Should Be Rejected"},
            }
        )

        self.assertIsInstance(result, dict)
        self.assertFalse(result.get("success"))
        self.assertEqual(result.get("error_type"), "child_doctype_direct_update")
        self.assertEqual(result.get("child_doctype"), "DocField")
        # When the row exists we should get parent-resolution hints back.
        if existing:
            self.assertIn("parent_doctype", result)
            self.assertIn("parent_name", result)
            self.assertIn("parent_table_fieldname", result)
            self.assertIn("suggestion", result)


class TestFetchToolRedaction(BaseAssistantTest):
    """FAC security hardening Task 6 (2026-08-09).

    The ChatGPT-compatible ``fetch`` tool used to call
    ``security_config.validate_document_access`` + ``filter_sensitive_fields``,
    both of which granted a ``System Manager`` bypass and superseded the
    central policy. It now relies on the central decision (already taken in
    ``BaseTool._safe_execute``) plus a native row-level read check, and runs
    ``SecurityPolicy.redact_output`` locally before serialising the document to
    a JSON-string ``text`` (which the central sink treats as opaque).

    These guards prove:
      * Sensitive keys nested inside the returned document are redacted for
        every actor, including System Manager.
      * The legacy ``security_config`` shims no longer carry a System Manager
        wildcard (matrix retirement).
    """

    def test_filter_sensitive_fields_redacts_for_system_manager(self):
        """``filter_sensitive_fields`` used to return the dict unchanged for
        ``System Manager``. After retirement it must apply universal sensitive
        fields to every caller."""
        from frappe_assistant_core.core.security_config import filter_sensitive_fields

        doc = {
            "name": "USR-001",
            "password": "hunter2",
            "api_key": "sk-leak",
            "email": "user@example.com",
        }

        redacted = filter_sensitive_fields(doc, "User", "System Manager")

        self.assertEqual(redacted["name"], "USR-001")
        self.assertEqual(redacted["email"], "user@example.com")
        self.assertEqual(redacted["password"], "***RESTRICTED***")
        self.assertEqual(redacted["api_key"], "***RESTRICTED***")

    def test_validate_document_access_denies_restricted_doctype_for_system_manager(self):
        """A System Manager must NOT pass ``validate_document_access`` for a
        restricted DocType (e.g. ``User``). Previously the matrix let SM
        through; the retired shim must fail-closed."""
        from contextlib import ExitStack
        from unittest.mock import patch

        from frappe_assistant_core.core.security_config import validate_document_access

        with ExitStack() as stack:
            # Pretend Frappe thinks the user has every permission. The
            # restricted-target gate is what must deny, not the native check.
            stack.enter_context(
                patch(
                    "frappe_assistant_core.core.security_config.frappe.has_permission",
                    return_value=True,
                )
            )
            stack.enter_context(
                patch(
                    "frappe_assistant_core.core.security_config.frappe.get_roles",
                    return_value=["System Manager"],
                )
            )

            result = validate_document_access(
                user="admin@example.com",
                doctype="User",
                name="admin@example.com",
                perm_type="read",
            )

        self.assertFalse(result.get("success"), result)
        self.assertIn("restricted", (result.get("error") or "").lower())

    def test_check_tool_access_is_fail_closed_for_system_manager(self):
        """``check_tool_access`` must never authorize anything post-retirement.

        The legacy matrix granted ``System Manager`` an ``*`` wildcard and
        allowed lists that included hard-denied legacy aliases. The function is
        now a backwards-compat shim that returns ``False`` unconditionally.
        """
        from frappe_assistant_core.core.security_config import check_tool_access

        # Even the most permissive sounding combinations must fail closed.
        self.assertFalse(check_tool_access("System Manager", "get_document"))
        self.assertFalse(check_tool_access("System Manager", "delete_document"))
        self.assertFalse(check_tool_access("System Manager", "run_python_code"))
        # Legacy aliases that used to be in the allowed list.
        self.assertFalse(check_tool_access("System Manager", "execute_python_code"))
        self.assertFalse(check_tool_access("System Manager", "metadata_permissions"))

    def test_is_doctype_accessible_has_no_system_manager_bypass(self):
        """``is_doctype_accessible("User", "System Manager")`` must return False.

        Restricted DocType set is authoritative; role cannot override it.
        """
        from unittest.mock import patch

        from frappe_assistant_core.core.security_config import is_doctype_accessible

        with patch("frappe_assistant_core.core.security_config.frappe.get_meta") as get_meta:
            # Restricted parent (User) is checked before meta is consulted, so
            # the meta mock is just defensive.
            get_meta.return_value.istable = False

            self.assertFalse(is_doctype_accessible("User", "System Manager"))
            self.assertFalse(is_doctype_accessible("DocType", "System Manager"))
            self.assertFalse(is_doctype_accessible("File", "System Manager"))
            # Child tables (any istable=1 DocType) are also not "accessible".
            get_meta.return_value.istable = True
            self.assertFalse(is_doctype_accessible("Has Role", "System Manager"))


class TestSecurityConfigLegacyCompat(BaseAssistantTest):
    """FAC v2.1 (2026-08-09).

    ``security_config`` keeps ``BASIC_CORE_TOOLS``, ``ROLE_TOOL_ACCESS`` and
    the dict-form ``RESTRICTED_DOCTYPES`` for backwards-compatibility with
    legacy imports. A naive empty dict for ``RESTRICTED_DOCTYPES`` is
    fail-OPEN: a legacy caller doing
    ``doctype in RESTRICTED_DOCTYPES.get(role, [])`` would get ``[]`` and
    conclude "not restricted" for a DocType the canonical policy in fact
    restricts. The export must remain fail-closed — every role key resolves
    to the canonical restricted set, derived lazily from
    ``SecurityPolicy.RESTRICTED_DOCTYPES``.
    """

    def test_legacy_restricted_doctypes_dict_proves_canonical(self):
        """Every role key returns the canonical restricted set, not ``[]``."""
        from frappe_assistant_core.core import security_config
        from frappe_assistant_core.core.security_policy import RESTRICTED_DOCTYPES as canonical

        for role in ("Assistant User", "Assistant Admin", "System Manager", "Default"):
            legacy_list = security_config.RESTRICTED_DOCTYPES.get(role, [])
            # Each known restricted DocType must appear in the legacy list.
            self.assertIn("User", legacy_list, f"role={role}")
            self.assertIn("DocType", legacy_list, f"role={role}")
            self.assertIn("File", legacy_list, f"role={role}")
            # And the legacy list must equal the canonical set (as a sorted
            # list), proving there is no second hand-maintained table.
            self.assertEqual(set(legacy_list), set(canonical))

    def test_legacy_restricted_doctypes_unknown_role_fails_closed(self):
        """An unknown role key still returns the canonical restricted set,
        never the empty default."""
        from frappe_assistant_core.core import security_config

        legacy_list = security_config.RESTRICTED_DOCTYPES.get("Unknown Role XYZ", [])
        self.assertIn("User", legacy_list)

    def test_legacy_basic_core_tools_and_role_tool_access_inert(self):
        """``BASIC_CORE_TOOLS`` and ``ROLE_TOOL_ACCESS`` cannot authorize
        anything — they are empty and cannot form an alternative allow
        system."""
        from frappe_assistant_core.core import security_config

        self.assertEqual(security_config.BASIC_CORE_TOOLS, ())
        self.assertEqual(dict(security_config.ROLE_TOOL_ACCESS), {})


class TestFetchRestrictedTargetDirectCall(BaseAssistantTest):
    """FAC Task 7 rev. 2 (2026-08-09).

    Central policy closes the MCP path, but a direct call into
    ``ChatGPTFetch.execute`` from privileged internal code could previously
    pass ``frappe.has_permission`` (System Manager has read on restricted
    DocTypes) and reach ``frappe.get_doc``. The restricted-target gate must
    fire BEFORE ``has_permission`` / ``get_doc`` for every restricted DocType —
    ``User``, ``File``, and FAC configuration DocTypes alike — and the
    external response must not distinguish them from one another.
    """

    def _assert_restricted_refused(self, doctype, name):
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools.chatgpt_fetch import ChatGPTFetch

        tool = ChatGPTFetch()
        # If the gate fails, has_permission returns True (privileged) and
        # get_doc would leak the restricted document.
        with patch(
            "frappe_assistant_core.plugins.core.tools.chatgpt_fetch.frappe.has_permission",
            return_value=True,
        ), patch(
            "frappe_assistant_core.plugins.core.tools.chatgpt_fetch.frappe.get_doc",
            side_effect=AssertionError(f"restricted target {doctype} must not reach frappe.get_doc"),
        ):
            try:
                tool.execute({"id": f"{doctype}/{name}"})
                self.fail(f"ChatGPTFetch.execute for restricted DocType {doctype} did not raise")
            except frappe.PermissionError:
                # Expected: same "Permission denied" answer for every
                # restricted target, regardless of which one was hit.
                pass

    def test_fetch_user_target_refused_directly(self):
        self._assert_restricted_refused("User", "admin@example.com")

    def test_fetch_file_target_refused_directly(self):
        self._assert_restricted_refused("File", "FILE-LEAK")

    def test_fetch_fac_tool_configuration_target_refused_directly(self):
        self._assert_restricted_refused("FAC Tool Configuration", "get_document")

    def test_fetch_fac_plugin_configuration_target_refused_directly(self):
        self._assert_restricted_refused("FAC Plugin Configuration", "core")

    def test_fetch_restricted_targets_indistinguishable(self):
        """All restricted targets must yield the same external answer so the
        response itself cannot be used to enumerate restricted DocTypes."""
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools.chatgpt_fetch import ChatGPTFetch

        tool = ChatGPTFetch()
        messages = []
        for doctype, name in [
            ("User", "admin@example.com"),
            ("File", "FILE-LEAK"),
            ("FAC Tool Configuration", "get_document"),
        ]:
            with patch(
                "frappe_assistant_core.plugins.core.tools.chatgpt_fetch.frappe.has_permission",
                return_value=True,
            ), patch(
                "frappe_assistant_core.plugins.core.tools.chatgpt_fetch.frappe.get_doc",
                side_effect=AssertionError("must not be reached"),
            ):
                try:
                    tool.execute({"id": f"{doctype}/{name}"})
                    msg = "no-exception"
                except frappe.PermissionError as e:
                    msg = str(e)
            messages.append(msg)
        # All three must produce identical external answers.
        self.assertEqual(messages[0], messages[1])
        self.assertEqual(messages[1], messages[2])
        self.assertNotEqual(messages[0], "no-exception")


class TestDocumentToolsIntegration(BaseAssistantTest):
    """Integration tests for document tools"""

    def setUp(self):
        super().setUp()
        self.registry = get_tool_registry()

    def test_document_lifecycle(self):
        """Test complete document lifecycle"""
        lifecycle_tools = ["create_document", "get_document", "update_document"]
        with legacy_tool_registry_access(lifecycle_tools):
            if not all(self.registry.has_tool(tool) for tool in lifecycle_tools):
                self.skipTest("Required document tools not available")

            doctype = "ToDo"

            # Create
            create_args = {"doctype": doctype, "data": {"description": "Lifecycle test document"}}

            try:
                create_result = self.registry.execute_tool("create_document", create_args)

                if not (create_result.get("success") and "name" in create_result):
                    self.skipTest("Could not create test document")

                doc_name = create_result["name"]

                # Read
                get_args = {"doctype": doctype, "name": doc_name}
                get_result = self.registry.execute_tool("get_document", get_args)

                if get_result.get("success"):
                    self.assertEqual(get_result["name"], doc_name)

                # Update
                update_args = {
                    "doctype": doctype,
                    "name": doc_name,
                    "data": {"description": "Updated description"},
                }
                update_result = self.registry.execute_tool("update_document", update_args)
                self.assertIsInstance(update_result, dict)

            except Exception as e:
                self.fail(f"Document lifecycle test failed: {str(e)}")

    def test_error_handling_scenarios(self):
        """Test various error scenarios"""
        # Test with invalid arguments
        invalid_tests = [
            ("create_document", {}),  # Missing required fields
            ("get_document", {"doctype": "User"}),  # Missing name
            ("list_documents", {}),  # Missing doctype
        ]

        for tool_name, args in invalid_tests:
            if self.registry.has_tool(tool_name):
                try:
                    result = self.registry.execute_tool(tool_name, args)
                    # Should return error dict, not crash
                    self.assertIsInstance(result, dict)
                except Exception:
                    # Exceptions are also acceptable for invalid input
                    pass


class _FakeChildRow:
    """Stand-in for a Frappe child docrow. Captures field updates and a stable name."""

    def __init__(self, name=None, **fields):
        self.name = name
        for k, v in fields.items():
            setattr(self, k, v)

    def set(self, key, value):
        setattr(self, key, value)


class _FakeDoc:
    """Stand-in for a Frappe parent doc. Holds named child-table lists and supports
    the subset of the doc API used by _apply_child_table_update."""

    def __init__(self, tables):
        # tables: dict[fieldname] -> list[_FakeChildRow]
        self._tables = {k: list(v) for k, v in tables.items()}

    def get(self, field):
        return self._tables.get(field)

    def set(self, field, value):
        self._tables[field] = list(value)

    def append(self, field, row_data):
        # Mirror Frappe's behavior: append a new row built from a dict.
        if not isinstance(row_data, dict):
            raise TypeError(f"append expected dict, got {type(row_data).__name__}")
        # Strip control keys before constructing the row.
        clean = {k: v for k, v in row_data.items() if k not in ("_delete",)}
        new_row = _FakeChildRow(**clean)
        self._tables.setdefault(field, []).append(new_row)
        return new_row

    def remove(self, row):
        for rows in self._tables.values():
            if row in rows:
                rows.remove(row)
                return
        raise ValueError("row not found in any table")


class TestApplyChildTableUpdate(unittest.TestCase):
    """Unit tests for _apply_child_table_update — DB-independent."""

    def _import_helper(self):
        from frappe_assistant_core.plugins.core.tools.update_document import (
            _apply_child_table_update,
        )

        return _apply_child_table_update

    def test_replace_mode_clears_and_appends(self):
        helper = self._import_helper()
        doc = _FakeDoc(
            {
                "items": [
                    _FakeChildRow(name="r1", item_code="OLD-A", qty=1),
                    _FakeChildRow(name="r2", item_code="OLD-B", qty=2),
                ]
            }
        )
        rows = [{"item_code": "NEW-A", "qty": 10}, {"item_code": "NEW-B", "qty": 20}]

        err = helper(doc, "items", "Sales Order Item", rows, set())

        self.assertIsNone(err)
        items = doc.get("items")
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].item_code, "NEW-A")
        self.assertEqual(items[0].qty, 10)
        self.assertEqual(items[1].item_code, "NEW-B")
        # No retained rows from before.
        self.assertNotIn("OLD-A", [getattr(r, "item_code", None) for r in items])

    def test_patch_mode_updates_matched_row_leaves_others(self):
        helper = self._import_helper()
        doc = _FakeDoc(
            {
                "items": [
                    _FakeChildRow(name="r1", item_code="A", qty=1),
                    _FakeChildRow(name="r2", item_code="B", qty=2),
                ]
            }
        )

        err = helper(doc, "items", "Sales Order Item", [{"name": "r1", "qty": 99}], set())

        self.assertIsNone(err)
        items = doc.get("items")
        self.assertEqual(len(items), 2)
        r1 = next(r for r in items if r.name == "r1")
        r2 = next(r for r in items if r.name == "r2")
        self.assertEqual(r1.qty, 99)
        self.assertEqual(r1.item_code, "A")  # untouched scalar preserved
        self.assertEqual(r2.qty, 2)  # other row untouched
        self.assertEqual(r2.item_code, "B")

    def test_patch_mode_appends_unnamed_rows(self):
        helper = self._import_helper()
        doc = _FakeDoc({"items": [_FakeChildRow(name="r1", item_code="A", qty=1)]})

        err = helper(
            doc,
            "items",
            "Sales Order Item",
            [{"name": "r1", "qty": 5}, {"item_code": "NEW", "qty": 7}],
            set(),
        )

        self.assertIsNone(err)
        items = doc.get("items")
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].qty, 5)
        self.assertEqual(items[1].item_code, "NEW")
        self.assertEqual(items[1].qty, 7)

    def test_patch_mode_delete_marker_removes_row(self):
        helper = self._import_helper()
        doc = _FakeDoc(
            {
                "items": [
                    _FakeChildRow(name="r1", item_code="A", qty=1),
                    _FakeChildRow(name="r2", item_code="B", qty=2),
                ]
            }
        )

        err = helper(doc, "items", "Sales Order Item", [{"name": "r1", "_delete": True}], set())

        self.assertIsNone(err)
        items = doc.get("items")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].name, "r2")

    def test_delete_marker_without_name_errors(self):
        helper = self._import_helper()
        doc = _FakeDoc({"items": [_FakeChildRow(name="r1", item_code="A", qty=1)]})

        err = helper(doc, "items", "Sales Order Item", [{"_delete": True, "qty": 5}], set())

        self.assertIsNotNone(err)
        self.assertFalse(err["success"])
        self.assertEqual(err["error_type"], "child_row_not_found")

    def test_patch_mode_unknown_name_errors(self):
        helper = self._import_helper()
        doc = _FakeDoc({"items": [_FakeChildRow(name="r1", item_code="A", qty=1)]})

        err = helper(doc, "items", "Sales Order Item", [{"name": "does-not-exist", "qty": 5}], set())

        self.assertIsNotNone(err)
        self.assertFalse(err["success"])
        self.assertEqual(err["error_type"], "child_row_not_found")

    def test_restricted_field_in_child_row_rejected(self):
        helper = self._import_helper()
        doc = _FakeDoc({"items": [_FakeChildRow(name="r1", item_code="A", qty=1)]})

        err = helper(
            doc,
            "items",
            "Sales Order Item",
            [{"name": "r1", "qty": 5, "secret_key": "leak"}],
            {"secret_key"},
        )

        self.assertIsNotNone(err)
        self.assertFalse(err["success"])
        self.assertIn("secret_key", err["error"])
        # Original row untouched on rejection.
        self.assertEqual(doc.get("items")[0].qty, 1)

    def test_value_not_a_list_errors(self):
        helper = self._import_helper()
        doc = _FakeDoc({"items": []})

        err = helper(doc, "items", "Sales Order Item", {"item_code": "A"}, set())

        self.assertIsNotNone(err)
        self.assertFalse(err["success"])
        self.assertEqual(err["error_type"], "child_table_handling_error")

    def test_row_not_a_dict_errors(self):
        helper = self._import_helper()
        doc = _FakeDoc({"items": []})

        err = helper(doc, "items", "Sales Order Item", ["not-a-dict"], set())

        self.assertIsNotNone(err)
        self.assertFalse(err["success"])
        self.assertEqual(err["error_type"], "child_table_handling_error")


# ---------------------------------------------------------------------------
# FAC v2.3 committed regression tests for fetch parity and legacy
# security_config fail-closed behaviour.
# ---------------------------------------------------------------------------


class TestFacV23FetchParity(BaseAssistantTest):
    """Missing and unreadable records yield one constant public answer, with
    no doctype/name/doc_id in the response or in logger arguments."""

    def test_restricted_targets_indistinguishable(self):
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools.chatgpt_fetch import ChatGPTFetch

        tool = ChatGPTFetch()
        msgs = []
        for doctype, name in [
            ("User", "admin@example.com"),
            ("File", "FILE-001"),
            ("FAC Tool Configuration", "get_document"),
            ("DocType", "User"),
        ]:
            with patch(
                "frappe_assistant_core.plugins.core.tools.chatgpt_fetch.frappe.has_permission",
                return_value=True,
            ), patch(
                "frappe_assistant_core.plugins.core.tools.chatgpt_fetch.frappe.get_doc",
                side_effect=AssertionError("restricted target must not reach get_doc"),
            ):
                try:
                    tool.execute({"id": f"{doctype}/{name}"})
                    msgs.append("no-exception")
                except frappe.PermissionError as exc:
                    msgs.append(str(exc))
        self.assertEqual(len(set(msgs)), 1)
        self.assertNotEqual(msgs[0], "no-exception")
        self.assertEqual(msgs[0], "Permission denied")

    def test_missing_and_unreadable_same_message(self):
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools import chatgpt_fetch

        tool = chatgpt_fetch.ChatGPTFetch()

        # Missing: get_doc raises DoesNotExistError.
        def raise_missing(doctype, name):
            raise frappe.DoesNotExistError("missing")

        # Unreadable: has_permission returns False at the second gate.
        with patch.object(chatgpt_fetch.frappe, "get_doc", side_effect=raise_missing):
            try:
                tool.execute({"id": "Customer/CUST-MISSING"})
                missing_msg = "no-exception"
            except frappe.PermissionError as exc:
                missing_msg = str(exc)

        with patch.object(chatgpt_fetch.frappe, "has_permission", return_value=False):
            try:
                tool.execute({"id": "Customer/CUST-PRIVATE"})
                unreadable_msg = "no-exception"
            except frappe.PermissionError as exc:
                unreadable_msg = str(exc)

        self.assertEqual(missing_msg, unreadable_msg)
        self.assertEqual(missing_msg, "Permission denied")

    def test_secret_bearing_doc_id_absent_from_response_and_log(self):
        from unittest.mock import patch

        from frappe_assistant_core.plugins.core.tools import chatgpt_fetch

        tool = chatgpt_fetch.ChatGPTFetch()
        secret_doc_id = "User/secret-token-in-doc-id-hunter2"

        capturing_logger = MagicMock()
        with patch.object(chatgpt_fetch.frappe, "has_permission", return_value=True), patch.object(
            chatgpt_fetch.frappe, "get_doc", side_effect=AssertionError("must not be reached")
        ), patch.object(chatgpt_fetch.frappe, "logger", return_value=capturing_logger):
            try:
                tool.execute({"id": secret_doc_id})
                response = {"no": "exception"}
            except frappe.PermissionError as exc:
                response = {"error": str(exc)}

        rendered = repr(response)
        self.assertNotIn("hunter2", rendered)
        self.assertNotIn("secret-token-in-doc-id", rendered)
        for call in capturing_logger.warning.call_args_list:
            args, kwargs = call
            joined = " ".join(str(a) for a in args)
            self.assertNotIn("hunter2", joined)
            self.assertNotIn("secret-token-in-doc-id", joined)
            self.assertNotIn("exc_info", kwargs)


class TestFacV23LegacyFailClosed(BaseAssistantTest):
    """FAC v2.3: legacy ``security_config.RESTRICTED_DOCTYPES`` must be
    fail-closed on every access pattern — membership, iteration, ``.get()``,
    truthiness, mutation, and canonical-import failure."""

    def test_membership_canonical_for_every_role(self):
        from frappe_assistant_core.core import security_config
        from frappe_assistant_core.core.security_policy import RESTRICTED_DOCTYPES as canonical

        for role in ("Assistant User", "Assistant Admin", "System Manager", "Default"):
            legacy = security_config.RESTRICTED_DOCTYPES.get(role, [])
            self.assertIn("User", legacy, f"role={role}")
            self.assertIn("DocType", legacy, f"role={role}")
            self.assertEqual(set(legacy), set(canonical))

    def test_unknown_role_returns_canonical_not_empty(self):
        from frappe_assistant_core.core import security_config

        legacy = security_config.RESTRICTED_DOCTYPES.get("Unknown Role XYZ", [])
        self.assertIn("User", legacy)

    def test_truthiness_non_empty(self):
        from frappe_assistant_core.core import security_config

        legacy = security_config.RESTRICTED_DOCTYPES.get("Assistant User", [])
        self.assertTrue(legacy)

    def test_mutation_rejected(self):
        from frappe_assistant_core.core import security_config

        with self.assertRaises((TypeError, NotImplementedError)):
            security_config.RESTRICTED_DOCTYPES["Assistant User"] = ["Customer"]

    def test_inert_basic_core_tools_immutable(self):
        from collections.abc import Mapping

        from frappe_assistant_core.core import security_config

        # Tuple / frozenset / MappingProxyType — all immutable.
        self.assertIsInstance(security_config.BASIC_CORE_TOOLS, (tuple, frozenset))
        self.assertIsInstance(security_config.ROLE_TOOL_ACCESS, (tuple, frozenset, Mapping))
        self.assertEqual(len(security_config.BASIC_CORE_TOOLS), 0)
        self.assertEqual(len(security_config.ROLE_TOOL_ACCESS), 0)

    def test_canonical_import_failure_fails_closed(self):
        """If canonical SecurityPolicy cannot be loaded, every membership
        test must report "restricted" (deny-all), and iteration must raise."""
        from frappe_assistant_core.core import security_config

        original = sys.modules.get("frappe_assistant_core.core.security_policy")
        sys.modules["frappe_assistant_core.core.security_policy"] = None
        try:
            legacy = security_config.RESTRICTED_DOCTYPES.get("Any Role", [])
            # Membership test: every doctype is restricted.
            self.assertIn("Customer", legacy)
            self.assertIn("AnythingElse", legacy)
            # Iteration explicitly raises (FAC v2.3).
            with self.assertRaises(RuntimeError):
                list(legacy)
        finally:
            if original is not None:
                sys.modules["frappe_assistant_core.core.security_policy"] = original
            else:
                sys.modules.pop("frappe_assistant_core.core.security_policy", None)
