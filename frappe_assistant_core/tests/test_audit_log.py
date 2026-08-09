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
Tests for Assistant Audit Log status classification and field capture.

These tests exercise BaseTool._safe_execute directly via a minimal in-memory
tool subclass, so they do not depend on any specific plugin being loaded.
"""

from typing import Any, Dict
from unittest.mock import patch

import frappe

from frappe_assistant_core.core.base_tool import BaseTool
from frappe_assistant_core.core.security_policy import PolicyDecision, SecurityPolicy, ToolContext
from frappe_assistant_core.tests.base_test import BaseAssistantTest
from frappe_assistant_core.utils.audit_trail import sanitize_for_audit

_TEST_TOOL_NAME = "test_audit_tool"
_RECORDING_TOOL_NAME = "recording_test_tool"
_ALLOWED_DECISION = PolicyDecision(
    allowed=True,
    reason_code="ALLOWED",
    context=ToolContext(operation="execute"),
)


class _ToolBase(BaseTool):
    """Minimal concrete BaseTool used only in these tests."""

    def __init__(self, executor=None):
        super().__init__()
        self.name = _TEST_TOOL_NAME
        self.description = "Test tool"
        self.inputSchema = {"type": "object", "properties": {}}
        self.requires_permission = None  # skip the DocType permission check
        self.source_app = "frappe_assistant_core"
        self._executor = executor

    def execute(self, arguments: Dict[str, Any]) -> Any:
        return self._executor(arguments)


class _RecordingToolForAuditTest(BaseTool):
    def __init__(self):
        super().__init__()
        self.name = _RECORDING_TOOL_NAME
        self.description = "Policy denial recorder"
        self.inputSchema = {"type": "object", "properties": {}}
        self.dependencies_checked = False
        self.executed = False

    def validate_dependencies(self):
        self.dependencies_checked = True
        return True, None

    def execute(self, arguments: Dict[str, Any]) -> Any:
        self.executed = True
        return {"should_not": "run"}


def _fetch_latest_audit_row(tool_name: str) -> Dict[str, Any]:
    rows = frappe.get_all(
        "Assistant Audit Log",
        filters={"tool_name": tool_name},
        fields=[
            "name",
            "status",
            "error_type",
            "error_message",
            "traceback",
            "source_app",
            "session_id",
            "client_id",
            "output_truncated",
        ],
        order_by="creation desc",
        limit=1,
    )
    assert rows, f"No audit row found for tool {tool_name}"
    return rows[0]


def _delete_test_rows(tool_name: str):
    frappe.db.delete("Assistant Audit Log", {"tool_name": tool_name})


class TestAuditLogStatusClassification(BaseAssistantTest):
    """A tool call's audit status must reflect what actually happened."""

    def setUp(self):
        super().setUp()
        _delete_test_rows(_TEST_TOOL_NAME)
        policy = patch.object(SecurityPolicy, "authorize", return_value=_ALLOWED_DECISION)
        policy.start()
        self.addCleanup(policy.stop)

    def test_successful_execution_logs_success(self):
        tool = _ToolBase(executor=lambda arguments: {"items": [1, 2, 3]})
        response = tool._safe_execute({})

        self.assertTrue(response["success"])
        row = _fetch_latest_audit_row(_TEST_TOOL_NAME)
        self.assertEqual(row["status"], "Success")
        self.assertIsNone(row["error_type"])
        self.assertIsNone(row["error_message"])

    def test_tool_reported_failure_logs_error(self):
        """A tool returning {"success": False, ...} was previously logged as
        Success. It must now be logged as Error with ToolReportedError type."""

        def executor(arguments):
            return {"success": False, "error": "file not found"}

        tool = _ToolBase(executor=executor)
        response = tool._safe_execute({})

        self.assertFalse(response["success"])
        self.assertEqual(response["error_type"], "ToolReportedError")

        row = _fetch_latest_audit_row(_TEST_TOOL_NAME)
        self.assertEqual(row["status"], "Error")
        self.assertEqual(row["error_type"], "ToolReportedError")
        self.assertIn("file not found", row["error_message"] or "")

    def test_tool_reported_secret_is_not_written_to_process_log(self):
        tool = _ToolBase(
            executor=lambda arguments: {
                "success": False,
                "error": "password=process-log-secret",
            }
        )
        with patch.object(tool.logger, "info") as info_log:
            tool._safe_execute({})

        logged = " ".join(str(call) for call in info_log.call_args_list)
        self.assertNotIn("process-log-secret", logged)

    def test_permission_error_logs_permission_denied(self):
        def executor(arguments):
            raise frappe.PermissionError("no access")

        tool = _ToolBase(executor=executor)
        tool._safe_execute({})

        row = _fetch_latest_audit_row(_TEST_TOOL_NAME)
        self.assertEqual(row["status"], "Permission Denied")
        self.assertEqual(row["error_type"], "PermissionError")

    def test_uncaught_exception_logs_error_with_traceback(self):
        def executor(arguments):
            raise RuntimeError("boom")

        tool = _ToolBase(executor=executor)
        tool._safe_execute({})

        row = _fetch_latest_audit_row(_TEST_TOOL_NAME)
        self.assertEqual(row["status"], "Error")
        self.assertEqual(row["error_type"], "ExecutionError")
        self.assertTrue(row["traceback"], "traceback must be captured on exception path")
        self.assertIn("RuntimeError", row["traceback"])

    def test_timeout_error_logs_timeout(self):
        def executor(arguments):
            raise TimeoutError("tool timed out")

        tool = _ToolBase(executor=executor)
        tool._safe_execute({})

        row = _fetch_latest_audit_row(_TEST_TOOL_NAME)
        self.assertEqual(row["status"], "Timeout")
        self.assertEqual(row["error_type"], "Timeout")

    def test_dependency_failure_is_logged_once(self):
        tool = _ToolBase(executor=lambda arguments: {"should_not": "run"})
        tool.dependencies = ["fac_dependency_that_does_not_exist"]
        response = tool._safe_execute({})

        self.assertEqual(response["error_type"], "DependencyError")
        self.assertEqual(
            frappe.db.count("Assistant Audit Log", {"tool_name": tool.name}),
            1,
        )


class TestAuditLogFieldCapture(BaseAssistantTest):
    """New audit columns must actually be populated end-to-end."""

    def setUp(self):
        super().setUp()
        _delete_test_rows(_TEST_TOOL_NAME)
        policy = patch.object(SecurityPolicy, "authorize", return_value=_ALLOWED_DECISION)
        policy.start()
        self.addCleanup(policy.stop)

    def test_source_app_is_written(self):
        tool = _ToolBase(executor=lambda arguments: {"ok": True})
        tool._safe_execute({})

        row = _fetch_latest_audit_row(_TEST_TOOL_NAME)
        self.assertEqual(row["source_app"], "frappe_assistant_core")

    def test_session_and_client_ids_from_frappe_local(self):
        frappe.local.assistant_session_id = "session-abc"
        frappe.local.assistant_client_id = "claude-desktop-test"
        try:
            tool = _ToolBase(executor=lambda arguments: {"ok": True})
            tool._safe_execute({})

            row = _fetch_latest_audit_row(_TEST_TOOL_NAME)
            self.assertEqual(row["session_id"], "session-abc")
            self.assertEqual(row["client_id"], "claude-desktop-test")
        finally:
            # Don't bleed state into other tests
            frappe.local.assistant_session_id = None
            frappe.local.assistant_client_id = None

    def test_large_output_is_truncated_and_flagged(self):
        # BaseTool._sanitize_data clips long values under common keys, so
        # build a payload that survives sanitization but still exceeds the
        # 50KB sink cap. Many small items under an unrecognised key works.
        big_payload = {f"item_{i}": "padding" * 200 for i in range(60)}

        tool = _ToolBase(executor=lambda arguments: big_payload)
        tool._safe_execute({})

        row = _fetch_latest_audit_row(_TEST_TOOL_NAME)
        self.assertEqual(row["output_truncated"], 1)

    def test_policy_context_controls_target_and_output_is_redacted(self):
        decision = PolicyDecision(
            allowed=True,
            reason_code="ALLOWED",
            context=ToolContext(
                operation="read",
                target_doctype="ToDo",
                target_name="SAFE-TARGET",
                required_permissions=frozenset({"read"}),
            ),
        )
        tool = _ToolBase(executor=lambda arguments: {"password": "output-secret"})

        with patch.object(SecurityPolicy, "authorize", return_value=decision):
            response = tool._safe_execute({"doctype": "User", "name": "Administrator"})

        self.assertEqual(response["result"]["password"], "***REDACTED***")
        row = frappe.get_all(
            "Assistant Audit Log",
            filters={"tool_name": tool.name},
            fields=["action", "target_doctype", "target_name", "output_data"],
            order_by="creation desc",
            limit=1,
        )[0]
        self.assertEqual(row["action"], "read")
        self.assertEqual(row["target_doctype"], "ToDo")
        self.assertEqual(row["target_name"], "SAFE-TARGET")
        self.assertNotIn("output-secret", row["output_data"] or "")

    def test_audit_sink_failure_does_not_echo_secret_to_process_log(self):
        tool = _ToolBase(executor=lambda arguments: {"ok": True})
        with patch(
            "frappe_assistant_core.utils.audit_trail.log_tool_execution",
            side_effect=RuntimeError("password=warning-log-secret"),
        ):
            with patch.object(tool.logger, "warning") as warning_log:
                tool.log_execution({}, {"success": True, "result": {}}, 0.01)

        logged = " ".join(str(call) for call in warning_log.call_args_list)
        self.assertNotIn("warning-log-secret", logged)


class TestAuditSinkSanitization(BaseAssistantTest):
    """The sink defensively redacts sensitive keys even if the caller forgot."""

    def test_nested_secrets_and_json_strings_are_redacted(self):
        value = {
            "headers": {"Authorization": "Bearer secret"},
            "rows": [{"api_secret": "x"}],
            "nested_json": '{"password":"inside"}',
            "malformed_json": "{password=malformed-secret",
            "variants": {
                "cookie": "a",
                "cookies": "b",
                "session": "c",
                "encryption-key": "d",
                "API-Key": "e",
            },
        }
        self.assertEqual(
            sanitize_for_audit(value),
            {
                "headers": {"Authorization": "***REDACTED***"},
                "rows": [{"api_secret": "***REDACTED***"}],
                "nested_json": '{"password":"***REDACTED***"}',
                "malformed_json": "{password=***REDACTED***",
                "variants": {
                    "cookie": "***REDACTED***",
                    "cookies": "***REDACTED***",
                    "session": "***REDACTED***",
                    "encryption-key": "***REDACTED***",
                    "API-Key": "***REDACTED***",
                },
            },
        )

    def test_policy_denial_is_logged_once_before_dependencies(self):
        _delete_test_rows(_RECORDING_TOOL_NAME)
        decision = PolicyDecision(
            allowed=False,
            reason_code="TOOL_HARD_DENY",
            context=ToolContext(operation="execute"),
        )
        tool = _RecordingToolForAuditTest()

        with patch.object(SecurityPolicy, "authorize", return_value=decision):
            result = tool._safe_execute({"password": {"token": "never-log"}})

        self.assertEqual(result["error_type"], "PolicyDenied")
        self.assertEqual(
            frappe.db.count("Assistant Audit Log", {"tool_name": tool.name}),
            1,
        )
        self.assertFalse(tool.dependencies_checked)
        self.assertFalse(tool.executed)

        row = frappe.get_all(
            "Assistant Audit Log",
            filters={"tool_name": tool.name},
            fields=["status", "error_type", "input_data", "output_data"],
            order_by="creation desc",
            limit=1,
        )[0]
        self.assertEqual(row["status"], "Permission Denied")
        self.assertEqual(row["error_type"], "PolicyDenied")
        self.assertNotIn("never-log", row["input_data"] or "")
        self.assertNotIn("never-log", row["output_data"] or "")

    def test_sink_redacts_sensitive_keys(self):
        from frappe_assistant_core.utils.audit_trail import log_tool_execution

        tool_name = "test_audit_sanitization"
        _delete_test_rows(tool_name)

        log_tool_execution(
            tool_name=tool_name,
            user=frappe.session.user,
            arguments={"password": "hunter2", "doctype": "ToDo"},
            status="Success",
            execution_time=0.01,
            source_app="frappe_assistant_core",
        )

        row = frappe.get_all(
            "Assistant Audit Log",
            filters={"tool_name": tool_name},
            fields=["input_data"],
            order_by="creation desc",
            limit=1,
        )[0]
        self.assertIn("REDACTED", row["input_data"])
        self.assertNotIn("hunter2", row["input_data"])

    def test_sink_redacts_secrets_in_all_persisted_payloads(self):
        from frappe_assistant_core.utils.audit_trail import log_tool_execution

        tool_name = "test_audit_all_payloads"
        _delete_test_rows(tool_name)
        log_tool_execution(
            tool_name=tool_name,
            user=frappe.session.user,
            arguments={"nested": [{"api_secret": "input-secret"}]},
            status="Error",
            execution_time=0.01,
            error_message="request failed: password=error-secret",
            traceback_str="Authorization: Bearer trace-secret",
            output_data={"headers": {"authorization": "output-secret"}},
        )

        row = frappe.get_all(
            "Assistant Audit Log",
            filters={"tool_name": tool_name},
            fields=["input_data", "output_data", "error_message", "traceback"],
            order_by="creation desc",
            limit=1,
        )[0]
        persisted = " ".join(str(row.get(field) or "") for field in row)
        for secret in ("input-secret", "output-secret", "error-secret", "trace-secret"):
            self.assertNotIn(secret, persisted)

    def test_invalid_status_is_coerced_to_error(self):
        from frappe_assistant_core.utils.audit_trail import log_tool_execution

        tool_name = "test_audit_invalid_status"
        _delete_test_rows(tool_name)

        log_tool_execution(
            tool_name=tool_name,
            user=frappe.session.user,
            arguments={},
            status="Failed",  # legacy value, not in the Select enum
            execution_time=0.0,
            source_app="frappe_assistant_core",
        )

        row = frappe.get_all(
            "Assistant Audit Log",
            filters={"tool_name": tool_name},
            fields=["status"],
            order_by="creation desc",
            limit=1,
        )[0]
        self.assertEqual(row["status"], "Error")


class TestSensitiveKeyMatcher(BaseAssistantTest):
    """_is_sensitive_key redacts credentials but preserves token-count metrics.

    Earlier versions used a substring blocklist that included ``token``, which
    over-redacted ``input_tokens`` / ``output_tokens`` / ``total_tokens`` in
    audit output_data — the regex-backed matcher fixes that without weakening
    redaction of access_token / refresh_token / jwt_token / bearer_token.
    """

    def test_credential_keys_are_redacted(self):
        from frappe_assistant_core.core.base_tool import _is_sensitive_key

        for key in [
            "password",
            "old_password",
            "api_key",
            "apiKey",
            "claude_api_key",
            "secret",
            "auth_header",
            "token",
            "access_token",
            "refresh_token",
            "jwt_token",
            "bearer_token",
        ]:
            self.assertTrue(_is_sensitive_key(key), f"{key} should be flagged sensitive")

    def test_token_count_metrics_are_not_redacted(self):
        from frappe_assistant_core.core.base_tool import _is_sensitive_key

        for key in ["input_tokens", "output_tokens", "total_tokens", "tokens_used"]:
            self.assertFalse(_is_sensitive_key(key), f"{key} must not be redacted")

    def test_unrelated_keys_are_not_redacted(self):
        from frappe_assistant_core.core.base_tool import _is_sensitive_key

        for key in ["model", "content", "file_url", "ocr_backend"]:
            self.assertFalse(_is_sensitive_key(key))

    def test_non_string_keys_return_false(self):
        from frappe_assistant_core.core.base_tool import _is_sensitive_key

        # Defensive: integer/None keys must not crash the matcher.
        self.assertFalse(_is_sensitive_key(None))
        self.assertFalse(_is_sensitive_key(42))
