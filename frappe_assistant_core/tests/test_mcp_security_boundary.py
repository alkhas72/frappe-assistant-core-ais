"""Security contracts for the authenticated MCP boundary."""

import json
import uuid
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import frappe
from werkzeug.wrappers import Response

from frappe_assistant_core.core.security_policy import (
    PolicyDecision,
    PolicyDenied,
    ToolContext,
)
from frappe_assistant_core.mcp.server import MCPServer
from frappe_assistant_core.mcp.tool_adapter import build_tool_dict
from frappe_assistant_core.tests.base_test import BaseAssistantTest


def _tool(name, fn):
    return {
        "name": name,
        "description": name,
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": None,
        "fn": fn,
    }


def _delete_boundary_audit_rows(tool_name):
    """Remove only the real audit row created by this boundary test."""
    frappe.db.delete("Assistant Audit Log", {"tool_name": tool_name})
    frappe.db.commit()


class _AdapterTool:
    name = "get_document"
    description = "Adapter boundary test tool"
    inputSchema = {"type": "object", "properties": {}}


class TestMCPToolCallBoundary(BaseAssistantTest):
    def setUp(self):
        super().setUp()
        self.server = MCPServer("security-test")

    def test_hidden_name_is_audited_without_inventory_or_argument_leak(self):
        logger = MagicMock()
        decision = PolicyDecision(
            False,
            "ROLE_NOT_ALLOWED",
            ToolContext(operation="authorize"),
        )
        with ExitStack() as stack:
            stack.enter_context(patch(
                "frappe_assistant_core.core.security_policy.SecurityPolicy.authorize",
                return_value=decision,
            ))
            audit = stack.enter_context(patch(
                "frappe_assistant_core.utils.audit_trail.log_denied_tool_attempt"
            ))
            stack.enter_context(patch.object(frappe, "logger", return_value=logger))
            result = self.server._handle_tools_call(
                {
                    "name": "hidden-secret-name",
                    "arguments": {"token": "never-echo"},
                },
                {"visible-tool": _tool("visible-tool", MagicMock())},
            )

        self.assertTrue(result["isError"])
        body = result["content"][0]["text"]
        self.assertEqual(body, "Tool is not available")
        self.assertNotIn("visible-tool", body)
        self.assertNotIn("hidden-secret-name", body)
        self.assertNotIn("never-echo", body)
        audit.assert_called_once()
        self.assertEqual(audit.call_args.kwargs["reason_code"], "ROLE_NOT_ALLOWED")
        self.assertNotIn("never-echo", str(logger.method_calls))

    def test_hidden_name_writes_one_sanitized_real_audit_row(self):
        hidden_name = "task4-hidden-" + uuid.uuid4().hex
        secret = "task4-boundary-secret"
        self.addCleanup(_delete_boundary_audit_rows, hidden_name)

        result = self.server._handle_tools_call(
            {
                "name": hidden_name,
                "arguments": {"token": secret},
            },
            {},
        )

        self.assertTrue(result["isError"])
        rows = frappe.get_all(
            "Assistant Audit Log",
            filters={"tool_name": hidden_name},
            fields=["status", "input_data", "output_data", "error_message"],
        )
        self.assertEqual(len(rows), 1)
        serialized = json.dumps(rows[0], default=str)
        self.assertEqual(rows[0]["status"], "Permission Denied")
        self.assertNotIn(secret, serialized)
        self.assertIn("REDACTED", serialized)

    def test_non_dict_arguments_are_rejected_before_executor_and_audited_once(self):
        executor = MagicMock()
        with patch(
            "frappe_assistant_core.utils.audit_trail.log_denied_tool_attempt"
        ) as audit:
            for arguments in (None, [], "{}", 1, True):
                with self.subTest(arguments=arguments):
                    audit.reset_mock()
                    result = self.server._handle_tools_call(
                        {
                            "name": "get_document",
                            "arguments": arguments,
                        },
                        {"get_document": _tool("get_document", executor)},
                    )

                    self.assertTrue(result["isError"])
                    self.assertEqual(
                        result["content"][0]["text"],
                        "Invalid tool arguments",
                    )
                    executor.assert_not_called()
                    audit.assert_called_once()
                    self.assertEqual(
                        audit.call_args.kwargs["reason_code"],
                        "ARGUMENTS_INVALID",
                    )

    def test_omitted_arguments_default_to_empty_object(self):
        executor = MagicMock(return_value={"ok": True})

        result = self.server._handle_tools_call(
            {"name": "get_document"},
            {"get_document": _tool("get_document", executor)},
        )

        self.assertFalse(result["isError"])
        executor.assert_called_once_with()

    def test_invalid_tool_names_are_stable_and_audited(self):
        with patch(
            "frappe_assistant_core.utils.audit_trail.log_denied_tool_attempt"
        ) as audit:
            for tool_name in (None, "", []):
                with self.subTest(tool_name=tool_name):
                    audit.reset_mock()
                    result = self.server._handle_tools_call(
                        {"name": tool_name, "arguments": {}},
                        {},
                    )

                    self.assertTrue(result["isError"])
                    self.assertEqual(
                        result["content"][0]["text"],
                        "Tool is not available",
                    )
                    audit.assert_called_once()
                    self.assertEqual(
                        audit.call_args.kwargs["tool_name"],
                        "<invalid-tool-name>",
                    )

    def test_generic_exception_returns_stable_message_without_process_log_secret(self):
        logger = MagicMock()
        canonical_audit = MagicMock()

        def fail(name, arguments):
            canonical_audit(name, arguments)
            raise RuntimeError(arguments["secret"])

        with patch.object(frappe, "logger", return_value=logger):
            result = self.server._handle_tools_call(
                {"name": "get_document", "arguments": {"secret": "never-echo"}},
                {
                    "get_document": build_tool_dict(
                        _AdapterTool(),
                        executor=fail,
                    )
                },
            )

        self.assertTrue(result["isError"])
        body = result["content"][0]["text"]
        self.assertEqual(body, "Tool execution failed")
        self.assertNotIn("never-echo", body)
        self.assertNotIn("Traceback", body)
        self.assertNotIn("never-echo", str(logger.method_calls))
        canonical_audit.assert_called_once()

    def test_policy_denial_from_executor_is_not_audited_twice(self):
        decision = PolicyDecision(
            False,
            "TOOL_DISABLED",
            ToolContext(operation="authorize"),
        )

        canonical_audit = MagicMock()

        def deny(name, arguments):
            canonical_audit(name, arguments)
            raise PolicyDenied(decision)

        with ExitStack() as stack:
            boundary_audit = stack.enter_context(patch(
                "frappe_assistant_core.utils.audit_trail.log_denied_tool_attempt"
            ))
            result = self.server._handle_tools_call(
                {"name": "get_document", "arguments": {}},
                {
                    "get_document": build_tool_dict(
                        _AdapterTool(),
                        executor=deny,
                    )
                },
            )

        self.assertTrue(result["isError"])
        self.assertEqual(result["content"][0]["text"], "Tool is not available")
        canonical_audit.assert_called_once_with("get_document", {})
        boundary_audit.assert_not_called()

    def test_tools_list_writes_one_count_only_summary(self):
        registry = {"get_document": _tool("get_document", MagicMock())}
        with ExitStack() as stack:
            stack.enter_context(patch(
                "frappe_assistant_core.core.security_policy.SecurityPolicy.inventory",
                return_value=frozenset({"get_document", "create_document", "run_workflow"}),
            ))
            audit = stack.enter_context(patch(
                "frappe_assistant_core.utils.audit_trail.log_tool_execution"
            ))
            result = self.server._handle_tools_list({}, registry)

        self.assertEqual([tool["name"] for tool in result["tools"]], ["get_document"])
        audit.assert_called_once()
        kwargs = audit.call_args.kwargs
        self.assertEqual(kwargs["tool_name"], "tools/list")
        self.assertEqual(kwargs["operation"], "publish")
        self.assertIsNone(kwargs["arguments"])
        self.assertEqual(
            kwargs["output_data"],
            {"published_count": 1, "hidden_count": 2},
        )


class TestMCPAuthenticationBoundary(BaseAssistantTest):
    def test_missing_auth_returns_401_and_audits_reason_only(self):
        from frappe_assistant_core.api import fac_endpoint

        request = SimpleNamespace(
            method="POST",
            headers={},
            url="https://fac-test.local/api/method/fac",
        )
        with ExitStack() as stack:
            stack.enter_context(patch.object(fac_endpoint.frappe, "request", request))
            build = stack.enter_context(
                patch.object(fac_endpoint, "_build_tool_registry")
            )
            audit = stack.enter_context(patch(
                "frappe_assistant_core.utils.audit_trail.log_security_event"
            ))
            response = fac_endpoint.mcp._entry_fn()

        self.assertIsInstance(response, Response)
        self.assertEqual(response.status_code, 401)
        build.assert_not_called()
        audit.assert_called_once()
        self.assertEqual(audit.call_args.kwargs["user"], "Guest")
        self.assertEqual(
            audit.call_args.kwargs["details"],
            {"reason_code": "AUTH_MISSING"},
        )

    def test_authentication_exception_does_not_echo_secret(self):
        from frappe_assistant_core.api import fac_endpoint

        request = SimpleNamespace(
            headers={"Authorization": "Bearer header-secret"},
            url="https://fac-test.local/api/method/fac",
        )
        logger = MagicMock()
        with ExitStack() as stack:
            stack.enter_context(patch.object(fac_endpoint.frappe, "request", request))
            stack.enter_context(
                patch.object(fac_endpoint.frappe, "logger", return_value=logger)
            )
            stack.enter_context(patch.object(
                fac_endpoint.frappe,
                "get_doc",
                side_effect=RuntimeError("internal-secret"),
            ))
            error_log = stack.enter_context(
                patch.object(fac_endpoint.frappe, "log_error")
            )
            audit = stack.enter_context(patch(
                "frappe_assistant_core.utils.audit_trail.log_security_event"
            ))
            response = fac_endpoint._authenticate_mcp_request()

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("header-secret", body)
        self.assertNotIn("internal-secret", body)
        self.assertNotIn("header-secret", str(logger.method_calls))
        self.assertNotIn("internal-secret", str(logger.method_calls))
        self.assertNotIn("header-secret", str(error_log.call_args_list))
        self.assertNotIn("internal-secret", str(error_log.call_args_list))
        audit.assert_called_once()
        self.assertEqual(
            audit.call_args.kwargs["details"],
            {"reason_code": "AUTHENTICATION_ERROR"},
        )

    def test_guest_never_builds_registry(self):
        from frappe_assistant_core.api import fac_endpoint

        request = SimpleNamespace(
            method="POST",
            headers={},
            url="https://fac-test.local/api/method/fac",
        )
        with ExitStack() as stack:
            stack.enter_context(patch.object(fac_endpoint.frappe, "request", request))
            stack.enter_context(patch.object(
                fac_endpoint,
                "_authenticate_mcp_request",
                return_value="Guest",
            ))
            stack.enter_context(patch.object(
                fac_endpoint,
                "_check_assistant_enabled",
                return_value=True,
            ))
            build = stack.enter_context(patch.object(fac_endpoint, "_build_tool_registry"))
            audit = stack.enter_context(patch(
                "frappe_assistant_core.utils.audit_trail.log_security_event"
            ))
            response = fac_endpoint.mcp._entry_fn()

        self.assertIsInstance(response, Response)
        self.assertEqual(response.status_code, 401)
        build.assert_not_called()
        audit.assert_called_once()


class TestMCPHandleLogging(BaseAssistantTest):
    def test_handle_does_not_log_raw_tool_arguments(self):
        request = MagicMock()
        request.method = "POST"
        request.get_json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_document",
                "arguments": {"token": "never-log"},
            },
        }
        request.headers = {}
        response = Response()
        logger = MagicMock()
        server = MCPServer("logging-test")

        original_request = getattr(frappe.local, "request", None)
        frappe.local.request = request
        try:
            with patch.object(frappe, "logger", return_value=logger):
                result = server.handle(
                    request,
                    response,
                    tool_registry={
                        "get_document": _tool(
                            "get_document",
                            lambda **arguments: {"ok": True},
                        )
                    },
                )
        finally:
            frappe.local.request = original_request

        self.assertEqual(result.status_code, 200)
        self.assertNotIn("never-log", str(logger.method_calls))
        payload = json.loads(result.get_data(as_text=True))
        self.assertFalse(payload["result"]["isError"])

    def test_unknown_method_does_not_echo_or_log_attacker_value(self):
        secret = "never-echo-method-secret"
        request = MagicMock()
        request.method = "POST"
        request.get_json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": secret,
        }
        request.headers = {}
        response = Response()
        logger = MagicMock()
        server = MCPServer("logging-test")

        original_request = getattr(frappe.local, "request", None)
        frappe.local.request = request
        try:
            with patch.object(frappe, "logger", return_value=logger):
                result = server.handle(request, response, tool_registry={})
        finally:
            frappe.local.request = original_request

        self.assertNotIn(secret, result.get_data(as_text=True))
        self.assertNotIn(secret, str(logger.method_calls))

    def test_non_dict_params_reach_stable_call_boundary_and_audit_once(self):
        logger = MagicMock()
        server = MCPServer("logging-test")

        for params in (["never-log"], "never-log"):
            with self.subTest(params=params):
                request = MagicMock()
                request.method = "POST"
                request.get_json.return_value = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": params,
                }
                request.headers = {}
                response = Response()
                original_request = getattr(frappe.local, "request", None)
                frappe.local.request = request
                try:
                    with ExitStack() as stack:
                        stack.enter_context(
                            patch.object(frappe, "logger", return_value=logger)
                        )
                        audit = stack.enter_context(patch(
                            "frappe_assistant_core.utils.audit_trail.log_denied_tool_attempt"
                        ))
                        result = server.handle(request, response, tool_registry={})
                finally:
                    frappe.local.request = original_request

                payload = json.loads(result.get_data(as_text=True))
                self.assertEqual(
                    payload["result"]["content"][0]["text"],
                    "Invalid tool arguments",
                )
                audit.assert_called_once()
                self.assertNotIn("never-log", str(logger.method_calls))

    def test_non_object_json_request_is_rejected_without_echo(self):
        secret = "never-echo-root-secret"
        request = MagicMock()
        request.method = "POST"
        request.get_json.return_value = [secret]
        request.headers = {}
        response = Response()
        server = MCPServer("logging-test")

        original_request = getattr(frappe.local, "request", None)
        frappe.local.request = request
        try:
            result = server.handle(request, response, tool_registry={})
        finally:
            frappe.local.request = original_request

        payload = json.loads(result.get_data(as_text=True))
        self.assertEqual(payload["error"]["message"], "Invalid Request")
        self.assertNotIn(secret, result.get_data(as_text=True))

    def test_non_object_client_info_reaches_stable_call_boundary(self):
        request = MagicMock()
        request.method = "POST"
        request.get_json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"clientInfo": ["invalid"]},
        }
        request.headers = {}
        response = Response()
        server = MCPServer("logging-test")

        original_request = getattr(frappe.local, "request", None)
        frappe.local.request = request
        try:
            with patch(
                "frappe_assistant_core.utils.audit_trail.log_denied_tool_attempt"
            ) as audit:
                result = server.handle(request, response, tool_registry={})
        finally:
            frappe.local.request = original_request

        payload = json.loads(result.get_data(as_text=True))
        self.assertEqual(
            payload["result"]["content"][0]["text"],
            "Tool is not available",
        )
        audit.assert_called_once()

    def test_tools_list_failure_writes_one_error_summary(self):
        request = MagicMock()
        request.method = "POST"
        request.get_json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }
        request.headers = {}
        response = Response()
        server = MCPServer("logging-test")
        malformed_registry = {"broken": {"name": "broken"}}

        original_request = getattr(frappe.local, "request", None)
        frappe.local.request = request
        try:
            with patch(
                "frappe_assistant_core.mcp.server.audit_tools_list_summary"
            ) as audit:
                result = server.handle(
                    request,
                    response,
                    tool_registry=malformed_registry,
                )
        finally:
            frappe.local.request = original_request

        payload = json.loads(result.get_data(as_text=True))
        self.assertEqual(payload["error"]["message"], "Internal error")
        audit.assert_called_once_with(0, status="Error")
