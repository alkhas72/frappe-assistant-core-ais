"""Security contracts for the alternate authenticated tool handler."""

import json
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import frappe

from frappe_assistant_core.tests.base_test import BaseAssistantTest


class TestAlternateToolHandlerBoundary(BaseAssistantTest):
    def setUp(self):
        super().setUp()
        from frappe_assistant_core.api.handlers import tools as tools_handler

        self.tools_handler = tools_handler
        self.registry = MagicMock()

    def test_list_and_call_use_only_canonical_registry_methods(self):
        self.registry.get_available_tools.return_value = [{"name": "get_document"}]
        self.registry.execute_tool.return_value = {"ok": True}

        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    self.tools_handler,
                    "get_tool_registry",
                    return_value=self.registry,
                )
            )
            list_audit = stack.enter_context(
                patch.object(self.tools_handler, "audit_tools_list_summary")
            )
            denial_audit = stack.enter_context(
                patch.object(self.tools_handler, "audit_unavailable_tool_call")
            )
            listed = self.tools_handler.handle_tools_list(1)
            called = self.tools_handler.handle_tool_call(
                {
                    "name": "get_document",
                    "arguments": {"doctype": "ToDo", "name": "TD-1"},
                },
                2,
            )

        self.assertEqual(listed["result"]["tools"], [{"name": "get_document"}])
        self.registry.get_available_tools.assert_called_once_with(
            user=frappe.session.user
        )
        self.registry.execute_tool.assert_called_once_with(
            "get_document",
            {"doctype": "ToDo", "name": "TD-1"},
        )
        list_audit.assert_called_once_with(1)
        denial_audit.assert_not_called()
        self.assertEqual(called["id"], 2)

    def test_malformed_calls_are_audited_once_before_registry_lookup(self):
        cases = (
            (None, "ARGUMENTS_INVALID"),
            ({}, "TOOL_UNKNOWN"),
            ({"name": "get_document", "arguments": []}, "ARGUMENTS_INVALID"),
        )
        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    self.tools_handler,
                    "get_tool_registry",
                    return_value=self.registry,
                )
            )
            audit = stack.enter_context(
                patch.object(self.tools_handler, "audit_unavailable_tool_call")
            )
            for params, reason_code in cases:
                with self.subTest(params=params):
                    audit.reset_mock()
                    self.registry.reset_mock()
                    result = self.tools_handler.handle_tool_call(params, 1)
                    self.assertIn("error", result)
                    audit.assert_called_once()
                    self.assertEqual(audit.call_args.args[-1], reason_code)
                    self.registry.execute_tool.assert_not_called()

    def test_registry_exceptions_do_not_reach_response_or_process_log(self):
        secret = "never-echo-handler-secret"
        error_log = MagicMock()
        self.registry.get_available_tools.side_effect = RuntimeError(secret)

        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    self.tools_handler,
                    "get_tool_registry",
                    return_value=self.registry,
                )
            )
            stack.enter_context(
                patch.object(self.tools_handler.api_logger, "error", error_log)
            )
            list_audit = stack.enter_context(
                patch.object(self.tools_handler, "audit_tools_list_summary")
            )
            listed = self.tools_handler.handle_tools_list(1)

        self.assertNotIn(secret, json.dumps(listed))
        self.assertNotIn(secret, str(error_log.call_args_list))
        self.assertNotIn("data", listed["error"])
        list_audit.assert_called_once_with(0, status="Error")

        self.registry.reset_mock()
        self.registry.execute_tool.side_effect = RuntimeError(secret)
        error_log.reset_mock()
        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    self.tools_handler,
                    "get_tool_registry",
                    return_value=self.registry,
                )
            )
            stack.enter_context(
                patch.object(self.tools_handler.api_logger, "error", error_log)
            )
            called = self.tools_handler.handle_tool_call(
                {"name": secret, "arguments": {"token": secret}},
                2,
            )

        self.assertNotIn(secret, json.dumps(called))
        self.assertNotIn(secret, str(error_log.call_args_list))
        self.assertNotIn("data", called["error"])
        self.assertNotIn("details", called["error"])
