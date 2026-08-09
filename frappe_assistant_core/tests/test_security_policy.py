from contextlib import ExitStack
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from frappe.tests.utils import FrappeTestCase

from frappe_assistant_core.core import security_policy as policy_module
from frappe_assistant_core.core.security_config import ADMIN_ONLY_FIELDS, SENSITIVE_FIELDS
from frappe_assistant_core.core.security_policy import (
    CONFIGURABLE_TOOLS,
    HARD_DENY_TOOLS,
    RESTRICTED_DOCTYPES,
    PolicyDecision,
    PolicyDenied,
    SecurityPolicy,
    ToolContext,
    discover_builtin_tool_names,
)

EXPECTED_24_TOOLS = {
    "get_document",
    "list_documents",
    "search_documents",
    "search_doctype",
    "search_link",
    "search",
    "fetch",
    "get_doctype_info",
    "report_list",
    "report_requirements",
    "generate_report",
    "get_pending_approvals",
    "create_document",
    "update_document",
    "submit_document",
    "run_workflow",
    "delete_document",
    "run_python_code",
    "run_database_query",
    "analyze_business_data",
    "extract_file_content",
    "create_dashboard",
    "create_dashboard_chart",
    "list_user_dashboards",
}
EXPECTED_HARD_DENY = {
    "delete_document", "run_python_code", "run_database_query", "analyze_business_data",
    "extract_file_content", "create_dashboard", "create_dashboard_chart", "list_user_dashboards",
    "document_create", "document_get", "document_update", "document_list", "search_global",
    "report_execute", "report_columns", "metadata_doctype", "create_visualization",
    "analyze_frappe_data", "workflow_status", "workflow_list", "execute_python_code",
    "query_and_analyze", "metadata_permissions", "metadata_workflow", "tool_registry_list",
    "tool_registry_toggle", "audit_log_view", "workflow_action",
}
EXPECTED_RESTRICTED_DOCTYPES = {
    "User", "Role", "User Permission", "Role Permission", "Custom Role", "Module Profile",
    "Role Profile", "Custom DocPerm", "DocShare", "System Settings", "Print Settings",
    "Email Domain", "LDAP Settings", "OAuth Settings", "Social Login Key", "Dropbox Settings",
    "Connected App", "OAuth Bearer Token", "OAuth Client", "Error Log", "Activity Log",
    "Access Log", "View Log", "Scheduler Log", "Integration Request", "Server Script",
    "Client Script", "Custom Script", "Property Setter", "Customize Form",
    "Customize Form Field", "DocType", "DocField", "DocPerm", "Custom Field", "Package",
    "Package Release", "Installed Application", "Data Import", "Data Export", "Bulk Update",
    "Rename Tool", "Database Storage Usage By Tables", "Workflow", "Workflow Action",
    "Workflow State", "Workflow Transition", "Email Queue", "Email Queue Recipient",
    "Email Alert", "Auto Email Report", "File", "Assistant Core Settings",
    "FAC Tool Configuration", "FAC Tool Role Access", "FAC Plugin Configuration",
    "Assistant Audit Log",
}
ALLOW_SYSTEM_MANAGER = {
    "enabled": True,
    "role_access_mode": "Restrict to Listed Roles",
    "roles": {"System Manager"},
}
ALLOW_ASSISTANT_USER = {
    "enabled": True,
    "role_access_mode": "Restrict to Listed Roles",
    "roles": {"Assistant User"},
}
ALLOW_ALL = {"enabled": True, "role_access_mode": "Allow All", "roles": set()}


class TestSecurityPolicy(FrappeTestCase):
    def _authorize(self, tool_name, arguments=None, config=ALLOW_ASSISTANT_USER):
        with ExitStack() as stack:
            stack.enter_context(patch.object(SecurityPolicy, "_is_actor_enabled", return_value=True))
            stack.enter_context(patch.object(SecurityPolicy, "_is_plugin_enabled", return_value=True))
            stack.enter_context(
                patch.object(SecurityPolicy, "_load_access_config", return_value=config)
            )
            stack.enter_context(
                patch.object(SecurityPolicy, "_get_actor_roles", return_value={"Assistant User"})
            )
            stack.enter_context(
                patch.object(SecurityPolicy, "_has_native_permissions", return_value=True)
            )
            return SecurityPolicy.authorize(
                actor="agent@example.com",
                tool_name=tool_name,
                arguments=arguments or {},
                phase="execute",
            )

    def test_inventory_contains_exact_upstream_tools(self):
        discovered = discover_builtin_tool_names()
        self.assertIsInstance(discovered, frozenset)
        self.assertEqual(discovered, EXPECTED_24_TOOLS)
        self.assertEqual(set(SecurityPolicy.inventory()), discovered)
        self.assertEqual(HARD_DENY_TOOLS, EXPECTED_HARD_DENY)
        self.assertEqual(RESTRICTED_DOCTYPES, EXPECTED_RESTRICTED_DOCTYPES)
        self.assertEqual(CONFIGURABLE_TOOLS, EXPECTED_24_TOOLS - EXPECTED_HARD_DENY)

    def test_decision_types_are_immutable_and_require_raises_stable_denial(self):
        context = ToolContext(operation="execute")
        decision = PolicyDecision(False, "TOOL_HARD_DENY", context)
        with self.assertRaises(PolicyDenied) as raised:
            decision.require()
        self.assertEqual(raised.exception.reason_code, "TOOL_HARD_DENY")
        self.assertIs(raised.exception.decision, decision)
        with self.assertRaises(FrozenInstanceError):
            decision.allowed = True

    def test_runtime_mutation_cannot_weaken_ratified_policy(self):
        with self.assertRaises(TypeError):
            policy_module._TOOL_PLUGIN["get_document"] = "external"

        with patch.dict(SENSITIVE_FIELDS, {"all_doctypes": []}):
            with patch.dict(ADMIN_ONLY_FIELDS, {"all_doctypes": []}):
                sensitive = self._authorize(
                    "update_document",
                    {"doctype": "ToDo", "name": "TD-1", "data": {"bank_account_no": "never"}},
                )
                admin_only = self._authorize(
                    "update_document",
                    {"doctype": "ToDo", "name": "TD-1", "data": {"owner": "never"}},
                )

        self.assertEqual(sensitive.reason_code, "FIELD_RESTRICTED")
        self.assertEqual(admin_only.reason_code, "FIELD_RESTRICTED")

    def test_hard_deny_cannot_be_overridden_for_system_manager(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(SecurityPolicy, "_is_actor_enabled", return_value=True))
            stack.enter_context(patch.object(SecurityPolicy, "_is_plugin_enabled", return_value=True))
            stack.enter_context(
                patch.object(SecurityPolicy, "_load_access_config", return_value=ALLOW_SYSTEM_MANAGER)
            )
            stack.enter_context(
                patch.object(SecurityPolicy, "_get_actor_roles", return_value={"System Manager"})
            )
            decision = SecurityPolicy.authorize(
                actor="Administrator",
                tool_name="run_python_code",
                arguments={"code": "print('never')"},
                phase="execute",
            )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "TOOL_HARD_DENY")
        self.assertTrue(EXPECTED_24_TOOLS & HARD_DENY_TOOLS)

    def test_missing_config_allow_all_and_empty_roles_fail_closed(self):
        cases = (
            (None, "CONFIG_MISSING"),
            (ALLOW_ALL, "CONFIG_MODE_DENIED"),
            ({"enabled": True, "role_access_mode": "Deny All", "roles": set()}, "CONFIG_MODE_DENIED"),
            (
                {"enabled": True, "role_access_mode": "Restrict to Listed Roles", "roles": set()},
                "ROLE_NOT_ALLOWED",
            ),
        )
        for config, reason in cases:
            with self.subTest(reason=reason):
                decision = self._authorize("get_document", {"doctype": "ToDo", "name": "TD-1"}, config)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason_code, reason)

    def test_role_intersection_allows_without_privileged_bypass(self):
        decision = self._authorize("get_document", {"doctype": "ToDo", "name": "TD-1"})
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason_code, "ALLOWED")
        self.assertEqual(decision.context.required_permissions, frozenset({"read"}))

    def test_unknown_tool_and_disabled_plugin_fail_closed(self):
        unknown = self._authorize("not_registered", {})
        self.assertFalse(unknown.allowed)
        self.assertEqual(unknown.reason_code, "TOOL_UNKNOWN")

        with patch.object(SecurityPolicy, "_is_actor_enabled", return_value=True):
            with patch.object(SecurityPolicy, "_is_plugin_enabled", return_value=False):
                disabled = SecurityPolicy.authorize(
                    "agent@example.com",
                    "get_document",
                    {"doctype": "ToDo", "name": "TD-1"},
                    "execute",
                )
        self.assertFalse(disabled.allowed)
        self.assertEqual(disabled.reason_code, "PLUGIN_DISABLED")

    def test_actor_disabled_tool_disabled_and_native_permission_fail_closed(self):
        guest = SecurityPolicy.authorize("Guest", "get_document", {}, "execute")
        self.assertFalse(guest.allowed)
        self.assertEqual(guest.reason_code, "ACTOR_UNAUTHENTICATED")

        with patch.object(SecurityPolicy, "_is_actor_enabled", return_value=False):
            actor_disabled = SecurityPolicy.authorize(
                "agent@example.com", "get_document", {}, "execute"
            )
        self.assertFalse(actor_disabled.allowed)
        self.assertEqual(actor_disabled.reason_code, "ASSISTANT_DISABLED")

        config = dict(ALLOW_ASSISTANT_USER, enabled=False)
        tool_disabled = self._authorize(
            "get_document", {"doctype": "ToDo", "name": "TD-1"}, config
        )
        self.assertFalse(tool_disabled.allowed)
        self.assertEqual(tool_disabled.reason_code, "TOOL_DISABLED")

        with ExitStack() as stack:
            stack.enter_context(patch.object(SecurityPolicy, "_is_actor_enabled", return_value=True))
            stack.enter_context(patch.object(SecurityPolicy, "_is_plugin_enabled", return_value=True))
            stack.enter_context(
                patch.object(
                    SecurityPolicy, "_load_access_config", return_value=ALLOW_ASSISTANT_USER
                )
            )
            stack.enter_context(
                patch.object(SecurityPolicy, "_get_actor_roles", return_value={"Assistant User"})
            )
            stack.enter_context(
                patch.object(SecurityPolicy, "_has_native_permissions", return_value=False)
            )
            native_denied = SecurityPolicy.authorize(
                "agent@example.com",
                "get_document",
                {"doctype": "ToDo", "name": "TD-1"},
                "execute",
            )
        self.assertFalse(native_denied.allowed)
        self.assertEqual(native_denied.reason_code, "NATIVE_PERMISSION_DENIED")

    def test_fetch_and_submit_context_are_deterministic(self):
        fetch = self._authorize("fetch", {"id": "ToDo/TD/2026/0001"})
        self.assertTrue(fetch.allowed)
        self.assertEqual(fetch.context.target_doctype, "ToDo")
        self.assertEqual(fetch.context.target_name, "TD/2026/0001")

        create = self._authorize(
            "create_document",
            {"doctype": "ToDo", "data": {"description": "safe"}, "submit": True},
        )
        self.assertTrue(create.allowed)
        self.assertEqual(create.context.operation, "create")
        self.assertEqual(create.context.required_permissions, frozenset({"create", "submit"}))

    def test_restricted_doctype_and_nested_sensitive_fields_are_denied(self):
        restricted = self._authorize("get_document", {"doctype": "User", "name": "Administrator"})
        self.assertFalse(restricted.allowed)
        self.assertEqual(restricted.reason_code, "DOCTYPE_RESTRICTED")

        nested = self._authorize(
            "update_document",
            {
                "doctype": "ToDo",
                "name": "TD-1",
                "data": {"items": [{"item_code": "A", "api_secret": "never"}]},
            },
        )
        self.assertFalse(nested.allowed)
        self.assertEqual(nested.reason_code, "FIELD_RESTRICTED")

        filter_list = self._authorize(
            "list_documents",
            {"doctype": "ToDo", "filters": [["api_secret", "=", "never"]]},
        )
        self.assertFalse(filter_list.allowed)
        self.assertEqual(filter_list.reason_code, "FIELD_RESTRICTED")

    def test_invalid_context_and_policy_exceptions_fail_closed(self):
        invalid = self._authorize("fetch", {"id": "missing-slash"})
        self.assertFalse(invalid.allowed)
        self.assertEqual(invalid.reason_code, "ARGUMENT_CONTEXT_INVALID")

        with patch.object(SecurityPolicy, "_is_actor_enabled", side_effect=RuntimeError("boom")):
            failed = SecurityPolicy.authorize("agent@example.com", "get_document", {}, "execute")
        self.assertFalse(failed.allowed)
        self.assertEqual(failed.reason_code, "POLICY_ERROR_FAIL_CLOSED")

    def test_execute_uses_fresh_configuration_and_publish_may_cache(self):
        for phase, fresh in (("execute", True), ("publish", False)):
            with self.subTest(phase=phase):
                with ExitStack() as stack:
                    stack.enter_context(
                        patch.object(SecurityPolicy, "_is_actor_enabled", return_value=True)
                    )
                    plugin_check = stack.enter_context(
                        patch.object(SecurityPolicy, "_is_plugin_enabled", return_value=True)
                    )
                    config = stack.enter_context(
                        patch.object(
                            SecurityPolicy,
                            "_load_access_config",
                            return_value=ALLOW_ASSISTANT_USER,
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            SecurityPolicy,
                            "_get_actor_roles",
                            return_value={"Assistant User"},
                        )
                    )
                    stack.enter_context(
                        patch.object(SecurityPolicy, "_has_native_permissions", return_value=True)
                    )
                    decision = SecurityPolicy.authorize(
                        "agent@example.com",
                        "get_document",
                        {"doctype": "ToDo", "name": "TD-1"},
                        phase,
                    )
                self.assertTrue(decision.allowed)
                plugin_check.assert_called_once_with("core", fresh=fresh)
                config.assert_called_once_with("get_document", fresh=fresh)

    def test_publish_does_not_require_call_arguments(self):
        with ExitStack() as stack:
            stack.enter_context(
                patch.object(SecurityPolicy, "_is_actor_enabled", return_value=True)
            )
            stack.enter_context(
                patch.object(SecurityPolicy, "_is_plugin_enabled", return_value=True)
            )
            stack.enter_context(
                patch.object(
                    SecurityPolicy,
                    "_load_access_config",
                    return_value=ALLOW_ASSISTANT_USER,
                )
            )
            stack.enter_context(
                patch.object(
                    SecurityPolicy,
                    "_get_actor_roles",
                    return_value={"Assistant User"},
                )
            )
            native = stack.enter_context(
                patch.object(SecurityPolicy, "_has_native_permissions")
            )
            decision = SecurityPolicy.authorize(
                "agent@example.com",
                "get_document",
                None,
                "publish",
            )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.context.operation, "publish")
        native.assert_not_called()
