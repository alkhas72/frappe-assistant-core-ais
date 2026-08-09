"""Contract tests for the canonical policy-driven tool registry path."""

from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import frappe

from frappe_assistant_core.core.base_tool import BaseTool
from frappe_assistant_core.core.security_policy import (
    PolicyDecision,
    PolicyDenied,
    SecurityPolicy,
    ToolContext,
)
from frappe_assistant_core.core.tool_registry import ToolRegistry
from frappe_assistant_core.mcp.server import MCPServer
from frappe_assistant_core.mcp.tool_adapter import build_tool_dict
from frappe_assistant_core.plugins.core.tools.get_document import DocumentGet
from frappe_assistant_core.tests.base_test import BaseAssistantTest
from frappe_assistant_core.tests.test_security_migration import (
    _restore_security_rows,
    _security_snapshot_hash,
    _snapshot_security_rows,
)
from frappe_assistant_core.utils.plugin_manager import get_plugin_manager

_module_security_snapshot = None


def setUpModule():
    global _module_security_snapshot
    _module_security_snapshot = _snapshot_security_rows()


def tearDownModule():
    after = _snapshot_security_rows()
    before_hash = _security_snapshot_hash(_module_security_snapshot)
    after_hash = _security_snapshot_hash(after)
    try:
        if after_hash != before_hash:
            raise AssertionError(
                f"FAC execution-policy snapshot changed: before={before_hash}, after={after_hash}"
            )
    finally:
        _restore_security_rows(_module_security_snapshot)
        frappe.db.commit()


class _DummyTool:
    name = "dummy"
    description = "Dummy tool"
    inputSchema = {"type": "object", "properties": {}}

    def _safe_execute(self, arguments):
        raise AssertionError("adapter bypassed the canonical executor")


class TestToolAdapterExecutor(BaseAssistantTest):
    def test_adapter_routes_through_registry_executor(self):
        executor = MagicMock(return_value={"ok": True})
        tool_dict = build_tool_dict(_DummyTool(), executor=executor)

        self.assertEqual(tool_dict["fn"](name="A"), {"ok": True})
        executor.assert_called_once_with("dummy", {"name": "A"})

    def test_adapter_rejects_missing_executor(self):
        with self.assertRaises(TypeError):
            build_tool_dict(_DummyTool())


class TestPolicyDrivenRegistry(BaseAssistantTest):
    def test_publication_uses_policy_not_legacy_registry_checks(self):
        allowed_tool = MagicMock()
        allowed_tool.get_metadata.return_value = {"name": "allowed"}
        denied_tool = MagicMock()
        denied_tool.get_metadata.return_value = {"name": "denied"}
        manager = MagicMock()
        manager.get_all_tools.return_value = {
            "allowed": SimpleNamespace(name="allowed", instance=allowed_tool),
            "denied": SimpleNamespace(name="denied", instance=denied_tool),
        }

        def decide(actor, tool_name, arguments, phase):
            self.assertEqual(actor, "actor@example.com")
            self.assertIsNone(arguments)
            self.assertEqual(phase, "publish")
            return PolicyDecision(
                allowed=tool_name == "allowed",
                reason_code="ALLOWED" if tool_name == "allowed" else "TOOL_DISABLED",
                context=ToolContext(operation="publish"),
            )

        registry = ToolRegistry()
        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "frappe_assistant_core.core.tool_registry.get_plugin_manager",
                    return_value=manager,
                )
            )
            stack.enter_context(patch.object(registry, "_get_external_tools", return_value={}))
            stack.enter_context(
                patch.object(
                    registry,
                    "_is_tool_accessible",
                    side_effect=AssertionError("legacy access path called"),
                )
            )
            stack.enter_context(
                patch.object(
                    registry,
                    "_check_tool_permission",
                    side_effect=AssertionError("legacy permission path called"),
                )
            )
            authorize = stack.enter_context(patch.object(SecurityPolicy, "authorize", side_effect=decide))
            published = registry.get_available_tools(user="actor@example.com")

        self.assertEqual(published, [{"name": "allowed"}])
        self.assertEqual(authorize.call_count, 2)
        denied_tool.get_metadata.assert_not_called()

    def test_known_execution_calls_safe_execute_without_legacy_prechecks(self):
        tool = MagicMock()
        tool._safe_execute.return_value = {"success": True, "result": {"ok": True}}
        registry = ToolRegistry()

        with ExitStack() as stack:
            stack.enter_context(patch.object(registry, "get_tool", return_value=tool))
            stack.enter_context(
                patch.object(
                    registry,
                    "_is_tool_accessible",
                    side_effect=AssertionError("legacy access path called"),
                )
            )
            stack.enter_context(
                patch.object(
                    registry,
                    "_check_tool_permission",
                    side_effect=AssertionError("legacy permission path called"),
                )
            )
            result = registry.execute_tool("get_document", {"doctype": "ToDo", "name": "TD-1"})

        self.assertEqual(result, {"ok": True})
        tool._safe_execute.assert_called_once_with({"doctype": "ToDo", "name": "TD-1"})

    def test_unknown_tool_is_audited_and_raises_policy_denied(self):
        registry = ToolRegistry()
        with ExitStack() as stack:
            stack.enter_context(patch.object(registry, "get_tool", return_value=None))
            audit = stack.enter_context(
                patch("frappe_assistant_core.utils.audit_trail.log_denied_tool_attempt")
            )
            with self.assertRaises(PolicyDenied) as raised:
                registry.execute_tool("unknown-tool", {"token": "never-log"})

        self.assertEqual(raised.exception.reason_code, "TOOL_UNKNOWN")
        audit.assert_called_once()
        self.assertEqual(audit.call_args.kwargs["reason_code"], "TOOL_UNKNOWN")

    def test_non_string_tool_name_is_audited_and_raises_policy_denied(self):
        registry = ToolRegistry()
        with patch("frappe_assistant_core.utils.audit_trail.log_denied_tool_attempt") as audit:
            with self.assertRaises(PolicyDenied) as raised:
                registry.execute_tool(["not", "a", "name"], {})

        self.assertEqual(raised.exception.reason_code, "TOOL_UNKNOWN")
        audit.assert_called_once()
        self.assertEqual(
            audit.call_args.kwargs["tool_name"],
            "<invalid-tool-name>",
        )


class TestExecuteTimeConfigurationFreshness(BaseAssistantTest):
    tool_name = "get_document"

    def setUp(self):
        super().setUp()
        frappe.set_user("Administrator")
        self._fac_security_snapshot = _snapshot_security_rows()
        self.actor = "fac-task3-config@example.com"
        self.assertFalse(frappe.db.exists("User", self.actor))
        frappe.get_doc(
            {
                "doctype": "User",
                "email": self.actor,
                "first_name": "FAC Task 3 Config",
                "enabled": 1,
                "user_type": "System User",
                "assistant_enabled": 1,
                "roles": [{"role": "System Manager"}],
            }
        ).insert(ignore_permissions=True)
        self.registry = ToolRegistry()
        self.plugin_manager = get_plugin_manager()

        frappe.db.set_value(
            "FAC Plugin Configuration",
            "core",
            "enabled",
            1,
            update_modified=False,
        )
        config = frappe.get_doc("FAC Tool Configuration", self.tool_name)
        config.enabled = 1
        config.role_access_mode = "Restrict to Listed Roles"
        config.set("role_access", [])
        config.append(
            "role_access",
            {"role": "System Manager", "allow_access": 1},
        )
        config.save(ignore_permissions=True)
        self.plugin_manager.refresh_plugins()
        self.registry.clear_cache()
        frappe.set_user(self.actor)

    def tearDown(self):
        try:
            frappe.set_user("Administrator")
            if frappe.db.exists("User", self.actor):
                frappe.delete_doc("User", self.actor, force=True)
            _restore_security_rows(self._fac_security_snapshot)
            restored = _snapshot_security_rows()
            self.assertEqual(restored, self._fac_security_snapshot)
            frappe.db.commit()
            self.plugin_manager.refresh_plugins()
            self.registry.clear_cache()
        finally:
            super().tearDown()

    def _assert_published(self, actor=None):
        actor = actor or self.actor
        decision = SecurityPolicy.authorize(
            actor=actor,
            tool_name=self.tool_name,
            arguments=None,
            phase="publish",
        )
        self.assertTrue(
            decision.allowed,
            f"publication denied: {decision.reason_code}",
        )
        published = self.registry.get_available_tools(user=actor)
        self.assertIn(self.tool_name, {tool["name"] for tool in published})

    def _assert_execute_denied(self):
        with self.assertRaises(PolicyDenied) as raised:
            self.registry.execute_tool(
                self.tool_name,
                {"doctype": "ToDo", "name": "TD-DOES-NOT-MATTER"},
            )
        self.assertEqual(raised.exception.reason_code, "TOOL_DISABLED")

    def test_disabled_after_publication_via_save_is_denied_at_call_time(self):
        self._assert_published()
        config = frappe.get_doc("FAC Tool Configuration", self.tool_name)
        config.enabled = 0
        config.save(ignore_permissions=True)
        self._assert_execute_denied()

    def test_disabled_after_publication_via_db_set_value_is_denied_at_call_time(self):
        self._assert_published()
        frappe.db.set_value(
            "FAC Tool Configuration",
            self.tool_name,
            "enabled",
            0,
            update_modified=False,
        )
        self._assert_execute_denied()

    def test_saved_mcp_publication_denies_once_after_tool_is_disabled(self):
        self._assert_published()
        tool = self.registry.get_tool(self.tool_name)
        published_tool = build_tool_dict(
            tool,
            executor=self.registry.execute_tool,
        )
        frappe.db.set_value(
            "FAC Tool Configuration",
            self.tool_name,
            "enabled",
            0,
            update_modified=False,
        )

        server = MCPServer("task4-toctou")
        with ExitStack() as stack:
            body = stack.enter_context(patch.object(tool, "execute"))
            execution_audit = stack.enter_context(patch.object(BaseTool, "log_execution"))
            boundary_audit = stack.enter_context(
                patch("frappe_assistant_core.mcp.server.audit_unavailable_tool_call")
            )
            result = server._handle_tools_call(
                {
                    "name": self.tool_name,
                    "arguments": {
                        "doctype": "ToDo",
                        "name": "TD-DOES-NOT-MATTER",
                    },
                },
                {self.tool_name: published_tool},
            )

        self.assertTrue(result["isError"])
        self.assertEqual(result["content"][0]["text"], "Tool is not available")
        body.assert_not_called()
        execution_audit.assert_called_once()
        boundary_audit.assert_not_called()

    def test_plugin_disabled_after_publication_is_classified_and_audited_once(self):
        self._assert_published()
        frappe.db.set_value(
            "FAC Plugin Configuration",
            "core",
            "enabled",
            0,
            update_modified=False,
        )
        self.plugin_manager.refresh_plugins()

        with ExitStack() as stack:
            empty_manager = MagicMock()
            empty_manager.get_all_tools.return_value = {}
            stack.enter_context(
                patch(
                    "frappe_assistant_core.core.tool_registry.get_plugin_manager",
                    return_value=empty_manager,
                )
            )
            unknown_audit = stack.enter_context(
                patch("frappe_assistant_core.utils.audit_trail.log_denied_tool_attempt")
            )
            execution_audit = stack.enter_context(patch.object(BaseTool, "log_execution"))
            with self.assertRaises(PolicyDenied) as raised:
                self.registry.execute_tool(
                    self.tool_name,
                    {"doctype": "ToDo", "name": "TD-DOES-NOT-MATTER"},
                )

        self.assertEqual(raised.exception.reason_code, "PLUGIN_DISABLED")
        unknown_audit.assert_not_called()
        execution_audit.assert_called_once()

    def test_role_revoked_after_publication_is_denied_without_cache_clear(self):
        actor = "fac-task3-role-revoke@example.com"
        self.assertFalse(frappe.db.exists("User", actor))
        user = frappe.get_doc(
            {
                "doctype": "User",
                "email": actor,
                "first_name": "FAC Task 3",
                "enabled": 1,
                "user_type": "System User",
                "assistant_enabled": 1,
                "roles": [{"role": "System Manager"}],
            }
        )
        user.insert(ignore_permissions=True)

        try:
            self._assert_published(actor=actor)
            frappe.db.delete(
                "Has Role",
                {
                    "parent": actor,
                    "parenttype": "User",
                    "role": "System Manager",
                },
            )

            frappe.set_user(actor)
            with self.assertRaises(PolicyDenied) as raised:
                self.registry.execute_tool(
                    self.tool_name,
                    {"doctype": "ToDo", "name": "TD-DOES-NOT-MATTER"},
                )
            self.assertEqual(raised.exception.reason_code, "ROLE_NOT_ALLOWED")
        finally:
            frappe.set_user("Administrator")
            frappe.delete_doc("User", actor, force=True)

    def test_administrator_cannot_use_a_role_not_assigned_in_has_role(self):
        actor = "fac-integration-policy-role@example.com"
        role_name = "FAC Integration Policy Role"
        self.assertFalse(frappe.db.exists("User", actor))
        self.assertFalse(frappe.db.exists("Role", role_name))
        frappe.get_doc({"doctype": "Role", "role_name": role_name, "disabled": 0}).insert(
            ignore_permissions=True
        )
        frappe.get_doc(
            {
                "doctype": "User",
                "email": actor,
                "first_name": "FAC Integration Policy Role",
                "enabled": 1,
                "user_type": "System User",
                "assistant_enabled": 1,
                "roles": [{"role": role_name}],
            }
        ).insert(ignore_permissions=True)

        config = frappe.get_doc("FAC Tool Configuration", self.tool_name)
        config.set("role_access", [])
        config.append("role_access", {"role": role_name, "allow_access": 1})
        config.save(ignore_permissions=True)

        try:
            self.assertFalse(
                frappe.db.exists(
                    "Has Role",
                    {
                        "parent": "Administrator",
                        "parenttype": "User",
                        "role": role_name,
                    },
                )
            )
            with patch.object(
                SecurityPolicy, "inventory", return_value=frozenset({self.tool_name})
            ), patch.object(SecurityPolicy, "_has_native_permissions", return_value=True):
                administrator_publish = SecurityPolicy.authorize(
                    actor="Administrator",
                    tool_name=self.tool_name,
                    arguments=None,
                    phase="publish",
                )
                administrator_tools = self.registry.get_available_tools(user="Administrator")
                assigned_actor_tools = self.registry.get_available_tools(user=actor)
                administrator_execute = SecurityPolicy.authorize(
                    actor="Administrator",
                    tool_name=self.tool_name,
                    arguments={"doctype": "ToDo", "name": "TD-DOES-NOT-MATTER"},
                    phase="execute",
                )
                assigned_actor = SecurityPolicy.authorize(
                    actor=actor,
                    tool_name=self.tool_name,
                    arguments={"doctype": "ToDo", "name": "TD-DOES-NOT-MATTER"},
                    phase="execute",
                )
                frappe.db.set_value("Role", role_name, "disabled", 1, update_modified=False)
                disabled_role = SecurityPolicy.authorize(
                    actor=actor,
                    tool_name=self.tool_name,
                    arguments={"doctype": "ToDo", "name": "TD-DOES-NOT-MATTER"},
                    phase="execute",
                )

            self.assertFalse(administrator_publish.allowed)
            self.assertEqual(administrator_publish.reason_code, "ROLE_NOT_ALLOWED")
            self.assertNotIn(self.tool_name, {tool["name"] for tool in administrator_tools})
            self.assertIn(self.tool_name, {tool["name"] for tool in assigned_actor_tools})
            self.assertFalse(administrator_execute.allowed)
            self.assertEqual(administrator_execute.reason_code, "ROLE_NOT_ALLOWED")
            self.assertTrue(assigned_actor.allowed)
            self.assertEqual(assigned_actor.reason_code, "ALLOWED")
            self.assertFalse(disabled_role.allowed)
            self.assertEqual(disabled_role.reason_code, "ROLE_NOT_ALLOWED")
        finally:
            frappe.delete_doc("User", actor, force=True)
            frappe.db.delete("Role", role_name)

    def test_disabled_role_after_publication_is_denied_without_resaving_config(self):
        actor = "fac-task-role-disabled@example.com"
        role_name = "FAC Task Disabled Role"
        self.assertFalse(frappe.db.exists("User", actor))
        self.assertFalse(frappe.db.exists("Role", role_name))
        frappe.get_doc({"doctype": "Role", "role_name": role_name, "disabled": 0}).insert(
            ignore_permissions=True
        )
        frappe.get_doc(
            {
                "doctype": "User",
                "email": actor,
                "first_name": "FAC Task Disabled Role",
                "enabled": 1,
                "user_type": "System User",
                "assistant_enabled": 1,
                "roles": [{"role": role_name}],
            }
        ).insert(ignore_permissions=True)

        config = frappe.get_doc("FAC Tool Configuration", self.tool_name)
        config.set("role_access", [])
        config.append("role_access", {"role": role_name, "allow_access": 1})
        config.save(ignore_permissions=True)

        try:
            # The fac-test image intentionally lacks pandas, so inventory
            # discovery of unrelated optional plugins fails closed. Isolate the
            # test to get_document while retaining real Frappe DB role/config
            # reads and the canonical execution path.
            with patch.object(SecurityPolicy, "inventory", return_value=frozenset({self.tool_name})):
                published = SecurityPolicy.authorize(
                    actor=actor,
                    tool_name=self.tool_name,
                    arguments=None,
                    phase="publish",
                )
                self.assertTrue(published.allowed)
                frappe.db.set_value("Role", role_name, "disabled", 1, update_modified=False)

                self.assertNotIn(
                    role_name,
                    SecurityPolicy._load_access_config(self.tool_name, fresh=True)["roles"],
                )
                self.assertNotIn(
                    role_name,
                    SecurityPolicy._get_actor_roles(actor, fresh=True),
                )

                frappe.set_user(actor)
                tool = DocumentGet()
                with patch.object(self.registry, "get_tool", return_value=tool), patch.object(
                    BaseTool, "log_execution"
                ) as execution_audit:
                    with self.assertRaises(PolicyDenied) as raised:
                        self.registry.execute_tool(
                            self.tool_name,
                            {"doctype": "ToDo", "name": "TD-DOES-NOT-MATTER"},
                        )

            self.assertEqual(raised.exception.reason_code, "ROLE_NOT_ALLOWED")
            execution_audit.assert_called_once()
        finally:
            frappe.set_user("Administrator")
            frappe.delete_doc("User", actor, force=True)
            frappe.db.delete("Role", role_name)
