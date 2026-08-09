"""Independent black-box acceptance matrix for FAC security (Task 8 v2).

Treats ToolRegistry, MCPServer and audit persistence as public interfaces.
Literal snapshots are independent of production constants; equality checks
compare both sides and fail on extra, missing or ambiguous inventory.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable, Iterable
from unittest.mock import MagicMock, patch

import frappe
from frappe.tests.utils import FrappeTestCase
from werkzeug.wrappers import Response

from frappe_assistant_core.core.security_policy import (
    CONFIGURABLE_TOOLS as PROD_CONFIGURABLE,
)
from frappe_assistant_core.core.security_policy import (
    HARD_DENY_TOOLS as PROD_HARD_DENY,
)
from frappe_assistant_core.core.security_policy import (
    RESTRICTED_DOCTYPES as PROD_RESTRICTED,
)
from frappe_assistant_core.core.security_policy import (
    PolicyDenied,
    SecurityPolicy,
    discover_builtin_tool_names,
)
from frappe_assistant_core.core.tool_registry import ToolRegistry
from frappe_assistant_core.mcp.server import MCPServer
from frappe_assistant_core.mcp.tool_adapter import build_tool_dict
from frappe_assistant_core.tests.test_security_migration import (
    _restore_security_rows,
    _security_snapshot_hash,
    _snapshot_security_rows,
)

_module_security_snapshot = None


def setUpModule():
    global _module_security_snapshot
    _module_security_snapshot = _snapshot_security_rows()


def tearDownModule():
    frappe.set_user("Administrator")
    frappe.db.delete(
        "Assistant Audit Log",
        {"session_id": ("like", "fac-t8-matrix-%")},
    )
    after = _snapshot_security_rows()
    before_hash = _security_snapshot_hash(_module_security_snapshot)
    after_hash = _security_snapshot_hash(after)
    try:
        if after_hash != before_hash:
            raise AssertionError(
                f"FAC matrix snapshot changed: before={before_hash}, after={after_hash}"
            )
    finally:
        _restore_security_rows(_module_security_snapshot)
        frappe.db.commit()

# --- Literal acceptance snapshots (independent of production imports) ---------

EXPECTED_24_TOOLS = frozenset(
    {
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
)

EXPECTED_HARD_DENY_BUILTIN = frozenset(
    {
        "delete_document",
        "run_python_code",
        "run_database_query",
        "analyze_business_data",
        "extract_file_content",
        "create_dashboard",
        "create_dashboard_chart",
        "list_user_dashboards",
    }
)

EXPECTED_CONFIGURABLE = EXPECTED_24_TOOLS - EXPECTED_HARD_DENY_BUILTIN

EXPECTED_RESTRICTED_DOCTYPES = frozenset(
    {
        "User",
        "Role",
        "User Permission",
        "Role Permission",
        "Custom Role",
        "Module Profile",
        "Role Profile",
        "Custom DocPerm",
        "DocShare",
        "System Settings",
        "Print Settings",
        "Email Domain",
        "LDAP Settings",
        "OAuth Settings",
        "Social Login Key",
        "Dropbox Settings",
        "Connected App",
        "OAuth Bearer Token",
        "OAuth Client",
        "Error Log",
        "Activity Log",
        "Access Log",
        "View Log",
        "Scheduler Log",
        "Integration Request",
        "Server Script",
        "Client Script",
        "Custom Script",
        "Property Setter",
        "Customize Form",
        "Customize Form Field",
        "DocType",
        "DocField",
        "DocPerm",
        "Custom Field",
        "Package",
        "Package Release",
        "Installed Application",
        "Data Import",
        "Data Export",
        "Bulk Update",
        "Rename Tool",
        "Database Storage Usage By Tables",
        "Workflow",
        "Workflow Action",
        "Workflow State",
        "Workflow Transition",
        "Email Queue",
        "Email Queue Recipient",
        "Email Alert",
        "Auto Email Report",
        "File",
        "Assistant Core Settings",
        "FAC Tool Configuration",
        "FAC Tool Role Access",
        "FAC Plugin Configuration",
        "Assistant Audit Log",
    }
)

ACTOR_ROLES = {
    "Assistant User": "Assistant User",
    "Assistant Admin": "Assistant Admin",
    "System Manager": "System Manager",
}

REAL_CHILD_DOCTYPE = "Has Role"


def _make_tools_call_request(tool_name: str, arguments: dict, request_id: int) -> MagicMock:
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    request = MagicMock()
    request.method = "POST"
    request.headers = {}
    request.get_json.return_value = payload
    request.get_data.return_value = json.dumps(payload)
    return request


def _make_tools_list_request(request_id: int) -> MagicMock:
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/list",
        "params": {},
    }
    request = MagicMock()
    request.method = "POST"
    request.headers = {}
    request.get_json.return_value = payload
    request.get_data.return_value = json.dumps(payload)
    return request


def _handle_mcp(server: MCPServer, request: MagicMock, tool_registry: OrderedDict) -> Response:
    frappe.local.request = request
    return server.handle(request, Response(), tool_registry=tool_registry)


def _result_of(response: Response) -> dict:
    body = json.loads(response.get_data(as_text=True))
    return body.get("result", {})


@dataclass(frozen=True)
class ConfigScenario:
    label: str
    setup: Callable[[SecurityMatrixAcceptance], None]
    publish_allowed: bool
    execute_reason: str | None  # None => success path for Assistant User only


class _RecordHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(self.format(record))


class SecurityMatrixAcceptance(FrappeTestCase):
    """Actor × configuration × phase acceptance through registry/MCP."""

    configurable_probe = "get_document"
    secret_marker: str

    def setUp(self):
        super().setUp()
        frappe.flags.in_test = True
        frappe.set_user("Administrator")
        self.fac_security_snapshot = _snapshot_security_rows()
        self.run_id = uuid.uuid4().hex[:12]
        self.session_id = f"fac-t8-matrix-{self.run_id}"
        self.secret_marker = f"fac-t8-secret-{self.run_id}"
        self.created_users: list[str] = []
        self.created_todos: list[str] = []
        self.created_roles: list[str] = []
        self.config_snapshots: dict[str, dict] = {}
        self.plugin_snapshots: dict[str, bool] = {}
        self.deleted_tool_configs: dict[str, dict] = {}
        self.probe_baseline = self._capture_tool_config(self.configurable_probe)
        self.core_plugin_baseline = bool(
            frappe.db.get_value("FAC Plugin Configuration", "core", "enabled")
        )
        self.actors = {label: self._unique_email(label) for label in ACTOR_ROLES}
        for label, email in self.actors.items():
            self._ensure_actor(email, ACTOR_ROLES[label])
        self.mismatch_role = f"FAC Matrix Mismatch {self.run_id}"
        frappe.get_doc(
            {
                "doctype": "Role",
                "role_name": self.mismatch_role,
                "disabled": 0,
            }
        ).insert(ignore_permissions=True)
        self.created_roles.append(self.mismatch_role)

    def tearDown(self):
        try:
            super().tearDown()
        finally:
            frappe.set_user("Administrator")
            frappe.db.delete(
                "Assistant Audit Log",
                {"session_id": ("like", f"{self.session_id}%")},
            )
            for name in self.created_todos:
                if frappe.db.exists("ToDo", name):
                    frappe.delete_doc("ToDo", name, force=True)
            for email in self.created_users:
                if frappe.db.exists("User", email):
                    frappe.delete_doc("User", email, force=True)
            for role in self.created_roles:
                if frappe.db.exists("Role", role):
                    frappe.delete_doc("Role", role, force=True)
            _restore_security_rows(self.fac_security_snapshot)
            self.assertEqual(_snapshot_security_rows(), self.fac_security_snapshot)
            frappe.db.commit()
            ToolRegistry().clear_cache()

    # --- helpers ------------------------------------------------------------

    def _unique_email(self, label: str) -> str:
        slug = label.lower().replace(" ", "-")
        return f"fac-t8-{self.run_id}-{slug}@example.com"

    def _ensure_actor(self, email: str, role: str | Iterable[str]) -> None:
        if frappe.db.exists("User", email):
            return
        roles = (role,) if isinstance(role, str) else tuple(role)
        user = frappe.get_doc(
            {
                "doctype": "User",
                "email": email,
                "first_name": "FAC Task8",
                "enabled": 1,
                "user_type": "System User",
                "assistant_enabled": 1,
                "roles": [{"role": role_name} for role_name in roles],
            }
        )
        user.insert(ignore_permissions=True)
        self.created_users.append(email)

    def _capture_tool_config(self, tool_name: str) -> dict | None:
        if not frappe.db.exists("FAC Tool Configuration", tool_name):
            return None
        current = frappe.get_doc("FAC Tool Configuration", tool_name)
        return {
            "enabled": current.enabled,
            "role_access_mode": current.role_access_mode,
            "roles": [
                {"role": row.role, "allow_access": row.allow_access}
                for row in current.role_access
            ],
        }

    def _apply_tool_config(self, tool_name: str, snapshot: dict) -> None:
        config = frappe.get_doc("FAC Tool Configuration", tool_name)
        config.enabled = snapshot["enabled"]
        config.role_access_mode = snapshot["role_access_mode"]
        config.set("role_access", [])
        for row in snapshot["roles"]:
            config.append("role_access", row)
        config.save(ignore_permissions=True)
        ToolRegistry().clear_cache()

    def _snapshot_tool_config(self, tool_name: str) -> None:
        if tool_name in self.config_snapshots:
            return
        captured = self._capture_tool_config(tool_name)
        if captured is not None:
            self.config_snapshots[tool_name] = captured

    def _configure_tool(
        self,
        tool_name: str,
        *,
        enabled: bool = True,
        mode: str = "Restrict to Listed Roles",
        roles: Iterable[str] = (),
    ) -> None:
        self._snapshot_tool_config(tool_name)
        config = frappe.get_doc("FAC Tool Configuration", tool_name)
        config.enabled = int(enabled)
        config.role_access_mode = mode
        config.set("role_access", [])
        for role in roles:
            config.append("role_access", {"role": role, "allow_access": 1})
        config.save(ignore_permissions=True)
        ToolRegistry().clear_cache()

    def _remove_tool_config(self, tool_name: str) -> None:
        if tool_name not in self.deleted_tool_configs:
            doc = frappe.get_doc("FAC Tool Configuration", tool_name)
            self.deleted_tool_configs[tool_name] = doc.as_dict()
        frappe.delete_doc("FAC Tool Configuration", tool_name, force=True)
        ToolRegistry().clear_cache()

    def _reset_probe_configuration(self) -> None:
        frappe.set_user("Administrator")
        if self.probe_baseline is not None:
            if not frappe.db.exists("FAC Tool Configuration", self.configurable_probe):
                payload = self.deleted_tool_configs[self.configurable_probe]
                frappe.get_doc(payload).insert(ignore_permissions=True)
            self._apply_tool_config(self.configurable_probe, self.probe_baseline)
        frappe.db.set_value(
            "FAC Plugin Configuration",
            "core",
            "enabled",
            int(self.core_plugin_baseline),
            update_modified=False,
        )
        ToolRegistry().clear_cache()

    def _snapshot_plugin(self, plugin_name: str) -> None:
        if plugin_name in self.plugin_snapshots:
            return
        enabled = frappe.db.get_value("FAC Plugin Configuration", plugin_name, "enabled")
        self.plugin_snapshots[plugin_name] = bool(enabled)

    def _set_plugin_enabled(self, plugin_name: str, enabled: bool) -> None:
        self._snapshot_plugin(plugin_name)
        frappe.db.set_value(
            "FAC Plugin Configuration",
            plugin_name,
            "enabled",
            int(enabled),
            update_modified=False,
        )
        ToolRegistry().clear_cache()

    def _bind_session(self, actor: str) -> None:
        frappe.set_user(actor)
        frappe.local.assistant_session_id = self.session_id
        frappe.local.assistant_client_id = f"matrix-client-{self.run_id}"

    def _create_todo(
        self,
        description: str = "FAC Task8 matrix",
        allocated_to: str | None = None,
    ) -> str:
        payload = {"doctype": "ToDo", "description": description}
        if allocated_to:
            payload["allocated_to"] = allocated_to
        doc = frappe.get_doc(payload)
        doc.insert(ignore_permissions=True)
        self.created_todos.append(doc.name)
        return doc.name

    def _audit_count(self, user: str, tool_name: str) -> int:
        return frappe.db.count(
            "Assistant Audit Log",
            {"user": user, "tool_name": tool_name, "session_id": self.session_id},
        )

    def _security_audit_count(self, user: str, event_type: str) -> int:
        return frappe.db.count(
            "Assistant Audit Log",
            {
                "user": user,
                "action": f"security_{event_type}",
                "session_id": self.session_id,
            },
        )

    def _assert_exactly_one_audit(self, user: str, tool_name: str, before: int) -> None:
        after = self._audit_count(user, tool_name)
        self.assertEqual(
            after,
            before + 1,
            f"Expected exactly one audit row for user={user} tool={tool_name}",
        )

    def _published_registry(self, actor: str) -> OrderedDict[str, dict]:
        self._bind_session(actor)
        registry = ToolRegistry()
        published: OrderedDict[str, dict] = OrderedDict()
        for meta in registry.get_available_tools(user=actor):
            tool = registry.get_tool(meta["name"])
            published[meta["name"]] = build_tool_dict(tool, registry.execute_tool)
        return published

    def _published_names(self, actor: str) -> set[str]:
        self._bind_session(actor)
        registry = ToolRegistry()
        return {tool["name"] for tool in registry.get_available_tools(user=actor)}

    def _mcp_tools_list(self, actor: str, registry: OrderedDict[str, dict]) -> set[str]:
        self._bind_session(actor)
        server = MCPServer(f"fac-matrix-list-{self.run_id}")
        before = self._audit_count(actor, "tools/list")
        result = server._handle_tools_list({}, registry)
        self._assert_exactly_one_audit(actor, "tools/list", before)
        return {tool["name"] for tool in result["tools"]}

    def _registry_execute(self, actor: str, tool_name: str, arguments: dict) -> Any:
        self._bind_session(actor)
        registry = ToolRegistry()
        return registry.execute_tool(tool_name, arguments)

    def _mcp_execute(self, actor: str, tool_name: str, arguments: dict) -> dict:
        self._bind_session(actor)
        registry = ToolRegistry()
        tool = registry.get_tool(tool_name)
        self.assertIsNotNone(tool)
        tools = {tool_name: build_tool_dict(tool, registry.execute_tool)}
        server = MCPServer(f"fac-matrix-call-{self.run_id}")
        return server._handle_tools_call({"name": tool_name, "arguments": arguments}, tools)

    def _todo_read_arguments(self, actor: str | None = None) -> dict:
        if actor:
            self._bind_session(actor)
        todo_name = self._create_todo(
            description=json.dumps({"authorization": f"Bearer {self.secret_marker}"}),
            allocated_to=actor,
        )
        return {"doctype": "ToDo", "name": todo_name}

    def _config_scenarios(self) -> list[ConfigScenario]:
        actor_role = "Assistant User"

        def missing(matrix: SecurityMatrixAcceptance) -> None:
            matrix._remove_tool_config(matrix.configurable_probe)

        def deny_all_disabled(matrix: SecurityMatrixAcceptance) -> None:
            matrix._configure_tool(
                matrix.configurable_probe,
                enabled=False,
                mode="Deny All",
            )

        def deny_all_enabled(matrix: SecurityMatrixAcceptance) -> None:
            matrix._configure_tool(
                matrix.configurable_probe,
                enabled=True,
                mode="Deny All",
            )

        def allow_all(matrix: SecurityMatrixAcceptance) -> None:
            matrix._configure_tool(
                matrix.configurable_probe,
                enabled=True,
                mode="Deny All",
            )
            frappe.db.set_value(
                "FAC Tool Configuration",
                matrix.configurable_probe,
                "role_access_mode",
                "Allow All",
                update_modified=False,
            )

        def empty_restricted(matrix: SecurityMatrixAcceptance) -> None:
            matrix._configure_tool(
                matrix.configurable_probe,
                mode="Deny All",
            )
            frappe.db.set_value(
                "FAC Tool Configuration",
                matrix.configurable_probe,
                "role_access_mode",
                "Restrict to Listed Roles",
                update_modified=False,
            )

        def role_mismatch(matrix: SecurityMatrixAcceptance) -> None:
            matrix._configure_tool(
                matrix.configurable_probe,
                roles=(matrix.mismatch_role,),
            )

        def unknown_mode(matrix: SecurityMatrixAcceptance) -> None:
            matrix._configure_tool(
                matrix.configurable_probe,
                roles=(actor_role,),
            )
            frappe.db.set_value(
                "FAC Tool Configuration",
                matrix.configurable_probe,
                "role_access_mode",
                "Matrix Unknown Mode",
                update_modified=False,
            )
            ToolRegistry().clear_cache()

        def plugin_disabled(matrix: SecurityMatrixAcceptance) -> None:
            matrix._configure_tool(matrix.configurable_probe, roles=(actor_role,))
            matrix._set_plugin_enabled("core", False)

        def allowed(matrix: SecurityMatrixAcceptance) -> None:
            matrix._configure_tool(matrix.configurable_probe, roles=(actor_role,))

        return [
            ConfigScenario("missing", missing, False, "CONFIG_MISSING"),
            ConfigScenario("deny_all_disabled", deny_all_disabled, False, "TOOL_DISABLED"),
            ConfigScenario("deny_all_enabled", deny_all_enabled, False, "CONFIG_MODE_DENIED"),
            ConfigScenario("allow_all", allow_all, False, "CONFIG_MODE_DENIED"),
            ConfigScenario("empty_restricted", empty_restricted, False, "ROLE_NOT_ALLOWED"),
            ConfigScenario("role_mismatch", role_mismatch, False, "ROLE_NOT_ALLOWED"),
            ConfigScenario("unknown_mode", unknown_mode, False, "CONFIG_MODE_DENIED"),
            ConfigScenario("plugin_disabled", plugin_disabled, False, "PLUGIN_DISABLED"),
            ConfigScenario("explicit_allowed", allowed, True, None),
        ]

    # --- inventory snapshots ------------------------------------------------

    def test_literal_inventory_matches_production_discovery(self):
        discovered = discover_builtin_tool_names()
        inventory = SecurityPolicy.inventory()
        self.assertEqual(discovered, EXPECTED_24_TOOLS)
        self.assertEqual(inventory, EXPECTED_24_TOOLS)
        self.assertEqual(len(discovered), 24)

    def test_literal_hard_deny_builtin_matches_production_intersection(self):
        prod_builtin_hard = PROD_HARD_DENY & EXPECTED_24_TOOLS
        self.assertEqual(EXPECTED_HARD_DENY_BUILTIN, prod_builtin_hard)
        self.assertEqual(EXPECTED_CONFIGURABLE, EXPECTED_24_TOOLS - EXPECTED_HARD_DENY_BUILTIN)
        self.assertEqual(PROD_CONFIGURABLE, EXPECTED_CONFIGURABLE)

    def test_literal_restricted_doctypes_match_production(self):
        self.assertEqual(EXPECTED_RESTRICTED_DOCTYPES, PROD_RESTRICTED)

    def test_administrator_has_no_hard_deny_bypass_via_registry(self):
        self._bind_session("Administrator")
        before = self._audit_count("Administrator", "delete_document")
        with self.assertRaises(PolicyDenied) as denied:
            ToolRegistry().execute_tool(
                "delete_document",
                {"doctype": "ToDo", "name": "MATRIX"},
            )
        self.assertEqual(denied.exception.reason_code, "TOOL_HARD_DENY")
        self._assert_exactly_one_audit("Administrator", "delete_document", before)

    def test_hard_deny_absolute_for_every_actor_via_registry(self):
        for role_label, actor in self.actors.items():
            for tool_name in sorted(EXPECTED_HARD_DENY_BUILTIN):
                with self.subTest(role=role_label, tool=tool_name, phase="publish"):
                    published = self._published_names(actor)
                    self.assertNotIn(tool_name, published)
                with self.subTest(role=role_label, tool=tool_name, phase="execute"):
                    before = self._audit_count(actor, tool_name)
                    with self.assertRaises(PolicyDenied) as denied:
                        self._registry_execute(
                            actor,
                            tool_name,
                            {"doctype": "ToDo", "name": "MATRIX"},
                        )
                    self.assertEqual(denied.exception.reason_code, "TOOL_HARD_DENY")
                    self._assert_exactly_one_audit(actor, tool_name, before)

    # --- actor × config × phase matrix --------------------------------------

    def test_actor_config_phase_matrix_via_registry_and_mcp(self):
        scenarios = self._config_scenarios()
        probe = self.configurable_probe

        for actor_label, actor in self.actors.items():
            for scenario in scenarios:
                for phase in ("publish", "execute"):
                    with self.subTest(
                        actor=actor_label,
                        config=scenario.label,
                        phase=phase,
                    ):
                        self._reset_probe_configuration()
                        scenario.setup(self)
                        args = self._todo_read_arguments(actor)

                        if phase == "publish":
                            published = self._published_names(actor)
                            registry = self._published_registry(actor)
                            listed = self._mcp_tools_list(actor, registry)
                            if scenario.publish_allowed and actor_label == "Assistant User":
                                self.assertIn(probe, published)
                                self.assertIn(probe, listed)
                            else:
                                self.assertNotIn(probe, published)
                                self.assertNotIn(probe, listed)
                            continue

                        before = self._audit_count(actor, probe)
                        if scenario.execute_reason:
                            with self.assertRaises(PolicyDenied) as denied:
                                self._registry_execute(actor, probe, args)
                            self.assertEqual(
                                denied.exception.reason_code,
                                scenario.execute_reason,
                            )
                        elif actor_label == "Assistant User":
                            result = self._registry_execute(actor, probe, args)
                            self.assertIsInstance(result, dict)
                            serialized = json.dumps(result, default=str)
                            self.assertNotIn(self.secret_marker, serialized)
                        else:
                            with self.assertRaises(PolicyDenied) as denied:
                                self._registry_execute(actor, probe, args)
                            self.assertEqual(
                                denied.exception.reason_code,
                                "ROLE_NOT_ALLOWED",
                            )
                        self._assert_exactly_one_audit(actor, probe, before)

                        mcp_before = self._audit_count(actor, probe)
                        mcp_result = self._mcp_execute(actor, probe, args)
                        if scenario.execute_reason or actor_label != "Assistant User":
                            self.assertTrue(mcp_result.get("isError"))
                        else:
                            self.assertFalse(mcp_result.get("isError"))
                            body = mcp_result["content"][0]["text"]
                            self.assertNotIn(self.secret_marker, body)
                        self._assert_exactly_one_audit(actor, probe, mcp_before)

    def test_allowed_todo_read_succeeds_for_assistant_user(self):
        actor = self.actors["Assistant User"]
        self._configure_tool(self.configurable_probe, roles=("Assistant User",))
        before = self._audit_count(actor, self.configurable_probe)
        result = self._registry_execute(
            actor,
            self.configurable_probe,
            self._todo_read_arguments(actor),
        )
        self.assertIsInstance(result, dict)
        self._assert_exactly_one_audit(actor, self.configurable_probe, before)

    # --- restricted targets -------------------------------------------------

    def test_every_ratified_restricted_doctype_denied_via_registry(self):
        actor = self.actors["Assistant User"]
        self._configure_tool(self.configurable_probe, roles=("Assistant User",))
        for doctype in sorted(EXPECTED_RESTRICTED_DOCTYPES):
            with self.subTest(doctype=doctype):
                before = self._audit_count(actor, self.configurable_probe)
                with self.assertRaises(PolicyDenied) as denied:
                    self._registry_execute(
                        actor,
                        self.configurable_probe,
                        {"doctype": doctype, "name": "MATRIX"},
                    )
                self.assertEqual(denied.exception.reason_code, "DOCTYPE_RESTRICTED")
                self._assert_exactly_one_audit(actor, self.configurable_probe, before)

    def test_real_child_doctype_denied_via_registry(self):
        actor = self.actors["Assistant User"]
        self._configure_tool(self.configurable_probe, roles=("Assistant User",))
        self.assertTrue(frappe.get_meta(REAL_CHILD_DOCTYPE).istable)
        before = self._audit_count(actor, self.configurable_probe)
        with self.assertRaises(PolicyDenied) as denied:
            self._registry_execute(
                actor,
                self.configurable_probe,
                {"doctype": REAL_CHILD_DOCTYPE, "name": "MATRIX"},
            )
        self.assertEqual(denied.exception.reason_code, "DOCTYPE_RESTRICTED")
        self._assert_exactly_one_audit(actor, self.configurable_probe, before)

    # --- fresh config between publication and execution ---------------------

    def test_save_and_db_set_value_take_effect_before_execute(self):
        actor = self.actors["Assistant User"]
        self._configure_tool(self.configurable_probe, roles=("Assistant User",))
        self.assertIn(self.configurable_probe, self._published_names(actor))

        config = frappe.get_doc("FAC Tool Configuration", self.configurable_probe)
        config.enabled = 0
        config.save(ignore_permissions=True)
        before_save = self._audit_count(actor, self.configurable_probe)
        with self.assertRaises(PolicyDenied) as denied_save:
            self._registry_execute(
                actor,
                self.configurable_probe,
                self._todo_read_arguments(actor),
            )
        self.assertEqual(denied_save.exception.reason_code, "TOOL_DISABLED")
        self._assert_exactly_one_audit(actor, self.configurable_probe, before_save)

        self._configure_tool(self.configurable_probe, roles=("Assistant User",))
        frappe.db.set_value(
            "FAC Tool Configuration",
            self.configurable_probe,
            "enabled",
            0,
            update_modified=False,
        )
        before_db = self._audit_count(actor, self.configurable_probe)
        with self.assertRaises(PolicyDenied) as denied_db:
            self._registry_execute(
                actor,
                self.configurable_probe,
                self._todo_read_arguments(actor),
            )
        self.assertEqual(denied_db.exception.reason_code, "TOOL_DISABLED")
        self._assert_exactly_one_audit(actor, self.configurable_probe, before_db)

    # --- System Manager real tool output paths ------------------------------

    def test_system_manager_real_tool_outputs_redact_nested_secrets(self):
        manager = self.actors["System Manager"]
        todo_name = self._create_todo(
            description=json.dumps(
                {
                    "authorization": f"Bearer {self.secret_marker}",
                    "rows": [{"api_secret": self.secret_marker}],
                }
            )
        )
        for tool_name in (
            "get_document",
            "list_documents",
            "search_documents",
            "get_doctype_info",
            "report_list",
            "fetch",
        ):
            self._configure_tool(tool_name, roles=("System Manager",))

        cases = {
            "get_document": {
                "tool": "get_document",
                "arguments": {"doctype": "ToDo", "name": todo_name},
            },
            "list_documents": {
                "tool": "list_documents",
                "arguments": {
                    "doctype": "ToDo",
                    "limit": 5,
                    "fields": ["name", "description"],
                    "filters": {"name": todo_name},
                },
            },
            "search_documents": {
                "tool": "search_documents",
                "arguments": {"query": todo_name},
            },
            "metadata": {
                "tool": "get_doctype_info",
                "arguments": {"doctype": "ToDo"},
            },
            "report_list": {
                "tool": "report_list",
                "arguments": {},
            },
            "fetch": {
                "tool": "fetch",
                "arguments": {"id": f"ToDo/{todo_name}"},
            },
        }

        for label, case in cases.items():
            with self.subTest(output_path=label):
                before = self._audit_count(manager, case["tool"])
                result = self._registry_execute(manager, case["tool"], case["arguments"])
                serialized = json.dumps(result, default=str)
                self.assertNotIn(self.secret_marker, serialized)
                if label in {"get_document", "list_documents", "fetch"}:
                    self.assertIn("REDACTED", serialized)
                self._assert_exactly_one_audit(manager, case["tool"], before)

    # --- MCP argument validation --------------------------------------------

    def test_non_dict_mcp_arguments_rejected_and_audited_once(self):
        actor = self.actors["Assistant User"]
        self._configure_tool(self.configurable_probe, roles=("Assistant User",))
        registry = self._published_registry(actor)
        server = MCPServer(f"fac-matrix-args-{self.run_id}")

        for arguments in (None, [], "{}", 1, True):
            with self.subTest(arguments=arguments):
                before = self._audit_count(actor, self.configurable_probe)
                result = server._handle_tools_call(
                    {"name": self.configurable_probe, "arguments": arguments},
                    registry,
                )
                self.assertTrue(result.get("isError"))
                self.assertEqual(result["content"][0]["text"], "Invalid tool arguments")
                self._assert_exactly_one_audit(actor, self.configurable_probe, before)

    # --- authentication boundary --------------------------------------------

    def test_missing_and_invalid_auth_persist_sanitized_security_audit(self):
        from frappe_assistant_core.api import fac_endpoint

        cases = [
            ("missing", SimpleNamespace(method="POST", headers={}, url="https://fac-test.local/api/method/fac"), "AUTH_MISSING"),
            (
                "invalid_bearer",
                SimpleNamespace(
                    method="POST",
                    headers={"Authorization": f"Bearer {self.secret_marker}"},
                    url="https://fac-test.local/api/method/fac",
                ),
                "AUTHENTICATION_ERROR",
            ),
        ]

        for label, request, reason in cases:
            with self.subTest(case=label):
                frappe.local.assistant_session_id = self.session_id
                before = self._security_audit_count("Guest", "permission_denied")
                original_get_doc = fac_endpoint.frappe.get_doc

                def fail_oauth_lookup(*args, **kwargs):
                    if args and args[0] == "OAuth Bearer Token":
                        raise RuntimeError(self.secret_marker)
                    return original_get_doc(*args, **kwargs)

                with ExitStack() as stack:
                    stack.enter_context(patch.object(fac_endpoint.frappe, "request", request))
                    if label == "invalid_bearer":
                        stack.enter_context(
                            patch.object(
                                fac_endpoint.frappe,
                                "get_doc",
                                side_effect=fail_oauth_lookup,
                            )
                        )
                    response = fac_endpoint.mcp._entry_fn()

                self.assertEqual(response.status_code, 401)
                body = response.get_data(as_text=True)
                self.assertNotIn(self.secret_marker, body)
                self.assertNotIn("Traceback", body)
                after = self._security_audit_count("Guest", "permission_denied")
                self.assertEqual(after, before + 1)
                rows = frappe.get_all(
                    "Assistant Audit Log",
                    filters={
                        "user": "Guest",
                        "action": "security_permission_denied",
                        "session_id": self.session_id,
                    },
                    fields=["output_data"],
                    order_by="creation desc",
                    limit=1,
                )
                self.assertEqual(json.loads(rows[0]["output_data"])["reason_code"], reason)
                self.assertNotIn(self.secret_marker, rows[0]["output_data"])

    def test_guest_session_never_builds_tool_registry(self):
        from frappe_assistant_core.api import fac_endpoint

        request = SimpleNamespace(method="POST", headers={}, url="https://fac-test.local/api/method/fac")
        with ExitStack() as stack:
            stack.enter_context(patch.object(fac_endpoint.frappe, "request", request))
            stack.enter_context(
                patch.object(fac_endpoint, "_authenticate_mcp_request", return_value="Guest")
            )
            stack.enter_context(
                patch.object(fac_endpoint, "_check_assistant_enabled", return_value=True)
            )
            build = stack.enter_context(patch.object(fac_endpoint, "_build_tool_registry"))
            response = fac_endpoint.mcp._entry_fn()

        self.assertEqual(response.status_code, 401)
        build.assert_not_called()

    # --- concurrency --------------------------------------------------------

    def test_parallel_users_isolated_tools_list_and_call(self):
        user_email = self._unique_email("parallel-user")
        manager_email = self._unique_email("parallel-manager")
        self._ensure_actor(user_email, ("System Manager", "Assistant User"))
        self._ensure_actor(manager_email, ("System Manager", "Assistant Admin"))
        frappe.set_user(user_email)
        todo_name = self._create_todo(description=f"parallel-{self.run_id}")
        frappe.set_user("Administrator")
        self._configure_tool("get_document", roles=("Assistant User",))
        self._configure_tool("list_documents", roles=("Assistant Admin",))
        site = frappe.local.site
        sites_path = frappe.local.sites_path
        frappe.db.commit()

        barrier = threading.Barrier(2)
        results: dict[str, Any] = {}
        errors: list[str] = []

        def worker(key: str, email: str, tool_name: str, call_args: dict) -> None:
            try:
                frappe.init(site=site, sites_path=sites_path, force=True)
                frappe.connect()
                barrier.wait(timeout=10)
                frappe.set_user(email)
                frappe.local.assistant_session_id = f"{self.session_id}-{key}"
                registry_obj = ToolRegistry()
                published = {
                    meta["name"]
                    for meta in registry_obj.get_available_tools(user=email)
                }
                tools_dict: OrderedDict[str, dict] = OrderedDict()
                for name in published:
                    tool = registry_obj.get_tool(name)
                    tools_dict[name] = build_tool_dict(tool, registry_obj.execute_tool)

                server = MCPServer(f"fac-matrix-par-{self.run_id}-{key}")
                list_before = frappe.db.count(
                    "Assistant Audit Log",
                    {
                        "user": email,
                        "tool_name": "tools/list",
                        "session_id": frappe.local.assistant_session_id,
                    },
                )
                list_response = _handle_mcp(
                    server,
                    _make_tools_list_request(1),
                    tools_dict,
                )
                list_after = frappe.db.count(
                    "Assistant Audit Log",
                    {
                        "user": email,
                        "tool_name": "tools/list",
                        "session_id": frappe.local.assistant_session_id,
                    },
                )
                call_before = frappe.db.count(
                    "Assistant Audit Log",
                    {
                        "user": email,
                        "tool_name": tool_name,
                        "session_id": frappe.local.assistant_session_id,
                    },
                )
                call_response = _handle_mcp(
                    server,
                    _make_tools_call_request(tool_name, call_args, 2),
                    tools_dict,
                )
                call_after = frappe.db.count(
                    "Assistant Audit Log",
                    {
                        "user": email,
                        "tool_name": tool_name,
                        "session_id": frappe.local.assistant_session_id,
                    },
                )

                results[key] = {
                    "published": published,
                    "list_error": _result_of(list_response).get("isError"),
                    "call_error": _result_of(call_response).get("isError"),
                    "list_audit_delta": list_after - list_before,
                    "call_audit_delta": call_after - call_before,
                }
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(f"{key}: {type(exc).__name__}: {exc}")
            finally:
                frappe.destroy()

        with ThreadPoolExecutor(max_workers=2) as pool:
            list(
                pool.map(
                    lambda item: worker(*item),
                    (
                        (
                            "user",
                            user_email,
                            "get_document",
                            {"doctype": "ToDo", "name": todo_name},
                        ),
                        (
                            "manager",
                            manager_email,
                            "list_documents",
                            {
                                "doctype": "ToDo",
                                "limit": 1,
                                "fields": ["name"],
                                "filters": {"name": todo_name},
                            },
                        ),
                    ),
                )
            )

        self.assertEqual(errors, [], f"worker failures: {errors}")
        self.assertIn("get_document", results["user"]["published"])
        self.assertNotIn("list_documents", results["user"]["published"])
        self.assertIn("list_documents", results["manager"]["published"])
        self.assertNotIn("get_document", results["manager"]["published"])
        self.assertFalse(results["user"]["list_error"])
        self.assertFalse(results["manager"]["list_error"])
        self.assertFalse(results["user"]["call_error"])
        self.assertFalse(results["manager"]["call_error"])
        self.assertEqual(results["user"]["list_audit_delta"], 1)
        self.assertEqual(results["manager"]["list_audit_delta"], 1)
        self.assertEqual(results["user"]["call_audit_delta"], 1)
        self.assertEqual(results["manager"]["call_audit_delta"], 1)

    # --- failure channels ---------------------------------------------------

    def test_secret_bearing_denial_sanitizes_logger_error_and_audit_rows(self):
        actor = self.actors["Assistant User"]
        hidden_tool = f"matrix-hidden-{self.run_id}"
        secret_args = {"token": self.secret_marker, "doctype": "ToDo", "name": "X"}

        error_before = frappe.db.count("Error Log")
        audit_before = self._audit_count(actor, hidden_tool)

        logger = logging.getLogger("frappe_assistant_core")
        handler = _RecordHandler()
        logger.addHandler(handler)
        try:
            self._bind_session(actor)
            server = MCPServer(f"fac-matrix-secret-{self.run_id}")
            result = server._handle_tools_call(
                {"name": hidden_tool, "arguments": secret_args},
                {},
            )
        finally:
            logger.removeHandler(handler)

        self.assertTrue(result.get("isError"))
        body = result["content"][0]["text"]
        self.assertNotIn(self.secret_marker, body)
        self.assertNotIn("Traceback", body)

        self._assert_exactly_one_audit(actor, hidden_tool, audit_before)

        rows = frappe.get_all(
            "Assistant Audit Log",
            filters={
                "user": actor,
                "tool_name": hidden_tool,
                "session_id": self.session_id,
            },
            fields=["input_data", "output_data", "error_message", "status"],
        )
        self.assertEqual(len(rows), 1)
        serialized = json.dumps(rows[0], default=str)
        self.assertNotIn(self.secret_marker, serialized)
        self.assertIn("REDACTED", serialized)

        error_after = frappe.db.count("Error Log")
        if error_after > error_before:
            latest = frappe.get_all(
                "Error Log",
                fields=["error"],
                order_by="creation desc",
                limit=1,
            )[0]
            self.assertNotIn(self.secret_marker, latest.get("error") or "")

        joined_logs = "\n".join(handler.messages)
        self.assertNotIn(self.secret_marker, joined_logs)

    def test_mcp_execution_failure_never_echoes_secret_or_traceback(self):
        actor = self.actors["Assistant User"]
        self._configure_tool("get_document", roles=("Assistant User",))

        registry = ToolRegistry()
        tool = registry.get_tool("get_document")
        self.assertIsNotNone(tool)
        tools = {"get_document": build_tool_dict(tool, registry.execute_tool)}
        server = MCPServer(f"fac-matrix-fail-{self.run_id}")
        self._bind_session(actor)
        arguments = self._todo_read_arguments(actor)
        before = self._audit_count(actor, "get_document")
        with patch.object(
            tool,
            "execute",
            side_effect=RuntimeError(self.secret_marker),
        ):
            result = server._handle_tools_call(
                {
                    "name": "get_document",
                    "arguments": arguments,
                },
                tools,
            )
        body = result["content"][0]["text"]
        self.assertTrue(result.get("isError"))
        self.assertEqual(body, "Tool execution failed")
        self.assertNotIn(self.secret_marker, body)
        self.assertNotIn("Traceback", body)
        self._assert_exactly_one_audit(actor, "get_document", before)
