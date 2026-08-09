"""Fail-closed authorization policy for FAC tools.

The policy in this module is deliberately independent of tool publication and
tool implementation details.  Configuration can narrow the immutable code
policy, but it cannot override hard denials, restricted targets or fields.
"""

from __future__ import annotations

import importlib
import inspect
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from types import MappingProxyType
from typing import Any, Mapping

import frappe

from frappe_assistant_core.core.base_tool import BaseTool
from frappe_assistant_core.core.security_config import (
    ADMIN_ONLY_FIELDS,
    SENSITIVE_FIELDS,
)
from frappe_assistant_core.utils.plugin_manager import PluginDiscovery

EXPECTED_BUILTIN_TOOL_NAMES = frozenset(
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

HARD_DENY_TOOLS = frozenset(
    {
        "delete_document",
        "run_python_code",
        "run_database_query",
        "analyze_business_data",
        "extract_file_content",
        "create_dashboard",
        "create_dashboard_chart",
        "list_user_dashboards",
        "document_create",
        "document_get",
        "document_update",
        "document_list",
        "search_global",
        "report_execute",
        "report_columns",
        "metadata_doctype",
        "create_visualization",
        "analyze_frappe_data",
        "workflow_status",
        "workflow_list",
        "execute_python_code",
        "query_and_analyze",
        "metadata_permissions",
        "metadata_workflow",
        "tool_registry_list",
        "tool_registry_toggle",
        "audit_log_view",
        "workflow_action",
    }
)

CONFIGURABLE_TOOLS = EXPECTED_BUILTIN_TOOL_NAMES - HARD_DENY_TOOLS
TRUSTED_EXTERNAL_TOOLS: frozenset[str] = frozenset()

RESTRICTED_DOCTYPES = frozenset(
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

_BUILTIN_PLUGINS = frozenset({"core", "data_science", "visualization"})
_TOOL_PLUGIN = MappingProxyType({
    **{name: "core" for name in EXPECTED_BUILTIN_TOOL_NAMES if name not in {
        "run_python_code", "run_database_query", "analyze_business_data", "extract_file_content",
        "create_dashboard", "create_dashboard_chart", "list_user_dashboards",
    }},
    **{name: "data_science" for name in {
        "run_python_code", "run_database_query", "analyze_business_data", "extract_file_content",
    }},
    **{name: "visualization" for name in {
        "create_dashboard", "create_dashboard_chart", "list_user_dashboards",
    }},
})

_FIELD_SEPARATOR = re.compile(r"[^a-z0-9]+")
_JSON_STRING_REDACTION_MAX_BYTES = 65_536
_UNIVERSAL_SENSITIVE_FIELDS = frozenset(
    {
        "token",
        "password",
        "secret",
        "authorization",
        "cookie",
        "cookies",
        "session",
        "api_key",
        "api_secret",
        "encryption_key",
    }
)


@dataclass(frozen=True)
class ToolContext:
    operation: str
    target_doctype: str | None = None
    target_name: str | None = None
    fields: frozenset[str] = frozenset()
    required_permissions: frozenset[str] = frozenset()
    action: str | None = None
    report_name: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason_code: str
    context: ToolContext
    audit_details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "audit_details", MappingProxyType(dict(self.audit_details)))

    def require(self) -> None:
        if not self.allowed:
            raise PolicyDenied(self)


class PolicyDenied(PermissionError):
    """Stable policy denial that never includes raw user arguments."""

    def __init__(self, decision: PolicyDecision):
        self.reason_code = decision.reason_code
        self.decision = decision
        super().__init__(decision.reason_code)


def _normalise_field_name(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return _FIELD_SEPARATOR.sub("_", value.strip().lower()).strip("_")


def _freeze_field_map(source: Mapping[str, Any]) -> Mapping[str, Any]:
    frozen = {}
    for scope, configured in source.items():
        if configured == "*":
            frozen[scope] = "*"
        else:
            frozen[scope] = frozenset(
                _normalise_field_name(item)
                for item in configured
                if isinstance(item, str)
            )
    return MappingProxyType(frozen)


_SENSITIVE_FIELDS_SNAPSHOT = _freeze_field_map(SENSITIVE_FIELDS)
_ADMIN_ONLY_FIELDS_SNAPSHOT = _freeze_field_map(ADMIN_ONLY_FIELDS)


def _collect_mapping_keys(value: Any) -> set[str]:
    fields: set[str] = set()
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str):
                fields.add(key)
            fields.update(_collect_mapping_keys(nested))
    elif isinstance(value, (list, tuple, set, frozenset)):
        for nested in value:
            fields.update(_collect_mapping_keys(nested))
    return fields


def _collect_filter_fields(value: Any) -> set[str]:
    if isinstance(value, Mapping):
        return {key for key in value if isinstance(key, str)}
    if isinstance(value, (list, tuple)):
        if len(value) >= 4 and isinstance(value[1], str):
            return {value[1]}
        if len(value) >= 3 and isinstance(value[0], str):
            return {value[0]}
        fields: set[str] = set()
        for nested in value:
            fields.update(_collect_filter_fields(nested))
        return fields
    return set()


def _collect_requested_fields(arguments: Mapping[str, Any], *payload_keys: str) -> frozenset[str]:
    fields: set[str] = set()
    for payload_key in payload_keys:
        payload = arguments.get(payload_key)
        if payload_key == "filters":
            fields.update(_collect_filter_fields(payload))
        elif payload_key == "fields" and isinstance(payload, (list, tuple, set, frozenset)):
            fields.update(value for value in payload if isinstance(value, str))
        else:
            fields.update(_collect_mapping_keys(payload))
    return frozenset(fields)


@lru_cache(maxsize=1)
def discover_builtin_tool_classes() -> Mapping[str, type[BaseTool]]:
    """Discover tool classes from built-in plugin source declarations.

    Enabled state and dependency validation are intentionally not consulted.
    Every declared module must resolve to exactly one locally-defined
    ``BaseTool`` subclass.
    """

    discovered_plugins = PluginDiscovery().discover_plugins()
    classes = {}

    for plugin_name in sorted(_BUILTIN_PLUGINS):
        plugin_info = discovered_plugins.get(plugin_name)
        if plugin_info is None or plugin_info.error_message:
            raise RuntimeError(f"Built-in plugin discovery failed: {plugin_name}")

        for declared_module in plugin_info.tools:
            module_name = (
                f"frappe_assistant_core.plugins.{plugin_name}.tools.{declared_module}"
            )
            module = importlib.import_module(module_name)
            candidates = {
                value
                for _, value in inspect.getmembers(module, inspect.isclass)
                if issubclass(value, BaseTool)
                and value is not BaseTool
                and value.__module__ == module.__name__
            }
            if len(candidates) != 1:
                raise RuntimeError(
                    f"Expected one BaseTool class in {module_name}, found {len(candidates)}"
                )
            tool_class = next(iter(candidates))
            tool_name = tool_class().name
            if not tool_name or tool_name in classes:
                raise RuntimeError(f"Invalid or duplicate tool name in {module_name}")
            classes[tool_name] = tool_class

    return MappingProxyType(classes)


@lru_cache(maxsize=1)
def discover_builtin_tool_names() -> frozenset[str]:
    """Return the immutable built-in name inventory."""
    return frozenset(discover_builtin_tool_classes())


def resolve_builtin_tool(tool_name: str) -> BaseTool | None:
    """Instantiate a known built-in independently of mutable enable state."""
    if not isinstance(tool_name, str):
        return None
    tool_class = discover_builtin_tool_classes().get(tool_name)
    return tool_class() if tool_class is not None else None


class SecurityPolicy:
    """Single fail-closed authorization boundary for FAC tools."""

    @classmethod
    def inventory(cls) -> frozenset[str]:
        # Intersection makes newly discovered tools unavailable until the
        # ratified snapshot and its contract test are deliberately updated.
        return frozenset(discover_builtin_tool_names()) & EXPECTED_BUILTIN_TOOL_NAMES

    @classmethod
    def authorize(
        cls,
        actor: str,
        tool_name: str,
        arguments: dict | None,
        phase: str,
    ) -> PolicyDecision:
        empty_context = ToolContext(operation="authorize")
        try:
            if phase not in {"publish", "execute"}:
                return cls._deny("POLICY_PHASE_INVALID", empty_context)
            if not actor or actor == "Guest":
                return cls._deny("ACTOR_UNAUTHENTICATED", empty_context)
            if not cls._is_actor_enabled(actor):
                return cls._deny("ASSISTANT_DISABLED", empty_context)
            if not isinstance(tool_name, str) or tool_name not in cls.inventory():
                return cls._deny("TOOL_UNKNOWN", empty_context)
            if tool_name in HARD_DENY_TOOLS:
                return cls._deny("TOOL_HARD_DENY", ToolContext(operation="deny"))

            fresh = phase == "execute"
            plugin_name = _TOOL_PLUGIN[tool_name]
            if not cls._is_plugin_enabled(plugin_name, fresh=fresh):
                return cls._deny("PLUGIN_DISABLED", empty_context)

            config = cls._load_access_config(tool_name, fresh=fresh)
            if config is None:
                return cls._deny("CONFIG_MISSING", empty_context)
            if not bool(config.get("enabled")):
                return cls._deny("TOOL_DISABLED", empty_context)
            if config.get("role_access_mode") != "Restrict to Listed Roles":
                return cls._deny("CONFIG_MODE_DENIED", empty_context)

            allowed_roles = {role for role in config.get("roles", set()) if role}
            if not allowed_roles.intersection(
                cls._get_actor_roles(actor, fresh=fresh)
            ):
                return cls._deny("ROLE_NOT_ALLOWED", empty_context)

            if tool_name not in EXPECTED_BUILTIN_TOOL_NAMES and tool_name not in TRUSTED_EXTERNAL_TOOLS:
                return cls._deny("EXTERNAL_TOOL_DENIED", empty_context)

            if phase == "publish":
                return PolicyDecision(
                    allowed=True,
                    reason_code="ALLOWED",
                    context=ToolContext(operation="publish"),
                )

            context = cls.extract_context(tool_name, arguments)
            if context is None:
                return cls._deny("ARGUMENT_CONTEXT_INVALID", empty_context)
            if cls._is_restricted_target(context.target_doctype):
                return cls._deny("DOCTYPE_RESTRICTED", context)
            if cls._contains_restricted_fields(context.target_doctype, context.fields):
                return cls._deny("FIELD_RESTRICTED", context)
            if not cls._has_native_permissions(actor, context):
                return cls._deny("NATIVE_PERMISSION_DENIED", context)

            return PolicyDecision(
                allowed=True,
                reason_code="ALLOWED",
                context=context,
                audit_details=cls._audit_details(context),
            )
        except Exception:
            return cls._deny("POLICY_ERROR_FAIL_CLOSED", empty_context)

    @classmethod
    def extract_context(
        cls, tool_name: str, arguments: dict | None
    ) -> ToolContext | None:
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return None

        def text(key: str, required: bool = True) -> str | None:
            value = arguments.get(key)
            if value is None and not required:
                return None
            if not isinstance(value, str) or not value.strip():
                raise ValueError(key)
            return value.strip()

        try:
            if tool_name == "create_document":
                doctype = text("doctype")
                data = arguments.get("data")
                if not isinstance(data, dict):
                    return None
                permissions = {"create"}
                if arguments.get("submit") is True:
                    permissions.add("submit")
                return ToolContext(
                    "create",
                    target_doctype=doctype,
                    fields=_collect_requested_fields(arguments, "data"),
                    required_permissions=frozenset(permissions),
                )
            if tool_name == "get_document":
                return ToolContext(
                    "read", text("doctype"), text("name"), required_permissions=frozenset({"read"})
                )
            if tool_name == "fetch":
                identifier = text("id")
                if "/" not in identifier:
                    return None
                doctype, name = identifier.split("/", 1)
                if not doctype.strip() or not name.strip():
                    return None
                return ToolContext(
                    "read", doctype.strip(), name.strip(), required_permissions=frozenset({"read"})
                )
            if tool_name == "update_document":
                if not isinstance(arguments.get("data"), dict):
                    return None
                return ToolContext(
                    "write",
                    text("doctype"),
                    text("name"),
                    _collect_requested_fields(arguments, "data"),
                    frozenset({"write"}),
                )
            if tool_name in {"list_documents", "search_doctype", "search_link"}:
                return ToolContext(
                    "read",
                    text("doctype"),
                    fields=_collect_requested_fields(arguments, "fields", "filters"),
                    required_permissions=frozenset({"read"}),
                )
            if tool_name in {"search_documents", "search"}:
                text("query")
                return ToolContext("read_many", required_permissions=frozenset({"read"}))
            if tool_name == "get_doctype_info":
                return ToolContext(
                    "metadata_read", text("doctype"), required_permissions=frozenset({"read"})
                )
            if tool_name == "report_list":
                return ToolContext("report_discover", required_permissions=frozenset({"read"}))
            if tool_name in {"report_requirements", "generate_report"}:
                report_name = text("report_name")
                return ToolContext(
                    "report_read",
                    "Report",
                    report_name,
                    _collect_requested_fields(arguments, "filters"),
                    frozenset({"read"}),
                    report_name=report_name,
                )
            if tool_name == "get_pending_approvals":
                doctype = text("doctype", required=False)
                permissions = frozenset({"read"}) if doctype else frozenset()
                return ToolContext("workflow_read", doctype, required_permissions=permissions)
            if tool_name == "submit_document":
                return ToolContext(
                    "submit", text("doctype"), text("name"), required_permissions=frozenset({"submit"})
                )
            if tool_name == "run_workflow":
                return ToolContext(
                    "workflow_write",
                    text("doctype"),
                    text("name"),
                    required_permissions=frozenset({"write"}),
                    action=text("action"),
                )
        except (TypeError, ValueError):
            return None
        return None

    @staticmethod
    def _deny(reason_code: str, context: ToolContext) -> PolicyDecision:
        return PolicyDecision(False, reason_code, context)

    @staticmethod
    def _audit_details(context: ToolContext) -> Mapping[str, Any]:
        details = {}
        if context.action:
            details["action"] = context.action
        if context.report_name:
            details["report_name"] = context.report_name
        return details

    @staticmethod
    def _is_actor_enabled(actor: str) -> bool:
        enabled = frappe.db.get_value("User", actor, "assistant_enabled")
        return bool(int(enabled)) if enabled is not None else False

    @staticmethod
    def _is_plugin_enabled(plugin_name: str, fresh: bool) -> bool:
        del fresh  # DB reads are intentionally fresh in both phases for now.
        if not frappe.db.table_exists("FAC Plugin Configuration"):
            return False
        enabled = frappe.db.get_value(
            "FAC Plugin Configuration", plugin_name, "enabled"
        )
        return bool(enabled)

    @staticmethod
    def _load_access_config(tool_name: str, fresh: bool) -> dict | None:
        del fresh  # Publication caching is optional; execution must remain fresh.
        if not frappe.db.table_exists("FAC Tool Configuration"):
            return None
        config = frappe.db.get_value(
            "FAC Tool Configuration",
            tool_name,
            ["enabled", "role_access_mode"],
            as_dict=True,
        )
        if not config:
            return None
        roles = frappe.get_all(
            "FAC Tool Role Access",
            filters={"parent": tool_name, "allow_access": 1},
            pluck="role",
        )
        return {
            "enabled": bool(config.get("enabled")),
            "role_access_mode": config.get("role_access_mode"),
            "roles": {
                role
                for role in roles
                if role and frappe.db.exists("Role", {"name": role, "disabled": 0})
            },
        }

    @staticmethod
    def _get_actor_roles(actor: str, fresh: bool = False) -> set[str]:
        if not fresh:
            return set(frappe.get_roles(actor))

        from frappe.permissions import (
            ALL_USER_ROLE,
            AUTOMATIC_ROLES,
            GUEST_ROLE,
            SYSTEM_USER_ROLE,
        )

        if actor == "Guest":
            return {GUEST_ROLE}

        assigned_roles = set(
            frappe.get_all(
                "Has Role",
                filters={"parenttype": "User", "parent": actor},
                pluck="role",
            )
        )
        roles = {
            role
            for role in assigned_roles
            if frappe.db.exists("Role", {"name": role, "disabled": 0})
        }
        roles.difference_update(AUTOMATIC_ROLES)
        roles.update({ALL_USER_ROLE, GUEST_ROLE})
        if frappe.db.get_value("User", actor, "user_type") == "System User":
            roles.add(SYSTEM_USER_ROLE)
        return roles

    @staticmethod
    def _is_restricted_target(doctype: str | None) -> bool:
        if not doctype:
            return False
        if doctype in RESTRICTED_DOCTYPES:
            return True
        return bool(getattr(frappe.get_meta(doctype), "istable", False))

    @classmethod
    def _contains_restricted_fields(
        cls, doctype: str | None, fields: frozenset[str]
    ) -> bool:
        restricted = set(_UNIVERSAL_SENSITIVE_FIELDS)
        for source in (_SENSITIVE_FIELDS_SNAPSHOT, _ADMIN_ONLY_FIELDS_SNAPSHOT):
            for scope in ("all_doctypes", doctype):
                configured = source.get(scope, []) if scope else []
                if configured == "*":
                    return bool(fields)
                restricted.update(configured)

        for field_name in fields:
            normalised = _normalise_field_name(field_name)
            if normalised in restricted:
                return True
            parts = set(normalised.split("_"))
            if parts.intersection({"password", "secret", "authorization", "cookie", "cookies", "session"}):
                return True
            if "token" in parts or normalised.endswith("_api_key") or normalised.endswith("_api_secret"):
                return True
        return False

    @staticmethod
    def _has_native_permissions(actor: str, context: ToolContext) -> bool:
        if not context.target_doctype:
            return True
        for permission in context.required_permissions:
            kwargs = {"user": actor}
            if context.target_name and permission != "create":
                kwargs["doc"] = context.target_name
            if not frappe.has_permission(
                context.target_doctype, ptype=permission, **kwargs
            ):
                return False
        return True

    @classmethod
    def redact_output(cls, context: ToolContext, value: Any) -> Any:
        """Recursively redact universal and target-specific sensitive fields."""
        return cls._redact_output(context, value, allow_row_doctype=True)

    @classmethod
    def _redact_output(
        cls, context: ToolContext, value: Any, allow_row_doctype: bool
    ) -> Any:
        if isinstance(value, Mapping):
            row_doctype = (
                value.get("doctype")
                if allow_row_doctype and isinstance(value.get("doctype"), str)
                else None
            )
            effective_doctype = row_doctype or context.target_doctype
            result = {}
            for key, nested in value.items():
                if cls._contains_restricted_fields(effective_doctype, frozenset({str(key)})):
                    result[key] = "***REDACTED***"
                else:
                    result[key] = cls._redact_output(
                        context, nested, allow_row_doctype=allow_row_doctype
                    )
            return result
        if isinstance(value, list):
            return [
                cls._redact_output(context, nested, allow_row_doctype=allow_row_doctype)
                for nested in value
            ]
        if isinstance(value, tuple):
            return tuple(
                cls._redact_output(context, nested, allow_row_doctype=allow_row_doctype)
                for nested in value
            )
        if isinstance(value, set):
            return {
                cls._redact_output(context, nested, allow_row_doctype=allow_row_doctype)
                for nested in value
            }
        if (
            isinstance(value, str)
            and value.startswith(("{", "["))
            and len(value.encode("utf-8")) <= _JSON_STRING_REDACTION_MAX_BYTES
        ):
            try:
                parsed = json.loads(value)
            except (TypeError, ValueError):
                return value
            return json.dumps(
                cls._redact_output(context, parsed, allow_row_doctype=False),
                separators=(",", ":"),
                sort_keys=True,
            )
        return value
