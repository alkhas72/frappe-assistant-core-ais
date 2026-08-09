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

import json
import re
from collections.abc import Mapping
from typing import Any, Dict, Optional

import frappe
from frappe.utils import now

# Allowed values for Assistant Audit Log `status` — must match the DocType Select.
AUDIT_STATUS_SUCCESS = "Success"
AUDIT_STATUS_ERROR = "Error"
AUDIT_STATUS_TIMEOUT = "Timeout"
AUDIT_STATUS_PERMISSION_DENIED = "Permission Denied"
_VALID_STATUSES = {
    AUDIT_STATUS_SUCCESS,
    AUDIT_STATUS_ERROR,
    AUDIT_STATUS_TIMEOUT,
    AUDIT_STATUS_PERMISSION_DENIED,
}

# Output data is stored as JSON text in a Code field; cap to keep audit rows
# from bloating when a tool returns a large payload.
_OUTPUT_DATA_MAX_BYTES = 50_000
_JSON_STRING_MAX_BYTES = 65_536
_AUDIT_SENSITIVE_FIELDS = frozenset(
    {
        "api_key",
        "api_secret",
        "authorization",
        "code",
        "cookie",
        "cookies",
        "encryption_key",
        "query",
        "session",
        "sql",
        "file_content",
        "raw_content",
    }
)
_FIELD_SEPARATOR = re.compile(r"[^a-z0-9]+")
_SENSITIVE_TEXT_PATTERN = re.compile(
    r"\b(password|secret|api[_-]?key|api[_-]?secret|access[_-]?token|"
    r"refresh[_-]?token|authorization)\b(\s*[:=]\s*)(?:bearer\s+)?([^\s,;]+)",
    re.IGNORECASE,
)


def _is_audit_sensitive_key(key: Any) -> bool:
    from frappe_assistant_core.core.base_tool import _is_sensitive_key

    if _is_sensitive_key(key):
        return True
    if not isinstance(key, str):
        return False
    normalized = _FIELD_SEPARATOR.sub("_", key.strip().lower()).strip("_")
    return normalized in _AUDIT_SENSITIVE_FIELDS


def sanitize_for_audit(value: Any, _seen: Optional[set] = None) -> Any:
    """Recursively remove credentials and executable payloads at the sink."""
    if _seen is None:
        _seen = set()

    if isinstance(value, str):
        candidate = value.lstrip()
        if (
            candidate.startswith(("{", "["))
            and len(value.encode("utf-8")) <= _JSON_STRING_MAX_BYTES
        ):
            try:
                decoded = json.loads(value)
            except (TypeError, ValueError, json.JSONDecodeError):
                decoded = None
            if isinstance(decoded, (dict, list)):
                sanitized = sanitize_for_audit(decoded, _seen)
                return json.dumps(
                    sanitized,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
        return _SENSITIVE_TEXT_PATTERN.sub(
            lambda match: f"{match.group(1)}{match.group(2)}***REDACTED***",
            value,
        )

    if isinstance(value, Mapping):
        identity = id(value)
        if identity in _seen:
            return "***RECURSIVE***"
        _seen.add(identity)
        try:
            return {
                key: "***REDACTED***"
                if _is_audit_sensitive_key(key)
                else sanitize_for_audit(nested, _seen)
                for key, nested in value.items()
            }
        finally:
            _seen.remove(identity)

    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in _seen:
            return "***RECURSIVE***"
        _seen.add(identity)
        try:
            return [sanitize_for_audit(nested, _seen) for nested in value]
        finally:
            _seen.remove(identity)

    if isinstance(value, (set, frozenset)):
        identity = id(value)
        if identity in _seen:
            return "***RECURSIVE***"
        _seen.add(identity)
        try:
            sanitized = [sanitize_for_audit(nested, _seen) for nested in value]
            return sorted(sanitized, key=repr)
        finally:
            _seen.remove(identity)

    return value


def _sanitize_arguments(arguments: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Backward-compatible wrapper around the recursive sink sanitizer."""
    return sanitize_for_audit(arguments)


def log_tool_execution(
    tool_name: str,
    user: str,
    arguments: Optional[Dict[str, Any]],
    status: str,
    execution_time: float,
    source_app: Optional[str] = None,
    error_message: Optional[str] = None,
    error_type: Optional[str] = None,
    traceback_str: Optional[str] = None,
    output_data: Optional[Any] = None,
    target_doctype: Optional[str] = None,
    target_name: Optional[str] = None,
    operation: Optional[str] = None,
):
    """
    Log tool execution for comprehensive audit trail.

    Args:
        tool_name: Name of the executed tool
        user: User who executed the tool
        arguments: Tool arguments (sensitive data should be pre-sanitized; the
            sink re-sanitizes defensively)
        status: One of "Success", "Error", "Timeout", "Permission Denied".
            Unknown values are coerced to "Error" with a warning.
        execution_time: Time taken in seconds
        source_app: App that provides the tool
        error_message: Error message if execution failed
        error_type: Exception class name or semantic category (e.g.
            "PermissionError", "ValidationError", "ToolReportedError")
        traceback_str: Full Python traceback (exception paths only)
        output_data: Tool output data for audit trail
    """
    try:
        if status not in _VALID_STATUSES:
            frappe.logger("audit_trail").warning(
                f"log_tool_execution: invalid status {status!r} for tool {tool_name}; coercing to 'Error'"
            )
            status = AUDIT_STATUS_ERROR

        sanitized_arguments = sanitize_for_audit(arguments)
        sanitized_output = sanitize_for_audit(output_data)
        sanitized_error = sanitize_for_audit(error_message)
        sanitized_traceback = sanitize_for_audit(traceback_str)

        # Serialize output for storage, clamp oversized payloads
        output_data_str, output_truncated = _serialize_for_audit(sanitized_output)

        input_data_str = None
        if sanitized_arguments is not None:
            try:
                input_data_str = json.dumps(sanitized_arguments, default=str)
            except (TypeError, ValueError):
                input_data_str = str(sanitized_arguments)[:_OUTPUT_DATA_MAX_BYTES]

        audit_doc = frappe.get_doc(
            {
                "doctype": "Assistant Audit Log",
                "action": operation or tool_name,
                "tool_name": tool_name,
                "user": user,
                "status": status,
                "timestamp": now(),
                "execution_time": execution_time,
                "target_doctype": target_doctype,
                "target_name": target_name,
                "client_id": getattr(frappe.local, "assistant_client_id", None),
                "session_id": getattr(frappe.local, "assistant_session_id", None),
                "source_app": source_app,
                "ip_address": getattr(frappe.local, "request_ip", None),
                "input_data": input_data_str,
                "output_data": output_data_str,
                "output_truncated": 1 if output_truncated else 0,
                "error_message": sanitized_error,
                "error_type": error_type,
                "traceback": sanitized_traceback,
            }
        )

        audit_doc.insert(ignore_permissions=True)

    except Exception as e:
        # Don't fail tool execution due to audit logging issues
        frappe.logger("audit_trail").warning(
            f"Failed to log tool execution: {type(e).__name__}"
        )


def log_denied_tool_attempt(
    tool_name: str,
    user: str,
    reason_code: str,
    arguments: Optional[Dict[str, Any]] = None,
    source_app: Optional[str] = None,
    execution_time: float = 0.0,
    target_doctype: Optional[str] = None,
    target_name: Optional[str] = None,
    operation: Optional[str] = None,
):
    """Write exactly one stable, sanitized audit row for a policy denial."""
    log_tool_execution(
        tool_name=tool_name,
        user=user,
        arguments=arguments,
        status=AUDIT_STATUS_PERMISSION_DENIED,
        execution_time=execution_time,
        source_app=source_app,
        error_message=reason_code,
        error_type="PolicyDenied",
        output_data={"reason_code": reason_code},
        target_doctype=target_doctype,
        target_name=target_name,
        operation=operation,
    )


def _serialize_for_audit(output_data: Any) -> tuple:
    """Serialize tool output for the audit row. Returns (json_str_or_none, truncated_bool)."""
    if output_data is None:
        return None, False
    try:
        serialized = json.dumps(sanitize_for_audit(output_data), default=str)
    except (TypeError, ValueError):
        serialized = str(output_data)
    if len(serialized) > _OUTPUT_DATA_MAX_BYTES:
        return serialized[:_OUTPUT_DATA_MAX_BYTES], True
    return serialized, False


def log_tool_discovery(app_name: str, tools_found: int, errors: int, discovery_time: float):
    """
    Log tool discovery events.

    Args:
        app_name: Name of the app being scanned
        tools_found: Number of tools discovered
        errors: Number of discovery errors
        discovery_time: Time taken for discovery
    """
    try:
        payload = {
            "app_name": app_name,
            "tools_found": tools_found,
            "errors": errors,
            "discovery_time": discovery_time,
        }
        output_str, truncated = _serialize_for_audit(payload)
        audit_doc = frappe.get_doc(
            {
                "doctype": "Assistant Audit Log",
                "action": "discover_tools",
                "user": frappe.session.user or "System",
                "status": AUDIT_STATUS_SUCCESS if errors == 0 else AUDIT_STATUS_ERROR,
                "timestamp": now(),
                "execution_time": discovery_time,
                "target_doctype": "Tool Discovery",
                "target_name": app_name,
                "source_app": app_name,
                "output_data": output_str,
                "output_truncated": 1 if truncated else 0,
            }
        )

        audit_doc.insert(ignore_permissions=True)

    except Exception as e:
        frappe.logger("audit_trail").warning(
            f"Failed to log tool discovery: {type(e).__name__}"
        )


def log_security_event(event_type: str, user: str, details: Dict[str, Any], severity: str = "Medium"):
    """
    Log security-related events.

    Args:
        event_type: Type of security event (e.g., 'permission_denied', 'suspicious_activity')
        user: User associated with the event
        details: Event details dictionary
        severity: Event severity (Low, Medium, High, Critical)
    """
    try:
        payload = sanitize_for_audit({"event_type": event_type, "severity": severity, **details})
        output_str, truncated = _serialize_for_audit(payload)
        audit_doc = frappe.get_doc(
            {
                "doctype": "Assistant Audit Log",
                "action": f"security_{event_type}",
                "user": user,
                "status": AUDIT_STATUS_PERMISSION_DENIED
                if event_type == "permission_denied"
                else AUDIT_STATUS_ERROR,
                "error_type": f"Security:{severity}",
                "timestamp": now(),
                "target_doctype": "Security Event",
                "target_name": event_type,
                "client_id": getattr(frappe.local, "assistant_client_id", None),
                "session_id": getattr(frappe.local, "assistant_session_id", None),
                "ip_address": getattr(frappe.local, "request_ip", None),
                "output_data": output_str,
                "output_truncated": 1 if truncated else 0,
            }
        )

        audit_doc.insert(ignore_permissions=True)

        # For critical events, also log to error log
        if severity == "Critical":
            frappe.log_error(
                title=f"Critical Security Event: {event_type}",
                message=f"User: {user}; details retained in sanitized audit row",
            )

    except Exception as e:
        frappe.logger("audit_trail").warning(
            f"Failed to log security event: {type(e).__name__}"
        )


def get_audit_summary(user: Optional[str] = None, days: int = 7) -> Dict[str, Any]:
    """
    Get audit trail summary for monitoring.

    Args:
        user: Filter by specific user (None for all users)
        days: Number of days to include

    Returns:
        Audit summary statistics
    """
    try:
        from frappe.utils import add_days

        # Calculate date range
        from_date = add_days(now(), -days)

        # Build filters
        filters = {"timestamp": [">=", from_date]}
        if user:
            filters["user"] = user

        # Get audit logs
        logs = frappe.get_all(
            "Assistant Audit Log",
            filters=filters,
            fields=["action", "status", "user", "timestamp"],
            order_by="timestamp desc",
            limit=1000,
        )

        # Calculate statistics
        summary = {
            "total_events": len(logs),
            "date_range": {"from": from_date, "to": now()},
            "user_filter": user,
            "actions": {},
            "status_breakdown": {},
            "recent_events": logs[:10],  # Last 10 events
        }

        # Action breakdown
        for log in logs:
            action = log.get("action", "unknown")
            summary["actions"][action] = summary["actions"].get(action, 0) + 1

        # Status breakdown
        for log in logs:
            status = log.get("status", "unknown")
            summary["status_breakdown"][status] = summary["status_breakdown"].get(status, 0) + 1

        return summary

    except Exception as e:
        frappe.logger("audit_trail").error(
            f"Failed to get audit summary: {type(e).__name__}"
        )
        return {"total_events": 0, "error": "Audit summary unavailable"}
