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

from typing import Any, Dict, List, Optional

import frappe
from frappe import _


def _log_safe(tag: str, exc=None) -> None:
    """FAC v2.2: tag + type(exc).__name__ only. No exc_info/str/traceback."""
    try:
        if exc is None:
            frappe.logger("fac.metadata_tools").warning(tag)
        else:
            frappe.logger("fac.metadata_tools").warning(f"{tag}: {type(exc).__name__}")
    except Exception:
        pass

class MetadataTools:
    """assistant tools for Frappe metadata operations"""

    @staticmethod
    def get_tools() -> List[Dict]:
        """Return list of metadata-related assistant tools"""
        return [
            {
                "name": "get_doctype_info",
                "description": "Get DocType metadata and field information",
                "inputSchema": {
                    "type": "object",
                    "properties": {"doctype": {"type": "string", "description": "DocType name"}},
                    "required": ["doctype"],
                },
            },
            {
                "name": "metadata_list_doctypes",
                "description": "List all available DocTypes",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "module": {"type": "string", "description": "Filter by module"},
                        "custom_only": {
                            "type": "boolean",
                            "default": False,
                            "description": "Show only custom DocTypes",
                        },
                    },
                },
            },
            {
                "name": "metadata_permissions",
                "description": "Get permission information for a DocType",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "doctype": {"type": "string", "description": "DocType name"},
                        "user": {"type": "string", "description": "User to check permissions for (optional)"},
                    },
                    "required": ["doctype"],
                },
            },
            {
                "name": "metadata_workflow",
                "description": "Get workflow information for a DocType",
                "inputSchema": {
                    "type": "object",
                    "properties": {"doctype": {"type": "string", "description": "DocType name"}},
                    "required": ["doctype"],
                },
            },
        ]

    @staticmethod
    def execute_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a metadata tool with given arguments"""
        if tool_name == "get_doctype_info":
            return MetadataTools.get_doctype_metadata(**arguments)
        elif tool_name == "metadata_list_doctypes":
            return MetadataTools.list_doctypes(**arguments)
        elif tool_name == "metadata_permissions":
            return MetadataTools.get_permissions(**arguments)
        elif tool_name == "metadata_workflow":
            return MetadataTools.get_workflow(**arguments)
        else:
            raise Exception(f"Unknown metadata tool: {tool_name}")

    @staticmethod
    def _serialize_field(field, doctype: Optional[str] = None) -> Dict[str, Any]:
        """Serialize a DocField row into the shape returned by get_doctype_metadata.

        FAC v2.2: ``default`` is dropped when the field itself is a
        sensitive/admin field name. The central redactor inspects mapping keys
        (it sees ``"default"``, not the original ``fieldname``), so a sensitive
        default value (e.g. ``password="hunter2"`` on a Custom Field, or
        ``auth_method="Bearer xxx"`` on ``Email Account``) would otherwise
        leak straight through the sink.

        Sensitive-field check now uses the REAL parent/child DocType (via the
        ``doctype`` argument) instead of ``None``. The previous ``None`` could
        miss target-specific fields: ``Email Account.auth_method`` /
        ``Email Account.connected_user`` are sensitive specifically for
        ``Email Account`` and were not caught.
        """
        from frappe_assistant_core.core.security_policy import RESTRICTED_DOCTYPES, SecurityPolicy

        fieldname = field.fieldname
        # Drop ``default`` for sensitive/admin field names so the value cannot
        # leak via the ``default`` key. The DocType context is mandatory:
        # without it target-specific fields (Email Account.auth_method, etc.)
        # are missed.
        include_default = True
        try:
            if SecurityPolicy._contains_restricted_fields(
                doctype, frozenset({fieldname})
            ):
                include_default = False
        except Exception:
            include_default = False

        entry = {
            "fieldname": fieldname,
            "label": field.label,
            "fieldtype": field.fieldtype,
            "options": field.options,
            "reqd": field.reqd,
            "read_only": field.read_only,
            "hidden": field.hidden,
            "description": field.description,
        }
        if include_default:
            entry["default"] = field.default
        return entry

    @staticmethod
    def get_doctype_metadata(doctype: str) -> Dict[str, Any]:
        """Get DocType metadata and field information.

        Restricted DocTypes (parent target) are rejected by the central policy
        before this helper runs — but defensively we re-check here too so a
        direct call from a non-MCP code path cannot leak schema. Direct
        requests for a child DocType (``istable == 1``) are also refused: per
        the design spec child rows are only ever surfaced inside an allowed
        parent document. The nested structure of an *allowed parent's*
        non-restricted child tables IS shown — only the ratified restricted
        child types (``DocPerm``, ``DocShare``, ``Custom Field``, ...) have
        their schema hidden (FAC Task 7 rev. 2, 2026-08-09).

        The ``permissions`` list (role→perm matrix) is intentionally NOT
        returned: it used to disclose role names and their permission bits to
        any caller with read on the DocType, which is a privilege-escalation
        primitive.
        """
        from frappe_assistant_core.core.security_policy import (
            RESTRICTED_DOCTYPES,
            SecurityPolicy,
        )

        try:
            if not frappe.db.exists("DocType", doctype):
                return {"success": False, "error": f"DocType '{doctype}' not found"}

            # Defensive restricted-target gate. ``_is_restricted_target``
            # covers both the ratified RESTRICTED_DOCTYPES baseline and
            # ``meta.istable == 1`` (direct child DocType requests are not
            # allowed — child rows surface only inside an allowed parent).
            if SecurityPolicy._is_restricted_target(doctype):
                return {"success": False, "error": f"DocType '{doctype}' is restricted"}

            if not frappe.has_permission(doctype, "read"):
                return {"success": False, "error": f"No permission to access DocType '{doctype}'"}

            meta = frappe.get_meta(doctype)

            fields = [MetadataTools._serialize_field(field, doctype) for field in meta.fields]

            link_fields = [
                {"fieldname": field.fieldname, "label": field.label, "options": field.options}
                for field in meta.get_link_fields()
            ]

            # Child tables: include the child DocType's own field metadata so
            # the caller can build nested row objects without a second tool
            # call (#192). Two scoping rules:
            #   * Only the RATIFIED RESTRICTED_DOCTYPES set hides its schema
            #     (NOT every istable DocType — otherwise every child schema
            #     would be empty, breaking #192's contract).
            #   * Sensitive fields inside an otherwise-readable child are
            #     still stripped by ``_serialize_field``.
            child_tables = []
            for table_field in meta.get_table_fields():
                child_doctype = table_field.options
                child_entry = {
                    "fieldname": table_field.fieldname,
                    "label": table_field.label,
                    "fieldtype": table_field.fieldtype,
                    "options": child_doctype,
                    "reqd": table_field.reqd,
                    "fields": [],
                }
                if (
                    child_doctype
                    and child_doctype not in RESTRICTED_DOCTYPES
                    and frappe.db.exists("DocType", child_doctype)
                ):
                    child_meta = frappe.get_meta(child_doctype)
                    child_entry["fields"] = [
                        MetadataTools._serialize_field(f, child_doctype) for f in child_meta.fields
                    ]
                else:
                    # Restricted child: keep the structural pointer so the
                    # caller knows a child row exists, but do NOT serialise
                    # the restricted child's own field schema.
                    child_entry["fields"] = []
                    child_entry["restricted"] = True
                child_tables.append(child_entry)

            return {
                "success": True,
                "doctype": doctype,
                "module": meta.module,
                "is_submittable": bool(meta.is_submittable),
                "is_tree": bool(meta.is_tree),
                "is_single": bool(meta.issingle),
                "is_child_table": bool(meta.istable),
                "naming_rule": meta.naming_rule,
                "title_field": meta.title_field,
                "fields": fields,
                "link_fields": link_fields,
                "child_tables": child_tables,
                # NOTE: ``permissions`` (role→perm matrix) intentionally omitted.
                # It used to disclose role names and permission bits to any
                # reader of the DocType — a privilege-escalation primitive.
            }

        except Exception:
            _log_safe("get doctype metadata failed")
            return {"success": False, "error": "Get DocType Metadata failed"}

    @staticmethod
    def list_doctypes(module: str = None, custom_only: bool = False) -> Dict[str, Any]:
        """List all available DocTypes"""
        try:
            filters = {}
            if module:
                filters["module"] = module
            if custom_only:
                filters["custom"] = 1

            doctypes = frappe.get_all(
                "DocType",
                filters=filters,
                fields=["name", "module", "is_submittable", "is_tree", "istable", "custom", "description"],
                order_by="name",
            )

            # Filter by read permissions
            accessible_doctypes = []
            for dt in doctypes:
                if frappe.has_permission(dt.name, "read"):
                    accessible_doctypes.append(dt)

            return {
                "success": True,
                "doctypes": accessible_doctypes,
                "count": len(accessible_doctypes),
                "filters_applied": {"module": module, "custom_only": custom_only},
            }

        except Exception:
            _log_safe("list doctypes failed")
            return {"success": False, "error": "List DocTypes failed"}

    @staticmethod
    def get_permissions(doctype: str, user: str = None) -> Dict[str, Any]:
        """Get permission information for a DocType"""
        try:
            if not frappe.db.exists("DocType", doctype):
                return {"success": False, "error": f"DocType '{doctype}' not found"}

            check_user = user or frappe.session.user

            # Reporting capabilities — not a security boundary. throw=False
            # keeps this explicit and silences the unchecked-permission rule.
            permissions = {
                "read": frappe.has_permission(doctype, "read", user=check_user, throw=False),
                "write": frappe.has_permission(doctype, "write", user=check_user, throw=False),
                "create": frappe.has_permission(doctype, "create", user=check_user, throw=False),
                "delete": frappe.has_permission(doctype, "delete", user=check_user, throw=False),
                "submit": frappe.has_permission(doctype, "submit", user=check_user, throw=False),
                "cancel": frappe.has_permission(doctype, "cancel", user=check_user, throw=False),
                "amend": frappe.has_permission(doctype, "amend", user=check_user, throw=False),
            }

            # Get user roles
            user_roles = frappe.get_roles(check_user)

            # Get DocType permission rules
            meta = frappe.get_meta(doctype)
            permission_rules = [p.as_dict() for p in meta.permissions]

            return {
                "success": True,
                "doctype": doctype,
                "user": check_user,
                "permissions": permissions,
                "user_roles": user_roles,
                "permission_rules": permission_rules,
            }

        except Exception:
            _log_safe("get permissions failed")
            return {"success": False, "error": "Get Permissions failed"}

    @staticmethod
    def get_workflow(doctype: str) -> Dict[str, Any]:
        """Get workflow information for a DocType"""
        try:
            if not frappe.db.exists("DocType", doctype):
                return {"success": False, "error": f"DocType '{doctype}' not found"}

            # Check if workflow exists for this DocType
            workflow = frappe.db.get_value("Workflow", {"document_type": doctype}, "name")

            if not workflow:
                return {
                    "success": True,
                    "doctype": doctype,
                    "has_workflow": False,
                    "message": f"No workflow defined for DocType '{doctype}'",
                }

            # Get workflow details
            workflow_doc = frappe.get_doc("Workflow", workflow)

            # Get workflow states
            states = []
            for state in workflow_doc.states:
                states.append(
                    {
                        "state": state.state,
                        "doc_status": state.doc_status,
                        "allow_edit": state.allow_edit,
                        "message": state.message,
                    }
                )

            # Get workflow transitions
            transitions = []
            for transition in workflow_doc.transitions:
                transitions.append(
                    {
                        "state": transition.state,
                        "action": transition.action,
                        "next_state": transition.next_state,
                        "allowed": transition.allowed,
                        "allow_self_approval": transition.allow_self_approval,
                    }
                )

            return {
                "success": True,
                "doctype": doctype,
                "has_workflow": True,
                "workflow_name": workflow_doc.name,
                "workflow_state_field": workflow_doc.workflow_state_field,
                "states": states,
                "transitions": transitions,
            }

        except Exception:
            _log_safe("get workflow failed")
            return {"success": False, "error": "Get Workflow failed"}
