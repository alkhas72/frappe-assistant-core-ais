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
ChatGPT-Compatible Fetch Tool

This tool provides a document retrieval interface compatible with ChatGPT's MCP requirements.
It wraps the existing get_document functionality but formats results according
to ChatGPT's specific schema requirements.

ChatGPT Requirements:
- Tool name must be exactly "fetch"
- Input: Single "id" string parameter (format: "doctype/name")
- Output: {"id": str, "title": str, "text": str, "url": str, "metadata": dict}
"""

import json
from typing import Any, Dict

import frappe
from frappe import _

from frappe_assistant_core.core.base_tool import BaseTool


class ChatGPTFetch(BaseTool):
    """
    ChatGPT-compatible fetch tool for MCP integration.

    This tool conforms to ChatGPT's specific MCP requirements:
    - Returns document with id, title, text, url, and metadata fields
    - Accepts a document ID in format "doctype/name"
    - Formats output as required by ChatGPT connectors
    """

    def __init__(self):
        super().__init__()
        self.name = "fetch"
        self.description = "Retrieve complete document content by ID for detailed analysis and citation. Use this after finding relevant documents with the search tool to get complete information for analysis and proper citation."

        self.inputSchema = {
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                    "description": "Document ID from search results (format: 'doctype/name', e.g., 'Customer/CUST-00001')",
                }
            },
            "required": ["id"],
        }

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Retrieve document and format for ChatGPT.

        Args:
            arguments: Dict with "id" key (format: "doctype/name")

        Returns:
            Dict with:
            - id: Document identifier
            - title: Document title
            - text: Full document content as JSON string
            - url: URL for citation
            - metadata: Additional document metadata
        """
        from frappe_assistant_core.core.security_policy import (
            SecurityPolicy,
            ToolContext,
        )

        try:
            doc_id = arguments.get("id", "").strip()

            if not doc_id:
                raise ValueError("Document ID is required")

            # Parse ID format: "doctype/name"
            if "/" not in doc_id:
                raise ValueError(f"Invalid document ID format. Expected 'doctype/name', got: {doc_id}")

            doctype, name = doc_id.split("/", 1)

            # FAC v2.2: stable, indistinguishable refusal message. The same
            # constant string is used for restricted DocTypes and for
            # unreadable business records — the message carries no doctype
            # or name so it cannot be used to enumerate targets. (Direct
            # Python callers receive this as ``frappe.PermissionError``;
            # the MCP path sees the central-policy denial.)
            _REFUSAL = "Permission denied"

            # FAC Task 7 (rev. 2): restricted-target gate MUST run before
            # ``frappe.has_permission`` and ``frappe.get_doc``. The central
            # policy closes the MCP path, but a direct call into
            # ``ChatGPTFetch.execute`` from a privileged internal caller could
            # otherwise pass ``has_permission`` (System Manager has read on
            # restricted DocTypes) and reach ``get_doc``.
            if SecurityPolicy._is_restricted_target(doctype):
                raise frappe.PermissionError(_REFUSAL)

            # Native Frappe row-level read permission. The central policy in
            # ``BaseTool._safe_execute`` already authorized the tool call
            # (restricted DocType, hard-deny set, role config, DocType-level
            # permission); this is the row-level second lock. There is no
            # System Manager bypass — the legacy ``validate_document_access``
            # shim granted one and is no longer consulted here.
            if not frappe.has_permission(doctype, "read", doc=name):
                raise frappe.PermissionError(_REFUSAL)

            doc = frappe.get_doc(doctype, name)
            # Central redaction removes universal sensitive keys (password,
            # token, ...) and DocType-specific sensitive/admin fields. Applied
            # locally here because ``_format_document_as_text`` serializes the
            # dict to a JSON string, which the central sink in
            # ``_safe_execute`` treats as opaque. The sink still runs after as
            # defence in depth. No role bypasses redaction.
            read_context = ToolContext(
                operation="read",
                target_doctype=doctype,
                target_name=name,
                required_permissions=frozenset({"read"}),
            )
            doc_dict = SecurityPolicy.redact_output(read_context, doc.as_dict())

            # Create title from name field or document name
            title = doc_dict.get("title") or doc_dict.get("name") or name

            # Convert document to formatted text
            text_content = self._format_document_as_text(doc_dict, doctype, name)

            # Generate URL for citation
            site_url = frappe.utils.get_url()
            url = f"{site_url}/app/{frappe.scrub(doctype)}/{name}"

            # Extract metadata
            metadata = {
                "doctype": doctype,
                "modified": str(doc_dict.get("modified", "")),
                "owner": doc_dict.get("owner", ""),
                "docstatus": doc_dict.get("docstatus", 0),
            }

            return {"id": doc_id, "title": title, "text": text_content, "url": url, "metadata": metadata}

        except frappe.DoesNotExistError:
            # FAC v2.3: missing record is INDISTINGUISHABLE from unreadable
            # record. Both raise the same constant ``PermissionError`` with
            # no doctype/name/doc_id in the message or in the log. The
            # underlying exception text never reaches the public surface; the
            # log keeps one safe record (constant tag + type only).
            try:
                frappe.logger("fac.chatgpt_fetch").warning(
                    "fetch refused: DoesNotExistError"
                )
            except Exception:
                pass
            raise frappe.PermissionError("Permission denied") from None

        except frappe.PermissionError as e:
            # Do NOT echo the underlying exception text — it may include the
            # sensitive value that triggered the permission failure. The
            # sanitized audit row in ``_safe_execute`` retains the stable
            # reason; we propagate a clean ``PermissionError`` with the SAME
            # constant message as the gates above so a downstream caller
            # cannot distinguish restricted-target from unreadable-record OR
            # from a missing record by inspecting the exception text.
            try:
                frappe.logger("fac.chatgpt_fetch").warning(
                    f"fetch refused: {type(e).__name__}"
                )
            except Exception:
                pass
            raise frappe.PermissionError("Permission denied") from e

        except ValueError:
            # Input validation errors raised above ("Document ID is required",
            # "Invalid document ID format", ...) — surface as-is.
            raise

    def _format_document_as_text(self, doc_dict: Dict, doctype: str, name: str) -> str:
        """
        Format document data as readable text for ChatGPT.

        Args:
            doc_dict: Document dictionary
            doctype: DocType name
            name: Document name

        Returns:
            Formatted text representation
        """
        lines = [f"# {doctype}: {name}", ""]

        # Add key fields first
        priority_fields = ["title", "subject", "description", "customer_name", "item_name"]

        for field in priority_fields:
            if field in doc_dict and doc_dict[field]:
                label = field.replace("_", " ").title()
                lines.append(f"**{label}**: {doc_dict[field]}")

        lines.append("")
        lines.append("## All Fields")
        lines.append("")

        # Add remaining fields as JSON for structured access
        lines.append("```json")
        lines.append(json.dumps(doc_dict, indent=2, default=str))
        lines.append("```")

        return "\n".join(lines)


# Export class for discovery
chatgpt_fetch = ChatGPTFetch
