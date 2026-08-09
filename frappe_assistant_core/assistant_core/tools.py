"""Deprecated compatibility adapter for the canonical FAC tool registry."""

from typing import Any, Dict, List

import frappe

from frappe_assistant_core.core.tool_registry import get_tool_registry


class ToolRegistry:
    """Backward-compatible facade with no independent authorization path."""

    @staticmethod
    def get_tools() -> List[Dict[str, Any]]:
        return get_tool_registry().get_available_tools(user=frappe.session.user)

    @staticmethod
    def create_document(
        doctype: str,
        data: Dict[str, Any],
        submit: bool = False,
    ) -> Dict[str, Any]:
        return get_tool_registry().execute_tool(
            "create_document",
            {
                "doctype": doctype,
                "data": data,
                "submit": submit,
            },
        )

    @staticmethod
    def get_document(doctype: str, name: str) -> Dict[str, Any]:
        return get_tool_registry().execute_tool(
            "get_document",
            {"doctype": doctype, "name": name},
        )

    @staticmethod
    def update_document(
        doctype: str,
        name: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        return get_tool_registry().execute_tool(
            "update_document",
            {
                "doctype": doctype,
                "name": name,
                "data": data,
            },
        )

    @staticmethod
    def search_documents(
        doctype: str,
        filters: Dict[str, Any] = None,
        fields: List[str] = None,
        limit: int = 20,
    ) -> Dict[str, Any]:
        return get_tool_registry().execute_tool(
            "list_documents",
            {
                "doctype": doctype,
                "filters": filters or {},
                "fields": fields or ["*"],
                "limit": limit,
            },
        )
