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
Search DocType Tool for Core Plugin.
Search within a specific DocType with permission-aware results.
"""

from typing import Any, Dict

import frappe
from frappe import _

from frappe_assistant_core.core.base_tool import BaseTool


class SearchDoctype(BaseTool):
    """
    Tool for searching within a specific DocType.

    Provides capabilities for:
    - Targeted search within specific DocTypes
    - Permission-aware results
    - Searchable field identification
    """

    def __init__(self):
        super().__init__()
        self.name = "search_doctype"
        self.description = "Search within a specific DocType"
        self.requires_permission = None  # Permission checked dynamically per DocType

        self.inputSchema = {
            "type": "object",
            "properties": {
                "doctype": {"type": "string", "description": "DocType to search in"},
                "query": {"type": "string", "description": "Search query"},
                "limit": {"type": "integer", "default": 20, "description": "Maximum results"},
            },
            "required": ["doctype", "query"],
        }

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute DocType search"""
        try:
            # Import the search implementation
            from .search_tools import SearchTools

            # Execute search using existing implementation
            return SearchTools.search_doctype(
                doctype=arguments.get("doctype"),
                query=arguments.get("query"),
                limit=arguments.get("limit", 20),
            )

        except Exception as exc:
            frappe.logger("fac.search_doctype").warning(f"search_doctype failed: {type(exc).__name__}")
            return {"success": False, "error": "Document search failed"}


# Make sure class name matches file name for discovery
search_doctype = SearchDoctype
