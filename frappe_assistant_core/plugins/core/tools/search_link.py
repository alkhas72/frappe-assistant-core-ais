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
Search Link Tool for Core Plugin.
Search for link field options with filtering.
"""

from typing import Any, Dict

import frappe
from frappe import _

from frappe_assistant_core.core.base_tool import BaseTool


class SearchLink(BaseTool):
    """
    Tool for searching link field options.

    Provides capabilities for:
    - Link field value search
    - Filter-based search
    - Permission-aware results
    """

    def __init__(self):
        super().__init__()
        self.name = "search_link"
        self.description = "Search for link field options"
        self.requires_permission = None  # Permission checked dynamically per DocType

        self.inputSchema = {
            "type": "object",
            "properties": {
                "doctype": {"type": "string", "description": "Target DocType for link"},
                "query": {"type": "string", "description": "Search query"},
                "filters": {"type": "object", "default": {}, "description": "Additional filters"},
            },
            "required": ["doctype", "query"],
        }

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute link search"""
        try:
            # Import the search implementation
            from .search_tools import SearchTools

            # Execute search using existing implementation
            return SearchTools.search_link(
                doctype=arguments.get("doctype"),
                query=arguments.get("query"),
                filters=arguments.get("filters", {}),
            )

        except Exception as exc:
            frappe.logger("fac.search_link").warning(f"search_link failed: {type(exc).__name__}")
            return {"success": False, "error": "Link search failed"}


# Make sure class name matches file name for discovery
search_link = SearchLink
