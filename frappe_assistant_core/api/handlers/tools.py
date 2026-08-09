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
Clean tools handlers using the new plugin manager architecture.
Replaces workarounds with proper state management and error handling.
"""

import json
from typing import Any, Dict, Optional

import frappe

from frappe_assistant_core.constants.definitions import ErrorCodes, ErrorMessages, LogMessages
from frappe_assistant_core.core.security_policy import PolicyDenied
from frappe_assistant_core.core.tool_registry import get_tool_registry
from frappe_assistant_core.mcp.server import (
    audit_tools_list_summary,
    audit_unavailable_tool_call,
)
from frappe_assistant_core.utils.logger import api_logger
from frappe_assistant_core.utils.plugin_manager import PluginError, PluginNotFoundError, PluginValidationError


def handle_tools_list(request_id: Optional[Any]) -> Dict[str, Any]:
    """Handle tools/list request - return available tools"""
    try:
        api_logger.debug(LogMessages.TOOLS_LIST_REQUEST)

        registry = get_tool_registry()
        tools = registry.get_available_tools(user=frappe.session.user)
        audit_tools_list_summary(len(tools))

        response = {"jsonrpc": "2.0", "result": {"tools": tools}}

        if request_id is not None:
            response["id"] = request_id

        api_logger.info(
            f"Tools list request completed for user {frappe.session.user}, returned {len(tools)} tools"
        )
        return response

    except Exception as e:
        api_logger.error(f"Error in handle_tools_list: type={type(e).__name__}")
        audit_tools_list_summary(0, status="Error")

        response = {
            "jsonrpc": "2.0",
            "error": {
                "code": ErrorCodes.INTERNAL_ERROR,
                "message": ErrorMessages.INTERNAL_ERROR,
            },
        }

        if request_id is not None:
            response["id"] = request_id

        return response


def handle_tool_call(params: Dict[str, Any], request_id: Optional[Any]) -> Dict[str, Any]:
    """Handle tools/call request - execute specific tool"""
    try:
        api_logger.debug(LogMessages.TOOL_CALL_REQUEST.format("<sanitized>"))

        if not isinstance(params, dict):
            audit_unavailable_tool_call(None, None, "ARGUMENTS_INVALID")
            response = {
                "jsonrpc": "2.0",
                "error": {
                    "code": ErrorCodes.INVALID_PARAMS,
                    "message": "Invalid tool arguments",
                },
            }
            if request_id is not None:
                response["id"] = request_id
            return response

        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if not tool_name:
            audit_unavailable_tool_call(tool_name, arguments, "TOOL_UNKNOWN")
            response = {
                "jsonrpc": "2.0",
                "error": {"code": ErrorCodes.INVALID_PARAMS, "message": ErrorMessages.MISSING_TOOL_NAME},
            }
            if request_id is not None:
                response["id"] = request_id
            return response

        if not isinstance(arguments, dict):
            audit_unavailable_tool_call(
                tool_name,
                None,
                "ARGUMENTS_INVALID",
            )
            response = {
                "jsonrpc": "2.0",
                "error": {
                    "code": ErrorCodes.INVALID_PARAMS,
                    "message": "Invalid tool arguments",
                },
            }
            if request_id is not None:
                response["id"] = request_id
            return response

        # Execute tool using registry
        registry = get_tool_registry()
        api_logger.info("Executing canonical tool request")

        try:
            result = registry.execute_tool(tool_name, arguments)
        except (PolicyDenied, PermissionError):
            api_logger.warning("Tool execution denied")
            response = {
                "jsonrpc": "2.0",
                "error": {"code": ErrorCodes.AUTHENTICATION_REQUIRED, "message": ErrorMessages.ACCESS_DENIED},
            }
            if request_id is not None:
                response["id"] = request_id
            return response
        except frappe.ValidationError:
            api_logger.warning("Tool validation failed")
            response = {
                "jsonrpc": "2.0",
                "error": {
                    "code": ErrorCodes.INVALID_PARAMS,
                    "message": "Tool validation failed",
                },
            }
            if request_id is not None:
                response["id"] = request_id
            return response
        except Exception as e:
            api_logger.error(f"Tool execution failed: type={type(e).__name__}")
            response = {
                "jsonrpc": "2.0",
                "error": {
                    "code": ErrorCodes.INTERNAL_ERROR,
                    "message": "Tool execution failed",
                },
            }
            if request_id is not None:
                response["id"] = request_id
            return response

        # Ensure result is a string for Claude Desktop compatibility
        if not isinstance(result, str):
            result = json.dumps(result, default=str)

        response = {"jsonrpc": "2.0", "result": {"content": [{"type": "text", "text": result}]}}

        if request_id is not None:
            response["id"] = request_id

        api_logger.info("Canonical tool request completed successfully")
        return response

    except Exception as e:
        api_logger.error(f"Error in handle_tool_call: type={type(e).__name__}")

        response = {
            "jsonrpc": "2.0",
            "error": {
                "code": ErrorCodes.INTERNAL_ERROR,
                "message": ErrorMessages.INTERNAL_ERROR,
            },
        }

        if request_id is not None:
            response["id"] = request_id

        return response
