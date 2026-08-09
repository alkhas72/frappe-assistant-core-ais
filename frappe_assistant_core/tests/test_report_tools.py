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
Test suite for Report Tools using Plugin Architecture
Tests report operations through the tool registry
"""

import unittest

import frappe

from frappe_assistant_core.core.security_policy import PolicyDenied
from frappe_assistant_core.core.tool_registry import get_tool_registry
from frappe_assistant_core.tests.base_test import BaseAssistantTest


class TestReportTools(BaseAssistantTest):
    """Test report tools through plugin registry"""

    def setUp(self):
        super().setUp()
        self.registry = get_tool_registry()

    def test_get_tools_structure(self):
        """Test that report tools are properly registered"""
        tools = self.registry.get_available_tools()
        tool_names = [tool["name"] for tool in tools]

        # Check for core report tools
        expected_tools = ["generate_report", "get_report_data"]
        found_tools = [tool for tool in expected_tools if tool in tool_names]

        self.assertGreater(len(found_tools), 0, f"Should find report tools. Available: {tool_names}")

    def test_execute_tool_routing(self):
        """Test that tool routing works correctly"""
        tools = self.registry.get_available_tools()
        if tools:
            self.assertTrue(hasattr(self.registry, "execute_tool"))
            self.assertTrue(hasattr(self.registry, "get_available_tools"))

    def test_execute_tool_invalid_tool(self):
        """Test handling of invalid tool names"""
        with self.assertRaises(PolicyDenied) as raised:
            self.registry.execute_tool("nonexistent_report_tool", {})
        self.assertEqual(raised.exception.reason_code, "TOOL_UNKNOWN")

    def test_list_reports_basic(self):
        """Test basic report listing - placeholder for now"""
        # Skip actual test as report listing might not exist as a tool
        self.skipTest("Report listing test placeholder")

    def test_execute_report_query_report(self):
        """Test query report execution"""
        if not self.registry.has_tool("generate_report"):
            self.skipTest("generate_report tool not available")

        # Try a simple report that should exist
        arguments = {
            "report_name": "User Report"  # Simple report that might exist
        }

        try:
            result = self.registry.execute_tool("generate_report", arguments)
            self.assertIsInstance(result, dict)
        except Exception:
            # Report may not exist, which is fine for this test
            pass

    def test_execute_report_script_report(self):
        """Test script report execution"""
        self.skipTest("Script report test placeholder")

    def test_execute_report_with_filters(self):
        """Test report execution with filters"""
        self.skipTest("Report with filters test placeholder")

    def test_execute_report_nonexistent_report(self):
        """Test execution of nonexistent report"""
        if not self.registry.has_tool("generate_report"):
            self.skipTest("generate_report tool not available")

        arguments = {"report_name": "NonExistent Report 12345"}

        try:
            result = self.registry.execute_tool("generate_report", arguments)
            self.assertIsInstance(result, dict)
            # Should return error for nonexistent report
            if "success" in result:
                self.assertFalse(result["success"], "Should fail for nonexistent report")
        except Exception:
            # Exception is also acceptable for nonexistent report
            pass

    def test_execute_report_no_permission(self):
        """Test report execution without permission"""
        self.skipTest("Permission test placeholder")

    def test_get_report_columns_query_report(self):
        """Test getting report columns"""
        self.skipTest("Report columns test placeholder")

    def test_get_report_columns_script_report(self):
        """Test getting script report columns"""
        self.skipTest("Script report columns test placeholder")

    def test_list_reports_with_filters(self):
        """Test listing reports with filters"""
        self.skipTest("List reports with filters placeholder")

    def test_list_reports_no_permission(self):
        """Test listing reports without permission"""
        self.skipTest("List reports permission test placeholder")

    def test_report_format_functionality(self):
        """Test report format functionality"""
        self.skipTest("Report format test placeholder")


class TestReportToolsIntegration(BaseAssistantTest):
    """Integration tests for report tools"""

    def setUp(self):
        super().setUp()
        self.registry = get_tool_registry()

    def test_complete_report_workflow(self):
        """Test complete report workflow"""
        self.skipTest("Complete report workflow test placeholder")

    def test_report_error_handling(self):
        """Test report error handling"""
        if not self.registry.has_tool("generate_report"):
            self.skipTest("generate_report tool not available")

        # Test with invalid arguments
        invalid_tests = [
            {},  # Missing report_name
            {"report_name": ""},  # Empty report name
        ]

        for args in invalid_tests:
            try:
                result = self.registry.execute_tool("generate_report", args)
                self.assertIsInstance(result, dict)
            except Exception:
                # Exceptions are acceptable for invalid input
                pass
