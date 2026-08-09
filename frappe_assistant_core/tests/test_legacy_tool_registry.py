"""The deprecated tool registry must only delegate to the canonical registry."""

from unittest.mock import MagicMock, patch

from frappe_assistant_core.tests.base_test import BaseAssistantTest


class TestLegacyToolRegistryAdapter(BaseAssistantTest):
    def setUp(self):
        super().setUp()
        from frappe_assistant_core.assistant_core import tools as legacy_tools

        self.legacy_tools = legacy_tools
        self.registry = MagicMock()
        self.registry.get_available_tools.return_value = [{"name": "get_document"}]
        self.registry.execute_tool.side_effect = lambda name, arguments: {
            "name": name,
            "arguments": arguments,
        }

    def _legacy_boundary(self):
        stack = [
            patch.object(
                self.legacy_tools,
                "get_tool_registry",
                return_value=self.registry,
                create=True,
            ),
            patch.object(
                self.legacy_tools.frappe,
                "get_all",
                side_effect=AssertionError("legacy get_all bypass"),
            ),
            patch.object(
                self.legacy_tools.frappe,
                "get_doc",
                side_effect=AssertionError("legacy get_doc bypass"),
            ),
            patch.object(
                self.legacy_tools.frappe,
                "has_permission",
                side_effect=AssertionError("legacy has_permission bypass"),
            ),
            patch.object(
                self.legacy_tools.frappe.db,
                "exists",
                side_effect=AssertionError("legacy db.exists bypass"),
            ),
        ]
        return stack

    def test_get_tools_delegates_to_canonical_publication(self):
        first, second, third, fourth, fifth = self._legacy_boundary()
        with first, second, third, fourth, fifth:
            result = self.legacy_tools.ToolRegistry.get_tools()

        self.assertEqual(result, [{"name": "get_document"}])
        self.registry.get_available_tools.assert_called_once()

    def test_crud_and_search_delegate_exact_arguments(self):
        first, second, third, fourth, fifth = self._legacy_boundary()
        with first, second, third, fourth, fifth:
            create = self.legacy_tools.ToolRegistry.create_document(
                "ToDo",
                {"description": "safe"},
                submit=True,
            )
            get = self.legacy_tools.ToolRegistry.get_document("ToDo", "TD-1")
            update = self.legacy_tools.ToolRegistry.update_document(
                "ToDo",
                "TD-1",
                {"description": "updated"},
            )
            search = self.legacy_tools.ToolRegistry.search_documents(
                "ToDo",
                filters={"status": "Open"},
                fields=["name"],
                limit=5,
            )

        self.assertEqual(create["name"], "create_document")
        self.assertEqual(get["name"], "get_document")
        self.assertEqual(update["name"], "update_document")
        self.assertEqual(search["name"], "list_documents")
        self.assertEqual(
            self.registry.execute_tool.call_args_list[0].args,
            (
                "create_document",
                {
                    "doctype": "ToDo",
                    "data": {"description": "safe"},
                    "submit": True,
                },
            ),
        )
        self.assertEqual(
            self.registry.execute_tool.call_args_list[1].args,
            ("get_document", {"doctype": "ToDo", "name": "TD-1"}),
        )
        self.assertEqual(
            self.registry.execute_tool.call_args_list[2].args,
            (
                "update_document",
                {
                    "doctype": "ToDo",
                    "name": "TD-1",
                    "data": {"description": "updated"},
                },
            ),
        )
        self.assertEqual(
            self.registry.execute_tool.call_args_list[3].args,
            (
                "list_documents",
                {
                    "doctype": "ToDo",
                    "filters": {"status": "Open"},
                    "fields": ["name"],
                    "limit": 5,
                },
            ),
        )
