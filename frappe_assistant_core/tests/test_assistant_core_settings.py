"""Behavior tests for Assistant Core settings updates."""

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from frappe_assistant_core.assistant_core.doctype.assistant_core_settings.assistant_core_settings import (
    AssistantCoreSettings,
)


class TestAssistantCoreSettings(unittest.TestCase):
    def test_enabling_server_enqueues_background_api_after_commit(self):
        """A worker must not observe settings until their update transaction commits."""
        settings = AssistantCoreSettings.__new__(AssistantCoreSettings)
        settings.server_enabled = True
        settings.has_value_changed = lambda fieldname: fieldname == "server_enabled"

        with patch(
            "frappe_assistant_core.assistant_core.server.get_server_instance",
            return_value=SimpleNamespace(running=False),
        ), patch(
            "frappe_assistant_core.assistant_core.doctype.assistant_core_settings.assistant_core_settings.frappe.enqueue"
        ) as enqueue:
            settings.on_update()

        enqueue.assert_called_once_with(
            "frappe_assistant_core.assistant_core.server.enable_background_api",
            queue="short",
            enqueue_after_commit=True,
        )
