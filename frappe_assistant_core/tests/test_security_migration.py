"""Tests for deny-by-default migration and configuration sync (Task 5).

Covers the idempotent ``harden_fac_tool_access_defaults`` patch, the
``_sync_tool_configurations``/``_sync_plugin_configurations`` deny-by-default
sync semantics, the canonical tool registry import in migration hooks, and the
fail-closed ``FAC Tool Configuration.user_has_access`` contract.
"""

import importlib
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import frappe
from frappe.tests.utils import FrappeTestCase

from frappe_assistant_core.patches.v2_5.harden_fac_tool_access_defaults import execute

TOOL_CONFIG_DOCTYPE = "FAC Tool Configuration"
ROLE_ACCESS_DOCTYPE = "FAC Tool Role Access"
PLUGIN_CONFIG_DOCTYPE = "FAC Plugin Configuration"

# (tool_name, enabled, role_access_mode, roles) -> expected (enabled, mode, roles)
CASES = (
    # hard-denied tool: hardened even with a valid restricted allowlist
    ("run_python_code", 1, "Restrict to Listed Roles", ["System Manager"], 0, "Deny All", []),
    # legacy Allow All: hardened
    ("get_document", 1, "Allow All", [], 0, "Deny All", []),
    # valid restricted config for a configurable tool: preserved untouched
    (
        "get_document",
        1,
        "Restrict to Listed Roles",
        ["Assistant User"],
        1,
        "Restrict to Listed Roles",
        ["Assistant User"],
    ),
)

EXTRA_CASES = (
    # hard-denied tool under legacy Allow All
    ("delete_document", 1, "Allow All", [], 0, "Deny All", []),
    # empty/unknown mode hardens
    ("list_documents", 1, "", [], 0, "Deny All", []),
    ("list_documents", 1, "Some Future Mode", [], 0, "Deny All", []),
    # restricted mode with an empty role list hardens
    ("list_documents", 1, "Restrict to Listed Roles", [], 0, "Deny All", []),
)


def _delete_config(tool_name):
    frappe.db.delete(ROLE_ACCESS_DOCTYPE, {"parent": tool_name})
    frappe.db.delete(TOOL_CONFIG_DOCTYPE, {"tool_name": tool_name})


def _seed_config(tool_name, enabled, mode, roles, plugin_name="core"):
    """Create a config row, including legacy states the new schema rejects."""
    _delete_config(tool_name)

    doc = frappe.get_doc(
        {
            "doctype": TOOL_CONFIG_DOCTYPE,
            "tool_name": tool_name,
            "plugin_name": plugin_name,
            "enabled": enabled,
            # Insert a schema-valid mode first; legacy modes are forced below
            # via frappe.db.set_value, which bypasses controller validation.
            "role_access_mode": "Restrict to Listed Roles" if roles else "Deny All",
        }
    )
    for role in roles:
        doc.append("role_access", {"role": role, "allow_access": 1})
    doc.insert(ignore_permissions=True)

    if mode != doc.role_access_mode:
        frappe.db.set_value(TOOL_CONFIG_DOCTYPE, tool_name, "role_access_mode", mode)


def _config_state(tool_name):
    enabled, mode = frappe.db.get_value(
        TOOL_CONFIG_DOCTYPE, tool_name, ["enabled", "role_access_mode"]
    )
    roles = frappe.get_all(ROLE_ACCESS_DOCTYPE, filters={"parent": tool_name}, pluck="role")
    return int(enabled or 0), mode, sorted(roles)


class TestHardenFacToolAccessDefaults(FrappeTestCase):
    touched_tools = tuple({case[0] for case in CASES + EXTRA_CASES})

    def tearDown(self):
        for tool_name in self.touched_tools:
            _delete_config(tool_name)
        frappe.db.commit()
        super().tearDown()

    def test_migration_matrix(self):
        for tool_name, enabled, mode, roles, exp_enabled, exp_mode, exp_roles in CASES + EXTRA_CASES:
            with self.subTest(tool_name=tool_name, mode=mode, roles=roles):
                _seed_config(tool_name, enabled, mode, roles)
                execute()
                self.assertEqual(_config_state(tool_name), (exp_enabled, exp_mode, exp_roles))

    def test_second_run_is_semantically_empty(self):
        for tool_name, enabled, mode, roles, *_ in CASES + EXTRA_CASES:
            _seed_config(tool_name, enabled, mode, roles)
        execute()

        def snapshot():
            configs = frappe.get_all(
                TOOL_CONFIG_DOCTYPE,
                filters={"tool_name": ("in", self.touched_tools)},
                fields=["name", "enabled", "role_access_mode"],
                order_by="name",
            )
            rows = frappe.get_all(
                ROLE_ACCESS_DOCTYPE,
                filters={"parent": ("in", self.touched_tools)},
                fields=["parent", "role", "allow_access"],
                order_by="parent, role",
            )
            return configs, rows

        before = snapshot()
        execute()
        after = snapshot()
        self.assertEqual(before, after)

    def test_no_allow_all_remains(self):
        for tool_name, enabled, mode, roles, *_ in CASES:
            _seed_config(tool_name, enabled, mode, roles)
        execute()
        remaining = frappe.get_all(
            TOOL_CONFIG_DOCTYPE,
            filters={"role_access_mode": "Allow All"},
            pluck="name",
        )
        self.assertEqual(remaining, [])


class TestSyncToolConfigurationDefaults(FrappeTestCase):
    created_tools = (
        "TEST_sync_new_tool",
        "TEST_sync_ext_tool",
        "TEST_sync_keep_tool",
        "TEST_sync_ghost_tool",
    )

    def tearDown(self):
        for tool_name in self.created_tools:
            _delete_config(tool_name)
        frappe.db.commit()
        super().tearDown()

    def _tool_info(self, plugin_name):
        return SimpleNamespace(
            plugin_name=plugin_name,
            description="Sync test tool",
            instance=SimpleNamespace(source_app="frappe_assistant_core"),
        )

    def _run_sync(self, tools, external=None):
        manager = MagicMock()
        manager.get_all_tools.return_value = tools
        manager.get_enabled_plugins.return_value = {
            info.plugin_name for info in tools.values()
        }
        with (
            patch(
                "frappe_assistant_core.utils.plugin_manager.get_plugin_manager",
                return_value=manager,
            ),
            patch(
                "frappe_assistant_core.utils.migration_hooks._get_external_tools_for_sync",
                return_value=external or {},
            ),
            patch(
                "frappe_assistant_core.utils.tool_category_detector.detect_tool_category",
                return_value="read_only",
            ),
        ):
            from frappe_assistant_core.utils.migration_hooks import _sync_tool_configurations

            _sync_tool_configurations()

    def test_new_plugin_tool_created_disabled_deny_all(self):
        self._run_sync({"TEST_sync_new_tool": self._tool_info("TEST_plugin")})
        self.assertEqual(_config_state("TEST_sync_new_tool"), (0, "Deny All", []))

    def test_new_external_tool_created_disabled_deny_all(self):
        self._run_sync(
            {},
            external={
                "TEST_sync_ext_tool": {
                    "description": "External sync test tool",
                    "source_app": "external_app",
                    "module_path": "external_app.tools.TestTool",
                }
            },
        )
        self.assertEqual(_config_state("TEST_sync_ext_tool"), (0, "Deny All", []))

    def test_existing_restricted_config_not_overwritten(self):
        _seed_config("TEST_sync_keep_tool", 1, "Restrict to Listed Roles", ["Assistant User"])
        self._run_sync({"TEST_sync_keep_tool": self._tool_info("TEST_plugin")})
        self.assertEqual(
            _config_state("TEST_sync_keep_tool"),
            (1, "Restrict to Listed Roles", ["Assistant User"]),
        )

    def test_disabled_plugin_config_survives_and_reenable_stays_denied(self):
        # Tool belongs to a plugin that is later disabled: the config must not
        # be deleted while the tool is absent from discovery, and re-enabling
        # the plugin must not recreate a permissive record.
        _seed_config("TEST_sync_ghost_tool", 1, "Restrict to Listed Roles", ["Assistant User"])

        self._run_sync({})  # plugin disabled -> tool absent from discovery
        self.assertEqual(
            _config_state("TEST_sync_ghost_tool"),
            (1, "Restrict to Listed Roles", ["Assistant User"]),
        )

        self._run_sync({"TEST_sync_ghost_tool": self._tool_info("TEST_plugin")})
        self.assertEqual(
            _config_state("TEST_sync_ghost_tool"),
            (1, "Restrict to Listed Roles", ["Assistant User"]),
        )


class TestSyncPluginConfigurationDefaults(FrappeTestCase):
    created_plugins = ("TEST_new_plugin", "TEST_ghost_plugin")

    def tearDown(self):
        for plugin_name in self.created_plugins:
            frappe.db.delete(PLUGIN_CONFIG_DOCTYPE, {"plugin_name": plugin_name})
        frappe.db.commit()
        super().tearDown()

    def _run_sync(self, discovered):
        discovery = MagicMock()
        discovery.discover_plugins.return_value = discovered
        with patch(
            "frappe_assistant_core.utils.plugin_manager.PluginDiscovery",
            return_value=discovery,
        ):
            from frappe_assistant_core.utils.migration_hooks import _sync_plugin_configurations

            _sync_plugin_configurations()

    def _plugin_info(self, display_name):
        return SimpleNamespace(display_name=display_name, description="Sync test plugin")

    def test_new_non_core_plugin_disabled_core_enabled(self):
        frappe.db.delete(PLUGIN_CONFIG_DOCTYPE, {"plugin_name": "core"})
        self._run_sync(
            {
                "core": self._plugin_info("Core"),
                "TEST_new_plugin": self._plugin_info("Test Plugin"),
            }
        )
        self.assertEqual(
            int(frappe.db.get_value(PLUGIN_CONFIG_DOCTYPE, "core", "enabled") or 0), 1
        )
        self.assertEqual(
            int(frappe.db.get_value(PLUGIN_CONFIG_DOCTYPE, "TEST_new_plugin", "enabled") or 0),
            0,
        )

    def test_missing_plugin_config_not_deleted(self):
        doc = frappe.get_doc(
            {
                "doctype": PLUGIN_CONFIG_DOCTYPE,
                "plugin_name": "TEST_ghost_plugin",
                "display_name": "Ghost Plugin",
                "enabled": 0,
            }
        )
        doc.insert(ignore_permissions=True)

        self._run_sync({})
        self.assertTrue(frappe.db.exists(PLUGIN_CONFIG_DOCTYPE, "TEST_ghost_plugin"))


class TestCanonicalRegistryImport(FrappeTestCase):
    def test_legacy_enhanced_tool_registry_module_removed(self):
        with self.assertRaises(ImportError):
            importlib.import_module("frappe_assistant_core.core.enhanced_tool_registry")

    def test_migration_status_uses_canonical_registry(self):
        from frappe_assistant_core.utils.migration_hooks import get_migration_status

        status = get_migration_status()
        self.assertTrue(status.get("migration_hooks_active"), status)
        self.assertIn("registry_stats", status)


class TestToolConfigurationAccess(FrappeTestCase):
    def _doc(self, enabled, mode, roles=()):
        doc = frappe.new_doc(TOOL_CONFIG_DOCTYPE)
        doc.tool_name = "TEST_access_tool"
        doc.plugin_name = "core"
        doc.enabled = enabled
        doc.role_access_mode = mode
        for role in roles:
            doc.append("role_access", {"role": role, "allow_access": 1})
        return doc

    def test_user_has_access_fail_closed(self):
        user = "fac-access-test@example.com"

        with patch("frappe.get_roles", return_value=["System Manager"]):
            # Deny All: no access, no System Manager bypass
            self.assertFalse(self._doc(1, "Deny All").user_has_access(user))
            # Legacy/unknown modes deny
            self.assertFalse(self._doc(1, "Allow All").user_has_access(user))
            self.assertFalse(self._doc(1, "").user_has_access(user))
            # Restricted mode with empty role list denies
            self.assertFalse(
                self._doc(1, "Restrict to Listed Roles").user_has_access(user)
            )

        with patch("frappe.get_roles", return_value=["Assistant User"]):
            # Disabled tool denies even with a matching role
            self.assertFalse(
                self._doc(0, "Restrict to Listed Roles", ["Assistant User"]).user_has_access(user)
            )
            # Valid restricted config grants only a listed role
            self.assertTrue(
                self._doc(1, "Restrict to Listed Roles", ["Assistant User"]).user_has_access(user)
            )

        with patch("frappe.get_roles", return_value=["System Manager"]):
            # No bypass: System Manager without a listed role is denied
            self.assertFalse(
                self._doc(1, "Restrict to Listed Roles", ["Assistant User"]).user_has_access(user)
            )

    def test_restrict_mode_requires_valid_role(self):
        doc = self._doc(1, "Restrict to Listed Roles")
        with self.assertRaises(frappe.ValidationError):
            doc.insert(ignore_permissions=True)

        doc = self._doc(1, "Restrict to Listed Roles", ["No Such Role TEST"])
        with self.assertRaises(frappe.ValidationError):
            doc.insert(ignore_permissions=True)
