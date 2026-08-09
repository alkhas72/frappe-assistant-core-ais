"""Tests for deny-by-default migration and configuration sync (Task 5).

Covers the idempotent ``harden_fac_tool_access_defaults`` patch, the
``_sync_tool_configurations``/``_sync_plugin_configurations`` deny-by-default
sync semantics, the canonical tool registry import in migration hooks, the
fail-closed ``FAC Tool Configuration.user_has_access`` contract, the hardened
admin endpoints, and the admin UI/API mode contract.

Isolation: each mutating test snapshots and restores the complete FAC tool,
role-access, and plugin configuration tables. Commit suppression and the
FrappeTestCase transaction rollback are secondary safeguards, not the only
isolation mechanism.
"""

import hashlib
import importlib
import inspect as pyinspect
import json
import os
import re
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import frappe
from frappe.tests.utils import FrappeTestCase

from frappe_assistant_core.patches.v2_5.harden_fac_tool_access_defaults import execute

TOOL_CONFIG_DOCTYPE = "FAC Tool Configuration"
ROLE_ACCESS_DOCTYPE = "FAC Tool Role Access"
PLUGIN_CONFIG_DOCTYPE = "FAC Plugin Configuration"

SNAPSHOT_TABLES = (
    "tabFAC Tool Role Access",
    "tabFAC Tool Configuration",
    "tabFAC Plugin Configuration",
)

_module_security_snapshot = None


def _snapshot_security_rows():
    return {
        table: frappe.db.sql(f"SELECT * FROM `{table}` ORDER BY name", as_dict=True)
        for table in SNAPSHOT_TABLES
    }


def _security_snapshot_hash(snapshot):
    serialized = json.dumps(snapshot, default=str, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest()


def _restore_security_rows(snapshot):
    for table in SNAPSHOT_TABLES:
        columns = [
            column.Field for column in frappe.db.sql(f"SHOW COLUMNS FROM `{table}`", as_dict=True)
        ]
        frappe.db.sql(f"DELETE FROM `{table}`")
        if not snapshot[table]:
            continue
        placeholders = ", ".join(["%s"] * len(columns))
        quoted_columns = ", ".join(f"`{column}`" for column in columns)
        statement = f"INSERT INTO `{table}` ({quoted_columns}) VALUES ({placeholders})"
        for row in snapshot[table]:
            frappe.db.sql(statement, tuple(row.get(column) for column in columns))


def setUpModule():
    global _module_security_snapshot
    _module_security_snapshot = _snapshot_security_rows()


def tearDownModule():
    after = _snapshot_security_rows()
    before_hash = _security_snapshot_hash(_module_security_snapshot)
    after_hash = _security_snapshot_hash(after)
    try:
        if after_hash != before_hash:
            raise AssertionError(
                f"FAC security snapshot changed: before={before_hash}, after={after_hash}"
            )
    finally:
        _restore_security_rows(_module_security_snapshot)
        frappe.db.commit()

PATCH_MODULE = "frappe_assistant_core.patches.v2_5.harden_fac_tool_access_defaults"

# Synthetic inventory used when running the migration patch: exactly one
# configurable tool; every other name is unknown/hard-denied/external and
# must harden to deny-by-default.
TEST_CONFIGURABLE_TOOLS = frozenset({"__test_configurable_tool"})

CONFIGURABLE = "__test_configurable_tool"
HARD_DENIED = "__test_hard_denied_tool"
UNKNOWN = "__test_unknown_tool"
EXTERNAL = "__test_external_tool"

# (tool_name, enabled, role_access_mode, role_rows) -> expected (enabled, mode, roles)
# role_rows are (role, allow_access) tuples.
CASES = (
    # hard-denied tool: hardened even with a valid restricted allowlist
    (HARD_DENIED, 1, "Restrict to Listed Roles", [("System Manager", 1)], 0, "Deny All", []),
    # legacy Allow All: hardened
    (CONFIGURABLE, 1, "Allow All", [], 0, "Deny All", []),
    # valid restricted config for a configurable tool: preserved untouched
    (
        CONFIGURABLE,
        1,
        "Restrict to Listed Roles",
        [("Assistant User", 1)],
        1,
        "Restrict to Listed Roles",
        ["Assistant User"],
    ),
    # unknown tool with a valid restricted allowlist: hardened (not in inventory)
    (UNKNOWN, 1, "Restrict to Listed Roles", [("Assistant User", 1)], 0, "Deny All", []),
    # external tool config (tool not in builtin inventory): hardened
    (EXTERNAL, 1, "Restrict to Listed Roles", [("Assistant User", 1)], 0, "Deny All", []),
    # empty/unknown modes harden
    (CONFIGURABLE, 1, "", [], 0, "Deny All", []),
    (CONFIGURABLE, 1, "Some Future Mode", [], 0, "Deny All", []),
    # restricted mode with an empty role list hardens
    (CONFIGURABLE, 1, "Restrict to Listed Roles", [], 0, "Deny All", []),
)


def _run_patch():
    """Run the migration patch against the synthetic test inventory."""
    with patch(f"{PATCH_MODULE}.CONFIGURABLE_TOOLS", TEST_CONFIGURABLE_TOOLS):
        execute()


def _delete_config(tool_name):
    frappe.db.delete(ROLE_ACCESS_DOCTYPE, {"parent": tool_name})
    frappe.db.delete(TOOL_CONFIG_DOCTYPE, {"tool_name": tool_name})


def _seed_config(tool_name, enabled, mode, role_rows, plugin_name="core"):
    """Create a config row, including legacy states the new schema rejects.

    Legacy child values and modes are forced via ``frappe.db.set_value`` after
    inserting a valid row, so controller validation never blocks seeding a
    state that could exist on a pre-migration site.
    """
    _delete_config(tool_name)

    doc = frappe.get_doc(
        {
            "doctype": TOOL_CONFIG_DOCTYPE,
            "tool_name": tool_name,
            "plugin_name": plugin_name,
            "enabled": enabled,
            "role_access_mode": "Deny All",
        }
    )
    doc.insert(ignore_permissions=True)

    for role, allow_access in role_rows:
        # A pre-hardening database can contain invalid Link values. Insert a
        # valid child through Frappe, then replace just the legacy role value
        # through the DB API so production validation remains intact.
        seeded_role = role if frappe.db.exists("Role", role) else "System Manager"
        child = frappe.get_doc(
            {
                "doctype": ROLE_ACCESS_DOCTYPE,
                "parent": tool_name,
                "parenttype": TOOL_CONFIG_DOCTYPE,
                "parentfield": "role_access",
                "role": seeded_role,
                "allow_access": allow_access,
            }
        )
        child.insert(ignore_permissions=True)
        if seeded_role != role:
            frappe.db.set_value(ROLE_ACCESS_DOCTYPE, child.name, "role", role)

    if mode != "Deny All":
        frappe.db.set_value(TOOL_CONFIG_DOCTYPE, tool_name, "role_access_mode", mode)


def _config_state(tool_name):
    enabled, mode = frappe.db.get_value(
        TOOL_CONFIG_DOCTYPE, tool_name, ["enabled", "role_access_mode"]
    )
    roles = frappe.get_all(ROLE_ACCESS_DOCTYPE, filters={"parent": tool_name}, pluck="role")
    return int(enabled or 0), mode, sorted(roles)


def _seed_plugin_config(plugin_name, enabled):
    frappe.db.delete(PLUGIN_CONFIG_DOCTYPE, {"plugin_name": plugin_name})
    doc = frappe.get_doc(
        {
            "doctype": PLUGIN_CONFIG_DOCTYPE,
            "plugin_name": plugin_name,
            "display_name": plugin_name.replace("_", " ").title(),
            "enabled": enabled,
        }
    )
    doc.insert(ignore_permissions=True)


def _no_commit():
    """Keep committing code inside the test transaction (rollback isolates)."""
    return patch.object(frappe.db, "commit", lambda *args, **kwargs: None)


class FACSecuritySnapshotTestCase(FrappeTestCase):
    """Restore FAC security rows exactly, even when a test raises.

    Migration tests intentionally exercise canonical configurations. A
    transaction rollback alone is insufficient because code under test can
    commit or alter singleton-backed state; take explicit low-level snapshots
    of every parent, child, and plugin row before the test and restore them in
    ``tearDown``.
    """

    _snapshot_tables = SNAPSHOT_TABLES

    def setUp(self):
        super().setUp()
        self._fac_security_snapshot = _snapshot_security_rows()

    def _restore_fac_security_snapshot(self):
        _restore_security_rows(self._fac_security_snapshot)

    def tearDown(self):
        try:
            self._restore_fac_security_snapshot()
            restored = _snapshot_security_rows()
            self.assertEqual(restored, self._fac_security_snapshot)
            # FrappeTestCase rolls back its class transaction after individual
            # tearDown calls. Commit the exact snapshot so that rollback cannot
            # resurrect a prior mutation (including `modified` metadata).
            frappe.db.commit()
        finally:
            super().tearDown()


class TestHardenFacToolAccessDefaults(FACSecuritySnapshotTestCase):
    def tearDown(self):
        try:
            for tool_name in {case[0] for case in CASES} | {"__test_mixed_tool"}:
                _delete_config(tool_name)
            frappe.db.delete(PLUGIN_CONFIG_DOCTYPE, {"plugin_name": ("like", "__test_%")})
            frappe.db.delete("Role", {"name": ("like", "__test_%")})
        finally:
            super().tearDown()

    def test_migration_matrix(self):
        for tool_name, enabled, mode, role_rows, exp_enabled, exp_mode, exp_roles in CASES:
            with self.subTest(tool_name=tool_name, mode=mode, role_rows=role_rows):
                _seed_config(tool_name, enabled, mode, role_rows)
                _run_patch()
                self.assertEqual(_config_state(tool_name), (exp_enabled, exp_mode, exp_roles))

    def test_mixed_restricted_config_prunes_only_invalid_rows(self):
        frappe.get_doc(
            {"doctype": "Role", "role_name": "__test_disabled_role", "disabled": 1}
        ).insert(ignore_permissions=True)

        _seed_config(
            "__test_mixed_tool",
            1,
            "Restrict to Listed Roles",
            [
                ("Assistant User", 1),  # valid: kept
                ("System Manager", 1),  # valid: kept
                ("__test_no_such_role", 1),  # role does not exist: pruned
                ("__test_disabled_role", 1),  # role disabled: pruned
                ("Assistant User", 0),  # allow_access=0: pruned
            ],
        )
        with patch(f"{PATCH_MODULE}.CONFIGURABLE_TOOLS", frozenset({"__test_mixed_tool"})):
            execute()

        self.assertEqual(
            _config_state("__test_mixed_tool"),
            (1, "Restrict to Listed Roles", ["Assistant User", "System Manager"]),
        )

    def test_patch_disables_non_core_plugins(self):
        _seed_plugin_config("__test_plugin_enabled", 1)
        _seed_plugin_config("__test_plugin_disabled", 0)

        core_enabled_before = None
        if frappe.db.exists(PLUGIN_CONFIG_DOCTYPE, "core"):
            core_enabled_before = frappe.db.get_value(PLUGIN_CONFIG_DOCTYPE, "core", "enabled")

        _run_patch()

        self.assertEqual(
            int(frappe.db.get_value(PLUGIN_CONFIG_DOCTYPE, "__test_plugin_enabled", "enabled") or 0),
            0,
        )
        self.assertEqual(
            int(frappe.db.get_value(PLUGIN_CONFIG_DOCTYPE, "__test_plugin_disabled", "enabled") or 0),
            0,
        )
        if core_enabled_before is not None:
            self.assertEqual(
                frappe.db.get_value(PLUGIN_CONFIG_DOCTYPE, "core", "enabled"),
                core_enabled_before,
            )

    def test_second_run_is_semantically_empty(self):
        for tool_name, enabled, mode, role_rows, *_ in CASES:
            _seed_config(tool_name, enabled, mode, role_rows)
        _seed_plugin_config("__test_plugin_enabled", 1)
        _run_patch()

        def snapshot():
            configs = frappe.get_all(
                TOOL_CONFIG_DOCTYPE,
                filters={"tool_name": ("like", "__test_%")},
                fields=["name", "enabled", "role_access_mode"],
                order_by="name",
            )
            rows = frappe.get_all(
                ROLE_ACCESS_DOCTYPE,
                filters={"parent": ("like", "__test_%")},
                fields=["parent", "role", "allow_access"],
                order_by="parent, role",
            )
            plugins = frappe.get_all(
                PLUGIN_CONFIG_DOCTYPE,
                filters={"plugin_name": ("like", "__test_%")},
                fields=["name", "enabled"],
                order_by="name",
            )
            return configs, rows, plugins

        before = snapshot()
        _run_patch()
        after = snapshot()
        self.assertEqual(before, after)

    def test_no_allow_all_remains(self):
        for tool_name, enabled, mode, role_rows, *_ in CASES:
            _seed_config(tool_name, enabled, mode, role_rows)
        _run_patch()
        remaining = frappe.get_all(
            TOOL_CONFIG_DOCTYPE,
            filters={"role_access_mode": "Allow All"},
            pluck="name",
        )
        self.assertEqual(remaining, [])


class TestSyncToolConfigurationDefaults(FACSecuritySnapshotTestCase):
    def tearDown(self):
        try:
            for tool_name in (
                "__test_sync_keep_tool",
                "__test_sync_ghost_tool",
                "__test_sync_ext_tool",
                "__test_declared_unimportable",
            ):
                _delete_config(tool_name)
        finally:
            super().tearDown()

    def _run_sync(self, tools, external=None):
        with (
            patch(
                "frappe_assistant_core.utils.migration_hooks._discover_all_plugin_tools",
                return_value=tools,
            ),
            patch(
                "frappe_assistant_core.utils.migration_hooks._get_external_tools_for_sync",
                return_value=external or {},
            ),
            patch(
                "frappe_assistant_core.utils.tool_category_detector.detect_tool_category",
                return_value="read_only",
            ),
            _no_commit(),
        ):
            from frappe_assistant_core.utils.migration_hooks import _sync_tool_configurations

            _sync_tool_configurations()

    def _tool_info(self, plugin_name):
        return SimpleNamespace(
            plugin_name=plugin_name,
            description="Sync test tool",
            instance=SimpleNamespace(source_app="frappe_assistant_core"),
        )

    def test_new_plugin_tool_created_disabled_deny_all(self):
        self._run_sync({"__test_sync_keep_tool": self._tool_info("__test_plugin")})
        self.assertEqual(_config_state("__test_sync_keep_tool"), (0, "Deny All", []))

    def test_new_external_tool_created_disabled_deny_all(self):
        self._run_sync(
            {},
            external={
                "__test_sync_ext_tool": {
                    "description": "External sync test tool",
                    "source_app": "external_app",
                    "module_path": "external_app.tools.TestTool",
                }
            },
        )
        self.assertEqual(_config_state("__test_sync_ext_tool"), (0, "Deny All", []))

    def test_existing_restricted_config_not_overwritten(self):
        _seed_config("__test_sync_keep_tool", 1, "Restrict to Listed Roles", [("Assistant User", 1)])
        self._run_sync({"__test_sync_keep_tool": self._tool_info("__test_plugin")})
        self.assertEqual(
            _config_state("__test_sync_keep_tool"),
            (1, "Restrict to Listed Roles", ["Assistant User"]),
        )

    def test_disabled_plugin_config_survives_and_reenable_stays_denied(self):
        # Tool belongs to a plugin that is later disabled: the config must not
        # be deleted while the tool is absent from discovery, and re-enabling
        # the plugin must not recreate a permissive record.
        _seed_plugin_config("__test_plugin", 0)
        _seed_config(
            "__test_sync_ghost_tool",
            1,
            "Restrict to Listed Roles",
            [("Assistant User", 1)],
            plugin_name="__test_plugin",
        )

        self._run_sync({})  # plugin disabled -> tool absent from discovery
        self.assertEqual(
            _config_state("__test_sync_ghost_tool"),
            (1, "Restrict to Listed Roles", ["Assistant User"]),
        )

        frappe.db.set_value(PLUGIN_CONFIG_DOCTYPE, "__test_plugin", "enabled", 1)
        self._run_sync({"__test_sync_ghost_tool": self._tool_info("__test_plugin")})
        self.assertEqual(
            _config_state("__test_sync_ghost_tool"),
            (1, "Restrict to Listed Roles", ["Assistant User"]),
        )

    def test_declared_tool_with_import_error_gets_safe_configuration(self):
        """Declared inventory remains deny-by-default when an optional import fails."""
        from frappe_assistant_core.utils import migration_hooks

        discovery = MagicMock()
        discovery.discover_plugins.return_value = {
            "__test_broken_plugin": SimpleNamespace(
                tools=["__test_declared_unimportable"],
                description="Declared tool whose optional dependency is unavailable",
            )
        }
        with (
            patch(
                "frappe_assistant_core.utils.plugin_manager.PluginDiscovery",
                return_value=discovery,
            ),
            patch(
                "frappe_assistant_core.utils.plugin_manager.PluginConfig.PLUGIN_BASE_PATH",
                "__test_optional_dependency_missing__",
            ),
            _no_commit(),
        ):
            migration_hooks._sync_tool_configurations()

        self.assertEqual(_config_state("__test_declared_unimportable"), (0, "Deny All", []))
        fallback = frappe.db.get_value(
            TOOL_CONFIG_DOCTYPE,
            "__test_declared_unimportable",
            ["plugin_name", "tool_category", "source_app", "module_path"],
            as_dict=True,
        )
        self.assertEqual(fallback.plugin_name, "__test_broken_plugin")
        self.assertTrue(fallback.tool_category)
        self.assertEqual(fallback.source_app, "frappe_assistant_core")
        self.assertEqual(
            fallback.module_path,
            "__test_optional_dependency_missing__.__test_broken_plugin.tools.__test_declared_unimportable",
        )


class TestSyncDiscoversDisabledPluginTools(FACSecuritySnapshotTestCase):
    """Unmocked discovery contract: disabled plugins still get tool configs.

    ``plugin_manager.get_all_tools()`` only returns tools of enabled plugins;
    the sync must instead discover tools independently of enabled state.
    Runs the real sync with real builtin plugins; only ``frappe.db.commit``
    is neutralised so the test transaction rolls everything back.
    """

    DATA_SCIENCE_TOOLS = (
        "run_python_code",
        "run_database_query",
        "analyze_business_data",
        "extract_file_content",
    )

    def test_sync_creates_deny_all_configs_for_disabled_plugin_tools(self):
        from frappe_assistant_core.utils import migration_hooks

        # Ensure data_science is disabled (default after hardening).
        if frappe.db.exists(PLUGIN_CONFIG_DOCTYPE, "data_science"):
            frappe.db.set_value(PLUGIN_CONFIG_DOCTYPE, "data_science", "enabled", 0)
        else:
            _seed_plugin_config("data_science", 0)

        for tool_name in self.DATA_SCIENCE_TOOLS:
            _delete_config(tool_name)

        with _no_commit():
            migration_hooks._sync_tool_configurations()

        for tool_name in self.DATA_SCIENCE_TOOLS:
            with self.subTest(tool_name=tool_name):
                self.assertEqual(_config_state(tool_name), (0, "Deny All", []))


class TestSyncPluginConfigurationDefaults(FACSecuritySnapshotTestCase):
    def tearDown(self):
        try:
            frappe.db.delete(PLUGIN_CONFIG_DOCTYPE, {"plugin_name": ("like", "__test_%")})
        finally:
            super().tearDown()

    def _run_sync(self, discovered):
        discovery = MagicMock()
        discovery.discover_plugins.return_value = discovered
        with (
            patch(
                "frappe_assistant_core.utils.plugin_manager.PluginDiscovery",
                return_value=discovery,
            ),
            _no_commit(),
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
                "__test_new_plugin": self._plugin_info("Test Plugin"),
            }
        )
        self.assertEqual(
            int(frappe.db.get_value(PLUGIN_CONFIG_DOCTYPE, "core", "enabled") or 0), 1
        )
        self.assertEqual(
            int(frappe.db.get_value(PLUGIN_CONFIG_DOCTYPE, "__test_new_plugin", "enabled") or 0),
            0,
        )

    def test_orphan_plugin_config_is_deleted(self):
        # Plugin discovery is independent of enabled state, so a plugin that
        # is absent from discovery is genuinely gone and its config is an
        # orphan. (Tool configs, in contrast, are never auto-deleted.)
        _seed_plugin_config("__test_ghost_plugin", 0)

        self._run_sync({})
        self.assertFalse(frappe.db.exists(PLUGIN_CONFIG_DOCTYPE, "__test_ghost_plugin"))


class TestCanonicalRegistryImport(FrappeTestCase):
    def test_legacy_enhanced_tool_registry_module_removed(self):
        with self.assertRaises(ImportError):
            importlib.import_module("frappe_assistant_core.core.enhanced_tool_registry")

    def test_migration_status_uses_canonical_registry(self):
        from frappe_assistant_core.core import tool_registry
        from frappe_assistant_core.utils import plugin_manager
        from frappe_assistant_core.utils.migration_hooks import get_migration_status

        # Earlier tests can leave singleton objects holding test doubles.
        # Exercise the real canonical API from a clean boundary and restore
        # both globals afterwards so this assertion cannot depend on order.
        fresh_plugin_manager = plugin_manager.PluginManager()
        fresh_registry = tool_registry.ToolRegistry()
        with (
            patch.object(tool_registry, "get_plugin_manager", return_value=fresh_plugin_manager),
            patch.object(tool_registry, "get_tool_registry", return_value=fresh_registry),
        ):
            status = get_migration_status()
        self.assertTrue(status.get("migration_hooks_active"), status)
        self.assertIn("registry_stats", status)

    def test_after_install_calls_canonical_registry_api(self):
        """after_install must call the real ToolRegistry API contract.

        Fails if the import path breaks again or if the registry API changes
        (e.g. refresh_tools gaining a required argument or returning a dict).
        """
        from frappe_assistant_core.core import tool_registry as registry_module
        from frappe_assistant_core.utils import migration_hooks

        # Verify the real API surface the hook relies on.
        self.assertTrue(hasattr(registry_module, "get_tool_registry"))
        refresh_sig = pyinspect.signature(registry_module.ToolRegistry.refresh_tools)
        self.assertEqual(list(refresh_sig.parameters), ["self"])
        self.assertTrue(callable(getattr(registry_module.ToolRegistry, "get_stats", None)))

        registry = MagicMock()
        registry.refresh_tools.return_value = True
        registry.get_stats.return_value = {"total_tools": 7}

        with (
            patch.object(registry_module, "get_tool_registry", return_value=registry),
            patch.object(migration_hooks, "_install_system_prompt_categories"),
            patch.object(migration_hooks, "_install_system_prompt_templates"),
            patch.object(migration_hooks, "_install_system_skills"),
            patch.object(migration_hooks, "_install_app_skills"),
            patch.object(migration_hooks, "_sync_plugin_configurations"),
            patch.object(migration_hooks, "_sync_tool_configurations"),
            patch.object(migration_hooks, "_set_settings_defaults"),
        ):
            migration_hooks.after_install()

        registry.refresh_tools.assert_called_once_with()  # no force kwarg
        registry.get_stats.assert_called_once_with()


class TestAfterInstallDenyByDefault(FACSecuritySnapshotTestCase):
    """Actual repair flow creates only safe configuration end states."""

    def test_after_install_repairs_to_safe_idempotent_end_state(self):
        from frappe_assistant_core.utils import migration_hooks

        frappe.db.delete(ROLE_ACCESS_DOCTYPE)
        frappe.db.delete(TOOL_CONFIG_DOCTYPE)
        frappe.db.delete(PLUGIN_CONFIG_DOCTYPE)

        with (
            patch.object(migration_hooks, "_install_system_prompt_categories"),
            patch.object(migration_hooks, "_install_system_prompt_templates"),
            patch.object(migration_hooks, "_install_system_skills"),
            patch.object(migration_hooks, "_install_app_skills"),
            patch.object(migration_hooks, "_set_settings_defaults"),
            _no_commit(),
        ):
            migration_hooks.after_install()
            first = frappe.get_all(
                TOOL_CONFIG_DOCTYPE,
                fields=["name", "enabled", "role_access_mode"],
                order_by="name",
            )
            migration_hooks.after_install()
            second = frappe.get_all(
                TOOL_CONFIG_DOCTYPE,
                fields=["name", "enabled", "role_access_mode"],
                order_by="name",
            )

        self.assertEqual(first, second)
        self.assertTrue(first)
        self.assertTrue(
            all(not row.enabled and row.role_access_mode == "Deny All" for row in first)
        )
        self.assertEqual(
            frappe.db.get_value(PLUGIN_CONFIG_DOCTYPE, "core", "enabled"),
            1,
        )
        self.assertEqual(
            frappe.get_all(
                PLUGIN_CONFIG_DOCTYPE,
                filters={"enabled": 1, "plugin_name": ("!=", "core")},
                pluck="name",
            ),
            [],
        )
        self.assertEqual(_config_state("get_document"), (0, "Deny All", []))


class TestAdminEndpointHardening(FACSecuritySnapshotTestCase):
    """Endpoint-level tests for the hardened admin API (runs as Administrator)."""

    def tearDown(self):
        try:
            for tool_name in ("__test_toggle_tool", "run_python_code", "__test_role_tool"):
                _delete_config(tool_name)
        finally:
            super().tearDown()

    def _mock_tool_inventory(self, *tool_names):
        tools = {
            name: SimpleNamespace(
                plugin_name="core",
                description="Test tool",
                instance=SimpleNamespace(source_app="frappe_assistant_core"),
            )
            for name in tool_names
        }
        plugin_manager = MagicMock()
        plugin_manager.get_all_tools.return_value = tools
        plugin_manager.get_enabled_plugins.return_value = {"core"}

        registry = MagicMock()
        registry._get_external_tools.return_value = {}

        return patch(
            "frappe_assistant_core.utils.plugin_manager.get_plugin_manager",
            return_value=plugin_manager,
        ), patch(
            "frappe_assistant_core.core.tool_registry.get_tool_registry",
            return_value=registry,
        ), patch(
            "frappe_assistant_core.utils.tool_category_detector.detect_tool_category",
            return_value="read_only",
        )

    def test_toggle_tool_cannot_enable_hard_denied(self):
        from frappe_assistant_core.api.admin.tools import toggle_tool

        # Start from a clean slate (in-transaction; rolled back after the test)
        _delete_config("run_python_code")

        pm, reg, cat = self._mock_tool_inventory("run_python_code")
        with pm, reg, cat, _no_commit():
            result = toggle_tool("run_python_code", True)

        self.assertFalse(result.get("success"))
        self.assertIn("hard-denied", result.get("message", ""))
        self.assertFalse(frappe.db.exists(TOOL_CONFIG_DOCTYPE, "run_python_code"))

    def test_toggle_tool_enable_without_config_creates_disabled_and_marks(self):
        from frappe_assistant_core.api.admin.tools import toggle_tool

        pm, reg, cat = self._mock_tool_inventory("__test_toggle_tool")
        with pm, reg, cat, _no_commit():
            result = toggle_tool("__test_toggle_tool", True)

        self.assertTrue(result.get("success"))
        self.assertTrue(result.get("requires_configuration"))
        self.assertFalse(result.get("enabled"))
        self.assertEqual(_config_state("__test_toggle_tool"), (0, "Deny All", []))

    def test_update_tool_role_access_rejects_allow_all(self):
        from frappe_assistant_core.api.admin.tools import update_tool_role_access

        pm, reg, cat = self._mock_tool_inventory("__test_role_tool")
        with pm, reg, cat, _no_commit():
            result = update_tool_role_access("__test_role_tool", "Allow All")

        self.assertFalse(result.get("success"))
        self.assertIn("Invalid mode", result.get("message", ""))

    def test_update_tool_role_access_rejects_empty_and_unknown_roles(self):
        from frappe_assistant_core.api.admin.tools import update_tool_role_access

        pm, reg, cat = self._mock_tool_inventory("__test_role_tool")
        with pm, reg, cat, _no_commit():
            empty = update_tool_role_access("__test_role_tool", "Restrict to Listed Roles", roles=[])
            unknown = update_tool_role_access(
                "__test_role_tool",
                "Restrict to Listed Roles",
                roles=[{"role": "__test_no_such_role"}],
            )

        self.assertFalse(empty.get("success"))
        self.assertIn("at least one role", empty.get("message", ""))
        self.assertFalse(unknown.get("success"))
        self.assertIn("Invalid role", unknown.get("message", ""))

    def test_update_tool_role_access_rejects_disabled_role(self):
        from frappe_assistant_core.api.admin.tools import update_tool_role_access

        role_name = "__test_disabled_admin_role"
        frappe.db.delete("Role", role_name)
        frappe.get_doc(
            {"doctype": "Role", "role_name": role_name, "disabled": 1}
        ).insert(ignore_permissions=True)
        self.addCleanup(frappe.db.delete, "Role", role_name)

        pm, reg, cat = self._mock_tool_inventory("__test_role_tool")
        with pm, reg, cat, _no_commit():
            result = update_tool_role_access(
                "__test_role_tool",
                "Restrict to Listed Roles",
                roles=[{"role": role_name, "allow_access": 1}],
            )

        self.assertFalse(result.get("success"))
        self.assertIn("Invalid role", result.get("message", ""))

    def test_deny_all_clears_stale_role_rows_and_keeps_enabled_state(self):
        from frappe_assistant_core.api.admin.tools import update_tool_role_access

        _seed_config("__test_role_tool", 0, "Restrict to Listed Roles", [("Assistant User", 1)])

        pm, reg, cat = self._mock_tool_inventory("__test_role_tool")
        with pm, reg, cat, _no_commit():
            result = update_tool_role_access("__test_role_tool", "Deny All")

        self.assertTrue(result.get("success"), result)
        # Stale role rows cleared; enabled untouched by the role change.
        self.assertEqual(_config_state("__test_role_tool"), (0, "Deny All", []))

    def test_role_change_does_not_implicitly_enable_tool(self):
        from frappe_assistant_core.api.admin.tools import update_tool_role_access

        _seed_config("__test_role_tool", 0, "Deny All", [])

        pm, reg, cat = self._mock_tool_inventory("__test_role_tool")
        with pm, reg, cat, _no_commit():
            result = update_tool_role_access(
                "__test_role_tool",
                "Restrict to Listed Roles",
                roles=[{"role": "Assistant User"}],
            )

        self.assertTrue(result.get("success"), result)
        self.assertEqual(
            _config_state("__test_role_tool"),
            (0, "Restrict to Listed Roles", ["Assistant User"]),
        )


class TestAdminUIContract(FrappeTestCase):
    """UI/API contract: modes the admin page can submit vs. modes the API accepts."""

    def _read_admin_js(self):
        import frappe_assistant_core

        js_path = os.path.join(
            os.path.dirname(frappe_assistant_core.__file__),
            "public",
            "js",
            "fac_admin_tools.js",
        )
        with open(js_path) as f:
            return f.read()

    def test_js_has_no_allow_all_and_offers_deny_all(self):
        role_select = self._role_mode_select()
        self.assertNotIn("Allow All", role_select)
        self.assertIn('value="Deny All"', role_select)
        self.assertIn('value="Restrict to Listed Roles"', role_select)

    def _role_mode_select(self):
        match = re.search(
            r'<select class="fac-config-select fac-role-mode-select".*?</select>',
            self._read_admin_js(),
            re.DOTALL,
        )
        self.assertIsNotNone(match, "role mode select is missing")
        return match.group(0)

    def test_js_role_mode_options_match_api_contract(self):
        js_role_modes = set(
            re.findall(r'<option value="([^"]+)"', self._role_mode_select())
        )
        self.assertEqual(js_role_modes, {"Deny All", "Restrict to Listed Roles"})

        # Every mode the UI can submit is accepted by the API (fails later on
        # tool existence, not on mode validation); 'Allow All' is rejected.
        from frappe_assistant_core.api.admin.tools import update_tool_role_access

        for mode in js_role_modes:
            with self.subTest(mode=mode):
                result = update_tool_role_access("__test_no_such_tool", mode)
                self.assertNotIn("Invalid mode", result.get("message", ""))

        result = update_tool_role_access("__test_no_such_tool", "Allow All")
        self.assertFalse(result.get("success"))
        self.assertIn("Invalid mode", result.get("message", ""))


class TestToolConfigurationAccess(FACSecuritySnapshotTestCase):
    RUNTIME_ROLE = "__test_runtime_disabled_role"
    RUNTIME_USER = "Administrator"

    def tearDown(self):
        try:
            _delete_config("__test_access_tool")
            frappe.db.delete("Has Role", {"parent": self.RUNTIME_USER, "role": self.RUNTIME_ROLE})
            frappe.db.delete("Role", self.RUNTIME_ROLE)
            frappe.clear_cache(user=self.RUNTIME_USER)
        finally:
            super().tearDown()

    def _doc(self, enabled, mode, roles=()):
        doc = frappe.new_doc(TOOL_CONFIG_DOCTYPE)
        doc.tool_name = "__test_access_tool"
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
            self.assertFalse(self._doc(1, "Restrict to Listed Roles").user_has_access(user))
            # No bypass: System Manager without a listed role is denied
            self.assertFalse(
                self._doc(1, "Restrict to Listed Roles", ["Assistant User"]).user_has_access(user)
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

    def test_restrict_mode_requires_valid_role(self):
        doc = self._doc(1, "Restrict to Listed Roles")
        with self.assertRaises(frappe.ValidationError):
            doc.insert(ignore_permissions=True)

        doc = self._doc(1, "Restrict to Listed Roles", ["No Such Role TEST"])
        with self.assertRaises(frappe.ValidationError):
            doc.insert(ignore_permissions=True)

        disabled_role = "__test_disabled_controller_role"
        frappe.get_doc(
            {"doctype": "Role", "role_name": disabled_role, "disabled": 1}
        ).insert(ignore_permissions=True)
        self.addCleanup(frappe.db.delete, "Role", disabled_role)
        doc = self._doc(1, "Restrict to Listed Roles", [disabled_role])
        with self.assertRaises(frappe.ValidationError):
            doc.insert(ignore_permissions=True)

    def test_disabled_role_cannot_grant_access_after_configuration_is_saved(self):
        frappe.get_doc(
            {"doctype": "Role", "role_name": self.RUNTIME_ROLE, "disabled": 0}
        ).insert(ignore_permissions=True)
        frappe.get_doc(
            {
                "doctype": "Has Role",
                "parent": self.RUNTIME_USER,
                "parenttype": "User",
                "parentfield": "roles",
                "role": self.RUNTIME_ROLE,
            }
        ).insert(ignore_permissions=True)
        frappe.clear_cache(user=self.RUNTIME_USER)

        config = self._doc(1, "Restrict to Listed Roles", [self.RUNTIME_ROLE])
        config.insert(ignore_permissions=True)
        self.assertTrue(config.user_has_access(self.RUNTIME_USER))

        frappe.db.set_value("Role", self.RUNTIME_ROLE, "disabled", 1)
        frappe.clear_cache(user=self.RUNTIME_USER)
        self.assertIn(self.RUNTIME_ROLE, frappe.get_roles(self.RUNTIME_USER))
        self.assertFalse(config.user_has_access(self.RUNTIME_USER))
