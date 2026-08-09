"""Idempotent migration: FAC tool/plugin access -> deny by default.

Tool configurations (FAC Tool Configuration):

1. A valid ``Restrict to Listed Roles`` config is preserved only for tools in
   ``core.security_policy.CONFIGURABLE_TOOLS`` (the ratified inventory minus
   hard-denied tools). Hard-denied tools, known legacy aliases, unknown tools
   and external tools are forced to ``enabled=0`` / ``Deny All``.
2. ``Allow All``, empty/unknown ``role_access_mode`` values and restricted
   configs without at least one valid role row are converted to
   ``enabled=0`` / ``Deny All``.
3. For preserved restricted configs, invalid child role rows (empty role
   name, ``allow_access=0``, role no longer exists or is disabled) are
   pruned; working rows are kept.

Plugin configurations (FAC Plugin Configuration):

4. Every non-core plugin is disabled (``enabled=0``). Only ``core`` may stay
   enabled; its tools remain governed by their own deny-by-default configs.

The patch only writes via ``frappe.db.set_value`` on exact fields and deletes
invalid child rows via ``frappe.db.delete`` — no ``doc.save()`` (so it does
not depend on controller or schema validation mid-migration) and no raw SQL.
No roles are assigned. Only aggregate counts are logged, caches are cleared
once after the batch, and nothing is committed per row: the patch runs as a
single transaction.

Idempotent: after one run every tool row is either preserved-valid (with only
valid role rows) or already ``enabled=0`` / ``Deny All`` with no child rows,
and every non-core plugin is already disabled, so a second run performs no
writes and can never reintroduce ``Allow All``.
"""

import frappe

from frappe_assistant_core.core.security_policy import CONFIGURABLE_TOOLS

TOOL_CONFIG_DOCTYPE = "FAC Tool Configuration"
ROLE_ACCESS_DOCTYPE = "FAC Tool Role Access"
PLUGIN_CONFIG_DOCTYPE = "FAC Plugin Configuration"
CORE_PLUGIN = "core"


def _classify_role_rows(parent: str) -> tuple:
    """Split child role rows into (valid, invalid) name lists.

    A row is valid only when it grants access (``allow_access=1``) to a
    non-empty role that still exists and is not disabled.
    """
    rows = frappe.get_all(
        ROLE_ACCESS_DOCTYPE,
        filters={"parent": parent},
        fields=["name", "role", "allow_access"],
    )
    valid, invalid = [], []
    for row in rows:
        role = row.role
        if (
            frappe.utils.cint(row.allow_access)
            and role
            and frappe.db.exists("Role", {"name": role, "disabled": 0})
        ):
            valid.append(row.name)
        else:
            invalid.append(row.name)
    return valid, invalid


def _harden_tool_configurations() -> dict:
    counts = {"hardened": 0, "preserved": 0, "role_rows_deleted": 0}

    if not frappe.db.table_exists(TOOL_CONFIG_DOCTYPE):
        return counts

    configs = frappe.get_all(
        TOOL_CONFIG_DOCTYPE,
        fields=["name", "enabled", "role_access_mode"],
    )

    for config in configs:
        # DocType is autonamed by tool_name, so name == tool_name.
        tool_name = config.name
        mode = config.role_access_mode
        is_configurable = tool_name in CONFIGURABLE_TOOLS

        valid_rows, invalid_rows = _classify_role_rows(tool_name)

        if is_configurable and mode == "Restrict to Listed Roles" and valid_rows:
            # Valid restricted config for a configurable tool: keep the row,
            # prune only the invalid child role rows.
            for row_name in invalid_rows:
                frappe.db.delete(ROLE_ACCESS_DOCTYPE, {"name": row_name})
            counts["role_rows_deleted"] += len(invalid_rows)
            counts["preserved"] += 1
            continue

        already_hardened = not frappe.utils.cint(config.enabled) and mode == "Deny All"
        if not already_hardened:
            frappe.db.set_value(
                TOOL_CONFIG_DOCTYPE,
                tool_name,
                {"enabled": 0, "role_access_mode": "Deny All"},
            )
            counts["hardened"] += 1

        # Deny All keeps no role rows; also clears stale rows on rows that
        # were already hardened but still carry child entries.
        if valid_rows or invalid_rows:
            frappe.db.delete(ROLE_ACCESS_DOCTYPE, {"parent": tool_name})
            counts["role_rows_deleted"] += len(valid_rows) + len(invalid_rows)

    return counts


def _disable_non_core_plugins() -> int:
    if not frappe.db.table_exists(PLUGIN_CONFIG_DOCTYPE):
        return 0

    disabled = 0
    plugins = frappe.get_all(
        PLUGIN_CONFIG_DOCTYPE,
        fields=["name", "enabled"],
    )
    for plugin in plugins:
        # DocType is autonamed by plugin_name, so name == plugin_name.
        if plugin.name == CORE_PLUGIN:
            continue
        if frappe.utils.cint(plugin.enabled):
            frappe.db.set_value(PLUGIN_CONFIG_DOCTYPE, plugin.name, "enabled", 0)
            disabled += 1
    return disabled


def _clear_caches_once():
    try:
        from frappe_assistant_core.core.tool_registry import get_tool_registry

        get_tool_registry().clear_cache()
    except Exception:
        pass
    try:
        cache = frappe.cache()
        cache.delete_keys("fac_tool_config_*")
        cache.delete_keys("fac_tool_configurations")
        cache.delete_keys("fac_tool_registry_*")
        cache.delete_keys("fac_plugin_config_*")
        cache.delete_keys("fac_plugin_configurations")
    except Exception:
        pass


def execute():
    counts = _harden_tool_configurations()
    plugins_disabled = _disable_non_core_plugins()
    _clear_caches_once()

    frappe.logger("fac_security_migration").info(
        "harden_fac_tool_access_defaults: "
        f"{counts['hardened']} tool config(s) hardened to deny-by-default, "
        f"{counts['preserved']} valid restricted config(s) preserved, "
        f"{counts['role_rows_deleted']} role access row(s) removed, "
        f"{plugins_disabled} non-core plugin(s) disabled"
    )
