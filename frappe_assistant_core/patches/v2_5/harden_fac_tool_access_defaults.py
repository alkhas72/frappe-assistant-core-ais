"""Idempotent migration: FAC Tool Configuration -> deny by default.

For every existing FAC Tool Configuration row:

1. Hard-denied tools (``core.security_policy.HARD_DENY_TOOLS``, including known
   legacy aliases) are forced to ``enabled=0`` / ``Deny All`` and their child
   role rows are deleted.
2. ``Allow All``, empty/unknown ``role_access_mode`` values and restricted
   configs without at least one valid role row are converted to
   ``enabled=0`` / ``Deny All``.
3. A valid ``Restrict to Listed Roles`` config (non-empty list of existing
   roles with ``allow_access=1``) for a tool that is not hard-denied is
   preserved unchanged.

The patch only writes via ``frappe.db.set_value`` on the exact ``enabled`` and
``role_access_mode`` fields and deletes invalid child rows via
``frappe.db.delete`` — no ``doc.save()`` (so it does not depend on controller
or schema validation mid-migration) and no raw SQL. No roles are assigned.
Only aggregate counts are logged, caches are cleared once after the batch,
and nothing is committed per row: the patch runs as a single transaction.

Idempotent: after one run every row is either preserved-valid or already
``enabled=0`` / ``Deny All`` with no child rows, so a second run performs no
writes and can never reintroduce ``Allow All``.
"""

import frappe

from frappe_assistant_core.core.security_policy import HARD_DENY_TOOLS

TOOL_CONFIG_DOCTYPE = "FAC Tool Configuration"
ROLE_ACCESS_DOCTYPE = "FAC Tool Role Access"


def _valid_role_rows(parent: str) -> list:
    """Roles that actually grant access: listed, allowed and still existing."""
    roles = frappe.get_all(
        ROLE_ACCESS_DOCTYPE,
        filters={"parent": parent, "allow_access": 1},
        pluck="role",
    )
    return [role for role in roles if role and frappe.db.exists("Role", role)]


def execute():
    if not frappe.db.table_exists(TOOL_CONFIG_DOCTYPE):
        return

    hardened_count = 0
    preserved_count = 0
    role_rows_deleted = 0

    configs = frappe.get_all(
        TOOL_CONFIG_DOCTYPE,
        fields=["name", "enabled", "role_access_mode"],
    )

    for config in configs:
        # DocType is autonamed by tool_name, so name == tool_name.
        tool_name = config.name
        mode = config.role_access_mode

        is_hard_denied = tool_name in HARD_DENY_TOOLS
        has_valid_restricted_roles = (not is_hard_denied) and bool(_valid_role_rows(tool_name))

        if not is_hard_denied and mode == "Restrict to Listed Roles" and has_valid_restricted_roles:
            # Valid restricted config for a configurable tool: keep as is.
            preserved_count += 1
            continue

        already_hardened = not frappe.utils.cint(config.enabled) and mode == "Deny All"
        if not already_hardened:
            frappe.db.set_value(
                TOOL_CONFIG_DOCTYPE,
                tool_name,
                {"enabled": 0, "role_access_mode": "Deny All"},
            )
            hardened_count += 1

        # Deny All keeps no role rows; also clears stale rows on rows that
        # were already hardened but still carry child entries.
        stale_rows = frappe.db.count(ROLE_ACCESS_DOCTYPE, {"parent": tool_name})
        if stale_rows:
            frappe.db.delete(ROLE_ACCESS_DOCTYPE, {"parent": tool_name})
            role_rows_deleted += stale_rows

    # Clear registry/config caches once after the batch, not per row.
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
    except Exception:
        pass

    frappe.logger("fac_security_migration").info(
        "harden_fac_tool_access_defaults: "
        f"{hardened_count} config(s) hardened to deny-by-default, "
        f"{preserved_count} valid restricted config(s) preserved, "
        f"{role_rows_deleted} role access row(s) removed"
    )
