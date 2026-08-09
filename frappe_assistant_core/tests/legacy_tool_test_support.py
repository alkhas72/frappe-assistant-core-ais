"""Test-only fixtures for legacy tool registry tests under deny-by-default.

Creates a disposable System Manager user, enables only the requested FAC Tool
Configuration rows, and restores exact SQL snapshots (parent + child rows,
including names/idx and service fields) after each use even when setup fails.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from contextlib import contextmanager
from typing import Iterable

import frappe

from frappe_assistant_core.core.tool_registry import ToolRegistry

SYSTEM_MANAGER_ROLE = "System Manager"
RESTRICT_TO_LISTED_ROLES = "Restrict to Listed Roles"

TOOL_CONFIG_TABLE = "tabFAC Tool Configuration"
ROLE_ACCESS_TABLE = "tabFAC Tool Role Access"


def capture_tool_configs_snapshot(tool_names: Iterable[str]) -> dict:
    """Exact SQL snapshot of parent FAC Tool Configuration + child role rows."""
    names = tuple(dict.fromkeys(tool_names))
    existing = [tool_name for tool_name in names if frappe.db.exists("FAC Tool Configuration", tool_name)]
    if not existing:
        return {"tool_names": (), "parents": [], "children": []}

    placeholders = ", ".join(["%s"] * len(existing))
    parents = frappe.db.sql(
        f"SELECT * FROM `{TOOL_CONFIG_TABLE}` WHERE name IN ({placeholders}) ORDER BY name",
        tuple(existing),
        as_dict=True,
    )
    children = frappe.db.sql(
        f"SELECT * FROM `{ROLE_ACCESS_TABLE}` WHERE parent IN ({placeholders}) " "ORDER BY parent, idx, name",
        tuple(existing),
        as_dict=True,
    )
    return {
        "tool_names": tuple(existing),
        "parents": parents,
        "children": children,
    }


def tool_configs_snapshot_hash(snapshot: dict) -> str:
    serialized = json.dumps(snapshot, default=str, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest()


def _table_columns(table: str) -> list[str]:
    return [column.Field for column in frappe.db.sql(f"SHOW COLUMNS FROM `{table}`", as_dict=True)]


def _insert_rows(table: str, rows: list[dict]) -> None:
    if not rows:
        return
    columns = _table_columns(table)
    placeholders = ", ".join(["%s"] * len(columns))
    quoted_columns = ", ".join(f"`{column}`" for column in columns)
    statement = f"INSERT INTO `{table}` ({quoted_columns}) VALUES ({placeholders})"
    for row in rows:
        frappe.db.sql(statement, tuple(row.get(column) for column in columns))


def restore_tool_configs_snapshot(snapshot: dict | None) -> None:
    """Restore an exact SQL snapshot for the affected tool configuration rows."""
    if not snapshot:
        return

    tool_names = snapshot.get("tool_names") or ()
    if not tool_names:
        return

    placeholders = ", ".join(["%s"] * len(tool_names))
    frappe.db.sql(
        f"DELETE FROM `{ROLE_ACCESS_TABLE}` WHERE parent IN ({placeholders})",
        tuple(tool_names),
    )
    frappe.db.sql(
        f"DELETE FROM `{TOOL_CONFIG_TABLE}` WHERE name IN ({placeholders})",
        tuple(tool_names),
    )
    _insert_rows(TOOL_CONFIG_TABLE, snapshot.get("parents") or [])
    _insert_rows(ROLE_ACCESS_TABLE, snapshot.get("children") or [])


def enable_tool_for_system_manager(tool_name: str) -> None:
    """Enable one tool for System Manager under Restrict to Listed Roles."""
    config = frappe.get_doc("FAC Tool Configuration", tool_name)
    config.enabled = 1
    config.role_access_mode = RESTRICT_TO_LISTED_ROLES
    config.set("role_access", [])
    config.append(
        "role_access",
        {"role": SYSTEM_MANAGER_ROLE, "allow_access": 1},
    )
    config.save(ignore_permissions=True)


def create_disposable_system_manager_user(email: str) -> None:
    """Insert a unique System User with System Manager and assistant access."""
    payload = {
        "doctype": "User",
        "email": email,
        "first_name": "FAC Legacy Test",
        "last_name": "User",
        "enabled": 1,
        "user_type": "System User",
        "roles": [{"role": SYSTEM_MANAGER_ROLE}],
    }
    if frappe.db.has_column("User", "assistant_enabled"):
        payload["assistant_enabled"] = 1
    frappe.get_doc(payload).insert(ignore_permissions=True)


class LegacyToolRegistryAccess:
    """Enable explicit tool configs for a disposable System Manager user."""

    def __init__(self, tool_names: Iterable[str], *, run_id: str | None = None):
        self.tool_names = tuple(dict.fromkeys(tool_names))
        self.run_id = run_id or uuid.uuid4().hex[:12]
        self.email = f"fac-legacy-{self.run_id}@example.com"
        self._previous_user: str | None = None
        self._snapshot: dict | None = None
        self._cleanup_needed = False
        self._user_created = False
        self._restored = False

    def __enter__(self) -> LegacyToolRegistryAccess:
        self._previous_user = frappe.session.user
        try:
            frappe.set_user("Administrator")
            self._snapshot = capture_tool_configs_snapshot(self.tool_names)
            self._cleanup_needed = bool(self._snapshot.get("tool_names"))

            for tool_name in self._snapshot.get("tool_names", ()):
                enable_tool_for_system_manager(tool_name)

            create_disposable_system_manager_user(self.email)
            self._user_created = True
            ToolRegistry().clear_cache()
            frappe.set_user(self.email)
            return self
        except Exception:
            self._restore_and_cleanup()
            raise

    def __exit__(self, exc_type, exc, tb):
        self._restore_and_cleanup()
        return False

    def _restore_and_cleanup(self) -> None:
        if self._restored or not self._cleanup_needed:
            return
        self._restored = True

        try:
            frappe.set_user("Administrator")
        except Exception:
            pass

        restore_tool_configs_snapshot(self._snapshot)

        if self._user_created:
            try:
                if frappe.db.exists("User", self.email):
                    frappe.delete_doc("User", self.email, force=True)
            except Exception:
                pass

        try:
            frappe.db.commit()  # nosemgrep: frappe-manual-commit — persist exact fixture restoration
        except Exception:
            pass

        ToolRegistry().clear_cache()

        if self._previous_user:
            try:
                frappe.set_user(self._previous_user)
            except Exception:
                pass


@contextmanager
def legacy_tool_registry_access(tool_names: Iterable[str], *, run_id: str | None = None):
    """Context manager: disposable System Manager + explicit tool enablement."""
    ctx = LegacyToolRegistryAccess(tool_names, run_id=run_id)
    ctx.__enter__()
    try:
        yield ctx
    finally:
        ctx.__exit__(None, None, None)
