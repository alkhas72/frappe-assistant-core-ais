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
Security configuration for Frappe Assistant Core.

AUTHORITY MOVED (Task 6, FAC security hardening, 2026-08-09): the legacy
``ROLE_TOOL_ACCESS`` matrix and ``BASIC_CORE_TOOLS`` list no longer authorize
anything. Runtime authorization lives in
:mod:`frappe_assistant_core.core.security_policy` (fail-closed ``SecurityPolicy``
called from ``BaseTool._safe_execute``). The functions kept here are
backwards-compatibility shims so existing tool implementations do not break at
import time, but they cannot re-enable a hard-denied tool, open a restricted
DocType, leak a sensitive field, or grant any System Manager / Administrator
bypass. Every code path that previously granted elevated access now either
delegates to ``SecurityPolicy`` or returns a fail-closed answer.

Only the data constants ``SENSITIVE_FIELDS`` and ``ADMIN_ONLY_FIELDS`` remain
authoritative here: they feed ``SecurityPolicy._contains_restricted_fields`` and
must not be removed without a coordinated change to the policy contract
(owned by the Foundation workstream).
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Dict, List, Optional

import frappe

# ---------------------------------------------------------------------------
# Deprecated inert / fail-closed exports (kept for import compatibility)
#
# Older code paths imported ``BASIC_CORE_TOOLS``, ``ROLE_TOOL_ACCESS`` and the
# dict-form ``RESTRICTED_DOCTYPES`` for role-matrix lookups. With Task 6 the
# matrix retired from runtime authority.
#
# FAC v2.2: ``BASIC_CORE_TOOLS`` and ``ROLE_TOOL_ACCESS`` are now IMMUTABLE
# empty containers (``tuple`` / ``MappingProxyType({})``) — legacy callers
# cannot mutate them into an alternative allow system.
#
# ``RESTRICTED_DOCTYPES`` is intentionally NOT a plain empty dict: a legacy
# caller doing ``doctype in RESTRICTED_DOCTYPES.get(role, [])`` would get
# ``[]`` and conclude "not restricted" — that was fail-OPEN (caught by the
# Frappe 15 review, v2.1). The export is now a read-only mapping that returns
# the canonical restricted set for EVERY role key, derived lazily from
# ``SecurityPolicy.RESTRICTED_DOCTYPES``. If the canonical import itself
# fails, we return a deny-all membership object so that
# ``doctype in legacy_list`` is always True — fail-closed rather than the
# sentinel-string approach that did not match any real DocType.
#
# Removing these exports entirely is a separate breaking-change decision for
# the Arbiter; until then they remain defined and fail-closed.
# ---------------------------------------------------------------------------

BASIC_CORE_TOOLS: tuple = ()
ROLE_TOOL_ACCESS: Mapping = MappingProxyType({})


class _DenyAll:
    """Membership container that reports every DocType as restricted.

    Used as the fail-closed fallback when the canonical restricted set
    cannot be loaded. ``__contains__`` is True for any value so the legacy
    pattern ``doctype in legacy_list`` cannot accidentally conclude "not
    restricted"; ``__len__`` is non-zero so ``if not legacy_list`` also
    fails closed.

    FAC v2.3: ``__iter__`` RAISES instead of yielding nothing. A naive
    ``for dt in legacy_list`` previously produced an empty iteration, which
    looked like "no restrictions defined" — exactly the false sense of
    safety that the v2.1/v2.2 rounds rejected at the membership-test level.
    Iterating a deny-all container is a programming error during a
    canonical-load failure; we surface it explicitly.
    """

    __slots__ = ()

    def __contains__(self, _item: Any) -> bool:
        return True

    def __iter__(self):
        raise RuntimeError(
            "fac_deny_all: canonical restricted-Doctype set is unavailable; "
            "iteration is not safe"
        )

    def __len__(self) -> int:
        return 1

    def __bool__(self) -> bool:
        return True

    def __eq__(self, other: Any) -> bool:
        # Two deny-all instances are equal; not equal to anything else.
        return isinstance(other, _DenyAll)

    def __hash__(self) -> int:
        return hash("__fac_deny_all__")

    def __repr__(self) -> str:
        return "<fac deny-all restricted-doctypes>"


_DENY_ALL = _DenyAll()


class _LegacyRestrictedDoctypes(Mapping):
    """Read-only dict view that derives the legacy ``{role: [doctypes]}``
    shape from the canonical frozenset on every access.

    Every role key resolves to the SAME canonical restricted list, so the old
    lookup pattern ``RESTRICTED_DOCTYPES.get(role, []).__contains__(dt)``
    cannot fail-open regardless of which role the caller supplies. If the
    canonical policy import itself fails, the mapping returns ``_DenyAll``
    so every membership test reports "restricted".
    """

    __slots__ = ()

    @staticmethod
    def _canonical() -> Any:
        # Lazy import: security_policy imports security_config for
        # SENSITIVE_FIELDS / ADMIN_ONLY_FIELDS, so we cannot import it at
        # module load here without creating a cycle.
        from frappe_assistant_core.core.security_policy import RESTRICTED_DOCTYPES

        return sorted(RESTRICTED_DOCTYPES)

    def _always_list(self) -> Any:
        try:
            return self._canonical()
        except Exception:
            # Canonical import failed. Fail closed: every membership test
            # must report "restricted". The previous sentinel-string
            # approach did not match any real DocType and was fail-OPEN.
            return _DENY_ALL

    def __getitem__(self, key: Any) -> Any:
        # Every role gets the canonical set — never an empty list, never a
        # wildcard. ``__getitem__`` (``d[key]``) covers ``.get(key)`` too.
        del key  # role is irrelevant in the post-matrix world
        return self._always_list()

    def __iter__(self):
        # Provide a stable iteration order based on the canonical set; the
        # keys themselves are not meaningful, but ``list(d)`` should not raise.
        return iter(("Assistant User", "Assistant Admin", "System Manager", "Default"))

    def __len__(self) -> int:
        return 4

    def __contains__(self, key: Any) -> bool:
        # ``"Assistant User" in RESTRICTED_DOCTYPES`` should behave like the
        # legacy dict did (True for known role keys).
        return key in ("Assistant User", "Assistant Admin", "System Manager", "Default")


RESTRICTED_DOCTYPES: Mapping[str, Any] = _LegacyRestrictedDoctypes()


# ---------------------------------------------------------------------------
# Sensitive / admin-only field snapshots (still authoritative for policy)
# ---------------------------------------------------------------------------

SENSITIVE_FIELDS: Dict[str, Any] = {
    "all_doctypes": [
        "password",
        "new_password",
        "api_key",
        "api_secret",
        "secret_key",
        "private_key",
        "access_token",
        "refresh_token",
        "reset_password_key",
        "unsubscribe_key",
        "email_signature",
        "bank_account_no",
        "iban",
        "encryption_key",
    ],
    "User": [
        "password",
        "new_password",
        "api_key",
        "api_secret",
        "reset_password_key",
        "unsubscribe_key",
        "email_signature",
        "login_after",
        "user_type",
        "simultaneous_sessions",
        "restrict_ip",
        "last_password_reset_date",
        "last_login",
        "last_active",
        "login_before",
        "bypass_restrict_ip_check_if_2fa_enabled",
    ],
    "System Settings": [
        "password_reset_limit",
        "session_expiry",
        "session_expiry_mobile",
        "email_footer_address",
        "backup_path",
        "backup_path_db",
        "backup_path_files",
        "backup_path_private_files",
        "encryption_key",
    ],
    "Email Account": [
        "password",
        "smtp_password",
        "access_token",
        "refresh_token",
        "auth_method",
        "connected_app",
        "connected_user",
    ],
    "Integration Request": [
        "data",
        "output",
        "error",
        "headers",
    ],
    "OAuth Bearer Token": [
        "access_token",
        "refresh_token",
        "scopes",
        "expires_in",
    ],
    "Connected App": [
        "client_secret",
        "client_id",
        "redirect_uris",
    ],
    "Social Login Key": [
        "client_secret",
        "client_id",
        "base_url",
        "custom_base_url",
    ],
    "Google Settings": [
        "client_secret",
        "client_id",
    ],
    "LDAP Settings": [
        "password",
        "ldap_password",
    ],
    "Dropbox Settings": [
        "app_access_token",
        "access_token",
        "app_secret",
    ],
    "Google Drive": [
        "refresh_token",
        "access_token",
        "indexing_refresh_token",
        "indexing_access_token",
    ],
    "S3 File Attachment": [
        "access_key_id",
        "secret_access_key",
        "region_name",
        "bucket_name",
        "folder_name",
        "file_url",
        "is_private",
    ],
}

ADMIN_ONLY_FIELDS: Dict[str, Any] = {
    "all_doctypes": [
        "owner",
        "creation",
        "modified",
        "modified_by",
        "docstatus",
        "idx",
        "_user_tags",
        "_comments",
        "_assign",
        "_liked_by",
    ],
    "User": [
        "enabled",
        "user_type",
        "module_profile",
        "role_profile_name",
        "roles",
        "user_permissions",
        "block_modules",
        "home_settings",
        "defaults",
        "system_user",
        "allowed_in_mentions",
        "banner_image",
        "interest",
        "bio",
        "mute_sounds",
        "desk_theme",
        "simultaneous_sessions",
        "restrict_ip",
        "login_before",
        "login_after",
        "user_image",
        "logout_all_sessions",
        "reset_password_key",
        "last_password_reset_date",
        "last_login",
        "last_active",
        "login_attempts",
        "reCAPTCHA",
    ],
    "System Settings": "*",  # Hide all system settings from Assistant Users
    "Print Settings": "*",
    "Email Domain": "*",
    "Domain Settings": "*",
    "Energy Point Settings": "*",
    "Google Settings": "*",
    "LDAP Settings": "*",
    "OAuth Settings": "*",
    "Social Login Key": "*",
    "Dropbox Settings": "*",
}


# ---------------------------------------------------------------------------
# Backwards-compatibility shims (NO LONGER AUTHORITATIVE)
#
# The legacy ``ROLE_TOOL_ACCESS`` matrix and ``BASIC_CORE_TOOLS`` list are
# intentionally gone. They leaked legacy aliases (``document_create``,
# ``execute_python_code``, ``metadata_permissions`` ...) into "allowed" sets and
# granted ``System Manager`` an implicit ``*`` wildcard that bypassed FAC's
# central policy. Callers that still import these symbols get fail-closed
# behaviour: the contract is "policy decides, not the matrix".
# ---------------------------------------------------------------------------


def _policy() -> Any:
    """Lazy import keeps this module importable from contexts that run before
    the policy contract is registered (e.g. early app boot)."""
    from frappe_assistant_core.core.security_policy import SecurityPolicy

    return SecurityPolicy


def check_tool_access(user_role: str, tool_name: str) -> bool:
    """Deprecated. Previously consulted ``ROLE_TOOL_ACCESS``; now fail-closed.

    The legacy matrix granted ``System Manager`` an ``*`` wildcard and allowed
    lists that included hard-denied legacy aliases (``execute_python_code``,
    ``metadata_permissions`` ...). With the matrix retired, this function can
    never authorize anything: it returns ``False`` unconditionally and exists
    only so legacy imports do not break at module load. Runtime authorization is
    owned by :func:`SecurityPolicy.authorize` and is invoked once per
    ``BaseTool._safe_execute`` call.
    """
    del user_role, tool_name  # Fail-closed: matrix authority removed.
    return False


def get_allowed_tools(user_role: str) -> List[str]:
    """Deprecated. The matrix no longer exists; there is no static per-role
    allowlist to return. Publication/execution authority lives in
    :class:`SecurityPolicy` and the FAC Tool Configuration rows it consults.
    """
    del user_role
    return []


def is_doctype_accessible(doctype: str, user_role: str | None = None) -> bool:
    """Deprecated role-based gate. Previously returned ``True`` for every
    DocType when ``user_role == "System Manager"``.

    Fail-closed replacement: delegates to
    :meth:`SecurityPolicy._is_restricted_target`, which checks both the
    ratified ``RESTRICTED_DOCTYPES`` baseline and ``meta.istable`` (child
    tables are not directly accessible). ``user_role`` is accepted for
    backwards compatibility but no longer creates a bypass — not even for
    ``System Manager``.
    """
    if not doctype:
        return False
    try:
        policy = _policy()
        # ``_is_restricted_target`` already covers RESTRICTED_DOCTYPES + child
        # tables (``meta.istable == 1``) in one call; re-implementing it here
        # would risk divergence from the central policy.
        return not policy._is_restricted_target(doctype)
    except Exception:
        # If the policy lookup fails we cannot prove accessibility.
        return False


def get_user_primary_role(user: str) -> str:
    """Return the highest-privilege role for ``user``.

    The return value is still useful for audit/display logic and for callers
    that need a label, but it must not be used as an authorization signal —
    :func:`check_tool_access` now ignores it and always returns ``False``.
    """
    try:
        user_roles = frappe.get_roles(user)
    except Exception:
        return "Default"

    if "System Manager" in user_roles:
        return "System Manager"
    if "Assistant Admin" in user_roles:
        return "Assistant Admin"
    if "Assistant User" in user_roles:
        return "Assistant User"
    return "Default"


def filter_sensitive_fields(
    doc_dict: Dict[str, Any], doctype: str, user_role: str | None = None
) -> Dict[str, Any]:
    """Redact sensitive/admin-only fields from ``doc_dict``.

    Previously granted ``System Manager`` a full bypass (returned the dict
    unchanged). That bypass was the root cause of credential leaks through
    read paths that did not pass through central ``SecurityPolicy``. The
    function now applies the union of ``SENSITIVE_FIELDS`` and
    ``ADMIN_ONLY_FIELDS`` for every caller, regardless of role, mirroring the
    universal redaction enforced by
    :meth:`SecurityPolicy.redact_output`.

    This local filter may ADD restrictions but cannot provide a privileged-role
    bypass. Tools that need true output redaction should rely on the central
    sink in ``BaseTool._safe_execute``; this helper exists for code paths that
    serialize documents before the central sink runs (e.g. JSON-string payloads
    produced inside a tool ``execute``).
    """
    if not isinstance(doc_dict, dict):
        return doc_dict

    filtered = dict(doc_dict)

    # Universal sensitive fields (any doctype)
    sensitive: set[str] = set(SENSITIVE_FIELDS.get("all_doctypes", []))
    sensitive.update(SENSITIVE_FIELDS.get(doctype, []))

    # Admin-only fields are now applied universally — no System Manager bypass.
    admin_all = ADMIN_ONLY_FIELDS.get("all_doctypes", [])
    if isinstance(admin_all, list):
        sensitive.update(admin_all)

    admin_for_doctype = ADMIN_ONLY_FIELDS.get(doctype, [])
    if admin_for_doctype == "*":
        # Whole DocType is admin-only; mirror the legacy "access restricted"
        # contract so callers do not print anything from it.
        return {"error": "Access to this document type is restricted"}
    if isinstance(admin_for_doctype, list):
        sensitive.update(admin_for_doctype)

    for field in sensitive:
        if field in filtered:
            filtered[field] = "***RESTRICTED***"

    return filtered


def validate_document_access(
    user: str,
    doctype: str,
    name: str,
    perm_type: str = "read",
    data: str | Dict[str, Any] | None = "",
) -> Dict[str, Any]:
    """Backwards-compatible wrapper around the central policy decision plus a
    native Frappe permission check.

    Previously called the legacy matrix (``is_doctype_accessible``) which let
    ``System Manager`` read every DocType, then a Frappe ``has_permission``
    call. The matrix step is gone; we now ask
    :meth:`SecurityPolicy._is_restricted_target` and fall through to Frappe's
    native permission check. There is no privileged-role bypass.
    """
    try:
        if not doctype:
            return {"success": False, "error": "DocType is required"}

        # Restricted DocType set is the authoritative gate; role cannot override.
        policy = _policy()
        if policy._is_restricted_target(doctype):
            return {
                "success": False,
                "error": f"Access to {doctype} is restricted",
            }

        if not frappe.has_permission(doctype, perm_type, user=user):
            return {"success": False, "error": f"Insufficient {perm_type} permissions for {doctype}"}

        if name:
            if not frappe.has_permission(doctype, perm_type, doc=name, user=user):
                return {
                    "success": False,
                    "error": f"Insufficient {perm_type} permissions for {doctype} {name}",
                }

            if perm_type in {"write", "delete"}:
                try:
                    doc = frappe.get_doc(doctype, name)
                    if hasattr(doc, "docstatus") and doc.docstatus == 1:
                        if perm_type == "delete":
                            return {
                                "success": False,
                                "error": f"Cannot delete submitted document {doctype} {name}",
                            }
                        if isinstance(data, dict):
                            meta = frappe.get_meta(doctype)
                            non_allowed = [
                                field
                                for field in data.keys()
                                if not meta.get_field(field) or not meta.get_field(field).allow_on_submit
                            ]
                            if non_allowed:
                                return {
                                    "success": False,
                                    "error": f"Cannot modify submitted document {doctype} {name}",
                                }
                except Exception:
                    # Document may not exist yet for create-like flows; the
                    # central policy and Frappe's own save() remain authoritative.
                    pass

        return {"success": True, "role": get_user_primary_role(user)}

    except Exception:
        # Never expose raw exception details to the caller.
        return {"success": False, "error": "Permission validation failed"}
