# FAC Security Policy

Operator-facing summary of Frappe Assistant Core (FAC) security controls after Tasks 1–7 integration at commit `85c7906`. This document separates **verified guarantees** (covered by existing unit/integration tests and production policy code) from **acceptance requirements** validated by Task 8 (`test_security_matrix.py`).

## Verified guarantees (Tasks 1–7)

These behaviors are enforced in production code and covered by the existing test suite (`test_security_policy.py`, `test_mcp_security_boundary.py`, `test_mcp_concurrency.py`, and related modules):

- Single fail-closed authorization boundary: `SecurityPolicy.authorize` for publish and execute phases.
- Hard-deny tools never publish and never execute for any actor, including **System Manager** and **Administrator**.
- Only the ratified 24-name built-in inventory participates in authorization; newly discovered tool classes remain unavailable until the snapshot is deliberately updated.
- Restricted DocTypes and child-table targets (`istable=1`) are denied at execute time even when role access passes.
- Sensitive output fields are recursively redacted, including values embedded in JSON strings.
- MCP boundary returns stable error bodies without tracebacks, raw exceptions, or secret echo.
- Per-request tool registries prevent cross-request registry corruption under concurrency.
- OAuth/API authentication failures write sanitized security audit rows.

## Pending Task 8 acceptance

The following are **requirements** exercised by `frappe_assistant_core/tests/test_security_matrix.py`. A production deployment should treat them as contractual only after Codex confirms:

```bash
bench --site "$FAC_TEST_SITE" run-tests \
  --app frappe_assistant_core \
  --module frappe_assistant_core.tests.test_security_matrix
```

Task 8 acceptance additionally proves:

- Literal inventory snapshots (24 tools, 8 hard-deny built-ins, 56 restricted DocTypes) match production discovery/constants with no extra/missing/ambiguous entries.
- Full actor × configuration × phase matrix through **ToolRegistry** and **MCPServer** (not direct `SecurityPolicy` calls).
- Exactly one persisted `Assistant Audit Log` row per boundary call, scoped by unique session identity.
- Real System Manager outputs for document/list/search/report/metadata/fetch paths (not direct `redact_output` stubs).
- Parallel request-local users with distinct role configurations, real `tools/list` + `tools/call`, no mocked authorization.
- Secret-bearing failures sanitized across logger, Error Log, and Assistant Audit Log channels.

## Ratified built-in inventory (24 tools)

| # | Tool name |
|---|-----------|
| 1 | `get_document` |
| 2 | `list_documents` |
| 3 | `search_documents` |
| 4 | `search_doctype` |
| 5 | `search_link` |
| 6 | `search` |
| 7 | `fetch` |
| 8 | `get_doctype_info` |
| 9 | `report_list` |
| 10 | `report_requirements` |
| 11 | `generate_report` |
| 12 | `get_pending_approvals` |
| 13 | `create_document` |
| 14 | `update_document` |
| 15 | `submit_document` |
| 16 | `run_workflow` |
| 17 | `delete_document` |
| 18 | `run_python_code` |
| 19 | `run_database_query` |
| 20 | `analyze_business_data` |
| 21 | `extract_file_content` |
| 22 | `create_dashboard` |
| 23 | `create_dashboard_chart` |
| 24 | `list_user_dashboards` |

**Usage timing:** only names in this ratified set enter `SecurityPolicy.inventory()`. Discovery may find additional classes; they stay blocked until this list and its contract test are updated together.

## Hard-deny built-ins (8 tools)

These built-in tools are **never** published and **never** executed, regardless of `FAC Tool Configuration`, plugin state, or actor role:

1. `delete_document`
2. `run_python_code`
3. `run_database_query`
4. `analyze_business_data`
5. `extract_file_content`
6. `create_dashboard`
7. `create_dashboard_chart`
8. `list_user_dashboards`

Production also maintains legacy alias names in `HARD_DENY_TOOLS` for defense in depth. Task 8 acceptance compares the **8 built-in names above** against production independently, then asserts equality with the production intersection.

## Configurable tools (16 tools)

All ratified built-ins except the 8 hard-deny tools:

`get_document`, `list_documents`, `search_documents`, `search_doctype`, `search_link`, `search`, `fetch`, `get_doctype_info`, `report_list`, `report_requirements`, `generate_report`, `get_pending_approvals`, `create_document`, `update_document`, `submit_document`, `run_workflow`

Each requires a `FAC Tool Configuration` row and passes authorization only under the modes below.

## Configuration modes

| Mode | Publish | Execute |
|------|---------|---------|
| **Missing row** | Denied (`CONFIG_MISSING`) | Denied (`CONFIG_MISSING`) |
| **Deny All** (disabled) | Denied (`TOOL_DISABLED`) | Denied (`TOOL_DISABLED`) |
| **Deny All** (enabled) | Denied (`CONFIG_MODE_DENIED`) | Denied (`CONFIG_MODE_DENIED`) |
| **Allow All** | Denied (`CONFIG_MODE_DENIED`) | Denied (`CONFIG_MODE_DENIED`) |
| **Restrict to Listed Roles** (empty list) | Denied (`ROLE_NOT_ALLOWED`) | Denied (`ROLE_NOT_ALLOWED`) |
| **Restrict to Listed Roles** (role mismatch) | Denied (`ROLE_NOT_ALLOWED`) | Denied (`ROLE_NOT_ALLOWED`) |
| **Restrict to Listed Roles** (matching role) | Allowed when plugin enabled | Allowed when native permissions pass |
| **Unknown / invalid mode value** | Denied (`CONFIG_MODE_DENIED`) | Denied (`CONFIG_MODE_DENIED`) |
| **Plugin disabled** | Denied (`PLUGIN_DISABLED`) | Denied (`PLUGIN_DISABLED`) |

**No bypass:** **System Manager** and **Administrator** follow the same policy path. Elevated Frappe roles do not skip hard-deny, config mode checks, or restricted DocType rules.

Configuration changes via DocType `.save()` or `frappe.db.set_value()` take effect on the next publish/execute call (fresh read on execute phase).

## Restricted DocTypes (56)

Direct reads/writes against these DocTypes are denied at execute time (`DOCTYPE_RESTRICTED`), including for System Manager when accessed through FAC tools:

`User`, `Role`, `User Permission`, `Role Permission`, `Custom Role`, `Module Profile`, `Role Profile`, `Custom DocPerm`, `DocShare`, `System Settings`, `Print Settings`, `Email Domain`, `LDAP Settings`, `OAuth Settings`, `Social Login Key`, `Dropbox Settings`, `Connected App`, `OAuth Bearer Token`, `OAuth Client`, `Error Log`, `Activity Log`, `Access Log`, `View Log`, `Scheduler Log`, `Integration Request`, `Server Script`, `Client Script`, `Custom Script`, `Property Setter`, `Customize Form`, `Customize Form Field`, `DocType`, `DocField`, `DocPerm`, `Custom Field`, `Package`, `Package Release`, `Installed Application`, `Data Import`, `Data Export`, `Bulk Update`, `Rename Tool`, `Database Storage Usage By Tables`, `Workflow`, `Workflow Action`, `Workflow State`, `Workflow Transition`, `Email Queue`, `Email Queue Recipient`, `Email Alert`, `Auto Email Report`, `File`, `Assistant Core Settings`, `FAC Tool Configuration`, `FAC Tool Role Access`, `FAC Plugin Configuration`, `Assistant Audit Log`

**Child tables:** any DocType with `istable=1` (for example `Has Role`) is also denied as a direct target.

## Reason codes

### Policy (`SecurityPolicy.authorize`)

| Code | Meaning |
|------|---------|
| `ALLOWED` | Authorization succeeded |
| `ACTOR_UNAUTHENTICATED` | Guest or empty actor |
| `ASSISTANT_DISABLED` | User has assistant access disabled |
| `CONFIG_MISSING` | No `FAC Tool Configuration` row |
| `CONFIG_MODE_DENIED` | Mode is not **Restrict to Listed Roles** |
| `TOOL_DISABLED` | Tool configuration exists but `enabled=0` |
| `ROLE_NOT_ALLOWED` | Actor role not in allowlist |
| `PLUGIN_DISABLED` | Owning plugin disabled |
| `TOOL_HARD_DENY` | Tool in hard-deny set |
| `TOOL_UNKNOWN` | Tool not in ratified inventory |
| `EXTERNAL_TOOL_DENIED` | External/unratified tool |
| `POLICY_PHASE_INVALID` | Phase not `publish` or `execute` |
| `ARGUMENT_CONTEXT_INVALID` | Tool arguments could not be parsed |
| `DOCTYPE_RESTRICTED` | Restricted or child DocType target |
| `FIELD_RESTRICTED` | Restricted field in request |
| `NATIVE_PERMISSION_DENIED` | Frappe permission check failed |
| `POLICY_ERROR_FAIL_CLOSED` | Unexpected internal error |

### MCP / boundary extensions

| Code | Meaning |
|------|---------|
| `ARGUMENTS_INVALID` | MCP `tools/call` arguments not a dict |
| `TOOL_UNPUBLISHED` | Tool absent from published registry |
| `AUTH_MISSING` | No credentials on MCP request |
| `AUTHENTICATION_ERROR` | Bearer/API key validation failed |

## External tools and Builder

Tools registered through `assistant_tools` hooks, Builder, or other external discovery paths are **excluded** from the ratified inventory until a separate security review adds them to `TRUSTED_EXTERNAL_TOOLS` and updates acceptance snapshots.

Do **not** assume hook-discovered tools are automatically usable by LLM clients.

## Audit and redaction

- Every tool call writes exactly one `Assistant Audit Log` row per boundary invocation.
- `tools/list` writes a summary row (`tool_name=tools/list`) with published/hidden counts only—never full inventory leakage.
- Security events write `action=security_<event_type>` rows with sanitized payloads.
- Denied attempts redact secrets in `input_data`, `output_data`, and `error_message`.
- Error Log entries must not contain raw secrets or tracebacks from MCP/policy boundaries.

## Roles

FAC ships two assistant-specific roles used in acceptance testing:

- **Assistant User** — standard LLM operator profile.
- **Assistant Admin** — elevated assistant administration; still subject to FAC policy (no hard-deny bypass).

Assign these roles explicitly in `FAC Tool Configuration` allowlists; legacy **Allow All** / **Deny All** modes are not valid under hardened policy.
