# FAC Security Hardening Implementation Plan

**Approval:** Алхас Тхагушев утвердил ревизию `642191d` 2026-08-09. Это утверждение ratifies exact `RESTRICTED_DOCTYPES` baseline из design spec и открывает Tasks 1–8; production gate Tasks 9–10 остаётся отдельным решением.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Построить fail-closed fork FAC 2.5.0, в котором каждый опубликованный и исполняемый tool проходит одну центральную policy, все отказы аудируются, а старые `Allow All` безопасно мигрируют в deny.

**Architecture:** Неизменяемая кодовая policy задаёт inventory, hard-deny, restricted DocTypes/fields и извлекает operation context. FAC Tool Configuration может только сузить эту policy. Все execution paths сходятся в `ToolRegistry.execute_tool` → `BaseTool._safe_execute`, где непосредственно перед tool code выполняется свежая авторизация; MCP publication остаётся отдельным неавторитетным фильтром.

**Tech Stack:** Python 3.8+; Frappe 15/16; MCP Streamable HTTP; Frappe DocTypes/patches; `unittest`/Frappe test runner; Ruff/Black; Git worktree.

## Global Constraints

- Основа неизменна: upstream `buildswithpaul/Frappe_Assistant_Core` 2.5.0, commit `e50c5c32bc7d28f10842c5779e0aec61d5b77bbb`.
- Рабочая ветка: `feat/security-hardening` в `/Users/alkhas.abaza/repo/frappe-assistant-core-ais--feat-security-hardening`.
- Боевую Frappe, роли, ключи, OAuth/MCP и реальные данные не менять.
- `delete_document`, четыре data-science tools, три visualization tools и все external `assistant_tools` остаются hard-denied.
- AIS Builder не входит в этот план.
- Нет bypass для `Administrator` или `System Manager`.
- Отсутствующая/ошибочная/устаревшая конфигурация закрывается отказом.
- `approved` устанавливает только Алхас.
- До реализации план проходит кросс-аудит Claude и Antigravity, затем гейт Алхаса.
- Для bench-команд исполнитель заранее задаёт `FAC_TEST_SITE` именем изолированного test site; production site использовать запрещено.

## Ownership and sequencing

План исполняется не как четыре независимых форка целиком, а как foundation + три непересекающихся workstreams.

| Этап | Владелец | Задачи | Запрещённые пересечения |
|---|---|---|---|
| Foundation | Codex | 1–2 | остальные исполнители не меняют policy contract и audit interface |
| Execution path | Codex | 3–4 | registry/base/MCP/adapter/endpoint и legacy adapter |
| Migration/config | Kimi | 5 | не меняет registry, MCP и core tools |
| Core-tool safety | Z | 6–7 | document/search/metadata/report/workflow; не меняет legacy adapter, policy contract, migrations и MCP |
| Verification/docs | Composer | 8 | не меняет production code без отдельного возврата Codex |
| Integration | Codex | 9–10 | сведение, конфликт-анализ, итоговые проверки |

Kimi и Z начинают после зелёных Task 1–2 и отдельного сообщения Codex с зафиксированными signatures. Composer получает карточку сразу, но исполняет black-box Task 8 только после integration review Tasks 3–7; до этого он может готовить только test fixture map и черновик документации без изменения production code. Каждый работает в sibling worktree своей ветки; общий worktree не используется одновременно.

---

### Task 1: Policy contract, inventory and context extraction

**Files:**
- Create: `frappe_assistant_core/core/security_policy.py`
- Create: `frappe_assistant_core/tests/test_security_policy.py`

**Interfaces:**
- Produces: `PolicyDecision`, `PolicyDenied`, `ToolContext`, `SecurityPolicy.authorize`, `SecurityPolicy.extract_context`, `discover_builtin_tool_names`, `HARD_DENY_TOOLS`, `CONFIGURABLE_TOOLS`, `RESTRICTED_DOCTYPES`.
- `SecurityPolicy.authorize(actor: str, tool_name: str, arguments: dict | None, phase: str) -> PolicyDecision` never logs and never mutates state.
- `PolicyDecision.require()` raises `PolicyDenied` carrying `reason_code` and the decision.

- [ ] **Step 1: Write failing classification and fail-closed tests**

```python
EXPECTED_24_TOOLS = {
    "get_document", "list_documents", "search_documents", "search_doctype",
    "search_link", "search", "fetch", "get_doctype_info", "report_list",
    "report_requirements", "generate_report", "get_pending_approvals",
    "create_document", "update_document", "submit_document", "run_workflow",
    "delete_document", "run_python_code", "run_database_query",
    "analyze_business_data", "extract_file_content", "create_dashboard",
    "create_dashboard_chart", "list_user_dashboards",
}
ALLOW_SYSTEM_MANAGER = {
    "enabled": True,
    "role_access_mode": "Restrict to Listed Roles",
    "roles": {"System Manager"},
}
ALLOW_ALL = {"enabled": True, "role_access_mode": "Allow All", "roles": set()}

class TestSecurityPolicy(FrappeTestCase):
    def test_inventory_contains_exact_upstream_tools(self):
        discovered = discover_builtin_tool_names()
        self.assertEqual(discovered, EXPECTED_24_TOOLS)
        self.assertEqual(set(SecurityPolicy.inventory()), discovered)

    def test_hard_deny_cannot_be_overridden_for_system_manager(self):
        with patch.object(SecurityPolicy, "_load_access_config", return_value=ALLOW_SYSTEM_MANAGER):
            decision = SecurityPolicy.authorize(
                actor="Administrator",
                tool_name="run_python_code",
                arguments={"code": "print('never')"},
                phase="execute",
            )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "TOOL_HARD_DENY")

    def test_missing_config_and_allow_all_fail_closed(self):
        for config, reason in ((None, "CONFIG_MISSING"), (ALLOW_ALL, "CONFIG_MODE_DENIED")):
            with self.subTest(reason=reason), patch.object(
                SecurityPolicy, "_load_access_config", return_value=config
            ):
                decision = SecurityPolicy.authorize("agent@example.com", "get_document", {}, "publish")
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason_code, reason)
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run: `bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_security_policy`

Expected: FAIL because `frappe_assistant_core.core.security_policy` does not exist.

- [ ] **Step 3: Implement immutable inventory and decision types**

```python
@dataclass(frozen=True)
class ToolContext:
    operation: str
    target_doctype: Optional[str] = None
    target_name: Optional[str] = None
    fields: FrozenSet[str] = frozenset()
    required_permissions: FrozenSet[str] = frozenset()

@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason_code: str
    context: ToolContext
    audit_details: Mapping[str, Any] = field(default_factory=dict)

    def require(self) -> None:
        if not self.allowed:
            raise PolicyDenied(self)
```

Implement `discover_builtin_tool_names()` by calling `PluginDiscovery.discover_plugins()`, selecting exactly built-in plugin names `core`, `data_science` and `visualization`, importing every declared tool module, locating its `BaseTool` subclass and collecting the instantiated `.name`. Do not consult enabled plugin state and do not call dependency validation. Any import/class ambiguity fails the test. Define all 24 exact names from the design spec and assert them against this runtime source discovery. Define hard deny as the eight current names plus every known stale dangerous alias:

```python
HARD_DENY_TOOLS = frozenset({
    "delete_document",
    "run_python_code",
    "run_database_query",
    "analyze_business_data",
    "extract_file_content",
    "create_dashboard",
    "create_dashboard_chart",
    "list_user_dashboards",
    "document_create",
    "document_get",
    "document_update",
    "document_list",
    "search_global",
    "report_execute",
    "report_columns",
    "metadata_doctype",
    "create_visualization",
    "analyze_frappe_data",
    "workflow_status",
    "workflow_list",
    "execute_python_code",
    "query_and_analyze",
    "metadata_permissions",
    "metadata_workflow",
    "tool_registry_list",
    "tool_registry_toggle",
    "audit_log_view",
    "workflow_action",
})
```

Do not add current registered names such as `search_doctype`, `search_link` or `report_list` to the alias deny-set. A runtime-discovered name absent from the exact snapshot fails the inventory test and is denied until reviewed.

- [ ] **Step 4: Implement deterministic context extraction**

Use an explicit mapping, not name heuristics. `fetch.id` must split once on `/`; `create_document.submit=true` sets audit `operation="create"` and `required_permissions=frozenset({"create", "submit"})`; search wrappers use `read_many`; report tools use `report_name`; workflow tools carry `action`. Invalid shapes return `ARGUMENT_CONTEXT_INVALID`, not an exception.

- [ ] **Step 5: Implement policy evaluation order**

Implement exact order from design §4: actor → inventory → hard deny → plugin config → tool config → restricted roles → trusted external → context → restricted target/fields → native permission. Catch internal errors at the public boundary and return `POLICY_ERROR_FAIL_CLOSED`. Treat `Allow All`, empty restricted roles and unknown modes as deny. Do not special-case privileged Frappe roles. `_load_access_config(..., fresh=True)` must bypass the 60-second registry cache for `phase="execute"`; cache is permitted only for `phase="publish"`.

- [ ] **Step 6: Run focused tests and confirm GREEN**

Run the Task 1 test command again.

Expected: PASS for inventory, hard-deny, config modes, role intersection, restricted target, nested fields, invalid context and policy exceptions.

- [ ] **Step 7: Commit the foundation contract**

```bash
git add frappe_assistant_core/core/security_policy.py frappe_assistant_core/tests/test_security_policy.py
git commit -m "feat: add fail-closed tool policy"
```

### Task 2: Recursive audit sanitization and policy-denial evidence

**Files:**
- Modify: `frappe_assistant_core/utils/audit_trail.py`
- Modify: `frappe_assistant_core/core/base_tool.py`
- Modify: `frappe_assistant_core/tests/test_audit_log.py`

**Interfaces:**
- Consumes: `PolicyDenied`, `SecurityPolicy.authorize` from Task 1.
- Produces: `sanitize_for_audit(value: Any) -> Any`, `log_denied_tool_attempt(...)`, policy enforcement inside `_safe_execute`.

- [ ] **Step 1: Add failing nested-secret and one-row denial tests**

```python
def test_nested_secrets_are_redacted(self):
    value = {
        "headers": {"Authorization": "Bearer secret"},
        "rows": [{"api_secret": "x"}],
        "nested_json": '{"password":"inside"}',
    }
    self.assertEqual(
        sanitize_for_audit(value),
        {
            "headers": {"Authorization": "***REDACTED***"},
            "rows": [{"api_secret": "***REDACTED***"}],
            "nested_json": '{"password":"***REDACTED***"}',
        },
    )

def test_policy_denial_is_logged_once_before_dependencies(self):
    decision = PolicyDecision(
        allowed=False,
        reason_code="TOOL_HARD_DENY",
        context=ToolContext(operation="execute"),
    )
    tool = _RecordingToolForAuditTest()
    with patch.object(SecurityPolicy, "authorize", return_value=decision):
        result = tool._safe_execute({"password": {"token": "never-log"}})
    self.assertEqual(result["error_type"], "PolicyDenied")
    self.assertEqual(
        frappe.db.count("Assistant Audit Log", {"tool_name": tool.name}),
        1,
    )
    self.assertFalse(tool.dependencies_checked)
    self.assertFalse(tool.executed)
```

`_RecordingToolForAuditTest` is a local test double in `test_audit_log.py` with `name="recording_test_tool"`; its dependency and execute methods only flip the two booleans above and must never be added to production inventory.

- [ ] **Step 2: Run audit tests and confirm RED**

Run: `bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_audit_log`

Expected: nested values remain unredacted and policy is not called.

- [ ] **Step 3: Replace top-level sanitizer with recursive sanitizer**

Handle `Mapping`, lists, tuples and sets; preserve JSON-compatible scalar values; redact by `_is_sensitive_key`. For strings beginning with `{` or `[` and no larger than 65,536 bytes, attempt `json.loads`, recursively sanitize, then emit deterministic compact JSON; parsing failure leaves the scalar unchanged. Sanitize `arguments`, `output_data`, `error_message` and traceback payloads at the persistence sink. Do not log raw Authorization, code, query, file content or raw arguments through `frappe.log_error`/MCP debug logging.

- [ ] **Step 4: Enforce policy as first operation in `_safe_execute`**

Call `authorize(..., phase="execute").require()` before dependency validation. Retain the returned `PolicyDecision` and derive audit `operation`, `target_doctype` and `target_name` only from `decision.context`. Catch `PolicyDenied` before `frappe.PermissionError`; write status `Permission Denied`, `error_type="PolicyDenied"`, and stable reason in sanitized output metadata. For allowed calls, pass the result through `SecurityPolicy.redact_output(decision.context, result)` before returning it and before audit persistence. Redaction always removes universal sensitive keys; it additionally applies target-specific keys from context and, for heterogeneous results, the `doctype` declared by each result row. Existing success/error/timeout behavior remains unchanged.

- [ ] **Step 5: Run audit and existing tool tests**

Run:

```bash
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_audit_log
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_document_tools
```

Expected: PASS; every `_safe_execute` path creates one row.

- [ ] **Step 6: Commit audit enforcement**

```bash
git add frappe_assistant_core/utils/audit_trail.py frappe_assistant_core/core/base_tool.py frappe_assistant_core/tests/test_audit_log.py
git commit -m "feat: audit fail-closed policy decisions"
```

### Task 3: Canonical registry execution path

**Files:**
- Modify: `frappe_assistant_core/core/tool_registry.py`
- Modify: `frappe_assistant_core/mcp/tool_adapter.py`
- Modify: `frappe_assistant_core/tests/test_mcp_concurrency.py`
- Create: `frappe_assistant_core/tests/test_tool_execution_policy.py`

**Interfaces:**
- Consumes: Task 1 policy and Task 2 `_safe_execute` enforcement.
- Produces: `build_tool_dict(tool_instance, executor)`; `executor(tool_name: str, arguments: dict) -> Any`.

- [ ] **Step 1: Write failing adapter and TOCTOU tests**

```python
class DummyTool:
    name = "dummy"

def test_adapter_routes_through_registry_executor(self):
    executor = Mock(return_value={"ok": True})
    tool_dict = build_tool_dict(DummyTool(), executor=executor)
    self.assertEqual(tool_dict["fn"](name="A"), {"ok": True})
    executor.assert_called_once_with("dummy", {"name": "A"})

def test_disabled_after_publication_is_denied_at_call_time(self):
    registry = get_tool_registry()
    actor = "fac-toctou@example.com"
    published = registry.get_available_tools(user=actor)
    self.assertIn("get_document", {tool.name for tool in published})
    config = frappe.get_doc("FAC Tool Configuration", "get_document")
    config.enabled = 0
    config.save()
    with self.assertRaises(PolicyDenied):
        registry.execute_tool("get_document", {"doctype": "ToDo", "name": "TD-1"})
```

Add a second TOCTOU case that resets the fixture, publishes the tool, then calls `frappe.db.set_value("FAC Tool Configuration", "get_document", "enabled", 0)` without controller hooks. Both cases must deny immediately; the execute phase may not wait for the cache TTL.

- [ ] **Step 2: Run new tests and confirm RED**

Run: `bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_tool_execution_policy`

Expected: adapter calls `_safe_execute` directly and stale publication remains executable.

- [ ] **Step 3: Make publication policy-driven**

In `get_available_tools`, call `SecurityPolicy.authorize(..., phase="publish")` for every discovered tool. Remove default-enabled and System Manager behavior from the authority path. Publication failures are hidden without leaking available names.

- [ ] **Step 4: Make execution canonical**

`execute_tool` resolves the actual instance, calls its `_safe_execute`, and converts the structured result without a pre-policy bypass. Delete the upstream `_is_tool_enabled` and `_check_role_access` checks/raises that currently precede `_safe_execute`; known-tool authorization belongs only to the fresh execute policy. Unknown names call `log_denied_tool_attempt(reason_code="TOOL_UNKNOWN")` and raise `PolicyDenied`. `get_tool` remains resolution-only and is never an authorization API.

- [ ] **Step 5: Route adapter through executor**

Change wrapper closure to:

```python
def tool_function(**kwargs):
    return executor(tool_instance.name, kwargs)
```

Reject missing executor rather than silently falling back to raw execution in production registration. Update concurrency test fixtures to pass a fake executor explicitly.

- [ ] **Step 6: Run registry, concurrency and annotation tests**

```bash
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_tool_execution_policy
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_mcp_concurrency
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_tool_annotations
```

Expected: PASS, including config change between list/call.

- [ ] **Step 7: Commit canonical registry path**

```bash
git add frappe_assistant_core/core/tool_registry.py frappe_assistant_core/mcp/tool_adapter.py frappe_assistant_core/tests/test_mcp_concurrency.py frappe_assistant_core/tests/test_tool_execution_policy.py
git commit -m "refactor: route tools through policy executor"
```

### Task 4: MCP endpoint, unknown calls and authentication audit

**Files:**
- Modify: `frappe_assistant_core/api/fac_endpoint.py`
- Modify: `frappe_assistant_core/mcp/server.py`
- Modify: `frappe_assistant_core/api/handlers/tools.py`
- Modify: `frappe_assistant_core/assistant_core/tools.py`
- Create: `frappe_assistant_core/tests/test_mcp_security_boundary.py`
- Create: `frappe_assistant_core/tests/test_legacy_tool_registry.py`

**Interfaces:**
- Consumes: registry executor and audit helpers.
- Produces: one audited outcome per `tools/call`; one sanitized summary event per `tools/list`.

- [ ] **Step 1: Add failing MCP boundary tests**

Cover: missing auth = 401; Guest never builds registry; top-level `arguments` must be a dict; hidden name direct call = MCP `isError=true` plus one audit row; response does not list available tools; generic exceptions return `Tool execution failed` without traceback/`str(exception)`; list writes one summary without arguments; disabled-after-list fails; legacy adapter has no CRUD/search implementation and routes only through canonical registry.

```python
def test_unknown_tool_is_audited_without_inventory_leak(self):
    result = server._handle_tools_call({"name": "hidden", "arguments": {"token": "x"}}, {})
    self.assertTrue(result["isError"])
    self.assertNotIn("Available tools", result["content"][0]["text"])
    rows = frappe.get_all(
        "Assistant Audit Log",
        filters={"tool_name": "hidden"},
        fields=["status", "input_data"],
        order_by="creation desc",
        limit=1,
    )
    self.assertEqual(rows[0].status, "Permission Denied")
    self.assertNotIn("x", rows[0].input_data or "")
```

- [ ] **Step 2: Run MCP boundary tests and confirm RED**

Run: `bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_mcp_security_boundary`

- [ ] **Step 3: Pass registry executor from endpoint to adapter**

In `_build_tool_registry`, call `build_tool_dict(tool_instance, executor=registry.execute_tool)`. Keep registry per request. Do not cache decisions in tool dicts.

- [ ] **Step 4: Audit MCP denials and list summaries**

In `_handle_tools_call`, require a dict/object `arguments`; unknown/unpublished name calls the audit helper and returns `Tool is not available`. The generic exception branch returns `Tool execution failed`, never traceback, available-tool names or `str(exception)`; sanitized diagnostic detail is internal only. Authentication failures call `log_security_event` with actor `Guest`, reason only, and never include the Authorization header. `_handle_tools_list` records published/hidden counts only. Every call path owns exactly one audit write.

- [ ] **Step 5: Keep alternate handler on canonical registry**

Verify `api/handlers/tools.py` uses only `registry.get_available_tools` and `registry.execute_tool`; replace exception formatting that exposes internal details with stable public error messages while retaining details in sanitized audit.

- [ ] **Step 6: Neutralize and test the legacy registry**

Replace static CRUD/search implementations in `assistant_core/tools.py` with a thin deprecated adapter to canonical `get_tool_registry().get_available_tools/execute_tool`; no `frappe.get_all`, raw `get_doc`, insert or save remains. The test patches those Frappe functions to raise and verifies the canonical executor receives the tool name and unpacked dict.

- [ ] **Step 7: Run MCP/auth/concurrency/legacy suites**

```bash
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_mcp_security_boundary
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_oauth_cors
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_mcp_concurrency
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_legacy_tool_registry
```

- [ ] **Step 8: Commit MCP boundary**

```bash
git add frappe_assistant_core/api/fac_endpoint.py frappe_assistant_core/mcp/server.py frappe_assistant_core/api/handlers/tools.py frappe_assistant_core/assistant_core/tools.py frappe_assistant_core/tests/test_mcp_security_boundary.py frappe_assistant_core/tests/test_legacy_tool_registry.py
git commit -m "feat: enforce and audit MCP tool boundary"
```

### Task 5: Deny-by-default configuration and idempotent migration

**Files:**
- Modify: `frappe_assistant_core/assistant_core/doctype/fac_tool_configuration/fac_tool_configuration.json`
- Modify: `frappe_assistant_core/assistant_core/doctype/fac_tool_configuration/fac_tool_configuration.py`
- Modify: `frappe_assistant_core/api/admin/tools.py`
- Modify: `frappe_assistant_core/utils/migration_hooks.py`
- Modify: `frappe_assistant_core/patches.txt`
- Create: `frappe_assistant_core/patches/v2_5/__init__.py`
- Create: `frappe_assistant_core/patches/v2_5/harden_fac_tool_access_defaults.py`
- Create: `frappe_assistant_core/tests/test_security_migration.py`

**Interfaces:**
- Consumes: hard-deny and inventory constants from Task 1.
- Produces: access modes `Deny All` and `Restrict to Listed Roles`; idempotent `execute()` migration patch.

- [ ] **Step 1: Write failing fresh-sync and existing-data migration tests**

Test matrix:

```python
CASES = (
    ("run_python_code", 1, "Restrict to Listed Roles", ["System Manager"], 0, "Deny All", []),
    ("get_document", 1, "Allow All", [], 0, "Deny All", []),
    ("get_document", 1, "Restrict to Listed Roles", ["Assistant User"], 1, "Restrict to Listed Roles", ["Assistant User"]),
)
```

Assert a second patch execution performs zero semantic changes. Assert newly discovered plugin/tool/external configs are disabled and `Deny All`. Disable a plugin, run sync, and assert its existing tool configs remain present and unchanged; re-enable it and assert no permissive config is recreated. Core plugin may be enabled, but its tools are not.

- [ ] **Step 2: Run migration tests and confirm RED**

Run: `bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_security_migration`

- [ ] **Step 3: Change schema and controller validation**

Set `enabled` default `0`; role modes become `Deny All\nRestrict to Listed Roles`, default `Deny All`. Restricted mode requires at least one enabled role. `user_has_access` returns false for every other state and has no System Manager bypass.

- [ ] **Step 4: Harden admin APIs**

`toggle_tool` cannot enable hard-denied tools. New configs start disabled/Deny All. `update_tool_role_access` accepts only the two new modes; `Restrict` requires non-empty valid role rows; role changes do not implicitly enable a tool. All endpoints retain `frappe.only_for(["System Manager", "Assistant Admin"])`.

- [ ] **Step 5: Implement migration patch**

For every existing config: force hard-deny to disabled/Deny All; convert `Allow All`, missing/unknown `role_access_mode`, or empty restricted rows to disabled/Deny All; preserve valid restricted rows for configurable tools. Update exact fields with `frappe.db.set_value("FAC Tool Configuration", name, {"enabled": 0, "role_access_mode": "Deny All"})`; remove invalid child rows with `frappe.db.delete`, not `doc.save()` or raw SQL. Do not auto-assign roles. Log aggregate counts, clear registry/config cache once after the batch, and do not commit inside each row; one patch transaction. Run the same test module on Frappe 15 and 16 test sites.

- [ ] **Step 6: Harden sync defaults**

New non-core plugins disabled. New tools and external tools disabled/Deny All. Existing explicit restricted configs remain unchanged. Remove automatic orphan deletion from `_sync_tool_configurations`: discovery includes only enabled plugins, so absence cannot prove a config is obsolete. Re-running sync never restores `Allow All`. Replace the broken `core.enhanced_tool_registry` import in `after_install`/migration hooks with the canonical registry import and cover it in the migration test.

- [ ] **Step 7: Run migration and admin permission tests**

```bash
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_security_migration
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_admin_api_permissions
```

- [ ] **Step 8: Commit configuration hardening**

```bash
git add frappe_assistant_core/assistant_core/doctype/fac_tool_configuration frappe_assistant_core/api/admin/tools.py frappe_assistant_core/utils/migration_hooks.py frappe_assistant_core/patches.txt frappe_assistant_core/patches/v2_5 frappe_assistant_core/tests/test_security_migration.py
git commit -m "feat: migrate FAC access to deny by default"
```

### Task 6: Document, search and metadata safety

**Files:**
- Modify: `frappe_assistant_core/core/security_config.py`
- Modify: `frappe_assistant_core/plugins/core/tools/search_tools.py`
- Modify: `frappe_assistant_core/plugins/core/tools/metadata_tools.py`
- Modify: `frappe_assistant_core/plugins/core/tools/chatgpt_search.py`
- Modify: `frappe_assistant_core/plugins/core/tools/chatgpt_fetch.py`
- Modify: `frappe_assistant_core/tests/test_document_tools.py`
- Modify: `frappe_assistant_core/tests/test_search_tools.py`
- Modify: `frappe_assistant_core/tests/test_metadata_tools.py`

**Interfaces:**
- Consumes: immutable restricted targets/fields and policy context.
- Produces: permission-aware search/metadata results; deprecated matrix cannot authorize anything.

- [ ] **Step 1: Add failing restricted-target and row-permission tests**

Cover the exact ratified `RESTRICTED_DOCTYPES` baseline, direct child DocType targets, `User`, `File`, FAC configuration DocTypes, `DocType`, child metadata, `search`, `fetch`, nested secret fields and a document lacking user-level read permission. Patch `frappe.get_all` in search paths to raise, proving it is not used for business records. For document/list/search/metadata/fetch outputs, include sensitive keys nested in dict/list and assert they are redacted for both Assistant User and System Manager.

- [ ] **Step 2: Run document/search/metadata suites and confirm RED**

```bash
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_document_tools
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_search_tools
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_metadata_tools
```

- [ ] **Step 3: Retire the stale authorization matrix**

Remove it from runtime authority. Keep compatibility functions only if imports exist, but make them delegate to `SecurityPolicy` or fail closed. Remove System Manager bypass from `is_doctype_accessible` and recursive field filtering.

- [ ] **Step 4: Harden global and targeted search**

Before querying each common DocType, authorize that target. Use only `frappe.get_list(..., ignore_permissions=False)` for records. `search` remains a formatter over the secured result and cannot reintroduce `User`/`DocType`.

- [ ] **Step 5: Harden metadata and fetch**

Check parent and each child DocType before serializing schema. `metadata_permissions`-style arbitrary `user` inspection remains unregistered and is not exposed via `get_doctype_info`. `fetch` keeps secure ID parsing and target authorization. All output paths use the central `SecurityPolicy.redact_output`; local filters may add restrictions but cannot provide a privileged-role bypass.

- [ ] **Step 6: Run the three suites and confirm GREEN**

Expected: permission-aware results only; restricted schemas absent; existing CRUD behavior preserved for allowed business DocTypes.

- [ ] **Step 7: Commit core read safety**

```bash
git add frappe_assistant_core/core/security_config.py frappe_assistant_core/plugins/core/tools/search_tools.py frappe_assistant_core/plugins/core/tools/metadata_tools.py frappe_assistant_core/plugins/core/tools/chatgpt_search.py frappe_assistant_core/plugins/core/tools/chatgpt_fetch.py frappe_assistant_core/tests/test_document_tools.py frappe_assistant_core/tests/test_search_tools.py frappe_assistant_core/tests/test_metadata_tools.py
git commit -m "fix: enforce document policy in search and metadata"
```

### Task 7: Report and workflow safety

**Files:**
- Modify: `frappe_assistant_core/plugins/core/tools/report_tools.py`
- Modify: `frappe_assistant_core/plugins/core/tools/run_workflow.py`
- Modify: `frappe_assistant_core/plugins/core/tools/get_pending_approvals.py`
- Modify: `frappe_assistant_core/tests/test_report_tools.py`
- Modify: `frappe_assistant_core/tests/test_workflow_tools.py`

**Interfaces:**
- Consumes: policy target checks and central output redaction.
- Produces: permission-aware, recursively redacted report/workflow results.

- [ ] **Step 1: Add failing report/workflow tests**

Assert report discovery and filter suggestions cannot use `frappe.get_all` for linked business records; a report whose `ref_doctype` is restricted is denied; pending approvals omit unreadable references; workflow checks target before `get_doc`; report and workflow outputs redact nested sensitive keys for Assistant User and System Manager.

- [ ] **Step 2: Run focused suites and confirm RED**

```bash
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_report_tools
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_workflow_tools
```

- [ ] **Step 3: Harden reports**

Use permission-aware Report discovery, validate `Report` plus `ref_doctype`, and replace filter suggestions/options `get_all` with `get_list(ignore_permissions=False)`. Prepared report retrieval must remain bound to the permitted report and current user.

- [ ] **Step 4: Harden workflow operations**

Authorize target before `frappe.get_doc` or query. Preserve Frappe `get_transitions`/`apply_workflow` as mandatory second checks. Filter each pending approval by reference read permission before returning or loading transitions. Apply central output redaction before results leave `_safe_execute`.

- [ ] **Step 5: Run suites and confirm GREEN**

Expected: reports/workflows preserve allowed behavior, deny restricted/unreadable targets and redact nested sensitive fields for every role.

- [ ] **Step 6: Commit report/workflow safety**

```bash
git add frappe_assistant_core/plugins/core/tools/report_tools.py frappe_assistant_core/plugins/core/tools/run_workflow.py frappe_assistant_core/plugins/core/tools/get_pending_approvals.py frappe_assistant_core/tests/test_report_tools.py frappe_assistant_core/tests/test_workflow_tools.py
git commit -m "fix: close report and workflow bypasses"
```

### Task 8: Independent verification matrix and operator documentation

**Files:**
- Create: `frappe_assistant_core/tests/test_security_matrix.py`
- Create: `docs/security/fac-security-policy.md`
- Create: `docs/security/fac-rollout-runbook.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: all public behavior from Tasks 1–7.
- Produces: black-box matrix and production runbook; no production-code changes.

- [ ] **Step 1: Write black-box actor/tool matrix tests**

Use Assistant User, Assistant Admin and System Manager fixtures. For each, assert hard-deny always fails; missing/Deny All/Allow All fail; explicit restricted role can publish and execute only configurable tools; every ratified restricted DocType and direct child target fails; an allowed `ToDo` read succeeds; every call maps to one audit row. Compare the explicit 24-name snapshot to `discover_builtin_tool_names()` and fail on extra, missing or ambiguous tool classes.

- [ ] **Step 2: Add authentication and parallel request cases**

Test invalid Bearer, invalid API key, Guest, `.save()` and `frappe.db.set_value` config changes between list/call, non-dict MCP arguments, and two concurrent users with different roles. Assert no registry cross-contamination; no secret in audit/error/Error Log; no traceback or `str(exception)` in 401/generic MCP bodies; JSON-looking nested strings are redacted; document/list/search/report/metadata/fetch outputs are recursively redacted for System Manager too.

- [ ] **Step 3: Run security matrix**

Run: `bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_security_matrix`

Expected: PASS without production-code edits by this task owner. Failures are returned to Codex with exact test name and evidence.

- [ ] **Step 4: Write policy documentation**

Document exact 24-name inventory, hard-deny set, config modes, reason codes, no-System-Manager-bypass rule, audit redaction and external/Builder exclusion. Remove README claims that all discovered tools are automatically usable.

- [ ] **Step 5: Write rollout/rollback runbook**

Include preflight snapshot, verified DB/public/private-files backup, staging migration, role allowlist setup, negative smoke tests, endpoint switch, rollback to old revision/config snapshot, and fallback `frappe_api.sh`. Mark every production command as requiring separate Алхас approval.

- [ ] **Step 6: Commit verification/docs**

```bash
git add frappe_assistant_core/tests/test_security_matrix.py docs/security README.md
git commit -m "test: add FAC security acceptance matrix"
```

### Task 9: Merge workstreams and run regression/security checks

**Files:**
- Modify only when resolving reviewed integration conflicts.
- Evidence: command output attached to the implementation handoff, not committed if it contains environment details.

**Interfaces:**
- Consumes: reviewed commits from Codex, Kimi, Z and Composer.
- Produces: one integrated branch with traceable commits and no unresolved findings.

- [ ] **Step 1: Review each workstream before integration**

For every commit, compare changed files with ownership boundaries, inspect tests first, verify no hard-deny/config bypass, and reject unrequested production changes.

- [ ] **Step 2: Integrate in dependency order**

Order: Tasks 1–2 → Tasks 3–4, Task 5 and Tasks 6–7 in parallel → integration review of 3–7 → Task 8 → final integration. Task 7 has no registry dependency because legacy adapter belongs to Task 4. Resolve conflicts by preserving policy signatures; do not merge alternate definitions.

- [ ] **Step 3: Run formatting/static checks**

```bash
ruff check frappe_assistant_core
black --check frappe_assistant_core
PYTHONPYCACHEPREFIX=/private/tmp/fac-pycache python3 -m compileall -q frappe_assistant_core
git diff --check upstream/main...HEAD
```

Expected: all exit 0. Formatting fixes use `ruff check --fix`/`black` only after reviewing the file list.

- [ ] **Step 4: Run focused security suites**

```bash
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_security_policy
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_audit_log
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_mcp_security_boundary
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_security_migration
bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core --module frappe_assistant_core.tests.test_security_matrix
```

- [ ] **Step 5: Run full app tests**

Run: `bench --site "$FAC_TEST_SITE" run-tests --app frappe_assistant_core`

Expected: PASS. If bench/site is unavailable, record `verification-blocked`; do not claim completion.

- [ ] **Step 6: Commit reviewed integration-only fixes**

```bash
git commit -m "fix: integrate FAC hardening workstreams"
```

Before this commit, run one explicit `git add` command per exact reviewed conflict file recorded in the integration log. If integration produced no conflict fix, skip the commit. No glob and no blanket `git add .`.

### Task 10: Final independent audit and delivery gate

**Files:**
- Create: `docs/security/fac-hardening-verification-2026-08-09.md`
- Modify: files named by accepted audit findings only.

**Interfaces:**
- Consumes: integrated tested branch.
- Produces: evidence report and deployment-ready, not deployed, revision.

- [ ] **Step 1: Request final audit against the approved spec**

Auditor checks all 24 names, direct `_safe_execute`, MCP call-time, unknown calls, audit cardinality/redaction, migration idempotence, System Manager behavior, external hooks, legacy path and production runbook.

- [ ] **Step 2: Classify findings**

Block delivery for any bypass, missing negative test, secret leak, non-idempotent migration or production action. Correctness/style findings are fixed only when reproducible and within scope.

- [ ] **Step 3: Re-run affected focused tests and the full suite**

Use the Task 9 commands; capture command, exit code, test totals and revision in the verification document.

- [ ] **Step 4: Verify clean final state**

```bash
git status --short
git log --oneline --decorate -12
git diff --check upstream/main...HEAD
```

Expected: empty status, traceable small commits, diff check exit 0.

- [ ] **Step 5: Commit verification report**

```bash
git add docs/security/fac-hardening-verification-2026-08-09.md
git commit -m "docs: record FAC hardening verification"
```

- [ ] **Step 6: Stop at production gate**

Deliver branch/revision, tests, remaining risks and rollout runbook to Алхас. Do not push, create PR, deploy, migrate production, change roles or enable MCP without the corresponding separate authorization.

## Pre-implementation cross-audit gate

Кросс-аудит завершён до Task 1:

1. **Совместный Claude/Fable + Opus 4.8:** `PASS WITH REQUIRED CHANGES`; приняты fresh execute read, удаление registry prechecks, MCP error containment, central output redaction, ratified restricted set, audit-context/sanitizer/logging tests и сохранение disabled-plugin configs. Замечание о 25-м runtime tool отозвано самим аудитом; добавлен runtime-discovery contract test.
2. **Antigravity:** `EXECUTABLE WITH REQUIRED CHANGES`; legacy adapter перенесён из Z Task 7 в Codex Task 4, migration использует точное поле `role_access_mode` и `frappe.db.set_value`, JSON-looking nested strings обрабатываются bounded sanitizer при обязательном dict-shape MCP arguments.

Codex публикует Алхасу таблицу `finding → решение → изменение plan`. Реализация начинается только после явного утверждения этой исправленной версии Алхасом; утверждение одновременно ratifies точный baseline `RESTRICTED_DOCTYPES` из design spec.
