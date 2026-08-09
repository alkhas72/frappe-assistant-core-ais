# FAC Security Rollout Runbook

Production rollout and rollback procedures for FAC security hardening (Tasks 1–8). Every **production** command below requires **explicit approval from Алхас** before execution. Staging commands may run under change-control without production approval but must use non-production sites.

## Preconditions

- Exact approved FAC Tasks 1–8 integration revision pinned.
- Staging site migrated and Task 8 matrix green:

  ```bash
  bench --site "$FAC_STAGING_SITE" run-tests \
    --app frappe_assistant_core \
    --module frappe_assistant_core.tests.test_security_matrix
  ```

- Verified inputs collected (see [External script requirements](#external-script-requirements)).

## Variable placeholders

| Variable | Example | Description |
|----------|---------|-------------|
| `$PROD_SITE` | `erp.example.com` | Production site name |
| `$STAGING_SITE` | `erp-staging.example.com` | Staging site name |
| `$BENCH_DIR` | `/home/frappe/frappe-bench` | Bench root |
| `$FAC_APP_DIR` | `$BENCH_DIR/apps/frappe_assistant_core` | FAC app path |
| `$SNAPSHOT_DIR` | `/var/backups/fac-hardening-YYYYMMDD-HHMM` | Backup destination |
| `$FAC_REVISION` | `<approved-task8-integration-sha>` | Exact Git commit SHA approved for rollout |
| `$FRAPPE_API_SH` | `/path/to/frappe_api.sh` | External helper (not in FAC repo) |

---

## Phase 1 — Preflight snapshot

> **Requires explicit approval from Алхас before running on production.**

```bash
mkdir -p "$SNAPSHOT_DIR"/{db,files,config,manifest}
date -u +"%Y-%m-%dT%H:%M:%SZ" | tee "$SNAPSHOT_DIR/manifest/timestamp.txt"
git -C "$FAC_APP_DIR" rev-parse HEAD | tee "$SNAPSHOT_DIR/manifest/fac_revision_before.txt"
bench --site "$PROD_SITE" execute frappe.utils.change_log.get_versions \
  | tee "$SNAPSHOT_DIR/manifest/installed_versions_before.json"
```

Capture current FAC tool configuration export:

```bash
bench --site "$PROD_SITE" export-doc \
  "FAC Tool Configuration" "get_document" \
  | tee "$SNAPSHOT_DIR/config/sample_tool_config.json"
```

Record checksum manifest:

```bash
find "$SNAPSHOT_DIR" -type f -print0 \
  | sort -z \
  | xargs -0 shasum -a 256 \
  | tee "$SNAPSHOT_DIR/manifest/sha256.txt"
```

---

## Phase 2 — Database and file backup

> **Requires explicit approval from Алхас before running on production.**

Database dump:

```bash
bench --site "$PROD_SITE" backup --with-files \
  --backup-path "$SNAPSHOT_DIR/db"
```

Verify backup artifacts exist:

```bash
ls -lh "$SNAPSHOT_DIR/db"/*.sql.gz
ls -lh "$SNAPSHOT_DIR/db"/private/files/*.tar 2>/dev/null || true
```

Private files checksum:

```bash
find "$SNAPSHOT_DIR/db" -type f -name '*.tar' -o -name '*.sql.gz' \
  | sort \
  | xargs shasum -a 256 \
  | tee "$SNAPSHOT_DIR/manifest/backup_sha256.txt"
```

---

## Phase 3 — Staging migration and validation

Run on staging first (no production approval required if site is non-production):

```bash
cd "$BENCH_DIR"
git -C "$FAC_APP_DIR" fetch origin
git -C "$FAC_APP_DIR" checkout "$FAC_REVISION"
bench --site "$STAGING_SITE" migrate
bench --site "$STAGING_SITE" run-tests --app frappe_assistant_core
bench --site "$STAGING_SITE" run-tests \
  --app frappe_assistant_core \
  --module frappe_assistant_core.tests.test_security_matrix
```

Negative smoke checks on staging:

```bash
# Hard-deny tool must not appear in published list for Assistant User
bench --site "$STAGING_SITE" execute frappe_assistant_core.tests.smoke.published_tools \
  --kwargs "{'user': 'assistant@example.com', 'deny': 'delete_document'}"

# Restricted DocType read must fail closed
bench --site "$STAGING_SITE" execute frappe_assistant_core.tests.smoke.restricted_doctype \
  --kwargs "{'user': 'assistant@example.com', 'doctype': 'User'}"
```

*(Replace smoke helpers with your site-specific validation scripts if not present.)*

---

## Phase 4 — Role allowlist setup

> **Requires explicit approval from Алхас before running on production.**

After migration, every configurable tool must use **Restrict to Listed Roles**:

```bash
bench --site "$PROD_SITE" console <<'PY'
import frappe
frappe.connect(site="$PROD_SITE")
for row in frappe.get_all("FAC Tool Configuration", pluck="name"):
    doc = frappe.get_doc("FAC Tool Configuration", row)
    if doc.role_access_mode != "Restrict to Listed Roles":
        doc.role_access_mode = "Restrict to Listed Roles"
        doc.save(ignore_permissions=True)
frappe.db.commit()
PY
```

Assign minimum roles per tool in Desk → **FAC Tool Configuration** (Assistant User / Assistant Admin as appropriate). Document the allowlist in change ticket `$SNAPSHOT_DIR/manifest/role_allowlist.txt`.

---

## Phase 5 — Production deploy

> **Requires explicit approval from Алхас before running on production.**

```bash
cd "$BENCH_DIR"
git -C "$FAC_APP_DIR" checkout "$FAC_REVISION"
bench --site "$PROD_SITE" migrate
bench --site "$PROD_SITE" clear-cache
sudo supervisorctl restart all   # adjust for your process manager
```

Post-deploy verification:

```bash
git -C "$FAC_APP_DIR" rev-parse HEAD | tee "$SNAPSHOT_DIR/manifest/fac_revision_after.txt"
bench --site "$PROD_SITE" execute frappe.utils.change_log.get_versions \
  | tee "$SNAPSHOT_DIR/manifest/installed_versions_after.json"
```

MCP endpoint negative test (expect 401 without token):

```bash
curl -sS -o /dev/null -w "%{http_code}\n" \
  -X POST "https://$PROD_SITE/api/method/frappe_assistant_core.api.fac_endpoint.mcp" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

---

## Phase 6 — Rollback

> **Requires explicit approval from Алхас before running on production.**

### 6a — Application revision rollback

```bash
cd "$BENCH_DIR"
PREV=$(cat "$SNAPSHOT_DIR/manifest/fac_revision_before.txt")
git -C "$FAC_APP_DIR" checkout "$PREV"
bench --site "$PROD_SITE" migrate
bench --site "$PROD_SITE" clear-cache
sudo supervisorctl restart all
```

### 6b — Database restore

```bash
bench --site "$PROD_SITE" restore \
  "$SNAPSHOT_DIR/db/<database-backup>.sql.gz" \
  --with-private-files "$SNAPSHOT_DIR/db/<private-files-backup>.tar"
```

### 6c — Restore verification

```bash
shasum -a 256 -c "$SNAPSHOT_DIR/manifest/backup_sha256.txt"
bench --site "$PROD_SITE" doctor
bench --site "$PROD_SITE" execute frappe.ping
```

Compare revision manifest:

```bash
diff -u \
  "$SNAPSHOT_DIR/manifest/fac_revision_before.txt" \
  <(git -C "$FAC_APP_DIR" rev-parse HEAD)
```

---

## External script requirements

`frappe_api.sh` is **not** shipped in the FAC repository. If your environment uses it for API smoke tests or endpoint switching:

1. Record verified **absolute path**, **git revision**, and **SHA-256 checksum** before rollout:

   ```bash
   FRAPPE_API_SH="/path/to/frappe_api.sh"
   shasum -a 256 "$FRAPPE_API_SH" | tee "$SNAPSHOT_DIR/manifest/frappe_api_sh.sha256"
   git -C "$(dirname "$FRAPPE_API_SH")" rev-parse HEAD \
     | tee "$SNAPSHOT_DIR/manifest/frappe_api_sh.revision"
   ```

2. Treat the script as **untrusted until separately audited**. Do **not** describe it as a safe fallback.

3. Any production invocation requires **explicit approval from Алхас**:

   ```bash
   # NOT SAFE BY DEFAULT — requires separate security audit
   "$FRAPPE_API_SH" --site "$PROD_SITE" --verify-mcp-endpoint
   ```

---

## Endpoint switch checklist

When moving LLM clients to the hardened MCP endpoint:

1. Confirm OAuth metadata advertises correct site URL and port.
2. Confirm Assistant Audit Log receives `tools/list` summary rows (not full inventory).
3. Confirm hard-deny tools absent from client tool picker.
4. Run one allowed read (`get_document` on `ToDo`) and one expected denial (restricted DocType).
5. Archive `$SNAPSHOT_DIR/manifest/sha256.txt` with the change ticket.

---

## Escalation

| Symptom | Action |
|---------|--------|
| Task 8 matrix failure | Stop rollout; capture test name + audit rows; do not patch production policy in Task 8 branch |
| Secret in Error Log | Stop traffic; rotate credential; invoke Phase 6 rollback |
| Registry cross-user leakage | Stop MCP workers; capture thread dumps; invoke Phase 6a immediately |

---

## Document status

| Section | Verified by Task 8 matrix | Requires bench run |
|---------|---------------------------|-------------------|
| Inventory / hard-deny / restricted DocTypes | Yes | Completed on `fac-test`, Frappe 15.112.1, 2026-08-09 |
| Actor × config × phase matrix | Yes | Completed on `fac-test`, Frappe 15.112.1, 2026-08-09 |
| Frappe 16 compatibility | No | Verification blocked: no Frappe 16 test site is available |
| Rollout commands | Operational guidance only | Manual staging drill |
