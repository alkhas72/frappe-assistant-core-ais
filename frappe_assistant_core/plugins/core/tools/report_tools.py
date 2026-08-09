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

import json
from typing import Any, Dict, List, Optional

import frappe
from frappe import _


def _log_safe(tag: str, exc: Optional[BaseException] = None) -> None:
    """FAC v2.2 safe logging: constant tag + ``type(exc).__name__`` only.

    Never log ``exc_info=True``, ``str(exc)``, traceback, query, filters,
    arguments, or result data. The technical log keeps one safe record per
    failure; helper re-raise paths do NOT log again to avoid duplicate
    writes.
    """
    try:
        if exc is None:
            frappe.logger("fac.report_tools").warning(tag)
        else:
            frappe.logger("fac.report_tools").warning(
                f"{tag}: {type(exc).__name__}"
            )
    except Exception:
        pass


def _parse_column_fieldname(column: Any) -> Optional[str]:
    """Normalise dict and string column descriptors to a fieldname.

    Frappe reports use two column shapes:
      * dict — ``{"fieldname": "password", "label": "Secret"}``
      * string — canonical ``label:fieldtype:options`` (e.g.
        ``"API Key:Data:120"``). When the label has no spaces it is also the
        fieldname; otherwise the fieldname is the underscored label.

    FAC v2.2: ``password:Data:120``, ``API Key:Data:120`` and
    ``api_key:Data:120`` must all classify as sensitive regardless of shape.
    """
    if isinstance(column, dict):
        return column.get("fieldname") or column.get("field_name")
    if isinstance(column, str):
        first = column.split(":", 1)[0].strip()
        if not first:
            return None
        # ``"API Key"`` → ``"api_key"`` to match SENSITIVE_FIELDS keys.
        return first.replace(" ", "_").lower()
    return None


class ReportTools:
    """
    Shared utility class for Frappe report operations.

    This class provides the core business logic for report-related operations
    that is used by the individual tool classes (generate_report.py, report_list.py,
    report_requirements.py). Each tool class extends BaseTool and delegates to
    methods in this utility class.

    Methods:
    - execute_report(): Execute reports (Query Reports, Script Reports, Custom Reports)
    - list_reports(): List available reports with filtering
    - get_report_columns(): Get report metadata and requirements
    - _validate_filters(): Validate filter values before execution
    """

    @staticmethod
    def _resolve_visible_report(report_name: str):
        """Resolve a Report document the caller is allowed to see.

        Returns ``(report_doc, None)`` on success, or ``(None, error_dict)``
        when the report is missing OR hidden from the caller. Both cases
        produce the SAME external answer so the response cannot be used to
        enumerate reports.

        FAC v2.2: switches to the canonical
        ``frappe.desk.query_report.get_report_doc()`` resolver inside a
        catch-all. ``get_report_doc`` raises ``frappe.PermissionError`` for
        both missing and role-hidden reports, which collapses those cases
        into a single failure mode; we wrap every exception path (including
        ``PermissionError``, ``DoesNotExistError`` and any internal Frappe
        error) into the same stable public answer so existence cannot be
        enumerated. Restricted ``ref_doctype`` is enforced AFTER resolution
        by ``execute_report`` / ``get_report_columns`` so it shares the same
        generic message.
        """
        if not report_name:
            return None, {"success": False, "error": "Report not available"}

        try:
            from frappe.desk.query_report import get_report_doc

            report_doc = get_report_doc(report_name)
        except Exception:
            # PermissionError, DoesNotExistError, ImportError on minimal
            # Frappe installs, or any internal failure: identical answer.
            return None, {"success": False, "error": "Report not available"}

        if report_doc is None:
            return None, {"success": False, "error": "Report not available"}

        # ``disabled`` reports are not runnable but their existence is not a
        # secret per se — we still collapse to the same message so a disabled
        # report and a hidden one are indistinguishable to the caller.
        try:
            if getattr(report_doc, "disabled", 0):
                return None, {"success": False, "error": "Report not available"}
        except Exception:
            return None, {"success": False, "error": "Report not available"}

        return report_doc, None

    @staticmethod
    def execute_report(
        report_name: str, filters: Dict[str, Any] = None, format: str = "json"
    ) -> Dict[str, Any]:
        """Execute a Frappe report.

        FAC security hardening (Task 7, rev. 2.1):

        * Missing and hidden reports produce the same external answer
          ``"Report not available"`` so the response cannot be used to
          enumerate reports.
        * ``ref_doctype`` restricted-target + native read permission are both
          enforced before any filter validation or execution. Restricted
          ``ref_doctype`` also yields the same generic refusal as a missing
          report — no "restricted DocType" leak.
        * Raw exception text, traceback and ``str(e)`` never leave this
          function. Public error category is stable; the technical log gets
          only the exception type and safe context.
        """
        from frappe_assistant_core.core.security_policy import SecurityPolicy

        report_doc, resolve_error = ReportTools._resolve_visible_report(report_name)
        if resolve_error is not None:
            return resolve_error

        try:
            # Restricted-target gate on the report's reference DocType. The
            # external message intentionally matches the "not available"
            # wording so the existence of a restricted-target report is not
            # disclosed.
            ref_doctype = getattr(report_doc, "ref_doctype", None)
            if ref_doctype and SecurityPolicy._is_restricted_target(ref_doctype):
                return {"success": False, "error": "Report not available"}

            # Native read permission on the report's reference DocType. Same
            # hidden-vs-missing indistinguishability: a missing ref_doctype
            # would already have been caught by Frappe at report save time;
            # here we cover the "exists but not readable" case.
            if ref_doctype and not frappe.has_permission(ref_doctype, "read"):
                return {"success": False, "error": "Report not available"}

            # Validate filters before execution
            validation_result = ReportTools._validate_filters(filters or {}, report_doc)
            if not validation_result.get("valid"):
                return {
                    "success": False,
                    "error": "Invalid filter values provided",
                    "validation_errors": validation_result.get("errors", []),
                    "suggestions": validation_result.get("suggestions", []),
                }

            # Snapshot user-provided filter keys before auto-defaults are injected
            user_filter_keys = set((filters or {}).keys())
            # Use a single dict so auto-defaults mutate it in-place
            effective_filters = dict(filters) if filters else {}

            # Execute report based on type
            if report_doc.report_type == "Query Report":
                result = ReportTools._execute_query_report(report_doc, effective_filters)
            elif report_doc.report_type == "Script Report":
                result = ReportTools._execute_script_report(report_doc, effective_filters)
            elif report_doc.report_type == "Report Builder":
                return {
                    "success": False,
                    "error": "Report Builder reports are not supported. Report Builder creates simple filtered views of DocTypes. For business intelligence and analytics, please use Script Reports, Query Reports, or Custom Reports instead.",
                }
            else:
                return {"success": False, "error": "Unsupported report type"}

            # Handle different result structures
            if isinstance(result, dict):
                # FAC v2.2: a prepared-report helper can return
                # ``{"success": False, ...}`` for owner/report mismatch or
                # generation failure. Preserve that failure verbatim — the
                # legacy branch below would have re-wrapped it as
                # ``success: True`` and silently swallowed the error.
                if result.get("success") is False:
                    # Strip the internal ``prepared_report_name`` so we do not
                    # echo the internal document id back to the caller.
                    result.pop("prepared_report_name", None)
                    return result
                # Extract the final filters that were actually used
                final_filters = result.pop("_final_filters", effective_filters)

                # Script/Query reports return {'result': [...], 'columns': [...]}
                raw_data = result.get("result", [])
                columns = result.get("columns", [])

                # Convert frappe._dict objects to plain Python dicts for pandas compatibility
                # This prevents "invalid __array_struct__" errors when using with pandas
                data = [dict(row) if isinstance(row, dict) else row for row in raw_data]

                # Determine which filters were auto-injected
                auto_added = {k: v for k, v in final_filters.items() if k not in user_filter_keys}

                debug_info = {
                    "success": True,
                    "report_name": report_name,
                    "report_type": report_doc.report_type,
                    "data": data,
                    "columns": columns,
                    "message": result.get("message"),
                    "filters_applied": final_filters,
                    "filters_auto_added": auto_added if auto_added else None,
                    "raw_result_keys": list(result.keys()) if result else [],
                    "data_count": len(data) if data else 0,
                    "result_type": type(result).__name__ if result else "None",
                }
            else:
                return {"success": False, "error": "Unexpected report result"}

            # FAC Task 7 (rev. 2): redact report output against the report's
            # ``ref_doctype``, NOT against ``Report``. Report rows typically do
            # not carry a ``doctype`` key, so the central sink in
            # ``_safe_execute`` (which infers the effective doctype from each
            # row's ``doctype`` field) cannot apply DocType-specific sensitive
            # fields. We pre-redact here using an explicit ref_doctype context;
            # the central sink still runs afterwards as defence in depth.
            debug_info = ReportTools._redact_report_output(debug_info, ref_doctype)

            # Add actionable guidance when report returns no data
            data = debug_info.get("data", [])
            if not data or len(data) == 0:
                debug_info["suggestion"] = (
                    f"Report returned 0 rows. This usually means the auto-defaulted filters "
                    f"(e.g. fiscal year dates, company) don't match any data. "
                    f"Call report_requirements('{report_name}') to see all mandatory filters "
                    f"with their valid options, then retry with explicit filter values."
                )
                if auto_added:
                    debug_info["suggestion"] += (
                        f" Auto-added filters were: {auto_added}. "
                        f"Check that these values match data in your system."
                    )

            return debug_info

        except Exception as exc:
            # FAC v2.2: never leak raw exception text, traceback, query or
            # filters. Safe log + stable public category.
            _log_safe("execute_report failed", exc)
            return {"success": False, "error": "Report execution failed"}

    @staticmethod
    def _redact_report_output(debug_info: Dict[str, Any], ref_doctype: Optional[str]) -> Dict[str, Any]:
        """Apply ref_doctype-aware redaction to report rows and columns.

        FAC v2.1 — three layers, all fail-closed:

        1. **Rows**: ``SecurityPolicy.redact_output`` with an explicit
           ``ref_doctype`` context. Dict rows are redacted in place; list and
           tuple rows are positional — we map column index → fieldname and
           redact or drop sensitive positions so columns and rows stay
           consistent. A row's ``doctype`` key (if any) is ignored — it cannot
           override the report's ``ref_doctype`` (proven by the malicious-row
           test).
        2. **Columns**: any column whose ``fieldname`` is itself a sensitive
           name (e.g. ``password``, ``api_key``) is dropped from the column
           list and its value is removed from every row (dict, list, tuple).
        3. **Filters**: universal redaction in case a sensitive value was
           pasted into a filter.
        """
        from frappe_assistant_core.core.security_policy import (
            SecurityPolicy,
            ToolContext,
        )

        if not isinstance(debug_info, dict):
            return debug_info

        # Without a ref_doctype we cannot prove what counts as sensitive for
        # these rows; the universal set still applies via the empty target.
        ctx = ToolContext(
            operation="report_read",
            target_doctype=ref_doctype,
            required_permissions=frozenset({"read"}),
        )

        # Step 1 — column pre-scan. Identifies sensitive column fieldnames and
        # builds an index→fieldname map for positional rows. ``debug_info`` is
        # mutated to drop sensitive columns immediately.
        columns = debug_info.get("columns")
        sensitive_column_fields: set = set()
        positional_fieldname_by_index: Dict[int, str] = {}
        if isinstance(columns, list):
            kept_columns = []
            for index, col in enumerate(columns):
                # FAC v2.2: use the canonical parser so both dict and string
                # column descriptors (``"password:Data:120"``,
                # ``"API Key:Data:120"``, ...) normalise to a fieldname.
                fieldname = _parse_column_fieldname(col)
                if isinstance(fieldname, str):
                    positional_fieldname_by_index[index] = fieldname
                    if SecurityPolicy._contains_restricted_fields(
                        ref_doctype, frozenset({fieldname})
                    ):
                        sensitive_column_fields.add(fieldname)
                        continue
                kept_columns.append(col)
            debug_info["columns"] = kept_columns

        def _strip_doctype_recursively(value: Any) -> Any:
            """Remove ``doctype`` keys at every depth so a malicious nested
            payload (``row.items[0].doctype="Customer"``) cannot downgrade
            ref_doctype-driven redaction. The authoritative context remains
            ``ref_doctype``."""
            if isinstance(value, dict):
                return {
                    k: _strip_doctype_recursively(v)
                    for k, v in value.items()
                    if k != "doctype"
                }
            if isinstance(value, list):
                return [_strip_doctype_recursively(v) for v in value]
            if isinstance(value, tuple):
                return tuple(_strip_doctype_recursively(v) for v in value)
            return value

        def _redact_dict_row(row: Dict[str, Any]) -> Dict[str, Any]:
            # Enforce ref_doctype by stripping any caller-supplied ``doctype``
            # before central redaction runs. Otherwise a malicious row could
            # claim ``doctype="Customer"`` to bypass User/File/Role-specific
            # sensitive fields (FAC v2.1, malicious-row test). v2.2 also
            # strips nested ``doctype`` keys so a row's child payload cannot
            # downgrade either.
            row = _strip_doctype_recursively(row)
            row = SecurityPolicy.redact_output(ctx, row)
            if sensitive_column_fields:
                row = {k: v for k, v in row.items() if k not in sensitive_column_fields}
            return row

        def _redact_positional_row(row):
            row_type = type(row)
            values = list(row)
            redacted: list = []
            for index, value in enumerate(values):
                fieldname = positional_fieldname_by_index.get(index)
                if fieldname and fieldname in sensitive_column_fields:
                    # Sensitive position: drop the value entirely. Columns and
                    # rows stay consistent because the column was dropped too.
                    continue
                if fieldname and SecurityPolicy._contains_restricted_fields(
                    ref_doctype, frozenset({fieldname})
                ):
                    redacted.append("***REDACTED***")
                    continue
                redacted.append(SecurityPolicy.redact_output(ctx, value))
            # Preserve list vs tuple shape. Other positional shapes (set, ...)
            # are not produced by Frappe reports — fall back to list.
            if row_type is tuple:
                return tuple(redacted)
            return redacted

        data = debug_info.get("data")
        if isinstance(data, list):
            new_rows: list = []
            for row in data:
                if isinstance(row, dict):
                    new_rows.append(_redact_dict_row(row))
                elif isinstance(row, (list, tuple)):
                    new_rows.append(_redact_positional_row(row))
                else:
                    # Scalar row — leave central sink to handle it.
                    new_rows.append(SecurityPolicy.redact_output(ctx, row))
            debug_info["data"] = new_rows
        elif isinstance(data, dict):
            debug_info["data"] = _redact_dict_row(data)
        elif isinstance(data, (list, tuple)) and not isinstance(data, list):
            # ``data`` itself is a tuple of rows — normalise to list.
            debug_info["data"] = [_redact_positional_row(r) if isinstance(r, (list, tuple))
                                  else _redact_dict_row(r) if isinstance(r, dict)
                                  else r
                                  for r in data]

        # Filters may carry a sensitive value (e.g. a token mistakenly pasted
        # into a filter). Apply universal redaction.
        if isinstance(debug_info.get("filters_applied"), dict):
            debug_info["filters_applied"] = SecurityPolicy.redact_output(
                ctx, debug_info["filters_applied"]
            )

        return debug_info

    @staticmethod
    def list_reports(module: str = None, report_type: str = None) -> Dict[str, Any]:
        """Get list of available reports.

        FAC security hardening Task 7 (2026-08-09): discovery now uses
        ``frappe.get_list(ignore_permissions=False)`` instead of
        ``frappe.get_all`` (the latter bypasses Frappe's DocType and row-level
        permission filters and would surface reports the user cannot read).
        Reports whose ``ref_doctype`` is a restricted DocType are also
        dropped, because their result set would disclose restricted data even
        though ``Report`` itself is not in ``RESTRICTED_DOCTYPES``.
        """
        from frappe_assistant_core.core.security_policy import SecurityPolicy

        try:
            filters = {}
            if module:
                filters["module"] = module
            if report_type:
                filters["report_type"] = report_type

            # Permission-aware lookup. ``frappe.get_all`` would silently include
            # reports the user cannot read and was the legacy discovery path.
            reports = frappe.get_list(
                "Report",
                filters=filters,
                fields=[
                    "name",
                    "report_name",
                    "report_type",
                    "module",
                    "is_standard",
                    "disabled",
                    "ref_doctype",
                ],
                order_by="report_name",
                ignore_permissions=False,
            )

            accessible_reports = []
            for report in reports:
                # ``frappe.get_list`` returns dict-like rows; use ``.get`` so
                # both frappe._dict and plain dict work without AttributeError.
                report_name = report.get("name") if hasattr(report, "get") else None
                if not report_name:
                    continue
                # FAC v2.2: disabled reports are never discoverable.
                if report.get("disabled"):
                    continue
                # Row-level permission on the Report document itself.
                if not frappe.has_permission("Report", "read", report_name):
                    continue
                # Restricted-target gate on the report's reference DocType.
                ref_doctype = report.get("ref_doctype") if hasattr(report, "get") else None
                if ref_doctype and SecurityPolicy._is_restricted_target(ref_doctype):
                    continue
                # FAC v2.2: native ``report`` ptype on the reference DocType.
                # Frappe roles carry a separate ``report`` permission bit; an
                # actor without it has no business seeing the report surface.
                if ref_doctype and not frappe.has_permission(ref_doctype, "report"):
                    continue
                # FAC v2.2: ``report.is_permitted()`` is Frappe's canonical
                # role-line check (``Has Role`` match against the report's
                # ``roles`` table). Skipping it was the gap that let
                # role-hidden reports appear in the listing.
                try:
                    report_doc = frappe.get_doc("Report", report_name)
                    if hasattr(report_doc, "is_permitted") and not report_doc.is_permitted():
                        continue
                except Exception:
                    # If we cannot load/inspect the report, fail closed.
                    continue
                accessible_reports.append(report)

            return {
                "success": True,
                "reports": accessible_reports,
                "count": len(accessible_reports),
                "filters_applied": {"module": module, "report_type": report_type},
            }

        except Exception:
            # FAC v2.1: stable public category; technical log records only the
            # exception type and a safe context tag (no arguments, no rows).
            _log_safe("list_reports failed")
            return {"success": False, "error": "Report listing failed"}

    @staticmethod
    def get_report_columns(report_name: str) -> Dict[str, Any]:
        """Get column information for a report.

        FAC v2.1: missing and hidden reports produce the same external answer
        via ``_resolve_visible_report``; ``ref_doctype`` restricted/hidden
        refusal uses the same generic wording. Raw exception text never leaks.
        """
        from frappe_assistant_core.core.security_policy import SecurityPolicy

        report_doc, resolve_error = ReportTools._resolve_visible_report(report_name)
        if resolve_error is not None:
            return resolve_error

        try:
            ref_doctype = getattr(report_doc, "ref_doctype", None)
            if ref_doctype and SecurityPolicy._is_restricted_target(ref_doctype):
                return {"success": False, "error": "Report not available"}
            if ref_doctype and not frappe.has_permission(ref_doctype, "read"):
                return {"success": False, "error": "Report not available"}

            columns = []

            if report_doc.report_type == "Query Report":
                # Try to get columns from query execution with minimal filters
                try:
                    # Try with empty filters first
                    result = ReportTools._execute_query_report(report_doc, {}, get_columns_only=True)
                    columns = result.get("columns", [])
                except Exception as e:
                    # If that fails, try with default company
                    try:
                        default_company = frappe.db.get_single_value("Global Defaults", "default_company")
                        if default_company:
                            result = ReportTools._execute_query_report(
                                report_doc, {"company": default_company}, get_columns_only=True
                            )
                            columns = result.get("columns", [])
                    except Exception:
                        # FAC v2.1: log type + safe context only (no str(e)).
                        _log_safe("query-report column extraction failed")
                        # Return basic info if column extraction fails
                        columns = [
                            {
                                "label": "Data not available - requires filters",
                                "fieldname": "info",
                                "fieldtype": "Data",
                            }
                        ]

            # Add helpful filter guidance based on report name patterns
            filter_guidance = []
            if "sales_analytics" in report_name.lower():
                filter_guidance.append("Required: 'doc_type' (Sales Invoice, Sales Order, Quotation, etc.)")
                filter_guidance.append("Required: 'tree_type' (Customer, Item, Territory, etc.)")
                filter_guidance.append("Optional: 'from_date' and 'to_date' (defaults to last 12 months)")
                filter_guidance.append("Optional: 'company' (uses default company if not specified)")
            elif report_doc.report_type == "Script Report":
                filter_guidance.append(
                    "Script Reports often have mandatory filters - use report_requirements tool to discover exact filter definitions"
                )

            result = {
                "success": True,
                "report_name": report_name,
                "report_type": report_doc.report_type,
                "columns": columns,
            }

            if filter_guidance:
                result["filter_guidance"] = filter_guidance

            return result

        except Exception:
            # FAC v2.1: never echo raw exception text. The internal log gets
            # the exception type only; the caller sees a stable category.
            _log_safe("get_report_columns failed")
            return {"success": False, "error": "Report not available"}

    @staticmethod
    def _handle_prepared_report_execution(report_doc, filters):
        """
        Smart handler for prepared reports with polling support for AI/MCP tools:
        1. Check for existing completed prepared report
        2. Try quick execution if appropriate
        3. Queue background job and WAIT for completion (polling)
        4. Return data when ready or timeout gracefully
        """
        import time

        from frappe.core.doctype.prepared_report.prepared_report import (
            get_completed_prepared_report,
            make_prepared_report,
        )
        from frappe.desk.query_report import get_prepared_report_result, run

        try:
            # Check if a completed prepared report exists with these filters
            prepared_report_name = get_completed_prepared_report(
                filters=filters, user=frappe.session.user, report_name=report_doc.name
            )

            if prepared_report_name:
                # Found existing prepared report - retrieve cached data
                result = get_prepared_report_result(report_doc, filters, dn=prepared_report_name)

                # FAC v2.2: bind the cached result to the current caller AND
                # the resolved report. ``get_completed_prepared_report`` is
                # user-scoped in Frappe, but a tampered or stale row could
                # surface another user's results; verify owner + report_name
                # on the actual Prepared Report document before returning.
                try:
                    prepared_doc_check = frappe.get_doc("Prepared Report", prepared_report_name)
                except Exception:
                    prepared_doc_check = None
                if (
                    prepared_doc_check is None
                    or getattr(prepared_doc_check, "owner", None) != frappe.session.user
                    or getattr(prepared_doc_check, "report_name", None) != report_doc.name
                ):
                    # Owner/report mismatch: do NOT return another user's
                    # prepared result. Stable public failure.
                    return {
                        "success": False,
                        "result": [],
                        "columns": [],
                        "error": "Prepared report not available",
                        "status": "error",
                    }

                if result and result.get("result"):
                    # Successfully retrieved cached data
                    prepared_doc = result.get("doc")
                    return {
                        "result": result.get("result", []),
                        "columns": result.get("columns", []),
                        "message": result.get("message"),
                        "prepared_report": True,
                        "source": "cached",
                        "prepared_report_name": prepared_report_name,
                        "generated_at": str(prepared_doc.modified) if prepared_doc else None,
                        "status": "completed",
                    }

            # Get report timeout configuration
            report_timeout = frappe.get_value("Report", report_doc.name, "timeout") or 120

            # Try quick direct execution for fast reports
            if report_timeout < 60:
                try:
                    direct_result = run(
                        report_name=report_doc.name,
                        filters=filters,
                        user=frappe.session.user,
                        ignore_prepared_report=True,  # Force direct execution
                    )

                    if direct_result and direct_result.get("result"):
                        return {
                            "result": direct_result.get("result", []),
                            "columns": direct_result.get("columns", []),
                            "message": direct_result.get("message"),
                            "prepared_report": False,
                            "source": "direct_execution",
                            "status": "completed",
                        }
                except Exception as e:
                    # Quick execution failed, fall through to background job.
                    # FAC v2.1: safe logging only — exception type + safe
                    # context tag, never the raw message.
                    _log_safe("quick prepared-report execution failed")

            # ===== Queue and WAIT for completion with polling =====

            # Queue the background job
            prepared_report = make_prepared_report(report_name=report_doc.name, filters=filters)
            prepared_report_name = prepared_report.get("name")

            # Poll for completion with exponential backoff
            max_wait_time = min(report_timeout, 300)  # Cap at 5 minutes for MCP tools
            poll_interval = 2.0  # Start with 2 seconds
            max_poll_interval = 15.0  # Max 15 seconds between polls
            elapsed_time = 0

            frappe.db.commit()  # Ensure job is committed to DB

            while elapsed_time < max_wait_time:
                time.sleep(poll_interval)
                elapsed_time += poll_interval

                # Check prepared report status - get fresh data
                frappe.db.rollback()
                prepared_doc = frappe.get_doc("Prepared Report", prepared_report_name)

                if prepared_doc.status == "Completed":
                    # Report is ready! Retrieve and return data
                    result = get_prepared_report_result(report_doc, filters, dn=prepared_report_name)

                    # FAC v2.2: re-bind owner + report_name before returning
                    # the background-job result too.
                    if (
                        getattr(prepared_doc, "owner", None) != frappe.session.user
                        or getattr(prepared_doc, "report_name", None) != report_doc.name
                    ):
                        return {
                            "success": False,
                            "result": [],
                            "columns": [],
                            "error": "Prepared report not available",
                            "status": "error",
                        }

                    if result and result.get("result"):
                        return {
                            "result": result.get("result", []),
                            "columns": result.get("columns", []),
                            "message": result.get("message"),
                            "prepared_report": True,
                            "source": "background_job_completed",
                            "prepared_report_name": prepared_report_name,
                            "wait_time_seconds": int(elapsed_time),
                            "status": "completed",
                        }

                elif prepared_doc.status == "Error":
                    # Report generation failed. FAC v2.2: NEVER echo
                    # ``prepared_doc.error_message`` — Frappe stores the full
                    # traceback there, which can include query text, document
                    # values, or stack frames with credentials. Return a
                    # stable category.
                    return {
                        "success": False,
                        "result": [],
                        "columns": [],
                        "error": "Prepared report generation failed",
                        "status": "error",
                    }

                # Exponential backoff - increase poll interval
                poll_interval = min(poll_interval * 1.5, max_poll_interval)

            # Timeout reached - report is still processing
            return {
                "result": [],
                "columns": [],
                "success": True,
                "status": "timeout",
                "prepared_report": True,
                "prepared_report_name": prepared_report_name,
                "message": f"Report generation is taking longer than expected ({int(max_wait_time)}s timeout reached). The report is still being generated in the background. You can retry with the same filters in a few minutes to retrieve the cached result.",
                "retry_guidance": f"Use report_name='{report_doc.name}' with the same filters to retrieve results.",
                "wait_time_seconds": int(elapsed_time),
            }

        except Exception:
            # FAC v2.1: safe logging only. Re-raise so the outer
            # ``execute_report`` handler can convert to a stable public answer.
            _log_safe("prepared-report handling failed")
            raise

    @staticmethod
    def _execute_query_report(report_doc, filters, get_columns_only=False):
        """Execute a Query Report"""
        from frappe.desk.query_report import run

        # Check if this is a prepared report
        if getattr(report_doc, "prepared_report", False) and not getattr(
            report_doc, "disable_prepared_report", False
        ):
            return ReportTools._handle_prepared_report_execution(report_doc, filters)

        try:
            # Add default filters for common requirements and clean None values
            if not filters:
                filters = {}

            # Clean any None values from filters that could cause startswith errors
            cleaned_filters = {}
            for key, value in filters.items():
                if value is not None:
                    cleaned_filters[key] = value
            filters = cleaned_filters

            # Add default date filters if missing - use current fiscal year dates
            if not filters.get("from_date") and not filters.get("to_date"):
                try:
                    # Get current fiscal year
                    fiscal_year = frappe.db.get_value(
                        "Fiscal Year",
                        {"disabled": 0},
                        ["year_start_date", "year_end_date"],
                        order_by="year_start_date desc",
                    )

                    if fiscal_year:
                        filters["from_date"] = str(fiscal_year[0])  # Fiscal year start
                        filters["to_date"] = str(fiscal_year[1])  # Fiscal year end
                    else:
                        # Fallback to last 12 months if no fiscal year found
                        from frappe.utils import add_months, getdate

                        today = getdate()
                        filters["to_date"] = str(today)
                        filters["from_date"] = str(add_months(today, -12))
                except Exception:
                    # Fallback to last 12 months on any error
                    from frappe.utils import add_months, getdate

                    today = getdate()
                    filters["to_date"] = str(today)
                    filters["from_date"] = str(add_months(today, -12))
            elif not filters.get("to_date") and filters.get("from_date"):
                from frappe.utils import getdate

                filters["to_date"] = str(getdate())
            elif not filters.get("from_date") and filters.get("to_date"):
                from frappe.utils import add_months, getdate

                filters["from_date"] = str(add_months(getdate(filters["to_date"]), -12))

            # Add company filter if required and not provided
            if "company" not in filters and frappe.db.exists("Company"):
                default_company = frappe.db.get_single_value("Global Defaults", "default_company")
                if default_company:
                    filters["company"] = str(default_company)

            # Add report-specific default parameters
            report_name_lower = report_doc.name.lower()

            # Sales Analytics defaults
            if "sales analytics" in report_name_lower and "value_quantity" not in filters:
                filters["value_quantity"] = "Value"

            # Quotation Trends defaults
            if "quotation trends" in report_name_lower and "based_on" not in filters:
                filters["based_on"] = "Item"

            # Final cleanup - ensure all filter values are strings or proper types
            final_filters = {}
            for key, value in filters.items():
                if value is not None:
                    # Convert dates to strings if they're not already
                    if hasattr(value, "strftime"):  # datetime object
                        final_filters[key] = value.strftime("%Y-%m-%d")
                    elif isinstance(value, (str, int, float, bool)):
                        final_filters[key] = value
                    else:
                        final_filters[key] = str(value)
            filters = final_filters

            result = run(
                report_name=report_doc.name,
                filters=filters,
                user=frappe.session.user,
                is_tree=getattr(report_doc, "is_tree", 0),
                parent_field=getattr(report_doc, "parent_field", None),
            )
            if isinstance(result, dict):
                result["_final_filters"] = filters
            return result
        except Exception as e:
            # FAC v2.1: detect the "company required" condition by exception
            # type/message locally (no public leak), then return a stable
            # message. ``str(e)`` is used only for branching here; it never
            # reaches the public response.
            lowered = ""
            try:
                lowered = str(e).lower()
            except Exception:
                lowered = ""
            if "company" in lowered and "required" in lowered:
                return {
                    "result": [],
                    "columns": [],
                    "message": "Report requires additional mandatory filters",
                    "error": "missing_required_filters",
                }
            raise

    @staticmethod
    def _execute_script_report(report_doc, filters):
        """Execute a Script Report"""
        from frappe.desk.query_report import run

        # Check if this is a prepared report
        if getattr(report_doc, "prepared_report", False) and not getattr(
            report_doc, "disable_prepared_report", False
        ):
            return ReportTools._handle_prepared_report_execution(report_doc, filters)

        try:
            # Ensure filters is a proper dict and clean None values
            if not isinstance(filters, dict):
                filters = {}

            # Clean any None values from filters that could cause startswith errors
            cleaned_filters = {}
            for key, value in filters.items():
                if value is not None:
                    cleaned_filters[key] = value
            filters = cleaned_filters

            # Add default date filters if missing - use current fiscal year dates
            if not filters.get("from_date") and not filters.get("to_date"):
                try:
                    # Get current fiscal year
                    fiscal_year = frappe.db.get_value(
                        "Fiscal Year",
                        {"disabled": 0},
                        ["year_start_date", "year_end_date"],
                        order_by="year_start_date desc",
                    )

                    if fiscal_year:
                        filters["from_date"] = str(fiscal_year[0])  # Fiscal year start
                        filters["to_date"] = str(fiscal_year[1])  # Fiscal year end
                    else:
                        # Fallback to last 12 months if no fiscal year found
                        from frappe.utils import add_months, getdate

                        today = getdate()
                        filters["to_date"] = str(today)
                        filters["from_date"] = str(add_months(today, -12))
                except Exception:
                    # Fallback to last 12 months on any error
                    from frappe.utils import add_months, getdate

                    today = getdate()
                    filters["to_date"] = str(today)
                    filters["from_date"] = str(add_months(today, -12))
            elif not filters.get("to_date") and filters.get("from_date"):
                from frappe.utils import getdate

                filters["to_date"] = str(getdate())
            elif not filters.get("from_date") and filters.get("to_date"):
                from frappe.utils import add_months, getdate

                filters["from_date"] = str(add_months(getdate(filters["to_date"]), -12))

            # For Accounts Receivable Summary, ensure company is set
            if report_doc.name == "Accounts Receivable Summary" and not filters.get("company"):
                default_company = frappe.db.get_single_value("Global Defaults", "default_company")
                if default_company:
                    filters["company"] = str(default_company)

            # Add default company for reports that need it
            if not filters.get("company"):
                default_company = frappe.db.get_single_value("Global Defaults", "default_company")
                if default_company:
                    filters["company"] = str(default_company)

            # Add report-specific default parameters
            report_name_lower = report_doc.name.lower()

            # Sales Analytics defaults
            if "sales analytics" in report_name_lower and "value_quantity" not in filters:
                filters["value_quantity"] = "Value"

            # Quotation Trends defaults
            if "quotation trends" in report_name_lower and "based_on" not in filters:
                filters["based_on"] = "Item"

            # Apply default values from JavaScript filter definitions
            filters = ReportTools._apply_filter_defaults(report_doc, filters)

            # Final cleanup - ensure all filter values are strings or proper types
            final_filters = {}
            for key, value in filters.items():
                if value is not None:
                    # Convert dates to strings if they're not already
                    if hasattr(value, "strftime"):  # datetime object
                        final_filters[key] = value.strftime("%Y-%m-%d")
                    elif isinstance(value, (str, int, float, bool)):
                        final_filters[key] = value
                    else:
                        final_filters[key] = str(value)
            filters = final_filters

            # Check if this is a prepared report (after all filter processing)
            if getattr(report_doc, "prepared_report", False) and not getattr(
                report_doc, "disable_prepared_report", False
            ):
                return ReportTools._handle_prepared_report_execution(report_doc, filters)

            result = run(report_name=report_doc.name, filters=filters, user=frappe.session.user)
            if isinstance(result, dict):
                result["_final_filters"] = filters
            return result

        except Exception as e:
            # FAC v2.1: never leak raw exception text in the public response or
            # in the technical log. We use ``str(e)`` ONLY for local branching
            # (matching known mandatory-filter messages) and emit a stable
            # public message; the technical log records the type + safe tag.
            _log_safe("script-report execution failed")

            raw = ""
            try:
                raw = str(e)
            except Exception:
                raw = ""
            lowered = raw.lower()

            # Provide helpful, STABLE messages for common issues — without
            # echoing the raw exception text.
            if "'NoneType' object has no attribute 'startswith'" in raw:
                error_message = (
                    f"Missing required filters for {report_doc.name}. This "
                    f"report requires mandatory filters that were not "
                    f"provided. Use the report_requirements tool to discover "
                    f"required filters."
                )
                if "sales_analytics" in report_doc.name.lower():
                    error_message += (
                        " For Sales Analytics, you need: 'doc_type' (e.g., "
                        "'Sales Invoice') and 'tree_type' (e.g., 'Customer')."
                    )
            elif "required" in lowered and any(
                word in lowered for word in ["filter", "field", "parameter"]
            ):
                error_message = (
                    f"Missing required filters for {report_doc.name}. Use "
                    f"the report_requirements tool to discover all required "
                    f"filters."
                )
            else:
                error_message = "Script report execution failed"

            return {
                "result": [],
                "columns": [],
                "message": error_message,
                "error": error_message,
                "suggestion": f"Use report_requirements tool with report_name='{report_doc.name}' to discover required filters, then retry with proper filters.",
            }

    @staticmethod
    def _validate_filters(filters: Dict[str, Any], report_doc) -> Dict[str, Any]:
        """Validate filter values against database to catch invalid references early.

        FAC security hardening Task 7 (rev. 2): the legacy implementation
        called ``frappe.db.exists(doctype, value)`` and ``frappe.get_all`` for
        linked business records (Company, Customer, Supplier, Item, ...).
        ``db.exists`` reveals whether a record exists even when the user
        cannot read it, and ``get_all`` bypasses row-level permissions. Both
        are now replaced with a single permission-aware lookup:

          * A hidden record (exists but the user has no ``read`` on it) and a
            truly missing record MUST produce the same external message —
            otherwise the difference itself discloses existence.
          * Suggestions use ``frappe.get_list(ignore_permissions=False)`` so
            only readable records appear, and only when at least one readable
            record matches.
          * Restricted DocTypes are not validated at all — they are rejected
            earlier by ``execute_report``.
        """
        from frappe_assistant_core.core.security_policy import SecurityPolicy

        errors = []
        suggestions = []

        # Common Link field filters to validate. Restricted DocTypes are
        # excluded — they cannot be reached through the report surface after
        # ``execute_report``'s gate, but defensively skip them here too.
        link_validations = {
            "company": "Company",
            "customer": "Customer",
            "supplier": "Supplier",
            "item": "Item",
            "project": "Project",
            "cost_center": "Cost Center",
            "warehouse": "Warehouse",
        }

        for filter_key, doctype in link_validations.items():
            if filter_key not in filters or not filters[filter_key]:
                continue
            filter_value = filters[filter_key]

            # Skip validation for list values (used in group reports)
            if isinstance(filter_value, list):
                continue

            # Defensive restricted-target skip — these are never reachable
            # through the report surface but we never want to validate or
            # disclose them.
            if SecurityPolicy._is_restricted_target(doctype):
                continue

            # Permission-aware existence check. ``frappe.has_permission(...,
            # doc=...)`` returns False both for missing records and for
            # records the user cannot read — that is exactly the
            # hidden-vs-missing indistinguishability we need.
            try:
                visible = frappe.has_permission(doctype, "read", doc=filter_value)
            except Exception:
                visible = False

            if visible:
                continue

            # Same external message for hidden and missing records.
            errors.append(f"Invalid {filter_key}: '{filter_value}'")

            # Suggestions only from records the user can actually read.
            try:
                similar = frappe.get_list(
                    doctype,
                    filters={"name": ["like", f"%{filter_value}%"]},
                    fields=["name"],
                    limit=3,
                    ignore_permissions=False,
                )
                if similar:
                    suggestions.append(
                        f"Did you mean one of these {doctype} names? "
                        f"{', '.join([s.name for s in similar])}"
                    )
                else:
                    valid_options = frappe.get_list(
                        doctype,
                        fields=["name"],
                        limit=5,
                        ignore_permissions=False,
                    )
                    if valid_options:
                        suggestions.append(
                            f"Valid {doctype} names include: "
                            f"{', '.join([v.name for v in valid_options])}"
                        )
            except Exception:
                # Never surface internal error text via suggestions.
                pass

        # Validate Select field options
        select_validations = {
            "tree_type": [
                "Customer",
                "Supplier",
                "Item",
                "Customer Group",
                "Supplier Group",
                "Item Group",
                "Territory",
                "Order Type",
                "Project",
            ],
            "doc_type": [
                "Sales Invoice",
                "Sales Order",
                "Quotation",
                "Purchase Invoice",
                "Purchase Order",
                "Purchase Receipt",
                "Delivery Note",
            ],
            "value_quantity": ["Value", "Quantity"],
            "range": ["Weekly", "Monthly", "Quarterly", "Half-Yearly", "Yearly"],
        }

        for filter_key, valid_options in select_validations.items():
            if filter_key in filters and filters[filter_key]:
                filter_value = filters[filter_key]
                if filter_value not in valid_options:
                    errors.append(
                        f"Invalid {filter_key}: '{filter_value}'. Must be one of: {', '.join(valid_options)}"
                    )

        # Validate date formats
        date_fields = ["from_date", "to_date", "posting_date", "transaction_date"]
        for date_field in date_fields:
            if date_field in filters and filters[date_field]:
                try:
                    from frappe.utils import getdate

                    getdate(filters[date_field])
                except Exception:
                    errors.append(
                        f"Invalid {date_field}: '{filters[date_field]}'. Expected format: YYYY-MM-DD"
                    )

        return {"valid": len(errors) == 0, "errors": errors, "suggestions": suggestions}

    @staticmethod
    def _apply_filter_defaults(report_doc, filters):
        """Apply default filter values from JavaScript filter definitions for Script Reports"""
        import os
        import re

        # Only apply for Script Reports
        if report_doc.report_type != "Script Report":
            return filters

        try:
            # Get the report's JavaScript file path
            module_name = report_doc.module
            report_name = report_doc.name
            report_folder = report_name.lower().replace(" ", "_").replace("-", "_")
            module_folder = module_name.lower().replace(" ", "_")

            # Search for the JS file in installed apps
            for app in frappe.get_installed_apps():
                app_path = frappe.get_app_path(app)
                js_path = os.path.join(
                    app_path, module_folder, "report", report_folder, f"{report_folder}.js"
                )

                if os.path.exists(js_path):
                    # nosemgrep: frappe-security-file-traversal — path built from frappe.get_app_path + report metadata, not user input
                    with open(js_path, encoding="utf-8") as f:
                        js_content = f.read()

                    # Extract filter definitions
                    filters_start = js_content.find("filters:")
                    if filters_start == -1:
                        continue

                    # Find the filter array using bracket counting
                    bracket_start = js_content.find("[", filters_start)
                    if bracket_start == -1:
                        continue

                    bracket_count = 0
                    bracket_end = -1
                    for i in range(bracket_start, len(js_content)):
                        if js_content[i] == "[":
                            bracket_count += 1
                        elif js_content[i] == "]":
                            bracket_count -= 1
                            if bracket_count == 0:
                                bracket_end = i
                                break

                    if bracket_end == -1:
                        continue

                    filters_text = js_content[bracket_start + 1 : bracket_end]

                    # Parse filter objects
                    filter_objects = []
                    brace_count = 0
                    current_obj_start = None

                    for i, char in enumerate(filters_text):
                        if char == "{":
                            if brace_count == 0:
                                current_obj_start = i
                            brace_count += 1
                        elif char == "}":
                            brace_count -= 1
                            if brace_count == 0 and current_obj_start is not None:
                                obj_content = filters_text[current_obj_start + 1 : i]
                                filter_objects.append(obj_content)
                                current_obj_start = None

                    # Extract default values from each filter
                    for filter_obj in filter_objects:
                        # Extract fieldname
                        fieldname_match = re.search(r'fieldname:\s*["\']([^"\']+)["\']', filter_obj)
                        if not fieldname_match:
                            continue
                        fieldname = fieldname_match.group(1)

                        # Skip if filter already has a value
                        if fieldname in filters and filters[fieldname] is not None:
                            continue

                        # Extract default value
                        default_match = re.search(r'default:\s*["\']([^"\']+)["\']', filter_obj)
                        if default_match:
                            default_value = default_match.group(1)
                            filters[fieldname] = default_value

                    break  # Found and processed the JS file

        except Exception:
            # FAC v2.1: safe logging only — never echo raw exception text.
            # Filter-default application is best-effort; falling through to
            # the caller-provided filters is the intended fallback.
            _log_safe("filter-default application failed")

        return filters
