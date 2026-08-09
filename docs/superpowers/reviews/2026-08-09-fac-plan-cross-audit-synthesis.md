---
title: "FAC security hardening plan: cross-audit synthesis"
date: 2026-08-09
status: approved
approved_by: Alkhas Tkhagushev
approved_date: 2026-08-09
approved_revision: 642191d
auditors:
  - Claude/Fable + Opus 4.8
  - Antigravity
---

# Сведение внешнего кросс-аудита плана FAC

## Итог

Оба независимых аудита считают архитектуру исполнимой после обязательных изменений. Исправленная спецификация и план остаются `review-required`: реализация не начинается до явного решения Алхаса. Авторство первого заключения фиксируется совместно как Claude/Fable + Opus 4.8, поскольку граница их вклада в исходном ответе неразличима.

## Матрица решений

| Источник / finding | Решение Codex | Изменение спецификации или плана |
|---|---|---|
| Claude F1: возможный 25-й tool | Принято с коррекцией: сам аудит отозвал runtime-классификацию `migrate_visualization` | Источник истины — runtime discovery; exact snapshot из 24 имён сравнивается с discovery и падает при любом расхождении |
| Claude F2: 60-секундный cache на execute | Принято | `phase=execute` читает config без cache; `.save()` и `frappe.db.set_value` TOCTOU tests |
| Claude F3: registry prechecks обходят единый audit | Принято | Удаляются `_is_tool_enabled`/`_check_role_access` prechecks до `_safe_execute`; известный tool имеет один execution policy gate |
| Claude F4: MCP traceback/inventory leak | Принято | Stable public errors, no traceback/`str(exception)`/available names, ровно одна audit row |
| Claude F5/F10: неполная output policy и незафиксированный restricted set | Принято | Central recursive output redaction для всех paths; exact immutable DocType baseline закреплён в design spec и ratifies решением Алхаса |
| Claude F6–F9: audit context, raw logs, recursive sanitizer, stale aliases | Принято | Audit target только из `PolicyDecision.context`; raw arguments исключены из Error Log/debug; bounded JSON-string sanitation; все известные stale aliases fail closed |
| Claude F11: недостаточные negative tests | Принято | Добавлены System Manager output tests, real-save/db-set TOCTOU, Error Log/401, runtime inventory и generic MCP exception cases |
| Claude F12: disabled-plugin configs удаляются sync | Принято | Orphan deletion удаляется из sync; config сохраняется при disable/re-enable; исправляется broken registry import |
| Antigravity 1: Task 7 зависит от незавершённого Codex registry | Принято | Legacy adapter и его тест перенесены в Codex Task 4; Z выполняет только Task 6 и report/workflow Task 7 |
| Antigravity 2: migration через `doc.save()` после schema change | Принято с технической коррекцией | Используется точное поле `role_access_mode`, `frappe.db.set_value` и `frappe.db.delete`; raw SQL не нужен; cache очищается после batch |
| Antigravity 3: секреты во вложенных JSON-строках | Принято | MCP принимает только dict arguments; JSON-looking strings до 64 KiB bounded-parse, sanitize и reserialize |

## Исполнительная последовательность после гейта

1. Codex выполняет Tasks 1–2 и публикует замороженные signatures.
2. После foundation параллельно стартуют Codex Tasks 3–4, Kimi Task 5 и Z Tasks 6–7.
3. Codex делает integration review Tasks 3–7.
4. Composer запускает независимую black-box Task 8 на интегрированной реализации.
5. Codex выполняет Tasks 9–10; финальный внешний аудит и production gate остаются отдельными решениями.

## Непереходимые границы

Нет push, PR, deploy, production migrate, изменения ролей/ключей/OAuth/MCP или включения tools без отдельного разрешения. Статус `approved` устанавливает только Алхас.
