# Бриф Claude: архитектурный кросс-аудит FAC-плана

## Роль

Ты — независимый архитектор и security reviewer. Не реализуешь код и не переписываешь документы. Твоя задача — найти архитектурные пробелы до старта исполнителей.

## Источники

Прочитай полностью:

1. `/Users/alkhas.abaza/repo/frappe-assistant-core-ais--feat-security-hardening/docs/superpowers/specs/2026-08-09-fac-security-hardening-design.md`
2. `/Users/alkhas.abaza/repo/frappe-assistant-core-ais--feat-security-hardening/docs/superpowers/plans/2026-08-09-fac-security-hardening.md`
3. Фактический код pinned commit в `/Users/alkhas.abaza/repo/frappe-assistant-core-ais--feat-security-hardening/`.

Прямое решение Алхаса: предварительный кросс-аудит выполняют Claude и Antigravity; исполнители после утверждения — Codex, Kimi, Z и Composer. Production не менять.

## Обязательные вопросы

1. Все ли execution paths сходятся в call-time policy, включая MCP adapter, alternate handler, direct `_safe_execute`, legacy registry и external hooks?
2. Может ли `tools/list` или кэш создать TOCTOU-обход?
3. Корректна ли граница immutable policy против FAC config, System Manager и Administrator?
4. Полон ли inventory 24 фактических имён; не осталось ли динамически зарегистрированных путей?
5. Достаточно ли operation-context extraction для CRUD, search wrappers, reports, workflow и child rows?
6. Не создаёт ли audit двойные строки, пропуски или утечки secrets/PII через error, traceback и output?
7. Безопасна ли временная политика hard-deny для delete/data-science/files/visualization/external/Builder?
8. Есть ли в плане продуктовые решения, которые разработчик будет вынужден принять сам?
9. Не конфликтует ли план с Frappe permission semantics или request lifecycle?
10. Какие negative tests отсутствуют?

## Формат заключения

Верни один Markdown-документ:

```markdown
# Claude cross-audit verdict

Verdict: PASS | PASS WITH REQUIRED CHANGES | BLOCK

## Findings

| ID | Severity | Plan task | Code evidence | Problem | Required correction |
|---|---|---|---|---|---|

## Confirmed strengths

- Только доказанные пункты.

## Gate

- Точный список изменений, обязательных до реализации.
```

Severity: `BLOCKER`, `HIGH`, `MEDIUM`, `LOW`. Для каждого BLOCKER/HIGH укажи файл и функцию из фактического кода. Если данных нет — `требует уточнения`. Не ставь `approved`.

## Границы

- Не изменять код, plan, spec, production, роли, ключи или MCP.
- Не предлагать расширение Builder/visualization/data-science в текущий этап.
- Не считать социальный plan-gate технической авторизацией удаления.
- Не пересказывать план: нужны только проверяемые находки.
