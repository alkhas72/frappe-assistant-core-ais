# Бриф Antigravity: исполнимость FAC-плана и интеграционный риск

## Роль

Ты — независимый implementation/audit reviewer. Не реализуешь код. Проверь, можно ли выполнить план заданными агентами без скрытых решений, конфликтов файлов и ложных зелёных тестов.

## Источники

Прочитай полностью:

1. `/Users/alkhas.abaza/repo/frappe-assistant-core-ais--feat-security-hardening/docs/superpowers/specs/2026-08-09-fac-security-hardening-design.md`
2. `/Users/alkhas.abaza/repo/frappe-assistant-core-ais--feat-security-hardening/docs/superpowers/plans/2026-08-09-fac-security-hardening.md`
3. Тесты, migrations, DocType schemas и MCP code в `/Users/alkhas.abaza/repo/frappe-assistant-core-ais--feat-security-hardening/`.

Прямое решение Алхаса: после утверждения Codex координирует, Kimi берёт migration/config, Z — core-tool safety, Composer — verification/docs. Production не менять.

## Обязательные вопросы

1. Содержит ли каждая задача точные файлы, interfaces, RED/GREEN команды и завершённый commit boundary?
2. Реальны ли приведённые test commands для Frappe 15/16 и существующей структуры tests?
3. Какие задачи имеют скрытые зависимости и не могут идти параллельно?
4. Пересекаются ли ownership Kimi/Z/Composer через imports, fixtures, schema или migrations?
5. Достаточна ли foundation Task 1–2 для заморозки signatures перед параллельной работой?
6. Идемпотентна ли предложенная migration; учитывает ли порядок schema sync/patch/sync hooks и существующие child rows?
7. Может ли UI/admin API снова создать `Allow All`, пустой restricted list или включить hard-denied tool?
8. Есть ли тесты, которые будут зелёными из-за чрезмерного mocking и не докажут реальный MCP/Frappe path?
9. Достаточны ли staging, backup и rollback gates; нет ли необратимого шага без доказательства?
10. Какие задачи нужно разделить, объединить или переназначить для минимизации merge conflicts?

## Формат заключения

Верни один Markdown-документ:

```markdown
# Antigravity cross-audit verdict

Verdict: EXECUTABLE | EXECUTABLE WITH REQUIRED CHANGES | NOT EXECUTABLE

## Findings

| ID | Severity | Task/step | Evidence | Execution risk | Exact plan correction |
|---|---|---|---|---|---|

## Dependency graph corrections

- Только изменения реальных зависимостей и ownership.

## Gate

- Точный список изменений до передачи исполнителям.
```

Severity: `BLOCKER`, `HIGH`, `MEDIUM`, `LOW`. BLOCKER/HIGH должен ссылаться на конкретный файл, функцию, test runner behavior или migration order. Если данных нет — `требует уточнения`. Не ставь `approved`.

## Границы

- Не изменять код, plan, spec, production, роли, ключи или MCP.
- Не выполнять тесты на production site.
- Не заменять независимое доказательство предположением или общим советом.
- Не расширять scope Builder/visualization/data-science/external tools.
