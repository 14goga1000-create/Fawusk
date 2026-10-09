# CustomAV 0.5 upgraded integration package

Пакет для внедрения CustomAV в Go-архиватор.

- `ОБЯЗАТЕЛЬНО ПРОЧИТАТЬ ПЕРЕД ВНЕДРЕНИЕМ.md` — инструкция для AI-разработчика.
- `engine/` — reference scanner 0.5 и зависимости.
- `go/customav/` — Go-клиент для безопасного вызова scanner.
- `protocol/scan_result.schema.json` — форма JSON-результата.
- `tests/` — место для локальных тестовых образцов; тестовый EICAR намеренно не включён.

Сам scanner ничего не выполняет. Go-клиент вызывает его отдельным процессом без shell.
