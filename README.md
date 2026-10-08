# Fawusk — alpha 0.1

**A small, portable Windows archiver with a native interface, ZIP support, and an experimental `.faw` container.**

Windows 10 / 11 · x64 · Go · No Electron · No runtime downloads

[English](#english) · [Русский](#русский)

## English

### What is Fawusk?

Fawusk is an early, offline desktop archiver. Add files or folders, choose a format and compression level, and create an archive. Extraction creates a **new folder**, rather than overwriting an existing destination. The application title includes **Fawusk alpha 0.1**.

This is a test release, not a production replacement for WinRAR or 7-Zip. Use copies of files and verify the extracted content before relying on an archive as a backup. No claim of better speed, compression, or security than those products has been established.

### Features

- Create and extract **ZIP** and **FAW** archives.
- Three DEFLATE compression levels: fast (default), balanced, maximum.
- Files, recursive folders, empty folders, and Unicode names.
- Drag-and-drop, multiple-file selection, progress, cancellation, and background work.
- Streaming file I/O: ordinary file contents are not loaded fully into RAM.
- No network features, telemetry, installer, administrator requirement, or automatic file execution.

| Format | Create | Extract | Notes |
| --- | --- | --- | --- |
| `.faw` | Yes | Yes | Versioned container, ZIP payload, SHA-256 integrity check |
| `.zip` | Yes | Yes | STORE / DEFLATE, no encryption, no split volumes |
| `.rar` | No | No | Visible as unavailable in the format selector; creation requires an appropriate licensed RAR implementation |
| `.7z` | No | No | Outside this alpha's scope |

**FAW is not a new compression algorithm.** Version 1 wraps a ZIP stream in a custom binary header and SHA-256 trailer. It is not simply a ZIP renamed to `.faw`. The hash detects corruption; it does **not** provide encryption or prove who created an archive. See [the format specification](docs/FAW_FORMAT.md).

### Run

1. Obtain `Fawusk-alpha-0.1.exe` from the provided release package. For a GitHub publication, the maintainer should attach it to a Release.
2. Launch it as a normal user on Windows 10 / 11 x64. No Go installation is needed to run the EXE.
3. Click **Добавить файлы** (Add files) or **Добавить папку** (Add folder), or drag items into the window.
4. Choose FAW or ZIP, a compression level, and a **new** output filename outside the selected source folder.
5. Click **Упаковать** (Pack). To extract, click **Распаковать…** and select an archive and a destination parent folder.

The UI is Russian in this alpha. **Удалить** and **Очистить** remove items from the selection only; they do not delete source files. Output archives are never deliberately overwritten. Existing extraction folders are not reused. The initial release is **unsigned**, so Windows may warn about an unknown publisher. Do not disable security protections; if you do not trust the binary, inspect and build the source instead.

### Safety limits and limitations

- At most 100,000 archive entries, 8 GiB per file, and 20 GiB total uncompressed data. ZIP central-directory data is limited to 64 MiB.
- Rejects path traversal, absolute paths, drive/alternate-stream paths, ambiguous names, Windows device names, case-insensitive duplicate paths, and file/directory conflicts.
- Rejects symbolic links, junctions / reparse points in selected source paths, and special files. Extraction rejects link entries and destination-parent links.
- CRC checks on extracted files; FAW adds header CRC-32 and whole-payload SHA-256 verification.
- Temporary output is published only after successful completion. Cancellation and ordinary errors attempt to remove temporary data. A crash or forced termination can leave temporary files.
- Not a sandbox or antivirus. Archive contents may still be malicious; do not execute untrusted extracted files. Concurrent modification of the destination by another local process is outside the threat model.
- No passwords, encryption, archive preview/editing, Explorer integration, split archives, RAR/7z support, or preservation of NTFS streams, ACLs, ownership, and full filesystem metadata.
- Already-compressed media may barely shrink or become slightly larger. Maximum compression costs more CPU time. FAW hashing requires an extra read of the compressed payload.
- The format is experimental; future compatibility is not guaranteed yet.

### Build from source

Use an up-to-date **Go 1.25 or newer** toolchain. The application itself uses only Go's standard library and Windows system APIs. A pinned resource-generation tool is downloaded at build time for the icon, version information, and manifest.

On Windows, from the repository root:

```powershell
./build.ps1
```

If your PowerShell policy blocks scripts, run the individual commands below under your existing policy instead of weakening it:

```powershell
go run github.com/tc-hib/go-winres@v0.3.3 make --arch amd64
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
go build -trimpath -ldflags='-s -w -H=windowsgui' -o dist/Fawusk-alpha-0.1.exe .
```

On Linux, cross-compile using `sh build.sh`. The result is `dist/Fawusk-alpha-0.1.exe`. Only the Windows x64 frontend is implemented.

### Tests and publication

```text
go test -v ./...
go test -race ./...
go test -run=^$ -fuzz=FuzzSafeName -fuzztime=10s
```

The race detector needs a supported native C toolchain; do not use it for cross-compilation. Core tests run on Windows and Linux. The Windows UI integration test is opt-in: set `FAWUSK_GUI_EXE` to the absolute path of the built EXE, then run `go test -run TestWindowsGUI -v` on Windows.

See [the delivery test report](docs/TESTING.md) for checks actually performed and remaining gaps. GitHub Actions configuration is included, but a workflow is not evidence that CI has already passed in your repository.

For GitHub: upload the repository contents, create tag **`v0.1.0-alpha.1`**, and attach the EXE plus its SHA-256 checksum to a Release. Do not upload your private test files or toolchain folders. Please report bugs with the Windows version, the operation, the error text, and a non-sensitive reproduction. Do not share private archive contents.

### License

Project source: [MIT](LICENSE). Go standard-library notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

## Русский

### Что такое Fawusk?

**Fawusk** — небольшой портативный архиватор для Windows с простым нативным интерфейсом. Добавьте файлы или папки, выберите формат и уровень сжатия, затем создайте архив. При распаковке создаётся **новая папка**, а существующие данные не перезаписываются. В заголовке приложения указано **Fawusk alpha 0.1**.

Это первая тестовая версия, а не готовая замена WinRAR или 7-Zip. Проверяйте её на копиях файлов и сравнивайте распакованные данные с исходными, прежде чем использовать архив как резервную копию. Превосходство в скорости, сжатии или безопасности над другими архиваторами пока не установлено.

### Возможности

- Упаковка и распаковка **ZIP** и **FAW**.
- Три уровня DEFLATE: быстрое (по умолчанию), сбалансированное и максимальное сжатие.
- Обычные файлы любого содержимого, вложенные и пустые папки, имена на русском языке.
- Перетаскивание, выбор нескольких файлов, прогресс, отмена и работа в фоне.
- Потоковое чтение и запись: содержимое обычных файлов не загружается целиком в память.
- Без сетевых функций, телеметрии, установки, прав администратора и автоматического запуска файлов.

| Формат | Упаковка | Распаковка | Особенности |
| --- | --- | --- | --- |
| `.faw` | Да | Да | Версионный контейнер, ZIP-поток, контроль SHA-256 |
| `.zip` | Да | Да | STORE / DEFLATE, без шифрования и многотомных архивов |
| `.rar` | Нет | Нет | В списке помечен как недоступный; создание требует подходящей лицензированной реализации RAR |
| `.7z` | Нет | Нет | Не входит в alpha 0.1 |

**FAW — новый контейнер, а не новый алгоритм сжатия.** Формат версии 1 содержит собственный двоичный заголовок, ZIP-поток и контрольную сумму SHA-256. Это не просто ZIP с другим расширением. Контрольная сумма позволяет обнаружить повреждение, но **не шифрует данные и не подтверждает авторство**. Подробнее: [спецификация FAW](docs/FAW_FORMAT.md).

### Как запустить

1. Скачайте `Fawusk-alpha-0.1.exe` из пакета релиза. При публикации на GitHub автору нужно прикрепить EXE к Release.
2. Запустите его обычным пользователем на Windows 10 / 11 x64. Для запуска EXE установка Go не нужна.
3. Нажмите **Добавить файлы** или **Добавить папку**, либо перетащите объекты в окно.
4. Выберите FAW или ZIP, уровень сжатия и **новое** имя архива вне выбранной исходной папки.
5. Нажмите **Упаковать**. Для распаковки нажмите **Распаковать…**, выберите архив и папку, внутри которой появится новая папка с результатом.

Интерфейс этой альфы — на русском языке. **Удалить** и **Очистить** меняют только список выбора, не удаляя исходные файлы. Архивы намеренно не перезаписываются; существующие папки распаковки не используются повторно. Первая сборка **не подписана** цифровой подписью, поэтому Windows может предупредить о неизвестном издателе. Не отключайте защиту; если не доверяете EXE, проверьте исходники и соберите программу самостоятельно.

### Защита и ограничения

- До 100 000 элементов, до 8 ГиБ на файл и 20 ГиБ распакованных данных на архив. Каталог ZIP — до 64 МиБ.
- Отклоняются выход за папку через `../`, абсолютные пути, пути дисков и альтернативных потоков, неоднозначные имена, имена устройств Windows, дубликаты без учёта регистра и конфликты файлов с папками.
- Не поддерживаются символические ссылки, junction / reparse points в исходных путях и специальные файлы. При распаковке отклоняются ссылочные записи и ссылки в родительском пути назначения.
- CRC при извлечении файлов; для FAW дополнительно CRC-32 заголовка и SHA-256 всего сжатого потока.
- Результат публикуется после успешного завершения. При отмене и обычных ошибках выполняется попытка удалить временные данные. После аварии или принудительного завершения они могут остаться.
- Это не песочница и не антивирус: не запускайте недоверенные извлечённые файлы. Изменение папки назначения другим локальным процессом во время работы не входит в модель защиты.
- Пока нет паролей, шифрования, просмотра и редактирования содержимого, интеграции с Проводником, многотомных архивов, RAR/7z и сохранения NTFS-потоков, ACL, владельцев и всех метаданных файловой системы.
- Уже сжатые фото, видео и другие данные могут почти не уменьшиться или немного увеличиться. Максимальное сжатие требует больше CPU. Проверка FAW дополнительно читает сжатый поток.
- Формат экспериментальный: совместимость будущих версий пока не гарантируется.

### Сборка из исходников

Нужен актуальный **Go 1.25 или новее**. Само приложение использует только стандартную библиотеку Go и системные API Windows. Для иконки, версии и манифеста во время сборки скачивается инструмент генерации ресурсов с фиксированной версией.

В Windows, из корня репозитория:

```powershell
./build.ps1
```

Если политика PowerShell запрещает запуск скрипта, выполните отдельные команды из английского раздела, не ослабляя политику. В Linux для кросс-компиляции используйте `sh build.sh`. Результат: `dist/Fawusk-alpha-0.1.exe`. Графическая версия реализована только для Windows x64.

### Тестирование и GitHub

Основные команды:

```text
go test -v ./...
go test -race ./...
go test -run=^$ -fuzz=FuzzSafeName -fuzztime=10s
```

Для проверки гонок нужен поддерживаемый нативный C-компилятор; этот режим не предназначен для кросс-компиляции. Тесты ядра работают на Windows и Linux. Для интеграционного теста окна в Windows задайте `FAWUSK_GUI_EXE` — абсолютный путь к собранному EXE — и выполните `go test -run TestWindowsGUI -v`.

Результаты реально выполненных проверок и оставшиеся пробелы описаны в [отчёте](docs/TESTING.md). Конфигурация GitHub Actions приложена, но это не означает, что CI уже успешно отработал в вашем репозитории.

Для публикации загрузите содержимое репозитория, создайте тег **`v0.1.0-alpha.1`** и прикрепите EXE с его SHA-256 к Release. Не публикуйте личные тестовые файлы и папки компилятора. В сообщении об ошибке укажите версию Windows, действие, текст ошибки и безопасный пример воспроизведения — без личных данных.

### Лицензия

Исходный код проекта — [MIT](LICENSE). Уведомления о стандартной библиотеке Go — [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
