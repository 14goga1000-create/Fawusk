# Fawusk — alpha 0.3

**Fawusk is being developed as a competitor to WinRAR and 7-Zip: a portable Windows archiver with a minimal native UI and an experimental `.faw` format.**

Windows 10 / 11 x64 · Go · Native Win32 · Offline

[English](#english) · [Русский](#русский)

## English

### Positioning

We are building Fawusk to compete with **WinRAR and 7-Zip**, with a focus on usability, compression, resource efficiency and safer extraction. This is the project's direction, **not evidence that alpha 0.3 already beats either product**. Universal “smaller, faster, safer” claims have not been established. Test on copies; this is not yet a production backup tool.

### New in alpha 0.3

- **One opened path per window.** Opening another file/folder replaces the current path; multiple dropped/startup paths use separate windows.
- **Folder browser:** immediate contents, double-click to enter a subfolder, Up to return. Ordinary files open with their Windows application on double-click.
- **Ordinary-file view:** only the path, not a fake file-content listing. Double-click the path to launch its associated application.
- **FAW/ZIP recognition and browsing:** open FAW 1/2/3 or ZIP, see verified entries and navigate archive folders. Archived files must be extracted before external opening; no automatic archive-content execution.
- **Path fixes:** modern IFileDialog, separate initial folder/name, absolute output paths, and extended-length paths for custom native file operations.
- **FAW 3 Solid Stream:** one streaming Zstandard history (up to 8 MiB) shared across file boundaries, compressed compact entry records, per-file CRC-32 and one-pass container SHA-256. Similar files can share redundancy instead of being compressed independently.
- Optional per-user registration in **Open with** for `.faw`. Existing default associations/UserChoice are not overwritten.

![Fawusk alpha 0.3 folder browser](docs/screenshot.png)

### Run and use

Run `Fawusk-alpha-0.3.exe` as a normal user on Windows 10/11 x64. No installer, Go, administrator privileges or runtime downloads are required. The EXE is unsigned; do not disable security protections to run an untrusted binary.

1. **Открыть… → Файл или архив… / Папку…**, or drag a path into the window.
2. In a folder, double-click subfolders to navigate; ordinary files open externally. A FAW/ZIP opens in Fawusk instead.
3. For a standalone ordinary file, double-click its displayed path to open it externally. Windows must have an associated application; Fawusk does not supply one.
4. For the current file/folder, choose **FAW 3** or **ZIP** and **Упаковать**. Save to a new filename outside the selected source folder. Packing includes the entire current folder, not just the highlighted row.
5. For an opened archive, use **Распаковать…** and select a parent folder. A new result folder is created.
6. **… → Сжатие** selects fast (default), balanced or maximum. The menu also has New window, Result folder, About and `.faw` Open-with registration.

For `.faw` Explorer integration use **… → Добавить .faw в «Открыть с помощью»**, then choose Fawusk using Windows. Registration is opt-in, per-user, and does not force the default application. Keep the EXE at the registered location. Ordinary external apps may have their own long-path restrictions.

### Compatibility and trade-offs

| Format | Create | Browse/extract |
| --- | --- | --- |
| FAW 3 | Yes, default FAW writer | Yes |
| FAW 2 | Legacy test helper only | Yes |
| FAW 1 | Legacy test helper only | Yes |
| ZIP | Yes | STORE / DEFLATE, supported ZIP64 within quotas |
| RAR / 7z | No | No |

**Alpha 0.1/0.2 do not read FAW 3.** Recipients need alpha 0.3, or use ZIP. All FAW variants share `.faw`; the header determines the version.

FAW 3 is our container and stream organization using **Zstandard**, not a newly invented compression algorithm. Solid history and compact metadata help some inputs, especially similar files, but random/already-compressed data may barely shrink or grow. There is no universal size improvement. Maximum compression and the larger history cost CPU/workspace. Peak process RAM is not the declared window size.

Archive browsing currently **scans/decompresses and verifies the stream before showing entries**, without writing extracted files. Large solid archives can take time to open; Cancel is available. There is no random-access index or instant selective extraction yet. Solid ordering also means recovering a damaged stream can be harder than with independent blocks. The checksum detects damage, not authorship; there is no encryption/signature.

### Limits and safety

100,000 entries/unique path nodes (including implied parents), 8 GiB/file, 20 GiB total uncompressed data. FAW name data ≤16 MiB, individual UTF-8 names ≤3,000 bytes, at most 128 path components. FAW 3 decoder window ≤8 MiB with a configured 32 MiB decoder memory ceiling (not a whole-process RAM limit). ZIP directory data ≤64 MiB. The folder UI reads at most 100,001 entries and refuses to display over 100,000.

Traversal, absolute/drive/stream paths, ambiguous/device names, duplicate paths and file/directory conflicts are rejected. FAW 2/3 also reject inconsistent ancestor casing. Links, junction/reparse points and special files are not supported. Linked destination parents are rejected; choose an ordinary destination folder if redirected/junction folders are refused.

Output goes to temporary files/folders and is published after checks. Existing archives/destination folders are not intentionally overwritten. Cancellation and errors attempt cleanup; forced termination can leave temporary data. This is not an antivirus, disk/time sandbox or protection against concurrent local tampering. Do not launch untrusted extracted files.

No passwords/encryption, RAR/7z, archive editing, split volumes, arbitrary-access FAW index, general deduplication or NTFS ACL/stream preservation. Native Windows behavior, different DPI and actual maximum-sized data still need testing. [Test report](docs/TESTING.md) · [FAW 3 specification](docs/FAW_FORMAT.md).

### Build and test

Use current **Go 1.25+**. Zstandard is pinned to `klauspost/compress v1.20.1`; dependency checksums are in `go.sum`. Resources use `go-winres v0.3.3`. No third-party runtime DLL is required.

Windows: `./build.ps1`. Linux cross-build: `sh build.sh`. Output: `dist/Fawusk-alpha-0.3.exe` and its SHA-256. If PowerShell policy prevents scripts, run the individual commands without weakening it:

```powershell
go mod download
go run github.com/tc-hib/go-winres@v0.3.3 make --arch amd64
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
go build -trimpath -ldflags='-s -w -H=windowsgui' -o dist/Fawusk-alpha-0.3.exe .
```

```text
go test -v ./...
go test -race ./...
go test -run=^$ -fuzz=FuzzFAW3Parser -fuzztime=10s
go test -run=^$ -bench BenchmarkFAWFast -benchtime=3x -count=3
```

Race tests need a supported native C toolchain. Windows GUI tests are opt-in: set `FAWUSK_GUI_EXE` to the absolute EXE path. They test folder/parent navigation, modern saving, packing and plain-file display. Benchmarks are synthetic FAW 1/2/3 tests, not competitor rankings or peak-RAM measurements.

GitHub: tag **`v0.3.0-alpha.3`**, attach EXE and `SHA256SUMS.txt`. Russian release text: `RELEASE_RU.md`. Included Actions has not yet run in your published repository. Do not upload private test data or toolchain/Wine folders.

Source: [MIT](LICENSE). Dependencies: [notices](THIRD_PARTY_NOTICES.md).

---

## Русский

### Позиционирование

**Fawusk разрабатывается как конкурент WinRAR и 7-Zip.** Мы работаем над удобством, сжатием, эффективным использованием ресурсов и проверками при распаковке. Это направление проекта, **а не уже доказанное превосходство alpha 0.3**. Пока нельзя обещать, что Fawusk всегда меньше, быстрее или безопаснее конкурентов. Проверяйте альфу на копиях; это ещё не готовый инструмент резервного копирования.

### Новое в alpha 0.3

- **Один открытый путь на окно.** Новый файл/папка заменяет текущий путь; несколько перетаскиваемых путей открываются в отдельных окнах.
- **Просмотр папки:** её содержимое, переход в подпапку двойным кликом, кнопка **Вверх**. Обычный файл открывается внешним приложением Windows.
- **Режим обычного файла:** показывается путь без списка «содержимого». Двойной клик по пути открывает файл назначенным приложением.
- **Распознавание и просмотр FAW 1/2/3 и ZIP.** Можно переходить по папкам архива. Архивные файлы сначала нужно распаковать; автоматически они не запускаются.
- **Исправления путей:** современный IFileDialog, отдельные начальные папка/имя, абсолютное назначение и расширенные длинные пути в собственных вызовах Windows.
- **FAW 3 Solid Stream:** общая потоковая история Zstandard до 8 МиБ между файлами, компактные сжатые записи, CRC-32 файлов и SHA-256 контейнера за один проход.
- Необязательная регистрация `.faw` в **«Открыть с помощью»** для текущего пользователя, без принудительной смены приложения по умолчанию.

### Как пользоваться

Запустите `Fawusk-alpha-0.3.exe` на Windows 10/11 x64. Установка, Go и права администратора для запуска не нужны. EXE не подписан: не отключайте защиту для запуска недоверенной сборки.

1. **Открыть… → Файл или архив… / Папку…**, либо перетащите путь в окно.
2. В папке двойной клик входит в подпапку или открывает обычный файл внешним приложением. FAW/ZIP открывается внутри Fawusk.
3. У отдельно открытого обычного файла двойной клик по пути запускает назначенное Windows приложение. Если обработчика нет, его нужно выбрать средствами Windows.
4. Для текущего файла/папки выберите **FAW 3** или **ZIP**, нажмите **Упаковать**, задайте новое имя вне исходной папки. Упаковывается вся текущая папка, а не только выделенная строка.
5. У открытого архива нажмите **Распаковать…**: внутри выбранной родительской папки появится новая папка с результатом.
6. **… → Сжатие**: быстрое (по умолчанию), сбалансированное, максимальное. Там же — новое окно, папка результата, сведения и регистрация FAW.

Для Проводника: **… → Добавить .faw в «Открыть с помощью»**, затем выберите Fawusk средствами Windows. Программа не перезаписывает пользовательский выбор по умолчанию. После регистрации не перемещайте EXE. Внешние приложения могут иметь собственные ограничения длинных путей.

### Совместимость и цена solid-сжатия

Alpha 0.3 создаёт **FAW 3 и ZIP**, читает **FAW 1/2/3 и поддерживаемые ZIP**. RAR и 7z пока не реализованы.

**Alpha 0.1/0.2 не читают FAW 3**: получателю нужна alpha 0.3 либо ZIP. Расширение остаётся `.faw`; версия определяется по заголовку.

FAW 3 — собственный контейнер и организация потока на основе **Zstandard**, не новый изобретённый алгоритм. Общая история и компактные записи помогают некоторым данным, особенно похожим файлам. Несжимаемые/уже сжатые данные могут почти не уменьшиться или увеличиться. Универсального уменьшения размера нет. Большая история и максимальный режим требуют памяти/CPU; размер окна не равен всей памяти процесса.

Для просмотра архив сейчас **последовательно читается, декодируется и проверяется до показа списка**, без записи извлечённых файлов. Большой solid-архив может открываться долго; доступна отмена. Индекса произвольного доступа и мгновенной выборочной распаковки пока нет. Повреждение solid-потока может осложнить восстановление последующих файлов. Контрольная сумма не подтверждает автора; шифрования/подписи нет.

### Ограничения и защита

До **100 000 элементов, 8 ГиБ на файл и 20 ГиБ распакованных данных**. Имена FAW суммарно — до 16 МиБ, отдельно — 3 000 UTF-8 байт, глубина — 128 компонентов. Окно декодера FAW 3 — до 8 МиБ, настроенный предел памяти декодера — 32 МиБ, **не всей программы**. Каталог ZIP — до 64 МиБ. В списке обычной папки также действует лимит 100 000 элементов.

Проверяются опасные пути, имена устройств, дубликаты, конфликты файлов/папок; FAW 2/3 проверяют неоднозначный регистр родительских путей. Ссылки, junction/reparse points и специальные файлы не поддерживаются. Родительские ссылки назначения отклоняются: если перенаправленная папка не принимается, выберите обычный каталог.

Результат публикуется из временного файла/папки после проверок без намеренной перезаписи существующих данных. При отмене выполняется попытка очистки; после аварии временные данные могут остаться. Это не антивирус, песочница времени/диска и не защита от одновременного вмешательства локального процесса. Не запускайте недоверенные извлечённые файлы.

Пока нет паролей, шифрования, RAR/7z, редактирования архивов, многотомности, индекса произвольного доступа FAW, общей дедупликации и сохранения NTFS-потоков/ACL. Проверки на настоящей Windows, разных DPI и максимальных физических объёмах ещё нужны. [Отчёт](docs/TESTING.md) · [Спецификация](docs/FAW_FORMAT.md).

### Сборка и публикация

Актуальный **Go 1.25+**, зафиксированный `klauspost/compress v1.20.1`, ресурсы `go-winres v0.3.3`. Windows: `./build.ps1`; Linux: `sh build.sh`. Команды ручной сборки, тестов и микробенчмарков — выше. Не ослабляйте политику PowerShell ради скрипта.

Для GitHub: тег **`v0.3.0-alpha.3`**, EXE и `SHA256SUMS.txt` — в Release. Русское описание — `RELEASE_RU.md`. Синтетические тесты не доказывают превосходство над WinRAR/7-Zip. Не публикуйте личные данные и папки инструментов.

Исходники: [MIT](LICENSE). Зависимости: [уведомления](THIRD_PARTY_NOTICES.md).
