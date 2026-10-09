# Fawusk — alpha 0.5

**A minimal local Windows archiver being developed as a competitor to WinRAR and 7-Zip.** This is an early test release, not a proven performance or security winner. Test on copies of important files.

![Fawusk alpha 0.5](docs/release-cover.png)

## English

### New in alpha 0.5
- **Clearer format names:** FAW 3 — Recommended; FAW 2 — Classic; FAW 1 — Compatibility; ZIP — Compatible. FAW 2's technical “block” label is gone. Internally it compresses each file independently; the name change does not alter its format.
- **Folder and file pictograms:** native Win32 vector graphics, not emoji. Folders, archives and file categories are visually distinguished without loading thumbnails or invoking per-file shell icon handlers. Rows have more breathing room and retain keyboard navigation.
- **Four-core-oriented scheduling:** one processor budget is reserved for I/O and file hashing; up to three codec workers compress/decode solid groups. The actual worker count honours Go's available CPU budget, has a ceiling of three, and falls to one for small archives or one/two-core budgets. This is not a physical four-core benchmark or a speed guarantee.
- **Buffer reuse:** bounded compression queues reuse raw and encoded buffers; unpacking prefetches and verifies groups in parallel and reuses each worker's input/output buffers. No full-archive RAM buffer. Extra workers cost memory, so the pipeline is capped.
- **Owned Temp cleanup:** normal close removes Fawusk's preview files. If a viewer holds a Windows deletion lock, a windowless helper retries for up to two minutes after the owning process exits. A later Fawusk start attempts recovery of remaining marked orphan directories. Active windows' directories and unrelated Temp data are left alone.

### Use
Windows 10/11 x64. Download `Fawusk-alpha-0.5.exe` from Releases and run it. No installer, .NET/Mono or administrator privileges. The EXE is unsigned; Windows may show a reputation warning. Verify the published SHA-256 and download origin; do not globally disable antivirus.

Open a single file, folder or archive with **Открыть…** or drag/drop. Additional paths open separate windows. Choose the format and **Быстрый / Хороший / Максимальный**, then **Упаковать**. Open an archive and select **Распаковать…** to create a new directory. Existing files and inputs are not overwritten.

Double-click folders to navigate. A normal file is opened using your Windows association. A permitted archive file is extracted to a randomly named `%TEMP%\Fawusk-preview-*` directory, checked and opened with your associated application. Only the selected file and parent directories are written, plus a small ownership marker outside the content directory. Indexed FAW 3 reads only needed groups; older solid archives may decode the entire stream but discard unrelated file bytes.

### Preview and cleanup safety
Preview supports common JPG/PNG/GIF/BMP/WebP/TIFF pictures, MP4/MOV/MKV/WebM/AVI videos, MP3/WAV/FLAC/OGG audio, TXT/MD/CSV/PDF and restricted DOCX/XLSX/PPTX. An updated suitable external viewer must be installed. Preview is **not an antivirus or a sandbox**: external applications can have vulnerabilities and their own network behaviour.

Executable/script/shortcut and macro-document extensions, misleading names such as `virus.exe.txt`, known executable signatures and active OOXML macro/ActiveX/embedded-object/external-link fixtures are blocked for archive preview. Unsupported files require full ordinary extraction and your own safety assessment; extraction itself never launches them.

Fawusk never purges the whole Temp directory or forcibly terminates your viewer. Windows can prevent deleting locked files; crashes, power loss, permissions or an unavailable cleanup helper can leave data behind. Ownership markers are checked before cleanup. Next-preview cleanup, close cleanup, retries and next-start recovery are best-effort. **Instant deletion under every circumstance cannot be guaranteed.** Unmarked `Fawusk-view-*` directories from older releases are not automatically deleted; remove your old leftover directories manually after closing viewers.

### Format compatibility and limits
Alpha 0.5 keeps the indexed **FAW 3 flags=1 format from alpha 0.4**; archives remain readable by 0.4. It also reads FAW 1/2, original alpha 0.3 FAW 3 flags=0 and ZIP. New indexed FAW 3 requires 0.4 or newer; 0.3 cannot read it. Writes FAW 1/2/3 and ZIP. RAR, 7z, encryption and archive editing are not implemented.

8 MiB solid groups preserve compression history across files within each group. Incompressible groups use STORE. Group/file SHA-256 detects corruption, not malicious authorship. Catalogue-only listing checks metadata, not all payload; data is verified when groups are read and full extraction checks every file. Limited groups trade some cross-group compression for parallelism and random access.

Limits: 100,000 paths, 8 GiB/file, 20 GiB uncompressed total, 16 MiB names, 32 MiB index, 1 GiB/preview. Symbolic/reparse links, device files, ACLs, alternate streams and hard-link identity are unsupported; this is not a full system-backup tool. The archiver itself has no telemetry, network client or automatic updater.

### Performance and verification
A synthetic **5 GiB sparse zero-filled file** packed in **6.919 seconds** in a **2-vCPU Linux sandbox**; full extraction and original/restored SHA-256 comparison passed. This is not ordinary data, native Windows, cold-cache disk throughput or a WinRAR/7-Zip comparison. The broad 5 GB/5–6 second goal is not reached or guaranteed. Physical four-core performance still needs testing. Correctness tests also exercise a `GOMAXPROCS=4` budget, not four physical cores.

See [testing notes](docs/TESTING.md) and included raw logs. Native Windows 10/11 testing and an independent security/performance audit remain needed.

### Build
Go 1.25+; this release used Go 1.27.2. Initial module/resource-tool downloads require internet.

```sh
go test ./...
go test -race ./...   # supported host with C toolchain
go vet ./...
sh build.sh          # Windows x64 cross-build
```

Windows PowerShell:
```powershell
.\build.ps1
$env:FAWUSK_GUI_EXE = (Resolve-Path .\dist\Fawusk-alpha-0.5.exe).Path
go test -v ./...
```

Optional engineering stress test (needs approximately 6 GiB free disk):
```sh
FAWUSK_5G_BENCH=1 go test -run '^TestFiveGiBOptIn$' -v -count=1 -timeout=10m
```

[Indexed FAW 3](docs/FAW_V3_INDEXED.md) · [Legacy FAW 3](docs/FAW_FORMAT.md) · [FAW 2](docs/FAW_V2.md) · [FAW 1](docs/FAW_V1.md) · [Third-party licences](THIRD_PARTY_NOTICES.md)

---

## Русский

**Fawusk — минималистичный локальный архиватор для Windows, который мы развиваем как конкурента WinRAR и 7-Zip.** Превосходство пока не доказано; проверяйте альфу на копиях важных файлов.

### Что нового в alpha 0.5
- **FAW 2 — «Классический»** вместо непонятного «Блочный». FAW 3 обозначен как рекомендуемый. Алгоритмы FAW 2 не изменены: файлы сжимаются независимо.
- **Графические иконки папок, архивов и файлов:** без эмоджи, миниатюр и загрузки оболочечных обработчиков. Более просторные строки, клавиатурная навигация сохранена.
- **Расчёт под четыре ядра:** до трёх рабочих потоков кодека плюс ресурс для чтения, записи и проверки. На малых архивах и меньшем CPU-бюджете число работников уменьшается. Учтены ограничения среды, число потоков не растёт бесконечно.
- **Меньше повторных выделений памяти:** повторно используются буферы сжатия и распаковки; группы читаются и проверяются заранее в ограниченном конвейере. Весь архив в память не загружается.
- **Очистка Temp:** при обычном закрытии удаляются свои временные файлы просмотра. Для заблокированных файлов отдельный помощник повторяет попытки до двух минут после завершения основного процесса; оставшиеся помеченные папки подбираются при следующем запуске.

### Запуск и безопасность
Windows 10/11 x64. Запустите `Fawusk-alpha-0.5.exe`: установка, .NET/Mono и администратор не нужны. EXE не подписан — сверяйте SHA-256 и источник.

Один открытый путь на окно. «Открыть…» → формат и сжатие → «Упаковать». Для извлечения откройте архив и нажмите «Распаковать…»: создаётся новая папка, перезаписи нет. Двойной клик по разрешённому файлу в архиве извлекает только его в отдельную Temp-папку и открывает установленным приложением Windows.

Приложения, скрипты, ярлыки, маскировка расширений и макросодержащие документы запрещены для просмотра из архива. Просмотрщик **не является антивирусом или песочницей**; внешние приложения должны быть доверенными и обновлёнными. Поддерживаемые расширения и ограничения перечислены выше.

**Чужие файлы в Temp не удаляются.** Мгновенная очистка при любых условиях невозможна: Windows может заблокировать файл, а процесс — аварийно завершиться. Просмотрщик не закрывается принудительно. Предусмотрены повторные попытки и восстановительная очистка. Старые непомеченные папки `Fawusk-view-*` из прежних версий автоматически не удаляются.

### Совместимость и проверка
Формат нового FAW 3 не менялся: alpha 0.4 и 0.5 совместимы. Читаются старые FAW 1/2/3 и ZIP; запись — FAW 1/2/3 и ZIP. Alpha 0.3 не читает индексированный FAW 3. RAR, 7z, шифрование и редактирование архивов пока отсутствуют.

Для 5 ГиБ синтетических нулевых данных в Linux на 2 vCPU упаковка заняла **6,919 с**, а SHA-256 после распаковки совпал. Это не скорость на обычных файлах, не результат настоящей Windows и не сравнение с конкурентами. Цель 5–6 секунд на любых данных не достигнута. Реальный четырёхъядерный ПК ещё нужно проверить; тест `GOMAXPROCS=4` проверяет корректность, а не физическую скорость четырёх ядер.

Ограничения: 8 ГиБ/файл, 20 ГиБ/архив, 100 000 путей, просмотр до 1 ГиБ/файл. Быстрое открытие проверяет каталог; данные проверяются при извлечении. ACL, альтернативные потоки, специальные файлы и ссылки не сохраняются. Исходники под MIT, сторонние лицензии приложены. Сборка и проверки — в английской секции и docs/TESTING.md.
