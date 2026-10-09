# Fawusk — alpha 0.7

**A minimal local Windows archiver being developed as a competitor to WinRAR and 7-Zip.** Early alpha; no demonstrated speed/compression/security superiority. Test on copies of important files.

![Fawusk alpha 0.7](docs/release-cover.png)

## English

### New in alpha 0.7
- Native adapted **CustomAV 0.5** static rules and signature layer, without Python or target execution. Original instruction/reference retained in `reference/customav/`.
- **FawReader** recognises FAW 1/2 and both FAW 3 variants, lists entries and supplies validated streams to CustomAV. ZIP and bounded nested FAW/ZIP/JAR are supported by the same scanner.
- Top security status with explanatory report, per-entry colours, JSON export and standalone `--scan-customav archive --report new-report.json` mode.
- Whole-archive scanning at open; scan before newly-created archive publication; stream rescan before extraction publication; approved identity and content checks before selected preview.
- Distinct vector icons for video/audio/image/PDF/office/code/application/font/data. Details table and one path per window remain.

### Security scope — please read
Green means **no positive indicators under these static rules**, not virus-free. Red blocks operations. Yellow review requires GUI confirmation. EICAR is a harmless test detection, not real malware. Grey/failed/partial scanning never grants whole-archive approval; strict alpha policy blocks preview/extraction/publication. Originals are neither executed nor deleted/uploaded. Scanner is not a sandbox or a replacement for Defender.

**Content analysis is limited to 16 MiB per file** (full SHA-256 is still read). Larger files produce incomplete scanning and are blocked by the strict policy, including ordinary large videos/game files. Additional bounds: 10,000 scanned file records, 20 GiB cumulative data, 1 GiB nested decoded bytes, depth 3 and 10-minute deadline. Script/text rule limits are 2/10 MB. Nested unsupported containers and unported/unknown threats remain limitations.

The embedded signature database contains **EICAR only**, not a real-malware corpus. Detection otherwise uses explainable heuristics; legitimate scripts/installers/command documentation can produce false positives. A sidecar `customav_signatures.json` supplements the database; invalid rules fail closed. This is an **adapted port**, not byte-identical feature parity with every Python reference rule. See [CustomAV integration and limits](docs/CUSTOMAV.md) for preserved rules and omitted entropy/packer/manifest/reputation features. Full security scanning decodes data and adds latency; earlier speed figures are not benchmarks of this path.

### Size and date semantics
Archive Size is the **original/uncompressed file size**, not its individual compressed contribution inside a shared solid group. Folders and unknown values show `—`. Size units use 1024 bytes (`КБ`, `МБ`, `ГБ`); values are rounded for display, and tiny nonzero files are distinguished from zero. Modification dates are displayed in the **computer's local time**, to minute precision; archive records retain their available seconds. Missing dates and implicit ZIP/FAW parent-directory dates are not invented.

The filesystem summary adds known **regular-file sizes directly in the current folder**; it does not recursively scan folders or include directory-allocation bytes. Files and folders are counted separately. Archive data totals add regular-file bytes, not empty-directory metadata. Empty-folder records necessarily occupy some bytes in the archive format: excluding them from payload totals is not a claim of zero archive overhead.

### Download and use
Windows 10/11 **x64**. Download `Fawusk-alpha-0.7.exe` from Releases and run it. No installer, .NET/Mono or administrator rights. EXE is unsigned: check its SHA-256 and source; do not disable antivirus globally.

Use **Открыть…** or drag/drop one path. Additional paths open separate windows. Double-click folders to navigate. Choose FAW 3 Recommended / FAW 2 Classic / FAW 1 Compatibility / ZIP and Fast / Good / Maximum, then **Упаковать**. Open an archive and select **Распаковать…** to create a new directory. Source files and existing output files are not overwritten. Ordinary single files retain their path-only view and open through the Windows association.

Click Name/Size/Date to toggle sorting. Open a permitted archived photo, video, audio or document with a double-click: only the selected file is written under its private Temp content directory and then opened by your installed associated application. Executables, scripts, shortcuts, macro documents and recognised disguised executable names/signatures are blocked for archive preview. Unsupported files require normal extraction and your own safety assessment; extraction never automatically launches them. External viewers must be trusted and updated: this is **not antivirus or a sandbox**.

### Compatibility, ZIP limits and safety
Reads FAW 1/2, continuous alpha 0.3 FAW 3, indexed alpha 0.4/0.5 FAW 3 and ZIP. Writes FAW 1/2/3 and ZIP. The indexed FAW 3 flags=1 wire format is unchanged; alpha 0.4/0.5 can read alpha 0.7 archives. Alpha 0.3 cannot read indexed FAW 3.

**Not every ZIP variant is supported.** Password/encrypted ZIP (including AES), multi-volume ZIP, Deflate64, ZIP-LZMA and other unimplemented methods are rejected explicitly. Legacy encodings other than CP437 are not guessed; UTF-8 or Unicode Path metadata is preferred. Zstandard window/memory is bounded to 64 MiB for ZIP. Unknown/corrupt/unsafe archives do not become trusted just because their catalogue opens. File CRC for ZIP and SHA-256/CRC for FAW detect corruption, not malware or authorship. Full extraction uses a staged new directory and checks file contents before publication.

Limits: 100,000 paths, 8 GiB/file, 20 GiB uncompressed total, bounded catalogue/names and decoder memory, 1 GiB/preview. Links/reparse points, device files, ACLs, alternate data streams and hard-link identity are unsupported. RAR, 7z, encryption and archive editing remain unimplemented. This is not a full Windows Explorer or system-backup replacement.

### Temp and resource use
Alpha 0.5's owned Temp cleanup is retained: normal close removes preview roots, a windowless helper retries Windows deletion locks for up to two minutes after owner exit, and a later launch attempts marked-orphan recovery. Other Temp data and live windows' roots are not deleted. Locked files, crashes/permissions/helper failure can leave data; instant or forensic deletion cannot be guaranteed. Old unmarked `Fawusk-view-*` directories require manual cleanup after closing viewers. See [Temp lifecycle](docs/TEMP_CLEANUP.md).

FAW 3 retains capped codec scheduling (up to three workers with a four-core CPU budget) and reused buffers. This release improves catalogue/view execution paths; no physical four-core performance or peak-RSS benchmark is claimed. The archiver has no telemetry/network/update client; an external viewer may have its own network behaviour.

### Build and checks
Go 1.25+; release built with Go 1.27.2. Initial dependency/resource-tool downloads need internet.
```sh
go test ./...
go test -race ./...    # supported host with C toolchain
go vet ./...
sh build.sh            # cross-build Windows x64 EXE
```
Windows:
```powershell
.\build.ps1
$env:FAWUSK_GUI_EXE = (Resolve-Path .\dist\Fawusk-alpha-0.7.exe).Path
go test -v ./...
```

Tests include independent Python-produced ZIP fixtures, ZIP64, BZip2/Zstandard, comments/names, metadata dates/sizes, empty items, CRC failure, unsafe paths and native table navigation/saving. Windows executable checks use Wine, **not a real Windows 10/11 machine**. See [testing notes](docs/TESTING.md), included logs and [ZIP behaviour](docs/ZIP_SUPPORT.md). Independent audit and native Windows/DPI/installed-viewer tests remain necessary.

MIT source; [third-party licences](THIRD_PARTY_NOTICES.md). [Indexed FAW 3 specification](docs/FAW_V3_INDEXED.md).

---

## Русский

**Fawusk — минималистичный архиватор для Windows, который мы развиваем как конкурента WinRAR и 7-Zip.** Пока это альфа; превосходство не заявляем.

### Новое в alpha 0.7
- CustomAV 0.5: адаптированный Go-порт статических правил и сигнатур без Python.
- FawReader читает заголовок/версию, каталог и потоки FAW 1/2/3 с проверками путей, размеров и CRC/SHA. Сам сканер проверяет содержимое entry; это не отдельный «обходной антивирус».
- Поддержаны ZIP и ограниченная проверка вложенных FAW/ZIP/JAR одним движком.
- Верхний статус проверки, цвета файлов, краткий отчёт и полный JSON через «…».
- Проверка архива при открытии и создании; повторная проверка потоков перед публикацией распаковки. Частичная проверка не подтверждает весь архив.
- Самостоятельный режим `--scan-customav archive.faw --report new-report.json`.
- Отдельные графические иконки видео, аудио, изображений, PDF, таблиц, презентаций, кода, приложений и данных. Без эмоджи. Колонки и один путь на окно сохранены.

### Обязательно учитывайте
Зелёный статус — «Угрозы не обнаружены», не гарантия отсутствия вирусов. Красный блокирует операции. Жёлтые предупреждения требуют подтверждения пользователя. EICAR — отдельная тестовая сигнатура, не настоящий вирус. Серый, ошибка или неполная проверка не разрешают просмотр/распаковку/публикацию в этой строгой альфе.

**Правила анализируют не более 16 МиБ одного файла**, хотя SHA-256 считается целиком. Большие видео и игровые файлы могут сделать архив неполностью проверенным и заблокировать операцию. Лимиты: 10 000 файлов, 20 ГиБ суммарных данных, 1 ГиБ вложенных данных, глубина 3 и 10 минут. Некоторые контейнеры и разновидности ZIP не поддерживаются.

В базе по умолчанию только EICAR; прочие находки — эвристики либо добавленные сигнатуры. Возможны ложные срабатывания на законные программы, скрипты и тексты. Неподдерживаемая база правил не выдаёт безопасный результат. Отличия от Python-оригинала, неперенесённые функции и политика описаны в `docs/CUSTOMAV.md`; оригинал сохранён в `reference/customav/`.

Проверка декодирует данные и добавляет время открытия/упаковки. Старые показатели скорости к новому полному пути проверки не относятся. Это не Defender, не песочница и не средство гарантированного выявления неизвестных вирусов. Оригиналы не удаляются, файлы никуда не отправляются и сканером не запускаются.

### Запуск
Windows 10/11 x64. EXE без установки, .NET/Mono, Python и администратора; не подписан — сверяйте SHA-256. «Открыть…» → дождаться CustomAV → просмотреть отчёт → распаковать в новую папку. Источники и существующие назначения не перезаписываются. Просмотр разрешённых документов/медиа использует выбранное извлечение в свой Temp и установленное приложение Windows, которое не изолируется.

Размер в архиве — исходные байты файла; для папок/неизвестных значений «—». Даты — локальное время компьютера. Пустые файлы и папки сохраняются; папки не добавляются к сумме файловых данных. Стандартные ZIP Store/Deflate/BZip2/Zstandard и ZIP64 читаются; пароль/AES, многотомные ZIP, Deflate64/ZIP-LZMA, RAR/7z, шифрование и редактирование не реализованы.

FAW-формат не менялся: читаются старые FAW 1/2/3; индексированный FAW 3 совместим с alpha 0.4–0.6. Очистка своего Temp сохранена и остаётся ограниченной/best-effort при блокировках или сбоях. Ссылки/junction/ACL/альтернативные потоки не сохраняются.

Сборка: Go 1.25+; `sh build.sh` или `./build.ps1`. Тесты: `go test ./...`, `go test -race ./...`, `go vet ./...`. Windows EXE проверяется через Wine, не настоящую Windows; независимый аудит и реальные аппаратные тесты ещё нужны. Подробности в `docs/TESTING.md`. Тестируйте на копиях.
