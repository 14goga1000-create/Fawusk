# Fawusk — alpha 0.7.1

**A minimal local Windows archiver being developed as a competitor to WinRAR and 7-Zip.** Early alpha; no demonstrated speed/compression/security superiority. Test on copies of important files.

## English

### New in alpha 0.7.1
- **CustomAV Faw Edition** policy/API integration, retaining the existing native adapted CustomAV 0.5 detector. Mandatory instruction and unchanged supplied reference are in `reference/customav_faw_edition/`.
- Actual `FawReader.Entries(context.Context)` adapter: entry paths, sizes, encryption flags, validated streams and available SHA-256 metadata. Production retains sequential solid decoding rather than opening every entry repeatedly.
- Hardened metadata preflight, explicit clean/review/test/incomplete distinctions and detailed JSON reports.
- **Всё равно** lets the user explicitly accept a warning or limited analysis for an intact archive. Confirmation defaults to No, binds to the current archive SHA-256/size and can be revoked with **Снять риск**. The original verdict/colour/scores remain unchanged.
- Ceremonial open-source cooperation with CustomAV Project: [memorandum](docs/cooperation/MEMORANDUM_SIGNED_RU.md), [confirmation](COOPERATION_CONFIRMED.md). This is not a legally binding company contract or verified electronic signature.

### Security scope — please read
Green means **no positive indicators under these static rules**, not virus-free. Red blocks operations by default; an explicit archive-scoped risk exception can enable extraction and permitted previews. Yellow review requires GUI confirmation. EICAR is a harmless test detection, not real malware. Grey/failed/partial scanning never becomes green or grants whole-archive approval. Limited analysis of an otherwise intact fully decoded archive can be overridden explicitly; corrupt/encrypted/unsafe paths, structural quotas and partial-only approval cannot. Newly-created archive publication remains strict. Originals are neither executed nor deleted/uploaded. Scanner is not a sandbox or a replacement for Defender.

**Content analysis is limited to 16 MiB per file** (full SHA-256 is still read). Larger files produce incomplete scanning and are blocked by default, including ordinary large videos/game files; accepting the risk does not make their scan complete. Additional bounds: 10,000 scanned file records, 20 GiB cumulative data, 1 GiB nested decoded bytes, depth 3 and 10-minute deadline. Script/text rule limits are 2/10 MB. Nested unsupported containers and unported/unknown threats remain limitations.

The embedded signature database contains **EICAR only**, not a real-malware corpus. Detection otherwise uses explainable heuristics; legitimate scripts/installers/command documentation can produce false positives. A sidecar `customav_signatures.json` supplements the database; invalid rules fail closed. This is an **adapted port**, not byte-identical feature parity with every Python reference rule. See [CustomAV integration and limits](docs/CUSTOMAV.md) for preserved rules and omitted entropy/packer/manifest/reputation features. Full security scanning decodes data and adds latency; earlier speed figures are not benchmarks of this path.

### Size and date semantics
Archive Size is the **original/uncompressed file size**, not its individual compressed contribution inside a shared solid group. Folders and unknown values show `—`. Size units use 1024 bytes (`КБ`, `МБ`, `ГБ`); values are rounded for display, and tiny nonzero files are distinguished from zero. Modification dates are displayed in the **computer's local time**, to minute precision; archive records retain their available seconds. Missing dates and implicit ZIP/FAW parent-directory dates are not invented.

The filesystem summary adds known **regular-file sizes directly in the current folder**; it does not recursively scan folders or include directory-allocation bytes. Files and folders are counted separately. Archive data totals add regular-file bytes, not empty-directory metadata. Empty-folder records necessarily occupy some bytes in the archive format: excluding them from payload totals is not a claim of zero archive overhead.

### Download and use
Windows 10/11 **x64**. Download `Fawusk-alpha-0.7.1.exe` from Releases and run it. No installer, .NET/Mono or administrator rights. EXE is unsigned: check its SHA-256 and source; do not disable antivirus globally.

Use **Открыть…** or drag/drop one path. Additional paths open separate windows. Double-click folders to navigate. Choose FAW 3 Recommended / FAW 2 Classic / FAW 1 Compatibility / ZIP and Fast / Good / Maximum, then **Упаковать**. Open an archive and select **Распаковать…** to create a new directory. Source files and existing output files are not overwritten. Ordinary single files retain their path-only view and open through the Windows association.

Click Name/Size/Date to toggle sorting. Open a permitted archived photo, video, audio or document with a double-click: only the selected file is written under its private Temp content directory and then opened by your installed associated application. Executables, scripts, shortcuts, macro documents and recognised disguised executable names/signatures are blocked for archive preview. Unsupported files require normal extraction and your own safety assessment; extraction never automatically launches them. External viewers must be trusted and updated: this is **not antivirus or a sandbox**.

### Compatibility, ZIP limits and safety
Reads FAW 1/2, continuous alpha 0.3 FAW 3, indexed alpha 0.4/0.5 FAW 3 and ZIP. Writes FAW 1/2/3 and ZIP. The indexed FAW 3 flags=1 wire format is unchanged; alpha 0.4/0.5 can read alpha 0.7.1 archives. Alpha 0.3 cannot read indexed FAW 3.

**Not every ZIP variant is supported.** Password/encrypted ZIP (including AES), multi-volume ZIP, Deflate64, ZIP-LZMA and other unimplemented methods are rejected explicitly. Legacy encodings other than CP437 are not guessed; UTF-8 or Unicode Path metadata is preferred. Zstandard window/memory is bounded to 64 MiB for ZIP. Unknown/corrupt/unsafe archives do not become trusted just because their catalogue opens. File CRC for ZIP and SHA-256/CRC for FAW detect corruption, not malware or authorship. Full extraction uses a staged new directory and checks file contents before publication.

Limits: 100,000 paths, 8 GiB/file, 20 GiB uncompressed total, bounded catalogue/names and decoder memory, 1 GiB/preview. Links/reparse points, device files, ACLs, alternate data streams and hard-link identity are unsupported. RAR, 7z, encryption and archive editing remain unimplemented. This is not a full Windows Explorer or system-backup replacement.

### Temp and resource use
Alpha 0.5's owned Temp cleanup is retained: normal close removes preview roots, a windowless helper retries Windows deletion locks for up to two minutes after owner exit, and a later launch attempts marked-orphan recovery. Other Temp data and live windows' roots are not deleted. Locked files, crashes/permissions/helper failure can leave data; instant or forensic deletion cannot be guaranteed. Old unmarked `Fawusk-view-*` directories require manual cleanup after closing viewers. See [Temp lifecycle](docs/TEMP_CLEANUP.md).

FAW 3 retains capped codec scheduling (up to three workers with a four-core CPU budget) and reused buffers. This mini-release changes security integration and consent policy, not the compression engine; no physical four-core performance or peak-RSS benchmark is claimed. The archiver has no telemetry/network/update client; an external viewer may have its own network behaviour.

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
$env:FAWUSK_GUI_EXE = (Resolve-Path .\dist\Fawusk-alpha-0.7.1.exe).Path
go test -v ./...
```

Tests include independent Python-produced ZIP fixtures, ZIP64, BZip2/Zstandard, comments/names, metadata dates/sizes, empty items, CRC failure, unsafe paths and native table navigation/saving. Windows executable checks use Wine, **not a real Windows 10/11 machine**. See [testing notes](docs/TESTING.md),  [ZIP behaviour](docs/ZIP_SUPPORT.md). Independent audit and native Windows/DPI/installed-viewer tests remain necessary.

MIT source; [third-party licences](THIRD_PARTY_NOTICES.md). [Indexed FAW 3 specification](docs/FAW_V3_INDEXED.md).

---

## Русский

**Fawusk — минималистичный архиватор для Windows, который мы развиваем как конкурента WinRAR и 7-Zip.** Пока это альфа; превосходство не заявляем.

### Новое в alpha 0.7.1
- Интеграция **CustomAV Faw Edition**: reader-адаптер FAW и усиленный слой проверок метаданных. Существующие адаптированные правила CustomAV 0.5 сохранены; это не обещание полноценного коммерческого антивируса.
- Кнопка **«Всё равно»** с отдельным подтверждением «на свой риск». Разрешение привязано к SHA-256/размеру текущего архива и текущему окну; **«Снять риск»** возвращает блокировку.
- Предупреждения, цвет, оценки и неполная проверка не скрываются; JSON фиксирует `user_override` и время подтверждения.
- Проверки целостности, опасных путей, лимитов, шифрования и запрет прямого открытия программ/скриптов из архива не отключаются.
- Проектный меморандум о сотрудничестве с CustomAV: `docs/cooperation/`, подтверждение `COOPERATION_CONFIRMED.md`. Подписи — текстовые церемониальные подтверждения, не юридические или квалифицированные электронные подписи.

### Обязательно учитывайте
Зелёный статус — «Угрозы не обнаружены», не гарантия отсутствия вирусов. Красный блокирует операции по умолчанию; «Всё равно» позволяет явно принять риск для структурно целого архива. Жёлтые предупреждения требуют подтверждения пользователя. EICAR — отдельная тестовая сигнатура, не настоящий вирус. Неполная проверка не становится зелёной. Ограниченность анализа целого архива можно принять на свой риск; повреждение, шифрование, опасные пути, превышение структурных лимитов и проверку только одного файла обойти нельзя. Создание архивов сохраняет строгую проверку перед публикацией.

**Правила анализируют не более 16 МиБ одного файла**, хотя SHA-256 считается целиком. Большие видео и игровые файлы могут сделать архив неполностью проверенным и заблокировать операцию. Лимиты: 10 000 файлов, 20 ГиБ суммарных данных, 1 ГиБ вложенных данных, глубина 3 и 10 минут. Некоторые контейнеры и разновидности ZIP не поддерживаются.

В базе по умолчанию только EICAR; прочие находки — эвристики либо добавленные сигнатуры. Возможны ложные срабатывания на законные программы, скрипты и тексты. Неподдерживаемая база правил не выдаёт безопасный результат. Отличия от Python-оригинала, неперенесённые функции и политика описаны в `docs/CUSTOMAV.md`; оригинал сохранён в `reference/customav/`.

Проверка декодирует данные и добавляет время открытия/упаковки. Старые показатели скорости к новому полному пути проверки не относятся. Это не Defender, не песочница и не средство гарантированного выявления неизвестных вирусов. Оригиналы не удаляются, файлы никуда не отправляются и сканером не запускаются.

### Запуск
Windows 10/11 x64. EXE без установки, .NET/Mono, Python и администратора; не подписан — сверяйте SHA-256. «Открыть…» → дождаться CustomAV → просмотреть отчёт → распаковать в новую папку. Источники и существующие назначения не перезаписываются. Просмотр разрешённых документов/медиа использует выбранное извлечение в свой Temp и установленное приложение Windows, которое не изолируется.

Размер в архиве — исходные байты файла; для папок/неизвестных значений «—». Даты — локальное время компьютера. Пустые файлы и папки сохраняются; папки не добавляются к сумме файловых данных. Стандартные ZIP Store/Deflate/BZip2/Zstandard и ZIP64 читаются; пароль/AES, многотомные ZIP, Deflate64/ZIP-LZMA, RAR/7z, шифрование и редактирование не реализованы.

FAW-формат не менялся: читаются старые FAW 1/2/3; индексированный FAW 3 совместим с alpha 0.4–0.6. Очистка своего Temp сохранена и остаётся ограниченной/best-effort при блокировках или сбоях. Ссылки/junction/ACL/альтернативные потоки не сохраняются.

Сборка: Go 1.25+; `sh build.sh` или `./build.ps1`. Тесты: `go test ./...`, `go test -race ./...`, `go vet ./...`. Windows EXE проверяется через Wine, не настоящую Windows; независимый аудит и реальные аппаратные тесты ещё нужны. Подробности в `docs/TESTING.md`. Тестируйте на копиях.

MIT includes warranty/liability disclaimers, not universal legal immunity. CustomAV Faw Edition is included under its supplied MIT licence (Copyright 2026 CustomAV Project); the full licence and upstream notice are preserved in docs/licenses/ and reference/customav_faw_edition/. See THIRD_PARTY_NOTICES.md.

MIT содержит отказ от гарантий, но не даёт безусловного юридического иммунитета. CustomAV Faw Edition включён по переданной лицензии MIT (Copyright 2026 CustomAV Project). Полный текст и NOTICE сохранены в docs/licenses/ и reference/customav_faw_edition/; см. THIRD_PARTY_NOTICES.md.

## Source-only distribution / Архив только исходников
This archive contains code, tests, build resources, licences and text documentation only. No EXE, compiled resources, release cover/screenshots, PDF, logs or demo archives. Original independent ZIP fixture bytes are preserved as Base64 test source literals in archive_fixtures_test.go and materialised only in test-owned temporary directories. winres/icon*.png are required build assets, not release artwork.

В архиве только код, тесты, ресурсы сборки, лицензии и текстовая документация. EXE, скомпилированные ресурсы, обложки, скриншоты, PDF, логи и демонстрационные архивы исключены. Тестовые ZIP хранятся как строковые данные в исходнике теста; иконки winres нужны для сборки приложения.
