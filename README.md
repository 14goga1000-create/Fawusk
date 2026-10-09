# Fawusk — alpha 0.6

**A minimal local Windows archiver being developed as a competitor to WinRAR and 7-Zip.** This is an early test release, not a demonstrated speed/compression/security winner. Test on copies of important files.

![Fawusk alpha 0.6](docs/release-cover.png)

## English

### New in alpha 0.6
- **Details table:** Name / Size / Modified date, native vector pictograms and clickable column sorting. Folders stay first. A virtual Win32 report view generates text for requested rows instead of inserting a separate native item/string for every file.
- **Real metadata:** filesystem file sizes/timestamps are loaded in a cancellable background task. Indexed FAW 3 uses sizes and modification seconds already stored in its compact catalogue; no format change. Legacy FAW and ZIP metadata are also shown.
- **Broader ZIP reading:** Store, Deflate, BZip2 (method 12) and Zstandard (methods 20/93); ZIP64, data descriptors, comments, UTF-8, standard legacy CP437 names and valid Unicode Path extras. Relative Windows backslashes, harmless `./` prefixes and repeated internal separators are normalised safely; absolute/device paths, `..`, links and ambiguous file collisions are rejected.
- **Catalogue-only ZIP opening:** listing doesn't decompress every file. CRC/content errors are detected during extraction/preview, not necessarily during listing. Selected ZIP preview reads only the chosen file.
- **Empty items:** zero-byte files display `0 КБ`; folders have no file size and are excluded from byte totals. Empty folders/archives remain browsable/extractable. Repeated identical directory records in ZIP are tolerated; duplicate files are not silently overwritten.

### Size and date semantics
Archive Size is the **original/uncompressed file size**, not its individual compressed contribution inside a shared solid group. Folders and unknown values show `—`. Size units use 1024 bytes (`КБ`, `МБ`, `ГБ`); values are rounded for display, and tiny nonzero files are distinguished from zero. Modification dates are displayed in the **computer's local time**, to minute precision; archive records retain their available seconds. Missing dates and implicit ZIP/FAW parent-directory dates are not invented.

The filesystem summary adds known **regular-file sizes directly in the current folder**; it does not recursively scan folders or include directory-allocation bytes. Files and folders are counted separately. Archive data totals add regular-file bytes, not empty-directory metadata. Empty-folder records necessarily occupy some bytes in the archive format: excluding them from payload totals is not a claim of zero archive overhead.

### Download and use
Windows 10/11 **x64**. Download `Fawusk-alpha-0.6.exe` from Releases and run it. No installer, .NET/Mono or administrator rights. EXE is unsigned: check its SHA-256 and source; do not disable antivirus globally.

Use **Открыть…** or drag/drop one path. Additional paths open separate windows. Double-click folders to navigate. Choose FAW 3 Recommended / FAW 2 Classic / FAW 1 Compatibility / ZIP and Fast / Good / Maximum, then **Упаковать**. Open an archive and select **Распаковать…** to create a new directory. Source files and existing output files are not overwritten. Ordinary single files retain their path-only view and open through the Windows association.

Click Name/Size/Date to toggle sorting. Open a permitted archived photo, video, audio or document with a double-click: only the selected file is written under its private Temp content directory and then opened by your installed associated application. Executables, scripts, shortcuts, macro documents and recognised disguised executable names/signatures are blocked for archive preview. Unsupported files require normal extraction and your own safety assessment; extraction never automatically launches them. External viewers must be trusted and updated: this is **not antivirus or a sandbox**.

### Compatibility, ZIP limits and safety
Reads FAW 1/2, continuous alpha 0.3 FAW 3, indexed alpha 0.4/0.5 FAW 3 and ZIP. Writes FAW 1/2/3 and ZIP. The indexed FAW 3 flags=1 wire format is unchanged; alpha 0.4/0.5 can read alpha 0.6 archives. Alpha 0.3 cannot read indexed FAW 3.

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
$env:FAWUSK_GUI_EXE = (Resolve-Path .\dist\Fawusk-alpha-0.6.exe).Path
go test -v ./...
```

Tests include independent Python-produced ZIP fixtures, ZIP64, BZip2/Zstandard, comments/names, metadata dates/sizes, empty items, CRC failure, unsafe paths and native table navigation/saving. Windows executable checks use Wine, **not a real Windows 10/11 machine**. See [testing notes](docs/TESTING.md), included logs and [ZIP behaviour](docs/ZIP_SUPPORT.md). Independent audit and native Windows/DPI/installed-viewer tests remain necessary.

MIT source; [third-party licences](THIRD_PARTY_NOTICES.md). [Indexed FAW 3 specification](docs/FAW_V3_INDEXED.md).

---

## Русский

**Fawusk — минималистичный локальный архиватор для Windows, который мы развиваем как конкурента WinRAR и 7-Zip.** Пока это альфа: превосходство не доказано, используйте копии важных файлов.

### Что нового
- **Таблица «Имя / Размер / Дата изменения»** вместо простого списка. Графические иконки, сортировка по колонкам и папки первыми. Эмоджи для интерфейса не используются.
- **Размеры и даты** берутся из файловой системы, каталогов FAW и ZIP. В компактном FAW 3 эти поля уже хранились — совместимость менять не понадобилось. Даты показаны в локальном времени компьютера.
- **Расширена поддержка ZIP:** Store, Deflate, BZip2, Zstandard, ZIP64, комментарии, дескрипторы данных, UTF-8, стандартные имена CP437 и Unicode Path. Поддержаны безопасные относительные Windows-пути и префиксы `./`.
- **Открытие ZIP по каталогу** без предварительного декодирования всех файлов; выбранный просмотр читает только нужный ZIP-файл. CRC проверяется при извлечении, а не при быстром просмотре каталога.
- **Пустые элементы:** файл 0 байт виден как «0 КБ», папки не прибавляются к файловым данным. Пустые папки и ZIP сохраняются и распаковываются корректно.

### Как понимать размер
В архиве колонка показывает размер исходного файла, а не его отдельный «вес» внутри solid-сжатия. Для папок и неизвестных значений — «—». КБ/МБ/ГБ считаются по 1024, значения округлены. Размер папок рекурсивно не вычисляется; сумма файлов обычной папки относится к её текущему уровню. Папки не считаются файлами и не добавляют байты данных, но их записи неизбежно занимают немного места в самом архиве. Отсутствующая дата не выдумывается.

### Запуск
Windows 10/11 x64. Скачайте `Fawusk-alpha-0.6.exe` и запустите: установка, .NET/Mono и администратор не нужны. EXE не подписан — сверяйте SHA-256.

«Открыть…» → файл, папка или архив → формат и сжатие → «Упаковать». Для ZIP/FAW откройте архив и нажмите «Распаковать…»: будет создана новая папка без перезаписи. Двойной клик по папке — переход; по разрешённому файлу в архиве — выбранное извлечение в Temp и открытие приложением Windows. Один открытый путь на окно сохранён.

### Ограничения
ZIP с паролем/AES, многотомные архивы, Deflate64, ZIP-LZMA и другие не реализованные методы пока не поддерживаются. Старые кодировки, кроме CP437, не угадываются. RAR, 7z, шифрование и редактирование архивов отсутствуют. Лимиты: 100 000 путей, 8 ГиБ/файл, 20 ГиБ/архив; просмотр до 1 ГиБ/файл. Ссылки, специальные файлы, ACL и альтернативные потоки не сохраняются.

FAW 3 совместим с alpha 0.4/0.5; старые FAW 1/2/3 читаются. Быстрое открытие каталога не доказывает целостность всех данных. Проверки CRC/SHA обнаруживают повреждения, но не вирусы или авторство. Приложения/скрипты/ярлыки/макросы запрещены для запуска из архива; просмотрщик не является антивирусом или песочницей.

Очистка своих Temp-файлов при закрытии, повторные попытки для блокировок и восстановление при следующем запуске сохранены. Чужой Temp не удаляется. Мгновенная очистка при любых сбоях и блокировках не гарантируется.

В этой версии нет нового измерения скорости на физическом четырёхъядерном ПК. Виртуальная таблица, фоновое чтение метаданных и каталог ZIP без полного декодирования уменьшают лишнюю работу, но превосходство над конкурентами не заявляем. Windows-сборка проверяется через Wine; настоящая Windows ещё требует тестирования. Исходники, сборка, тесты и лицензии приложены.
