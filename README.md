# Fawusk — alpha 0.4

**A minimal, local Windows archiver being developed as a competitor to WinRAR and 7-Zip.** The project is early-stage: superior speed, compression ratio and security have **not** been demonstrated. Test on copies of your files.

![Fawusk alpha 0.4](docs/release-cover.png)

## English

### What's new
- **One open path per window.** Browse a folder or an archive; regular files show their path. Extra paths open in separate windows.
- **Indexed FAW 3 solid groups.** Files share compression history within 8 MiB groups. Two groups can compress in parallel, memory is bounded, and incompressible groups use STORE. A compact catalogue opens without decompressing the whole archive.
- **Selected-file viewer.** Double-click supported pictures, videos, audio or documents inside an archive. Only the selected file is written to a private, randomly named `%TEMP%\Fawusk-view-*` directory and then opened with your Windows-associated application. FAW 3 indexed archives decode only the required groups. Older archives may require decoding the entire stream, but other files are discarded, not written.
- **Preview restrictions.** Executables, scripts, shortcuts, macro-enabled Office documents, misleading executable extensions and recognized executable signatures cannot be launched from the archive. OOXML macro/ActiveX/embedded-object/external-relationship checks are conservative; rejected files require normal extraction.
- **Human presets:** Fast / Good / Maximum (Russian UI: «Быстрый», «Хороший», «Максимальный»). Format choices: FAW 3 / FAW 2 / FAW 1 / ZIP.

### Download and use
Windows 10/11 **x64**. Download `Fawusk-alpha-0.4.exe` from Releases, put it in a folder and run it. No installer, .NET, Mono or administrator rights are required. The EXE is unsigned; Windows may show a reputation warning. Check the published SHA-256 and use files from the repository owner. Do not disable antivirus globally.

Open one file/folder/archive using **Открыть…** or drag it into the window. Select the format and preset, then **Упаковать**. To extract, open an archive and choose **Распаковать…**. Extraction creates a **new** directory; existing files and source files are not overwritten. Double-click folders to navigate and supported archive files to preview. Unsupported/blocked files must be fully extracted and checked before any external launch.

Supported preview extensions: JPG/JPEG, PNG, GIF, BMP, WebP, TIFF, MP4/M4V/MOV, MKV/WebM, AVI, MP3/WAV/FLAC/OGG, TXT/MD/CSV, PDF and restricted DOCX/XLSX/PPTX. A suitable Windows application must be installed. Not every codec/document will be recognized by that application.

### Compatibility and limitations
- Reads legacy FAW 1, FAW 2, original alpha 0.3 FAW 3, indexed alpha 0.4 FAW 3, and ZIP. Writes FAW 1/2/3 and ZIP. **RAR and 7z are not implemented**; no RAR-writing promise or renamed ZIP masquerading as RAR.
- **New indexed FAW 3 files require Fawusk alpha 0.4 or later. Alpha 0.3 cannot read them.** Choose FAW 1/2 or ZIP when sending files to older versions. FAW 1 is a legacy ZIP-based container, not labelled unstable without evidence.
- SHA-256 and CRC detect accidental corruption; they do **not** establish authorship or guarantee that files are safe. Fast catalogue listing validates metadata, **not all payload**. Data is checked when its groups are read; full extraction checks every file.
- Preview is **not an antivirus or a sandbox**. PDF, media and Office renderers may have vulnerabilities; use updated trusted applications. Passwords/encryption, ACLs/alternate data streams, hard-link identity, device files and symbolic/reparse links are unsupported. File bytes, relative names, empty directories and modification timestamps are the supported data model; this is not a complete system-backup tool.
- Limits: 100,000 paths, 8 GiB per file, 20 GiB total uncompressed data, 16 MiB names and 32 MiB indexed catalogue. Preview: 1 GiB per selected file. The bounded worker pipeline avoids loading the full archive into RAM, but «Maximum» is slower and uses more memory.
- Temporary preview files remain until the next preview or window close, so viewers can access them. Both actions attempt cleanup. A locked file or a crash can leave temporary files; close viewers and delete the corresponding `Fawusk-view-*` directory if needed.
- The archiver itself has no network features, telemetry or update client. An external viewer can have its own network behaviour.

### Performance goal, not a guarantee
The requested **5 GB in 5–6 seconds** remains a development target, **not achieved or guaranteed in this release**. Compression speed and size depend on data, preset, CPU, storage and cache. JPEG/video and already compressed archives may barely shrink. Independent 8 MiB solid groups improve random access and parallelism, but can compress less well than an unrestricted single solid stream. No WinRAR/7-Zip benchmark has been performed.

An engineering test processed a **5 GiB sparse zero-filled file** in about **11.23 seconds** on a 2-vCPU Linux sandbox with other build/test work present; a complete extraction and original/restored SHA-256 comparison passed. This synthetic case is not representative of Windows, mixed files, real disks or cold-cache performance. See [testing notes](docs/TESTING.md).

### Build and test
Requires Go **1.25+** (release built with Go 1.27.2), internet for initial module/resource-tool downloads.

```sh
go test ./...
go test -race ./...    # supported host with a C toolchain
go vet ./...
sh build.sh           # Linux cross-build to dist/Fawusk-alpha-0.4.exe
```

Windows PowerShell:
```powershell
.\build.ps1
$env:FAWUSK_GUI_EXE = (Resolve-Path .\dist\Fawusk-alpha-0.4.exe).Path
go test -v ./...
```

Opt-in engineering stress test (needs approximately 6 GiB disk space and time for hashing):
```sh
FAWUSK_5G_BENCH=1 go test -run '^TestFiveGiBOptIn$' -v -count=1 -timeout=10m
```

[Indexed format specification](docs/FAW_V3_INDEXED.md) · [Legacy FAW 3](docs/FAW_FORMAT.md) · [FAW 2](docs/FAW_V2.md) · [FAW 1](docs/FAW_V1.md) · [Third-party notices](THIRD_PARTY_NOTICES.md)

---

## Русский

**Fawusk — минималистичный локальный архиватор для Windows, который мы развиваем как конкурента WinRAR и 7-Zip.** Пока это ранняя альфа: превосходство по скорости, сжатию и безопасности не доказано. Проверяйте программу на копиях файлов.

### Что изменилось в alpha 0.4
- **Один открытый путь на окно:** папка, файл или архив. Папки и архивы показывают содержимое; обычный файл — свой путь. Дополнительные пути открываются отдельными окнами.
- **Индексированный FAW 3:** solid-группы по 8 МиБ, два параллельных задания, компактный каталог и хранение несжимаемых групп без дополнительного сжатия. Открытие нового архива не требует декодировать все данные.
- **Просмотр выбранного файла:** двойной клик извлекает только выбранное фото, видео, аудио или документ в отдельную случайную папку Temp и открывает его приложением Windows. Новый FAW 3 читает нужные группы; старые solid-архивы могут требовать декодирования всего потока, но остальные файлы на диск не записываются.
- **Ограничения просмотра:** запрещены приложения, скрипты, ярлыки, макросодержащие документы и маскировка вроде `virus.exe.txt`. Проверяются известные сигнатуры исполняемых файлов и активное содержимое OOXML. Не прошедший проверку файл можно только обычным образом распаковать, затем самостоятельно проверить.
- **Понятные настройки:** «Быстрый», «Хороший», «Максимальный»; форматы FAW 3, FAW 2, FAW 1 и ZIP. Настройки вынесены прямо в окно, без лишнего подменю.

### Запуск
Windows 10/11 x64. Скачайте `Fawusk-alpha-0.4.exe` из Releases и запустите: установка, .NET/Mono и права администратора не требуются. EXE не подписан, поэтому Windows может предупредить о репутации файла. Сверяйте SHA-256 и источник загрузки; не отключайте антивирус целиком.

«Открыть…» → выберите путь → формат и сжатие → «Упаковать». Для распаковки откройте архив и нажмите «Распаковать…»: будет создана новая папка. Исходные файлы и существующие результаты не перезаписываются. Двойной клик по папке — переход, по разрешённому файлу в архиве — просмотр внешним приложением.

### Важно
- Читаются FAW 1/2, старый FAW 3 из alpha 0.3, новый FAW 3 из alpha 0.4 и ZIP. **Новый FAW 3 не открывается в alpha 0.3**; для обмена со старыми версиями выбирайте FAW 1/2 или ZIP. RAR, 7z и шифрование пока не реализованы.
- Просмотр — **не антивирус и не песочница**. Поддерживаемые типы перечислены в английской секции выше. Для них нужны установленные и обновлённые приложения Windows; они могут иметь собственные уязвимости и сетевые функции.
- SHA-256/CRC обнаруживают повреждение, но не доказывают безопасность или авторство. Быстрое открытие проверяет каталог; данные проверяются при чтении соответствующих групп и полной распаковке.
- Лимиты: 100 000 путей, 8 ГиБ на файл, 20 ГиБ на архив; просмотр — 1 ГиБ на выбранный файл. Символические/reparse-ссылки, специальные файлы, ACL и альтернативные потоки не сохраняются. Это не полноценный инструмент резервного копирования системы.
- Временные файлы хранятся до следующего просмотра или закрытия окна. Очистка выполняется по возможности; после сбоя или блокировки внешним приложением папка `Fawusk-view-*` может остаться в Temp.
- **5 ГБ за 5–6 секунд — пока цель, а не результат релиза.** Тест синтетического файла из нулей размером 5 ГиБ в Linux-среде с 2 vCPU занял около 11,23 с на упаковку; после распаковки SHA-256 совпал. На этом ПК параллельно шли сборочные/тестовые задачи. Это не результат для Windows или обычных данных и не сравнение с WinRAR/7-Zip. Степень сжатия зависит от содержимого; ограниченные solid-группы иногда уступают одному непрерывному потоку.

Исходники — под MIT; сторонние лицензии приложены. Сборка и проверки описаны выше. Перед публикацией собственного релиза дополнительно проверьте EXE на реальной Windows 10/11.
