# Fawusk — alpha 0.2

**A compact, portable Windows archiver with ZIP support and an experimental, streaming `.faw` format.**

Windows 10 / 11 x64 · Native Win32 UI · Go · Offline

[English](#english) · [Русский](#русский)

## English

### What's new

- A smaller main window: one **Add** button, a file list, a format selector, **Pack** and **Extract**. Secondary actions live in the **…** menu.
- Save location is requested when packing, rather than occupying the main screen.
- **FAW 2** uses independent **1 MiB Zstandard blocks**. If compression does not shrink a block, the original block is stored instead.
- Hashes are calculated as bytes are written/read: no additional whole-archive hashing pass for FAW 2.
- Reused buffers, one codec worker, bounded decoder output/window, per-block CRC-32 and final SHA-256.
- Reads old **FAW 1** archives from alpha 0.1. New FAW archives are version 2.

This is an alpha, not a claim to outperform WinRAR or 7-Zip. The goal is a competitive archiver developed with reproducible tests, compatibility and clear trade-offs. Test on copies and verify extracted files before using archives as backups.

![Fawusk alpha 0.2 interface](docs/screenshot.png)

### Run

Download `Fawusk-alpha-0.2.exe` and run it as a normal user on Windows 10/11 x64. No installer, Go installation, internet connection or administrator privileges are needed to run it.

1. Click **Добавить…** → **Файлы…** or **Папку…**, or drag items into the window.
2. Choose **FAW** or **ZIP**.
3. Optionally choose **… → Сжатие**: fast (default), balanced or maximum.
4. Click **Упаковать**, then choose a **new** archive name outside the selected source folder.
5. To extract, click **Распаковать…**, select an archive and a parent folder. A new result folder is created.

To remove a selected item use **… → Убрать выбранное** or Delete. **Очистить список** changes only the selection, never source files. Full paths and the last result folder are available from **…**. During work, Extract is replaced by Cancel.

The UI is Russian. The EXE is unsigned: Windows may warn about an unknown publisher. Do not disable security protections to run a binary you do not trust; inspect and build the source instead.

### Formats

| Format | Create | Read |
| --- | --- | --- |
| FAW 2 | Yes | Yes |
| FAW 1 (alpha 0.1) | No GUI option | Yes |
| ZIP | Yes | STORE / DEFLATE, including supported ZIP64 within alpha limits |
| RAR / 7z | No | No |

FAW 2 is an original container using **Zstandard**, not an original compression algorithm. FAW 1 used a ZIP/DEFLATE payload. Alpha 0.1 **cannot read FAW 2**: recipients need alpha 0.2 or use ZIP. A checksum detects damage; it does not authenticate an author or encrypt data. [Format specification](docs/FAW_FORMAT.md).

### Safety and limits

- 100,000 entries, 8 GiB per file, 20 GiB total expanded data.
- FAW 2: aggregate names ≤16 MiB, each name ≤3,000 UTF-8 bytes; bounded 1 MiB blocks. ZIP central directory ≤64 MiB.
- Rejects traversal, absolute/drive/alternate-stream paths, ambiguous names, device names, duplicate case-insensitive paths, deep paths and file/directory conflicts. FAW 2 also rejects inconsistent ancestor casing.
- Rejects source symlinks/junctions/reparse points and special files; link entries and linked destination parents are not supported.
- Writes into temporary files/folders and publishes only after successful checks. Existing archives and result folders are not intentionally overwritten. Cancellation/errors attempt to clean temporary data; a forced termination can leave it behind.
- Not an antivirus or sandbox. Do not execute untrusted extracted files. Concurrent tampering by another local process is outside the protection model.
- No encryption, passwords, archive editing, Explorer integration, split volumes, solid compression, deduplication or NTFS streams/ACL preservation. FAW 2 is sequential; it has no random-access index yet.
- Codec buffers are bounded, but total process memory also includes codecs, runtime and file metadata. Maximum compression uses more CPU. Incompressible and very small inputs can still produce a larger archive due to container overhead.
- Formats remain experimental. Physical maximum-size files and native Windows behavior are not fully verified. See [testing](docs/TESTING.md).

### Build

Use an up-to-date **Go 1.25+** toolchain. Zstandard is provided by pinned `github.com/klauspost/compress v1.20.1`; dependencies are recorded in `go.mod` / `go.sum`. Resources use `go-winres v0.3.3` at build time. No third-party runtime DLL is required.

Windows:

```powershell
./build.ps1
```

If your existing PowerShell policy blocks scripts, run these commands individually rather than weakening it:

```powershell
go mod download
go run github.com/tc-hib/go-winres@v0.3.3 make --arch amd64
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
go build -trimpath -ldflags='-s -w -H=windowsgui' -o dist/Fawusk-alpha-0.2.exe .
```

Linux cross-build: `sh build.sh`. Output: `dist/Fawusk-alpha-0.2.exe` and its checksum. Only the Windows x64 GUI is implemented.

### Test and benchmark

```text
go test -v ./...
go test -race ./...
go test -run=^$ -fuzz=FuzzFAW2Parser -fuzztime=10s
go test -run=^$ -bench BenchmarkFAWFast -benchtime=3x -count=3
```

The race detector needs a supported native C toolchain. For the opt-in Windows GUI test set `FAWUSK_GUI_EXE` to the absolute path of the built EXE and run `go test -run TestWindowsGUI -v`. It exercises selection, the save dialog, packing and a verified FAW 2 round trip.

The microbenchmark compares FAW 1 and FAW 2 **fast presets** on synthetic text and random bytes, includes packing/fsync, and verifies extraction outside the timed section. Allocation figures are not peak RSS; one sample is not a performance guarantee, and this is not a WinRAR/7-Zip benchmark. [Completed checks and gaps](docs/TESTING.md).

### GitHub release

Upload the source repository, create tag **`v0.2.0-alpha.2`**, and attach the EXE with `SHA256SUMS.txt` to the Release. A Russian release description is in `RELEASE_RU.md`. Included GitHub Actions has not already run in your repository. Do not upload private files, toolchain folders or local Wine data.

Source: [MIT](LICENSE). [Third-party notices](THIRD_PARTY_NOTICES.md).

---

## Русский

### Что изменилось

**Fawusk alpha 0.2** — компактный портативный архиватор для Windows с переработанным интерфейсом и новым движком FAW.

- На главном экране: **Добавить…**, список, выбор FAW/ZIP, **Упаковать** и **Распаковать…**. Остальное перенесено в **…**.
- Место сохранения выбирается при упаковке — постоянное поле пути убрано.
- **FAW 2** сжимает независимые блоки по **1 МиБ через Zstandard**. Если блок не уменьшается, он записывается без сжатия.
- Контрольные суммы считаются во время записи/чтения: для FAW 2 нет дополнительного прохода по всему архиву.
- Буферы переиспользуются, кодек работает одним потоком; выход декодера и размер окна ограничены. Есть CRC-32 блоков и итоговая SHA-256.
- Сохранено чтение **FAW 1** из alpha 0.1. Новая упаковка FAW создаёт версию 2.

Мы готовим конкурентный архиватор, но пока **не заявляем превосходство над WinRAR и 7-Zip**. Это альфа: проверяйте её на копиях и сравнивайте извлечённые файлы с исходными, прежде чем полагаться на архив как на резервную копию.

### Как пользоваться

Скачайте `Fawusk-alpha-0.2.exe` и запустите обычным пользователем на Windows 10/11 x64. Установка, Go, сеть и права администратора для запуска не нужны.

1. **Добавить… → Файлы… / Папку…**, либо перетащите объекты в окно.
2. Выберите **FAW** или **ZIP**.
3. При необходимости откройте **… → Сжатие**: быстрое (по умолчанию), сбалансированное или максимальное.
4. Нажмите **Упаковать** и выберите новое имя архива вне исходной папки.
5. Для распаковки нажмите **Распаковать…**, выберите архив и папку, внутри которой появится новая папка с результатом.

Убрать выбранное можно через **…** или Delete. **Очистить список** не удаляет исходные файлы. Полный путь и открытие папки результата доступны в **…**. Во время работы кнопка распаковки заменяется на отмену.

EXE не подписан: Windows может предупредить о неизвестном издателе. Не отключайте защиту для запуска недоверенной сборки; при сомнениях проверяйте исходники и собирайте самостоятельно.

### Форматы и совместимость

- **FAW 2** — упаковка и распаковка.
- **FAW 1** — чтение старых архивов; отдельной кнопки создания старого формата нет.
- **ZIP** — упаковка и распаковка STORE/DEFLATE, ZIP64 в пределах поддерживаемых лимитов.
- **RAR и 7z** пока не поддерживаются.

FAW 2 — собственный контейнер на основе Zstandard, **не новый алгоритм сжатия**. Alpha 0.1 **не читает FAW 2**: для передачи используйте alpha 0.2 или ZIP. Контрольная сумма не шифрует архив и не подтверждает его автора. Подробнее: [спецификация](docs/FAW_FORMAT.md).

### Защита и ограничения

До **100 000 элементов, 8 ГиБ на файл и 20 ГиБ распакованных данных**. Для FAW 2 суммарный размер имён ограничен 16 МиБ, отдельное имя — 3 000 UTF-8 байт; для ZIP каталог ограничен 64 МиБ.

Проверяются опасные и неоднозначные пути, дубликаты без учёта регистра, имена устройств и конфликты файлов/папок. Символические ссылки, junction/reparse points и специальные файлы не предназначены для упаковки. Результат публикуется после проверок без намеренной перезаписи существующих файлов. При отмене выполняется попытка удалить временные данные; после аварии они могут остаться.

Это не антивирус и не песочница. Не запускайте недоверенные извлечённые файлы. Изменение папки другим локальным процессом во время работы не входит в модель защиты.

Пока нет паролей, шифрования, просмотра/редактирования архивов, интеграции с Проводником, многотомных архивов, solid-сжатия, дедупликации, сохранения NTFS-потоков/ACL и индекса произвольного доступа FAW 2. Память процесса включает не только блочные буферы, но и кодек, среду выполнения и сведения о файлах. Максимальное сжатие требует больше CPU; маленькие и несжимаемые данные могут увеличиться из-за служебных записей.

### Сборка и тестирование

Нужен актуальный **Go 1.25+**. Zstandard: зафиксированный `klauspost/compress v1.20.1`, ресурсы: `go-winres v0.3.3`. Зависимости скачиваются при сборке, но для запуска EXE сторонние DLL не нужны.

Windows: `./build.ps1`; Linux: `sh build.sh`. Если политика PowerShell запрещает скрипт, выполните команды из английского раздела, не ослабляя политику. Результат — `dist/Fawusk-alpha-0.2.exe` и SHA-256.

Команды тестов и микробенчмарка — в английском разделе. Измерения на синтетических данных не являются сравнением с WinRAR/7-Zip или гарантией скорости на вашем ПК. Проверки выполнены на Linux и через Wine; полноценный запуск на настоящей Windows, включая junction и разные DPI, ещё нужен. [Отчёт](docs/TESTING.md).

Для GitHub: загрузите исходники, создайте тег **`v0.2.0-alpha.2`**, прикрепите EXE и `SHA256SUMS.txt` к Release. Русский текст релиза — `RELEASE_RU.md`. Не публикуйте личные тестовые данные и папки инструментов.

Лицензия исходников — [MIT](LICENSE); зависимости — [уведомления](THIRD_PARTY_NOTICES.md).
