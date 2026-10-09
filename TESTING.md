# Alpha 0.4 delivery checks

## Environment
Go 1.27.2; 2-vCPU Linux sandbox; Windows/amd64 CGO-disabled cross-build. Native GUI EXE has icon, alpha 0.4 version resource and long-path-aware/as-invoker manifest. Windows checks used Wine 10.0, UTF-8 locale and Xvfb. **No real Windows 10/11 machine was available.** EXE is unsigned. No independent security audit, antivirus certification or superiority over WinRAR/7-Zip is claimed.

## Automated checks
- Linux: **41 top-level Test functions passed** with race detector; opt-in stress/demo helpers skipped in normal suite. Fuzz seed tests passed separately from this count.
- Windows test binary under Wine: **43 top-level Test functions passed**, including real GUI folder navigation/modern save/FAW packing and plain-file path-only view. Source-symlink test explicitly skipped under Wine; stress/demo helpers skipped unless opted in. Linux source-symlink checks passed.
- ZIP and FAW round trips across presets; legacy FAW 1, FAW 2, original flags=0 FAW 3 and new flags=1 FAW 3 compatibility.
- Random binary multi-group/multi-file fixture (~38 MiB), empty files/directories and Unicode; original and restored byte equality / SHA-256 comparisons.
- Indexed selective extraction writes exactly one selected file and required directories. An unrelated corrupted group is not decoded for a selected file in another group; full extraction rejects it and publishes no directory. Listing intentionally does not verify payload.
- Header/catalogue/group corruption, truncation, recomputed malicious metadata hashes, unsafe paths, oversized quotas/offsets, conflicts and decoder output bounds rejected.
- Cancellation with compression tasks in flight: no archive published, temporary files cleaned. Existing destinations unchanged.
- Executable/script/shortcut/macro extensions, double executable extensions, bidirectional format characters and disguised PE bytes rejected for preview. OOXML macro and external relationship fixtures rejected; non-active OOXML fixture accepted.
- Distant long Unicode output/extraction paths >260 characters, ZIP and FAW; passed under Linux and Wine. Native UNC shares, group policies and other viewers' long-path limits remain unverified.
- Linux `go vet` and race detector passed; Windows GUI was not race-instrumented.
- 12-second indexed parser fuzz run with valid and invalid seeds: **148,135 executions**, no crash. This is not a comprehensive fuzz campaign or audit. Raw logs included.

## 5 GiB stress test
`FAWUSK_5G_BENCH=1 go test -run '^TestFiveGiBOptIn$' -v -count=1 -timeout=10m` ran a **5,368,709,120-byte sparse zero-filled file** at Fast preset through the indexed writer and full reader. Archive size: 1,067,751 bytes. Pack wall time: 11.226 seconds; complete test including extraction and SHA-256 comparison: 34.32 seconds. Original/restored SHA-256 matched.

This was a synthetic, exceptionally compressible Linux test on 2 vCPU, with concurrent build/test tasks and cache/sparse-file effects. The archive size is not a real-world compression ratio claim. This does not establish Windows speed, disk throughput, mixed-file performance, peak RSS, or superiority over WinRAR/7-Zip. **The 5–6 second goal was not achieved.** No native Windows or competitor performance benchmark was performed.

## Manual GUI checks
Actual EXE folder view and indexed archive navigation were visually inspected. Only one path/archive was shown per window, with presets and formats visible for packing and hidden inside the archive. A selected archive TXT was opened with Wine Notepad externally, using a `.txt` association configured only inside the isolated Wine prefix. Exactly one preview file was found in its randomly named Temp directory, and its bytes matched the source. UTF-8 BOM in the demonstration TXT was supplied by that fixture, not inserted by the archiver; files are not rewritten to fit a viewer's encoding.

Temp cleanup is best-effort on next preview and window close. Locked files and crashes may leave directories. The actual native GUI screenshot is used in the release cover, not a mock application window.

## Remaining gaps
Real Windows 10/11, multiple DPI/monitors, installed media/Office/PDF applications and codecs, actual NTFS reparse/UNC behaviour, crash/power-loss recovery, representative performance/memory corpus, native security review and sustained malicious-input testing are needed. External viewers are not sandboxed; checks are conservative, not complete malware detection. General archive editing, encryption, RAR/7z and backup metadata preservation remain unsupported. GitHub Actions configuration is included but has not run in a published repository here.

## Русский
Проверены Linux-ядро, Windows EXE через Wine, совместимость, кириллица/длинные пути, побайтовая сохранность, выбранное извлечение, повреждения, отмена и политика просмотра. Для 5 ГиБ синтетических нулевых данных SHA-256 после распаковки совпал, но цель 5–6 секунд не достигнута. Настоящая Windows и независимый аудит ещё нужны. Быстрое открытие проверяет только каталог; полная распаковка проверяет данные всех файлов. Это альфа и не антивирус.
