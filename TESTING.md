# Delivery test report — alpha 0.1

## Build

- Go 1.27.1, current stable version reported by the Go downloads endpoint during preparation.
- Windows / amd64; CGO disabled; native Win32 GUI subsystem; no external runtime DLLs shipped.
- EXE includes an application icon, version resource, and an as-invoker manifest.
- Built successfully using the repository's `build.sh`, not just an ad-hoc compilation command.
- EXE is unsigned. No malware scan, penetration test, independent audit, or performance comparison is claimed.

## Completed checks

- Linux core suite: 18 top-level tests/seed suites passed, including six format/level round trips.
- Round trips for ZIP and FAW at DEFLATE levels 1, 6, 9; Unicode paths; empty files and directories; binary content.
- Existing-output preservation and prevention of writing an archive inside its own source folder.
- Traversal, absolute and drive paths, reserved Windows names, duplicate case-insensitive names, and file/directory conflicts rejected.
- Corrupted FAW headers, payloads and digests rejected; corrupted ZIP file CRC rejected without publishing a partial destination.
- ZIP link entries rejected; real source symlinks rejected on Linux.
- Existing extraction destinations rejected; declared oversized files and oversized central directories rejected.
- Cancellation before an operation and during packing/extraction; temporary-data cleanup checked.
- Race detector: passed for the Linux core suite. The GUI/shared-OS integration path was not race-instrumented.
- Path-validator fuzzing: 62,072 executions in the final timed run, no crash. This is not comprehensive archive-parser fuzzing.
- `go vet` completed for Linux and Windows source configurations, with no remaining warnings.
- Wine 10.0 with UTF-8 locale: Windows test executable passed, including title/version lookup, initial selection, primary GUI pack action, and subsequent FAW round-trip verification.
- Visual inspection of the empty, selected and completed GUI states, and the native file-selection dialog.
- Manual file selection and packing through the GUI produced a `.faw` archive.
- Russian release cover inspected for spacing, readability and overlap.

## Important gaps

**No physical or virtual Windows 10/11 system was available.** Wine is compatibility testing, not certification of native Windows behavior. Native Windows installation-free startup, multiple DPI settings, multi-monitor use, Explorer integration expectations and broad dialog behavior still need user testing.

The source-symlink test was explicitly skipped under Wine: it does not reliably expose native Windows reparse-point semantics on this Unix filesystem. The code checks Windows reparse attributes, but actual Windows symlink/junction behavior remains unverified here. The Linux symlink and archived-symlink tests passed. Do not represent this skip as a passed native Windows safety test.

There were initial Wine setup failures caused by the POSIX locale and incompatible symlink metadata. They were investigated; final tests use UTF-8 and explicitly report the native-Windows-only gap rather than hiding it.

No measured claims are made about beating WinRAR / 7-Zip, peak RAM on Windows, disk throughput, compression ratio across a representative corpus, or extraction from every ZIP producer. Large-file/ZIP64 limits are tested through declared-size rejection, not through physically reading and writing every maximum-sized allowed archive. Encryption, RAR and 7z are not implemented.

## Русский

Ядро проверено на Linux, Windows-сборка — через Wine. Пройдены проверки упаковки/распаковки, повреждённых архивов, опасных путей, перезаписи и отмены; интерфейс проверен визуально и через тест упаковки. Полноценный запуск на настоящей Windows ещё нужен. Проверка исходных Windows-ссылок/junction в Wine пропущена явно, потому что Wine не воспроизводит их семантику достаточно надёжно. Превосходство по скорости, памяти и безопасности не заявляется.

Raw logs are included under `docs/test-logs/`. GitHub Actions is supplied for future runs; it has not been executed in a published repository during this delivery.
