# alpha 0.2 — delivery checks

## Environment

Go 1.27.1, Linux sandbox, Windows / amd64 cross-compilation, CGO disabled. Windows code was executed through Wine 10.0 with UTF-8 locale and inspected under Xvfb. **No native Windows 10/11 machine was used.** EXE is unsigned. No independent security audit, antivirus certification or WinRAR/7-Zip comparison is claimed.

The application was built using the repository's `build.sh`. Resource generation includes the icon, alpha 0.2 file version and as-invoker manifest. Third-party compression is pinned to klauspost/compress v1.20.1.

## Core checks

- ZIP and FAW round trips at fast, balanced and maximum presets; Unicode paths, empty files/directories and binary data.
- FAW 2 multi-block files, independent blocks, mixed compressed/random data and changing output-buffer sizes.
- FAW 1 compatibility: creation through the legacy test helper and verified reading with the current reader.
- FAW 1 header/payload/digest corruption and ZIP CRC rejection.
- FAW 2 header, payload/digest corruption, truncation, trailing bytes, declared-size/count/name/chunk bounds and unknown codecs.
- Real Zstandard output exceeding the declared raw-size capacity rejected with `ErrDecoderSizeExceeded`.
- Dangerous paths, device names, case-insensitive duplicates, inconsistent ancestor casing and file/directory conflicts rejected.
- Existing file/directory preservation, no writing archives inside the selected source folder, cancellation during packing/extraction and temporary-data cleanup.
- Source symlink rejection on Linux and link-entry rejection in ZIP. Native Windows source symlink/junction behavior remains unverified: this test is explicitly skipped under Wine.
- `go test -race` passed for the Linux core suite. GUI/shared-OS integration was not race-instrumented.
- `go vet` passed for Linux and Windows source configurations.
- FAW 2 parser fuzzing: final timed run completed 45,920 executions with no crash. It starts from empty and non-empty valid seeds; this short run is not a comprehensive fuzzing/audit claim.

## GUI checks

Wine integration test exercises window title/version, initial selection, the new save dialog, packing and verified FAW 2 extraction. Visual inspection covered empty, selected, Add menu, More menu, save dialog, completed and error states. Manual Add → Files → Pack → Save produced a FAW 2 archive, and choosing an existing archive name was rejected.

The main screen no longer exposes Remove, Clear, compression-level selector, persistent destination edit, Browse, Open Folder and permanent Cancel controls together. Secondary actions are in menus; destination selection is deferred until packing. Cancel is shown only during work.

## Microbenchmark

`benchmark_test.go` includes a reproducible **fast-preset** FAW 1/2 packing microbenchmark on 16 MiB repeated text and 16 MiB random bytes. Each iteration includes planning, packing, hashing and fsync. Extraction and byte-for-byte checks are outside the timed section. Raw output from one iteration per case is included in `test-logs/benchmark.txt`.

These are synthetic, warm/cache-affected Linux measurements, not native Windows measurements or a representative corpus. One observation per case is insufficient to make a robust speed ranking. `B/op` records allocations, **not peak RAM/RSS**. The newer codec also has allocation/workspace costs: bounded block buffers do not imply less memory than the old codec. Do not market these numbers as defeating WinRAR/7-Zip or as a universal compression/speed improvement.

## Remaining work

Native Windows testing, symlink/junction verification, multiple DPI and monitor settings, long-path producers, crash/power-loss behavior, physical maximum-size files, broad third-party ZIP compatibility, peak RAM/CPU/disk profiling and adversarial archive auditing remain needed. There is no time/disk sandbox or authentication; configured extraction-size limits still allow sizable output. Concurrent local tampering is outside the protection model.

RAR/7z, encryption, solid compression, deduplication, a random-access FAW index and Explorer integration are not implemented. FAW 2 is a sequential container using an existing codec. Alpha 0.1 cannot read it; use ZIP for older recipients.

## Русский

Пройдены проверки ядра на Linux и Windows-сборки через Wine, включая новый диалог сохранения и упаковку. Проверены FAW 1/2, повреждения, опасные пути, лимиты декодера, перезапись и отмена. Интерфейс осмотрен в основных состояниях.

На настоящей Windows тестов пока не было; поведение junction/reparse points и разные DPI требуют проверки. Синтетические замеры приложены, но они не доказывают превосходство над конкурентами и не измеряют пиковую память. FAW 2 использует Zstandard; новых собственных алгоритмов, шифрования, solid-сжатия и дедупликации здесь нет.
