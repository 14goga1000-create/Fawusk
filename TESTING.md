# Alpha 0.5 delivery checks

## Environment
Go 1.27.2, Linux sandbox with 2 vCPU; Windows x64 CGO-disabled cross-build with icon, version resource, long-path-aware/as-invoker manifest. Native GUI EXE tested using Wine 10.0/Xvfb and UTF-8 locale. **No physical four-core machine or native Windows 10/11 system was available.** EXE is unsigned; no independent security audit or competitor ranking is claimed.

Normal suites: **48 top-level Linux tests passed** with the race detector; **51 top-level Windows/Wine tests passed**, including real GUI and deletion-lock checks. Fuzz seeds are separate from those counts. Linux and Windows `go vet` checks passed.

## Core verification
- Linux race detector, vet and round-trip tests; Windows test binary under Wine.
- FAW 1/2, legacy continuous FAW 3, indexed FAW 3 and ZIP compatibility. Alpha 0.4 indexed sample remains readable; alpha 0.5 does not change the format.
- `GOMAXPROCS=4` correctness case processes a 41 MiB fixture with both STORE random-data groups and Zstandard zero-filled groups. SHA-256 after parallel compression/prefetch/decode matches the source. This tests scheduling/ownership correctness, not four physical cores.
- Worker-budget tests: one worker for 1/2 CPUs or a single group, three for a four-core budget and many groups, three-worker maximum. No unrestricted thread count.
- Cancellation, bounded queues and staged publication; corrupted groups/indexes/paths, quotas, no-overwrite and long Unicode destinations retained from prior tests.
- Selected-file preview writes one content file and reads only its group range. The metadata ownership marker is outside `content/`. Unsupported executables/scripts/macros/misleading extensions remain blocked.
- Owned Temp cleanup, active-owner protection, foreign Temp preservation, marked orphan recovery and Windows deletion-lock preservation/retry after unlock.
- Parser fuzzing: 119,420 executions in a short 10-second run, no crash; not an exhaustive audit.

## Stress observation
A 5,368,709,120-byte **sparse zero-filled** source packed at Fast preset in **6.919 seconds**; archive size 1,067,751 bytes. Full extraction and comparison of original/restored SHA-256 passed; complete test took 24.90 seconds.

The machine exposed 2 vCPU; ordinary data, real storage, native Windows and physical four-core speed were not measured. Sparse zero data is exceptionally compressible and cache effects matter. This is not directly comparable to earlier runs on other sandbox workloads and is not proof of universal speed improvement or a WinRAR/7-Zip comparison. The 5–6-second goal is not achieved or guaranteed for general data. Allocation reductions/bounded buffers are implementation changes, not a measured peak-RSS promise.

## GUI and cleanup inspection
Real native folder/archive views with graphical pictograms, larger rows and all format names were inspected. No emoji or per-file shell thumbnail/icon handler is used. Ordinary-file path-only mode, keyboard/double-click navigation, modern save and actual FAW packing are integration-tested. GUI test windows are matched by owning PID so another Fawusk window cannot be mistaken for the test window.

Manual archive preview opened the selected UTF-8-BOM TXT through Wine Notepad after configuring its association only inside the isolated Wine prefix. One content file was written, its bytes exactly matched the source, and its owned Temp directory was absent after closing the viewer and Fawusk window. Windows deletion-lock tests keep the marker while locked and clean successfully after unlock. The archiver does not force viewers to quit.

Retry helper and next-start recovery are bounded/best-effort. Crash, permission problems, helper-start failure, long-held locks and PID reuse can leave directories. Old unmarked preview folders are deliberately not deleted. See TEMP_CLEANUP.md for scope and validation. This is normal deletion, not forensic erasure.

## Remaining gaps
Native Windows 10/11, actual four-core hardware and representative mixed-file performance/memory tests, multiple DPI/monitors, NTFS reparse/UNC policies, installed media/Office/PDF applications, sustained fuzzing and independent review remain necessary. Source symlink test is skipped under Wine; Linux test covers it. External viewers are not sandboxed; preview policy is not antivirus. GitHub Actions configuration is included but not run in a published repository here.
