# Alpha 0.8 delivery checks

Go 1.27.2, Linux sandbox with 2 vCPU. Windows x64 build with native resources and long-path/as-invoker manifest. Windows EXE/GUI checks use Wine 10.0/Xvfb, not actual Windows 10/11; EXE is unsigned. Generated logs/artwork/binaries are deliberately outside the source package.

Full-suite results after restoring and retesting: Linux 87 main-package tests + 5 SDK tests; Windows/Wine 94 main-package tests + 5 SDK tests. 3 Linux and 4 Windows opt-in/environment-specific tests skipped. Subtests/fuzz seeds are not counted. All listed tests passed; zero failed. Linux race detector and Linux/Windows vet are included.

New regressions: preference defaults/save/replace/malformed/invalid/oversized data; actual GOMAXPROCS/soft-memory application; worker budgets and low-budget byte-preserving FAW round trip; RU/EN labels/units, unchanged paths, translation/format coverage; native English switch and Settings save/persistence/status.

Native GUI waits for child-control construction and scan completion, matched by PID. A window title alone does not imply that child controls exist. Native RU/EN menus/settings, mouse language switching, restart/persistence, soft-budget explanations, width of English risk buttons and cover were individually inspected before the interrupted delivery; restored code/build is retested. Cover is an actual native Settings/main-window capture, not a fabricated app state.

Inherited tests cover all FAW variants, standard ZIP/ZIP64/Store/Deflate/BZip2/Zstandard and independent fixture bytes, metadata/empty entries, paths/quotas, CRC/SHA, source mutation, cancellation, staged no-overwrite publication, concurrency, restricted preview, owned Temp, CustomAV rules/database/nested readers and archive-bound risk consent. Fixtures are test source literals, not binary demo archives.

No real-Windows/four-core throughput, peak-RSS, competitor benchmark, malware corpus or independent audit claim. CustomAV samples at most 16 MiB/file with full hashing; built-in signatures contain EICAR only. Soft Go-memory budget can be exceeded; CPU is not OS affinity/thread cap. No resource setting weakens validation/quotas. Real Windows/DPI/viewers, broader resource measurements, sustained fuzzing and independent review remain necessary.
