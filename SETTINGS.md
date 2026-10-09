# Settings and RU/EN — alpha 0.8

CPU values: Auto (at most 4), 1, 2, 4. Applied via Go GOMAXPROCS, bounded by the startup CPU budget; existing codec scheduling reserves one CPU slot for I/O/hash, caps at 3 codec workers and avoids idle workers for small archives.

Memory values: 256, 512, 1024, 2048 MiB; default 512. Applied via runtime/debug.SetMemoryLimit and conservative scheduling: 128 MiB reserve + 128 MiB/worker. This is a soft Go-memory target, not a hard OS working-set/RSS cap. Native allocations, live objects and decoder buffers can exceed it. CPU is not physical-core affinity or an OS thread-count limit. Budgets are per process/window, not aggregate across all app instances. No speed/peak-RSS guarantee.

Windows preferences normally use %APPDATA%\Fawusk\settings.json. JSON schema version 1: version, language, cpu_threads, memory_mib only. Bound to 4096 bytes, regular files; invalid values/version/unknown fields/extra JSON fall back to defaults with a GUI warning. Save uses a temporary file, flush/close and rename; save failure does not apply values. Passwords, archive data and AV consent are not persisted. Defaults resets resources and preserves language; Cancel/Escape discards changes. Other already-open windows retain their loaded preferences. Settings and language are disabled during work.

Language changes are deferred until combo selection completion to avoid rebuilding controls while the native dropdown tracks selection. Current path, format/level and AV state/consent remain. Names/content are not translated. Existing technical finding detail may retain its original language; machine report keys/rule IDs are unchanged. Switching does not rescan or rewrite a saved report. Decimal separator follows RU/EN; size units use 1024 bytes.

Security checks, quotas, archive format/window size, decoder bounds, no-executable-preview and owned Temp cleanup are unchanged. FAWUSK_CONFIG_DIR is available for isolated test profiles; no remote config/telemetry/updater was added.
