# Alpha 0.6 delivery checks

## Environment and results
Go 1.27.2, Linux sandbox with 2 vCPU. Windows x64 CGO-disabled cross-build with icon, version resource and long-path-aware/as-invoker manifest. Native GUI EXE tested through Wine 10.0/Xvfb using a UTF-8 locale. No native Windows 10/11 or physical four-core computer was available. The executable is unsigned.

- 59 top-level Linux tests passed with the race detector.
- 63 top-level Windows/Wine tests passed, including GUI integration and deletion-lock checks.
- Linux and Windows go vet checks passed.
- ZIP catalogue fuzzing: 10,000 executions with two workers, no crash (0.929 seconds). This short run is not an exhaustive security audit.
- Fuzz seed cases are separate from the top-level Test counts.

Final suite logs are included in test-logs/. No new alpha 0.6 throughput or peak-RSS benchmark was performed. Earlier alpha 0.5 sparse-zero observations must not be represented as alpha 0.6 measurements or as general-data performance guarantees.

## Metadata and compatibility
Round trips cover FAW 1/2, legacy continuous FAW 3, indexed FAW 3 and ZIP. File sizes, modification dates and empty entries are checked against the sources. FAW 3 indexed metadata uses the existing stored timestamp: no wire-format change. Alpha 0.4/0.5 indexed archives remain compatible; alpha 0.3 cannot read the newer indexed representation.

Independent Python-produced STORE, DEFLATE and BZIP2 ZIP fixtures are included. ZIP tests cover ZIP64 structures, comments, data descriptors, both Zstandard method identifiers, CRC failures, empty archives, duplicate directory records, CP437 names, Unicode Path extras, backslashes, harmless dot prefixes and strict zipinsecurepath mode. Traversal, ambiguous duplicates, encrypted ZIP, unsupported methods and resource limits are checked. Missing DOS dates are shown as unknown, not fake 1979 dates.

## UI and selected preview
Actual native folder, empty-folder and FAW views were inspected. Three columns remain visible in an empty table. Size sorting keeps folders first and uses numeric byte values. Folder bytes are excluded from file totals; zero-byte files remain visible. Icons are graphical GDI pictograms, not emoji. The native virtual table avoids creating a native item for every row. Filesystem metadata reads are background/cancellable; this is an architectural improvement, not a measured memory claim.

The final release EXE opened an independently generated ZIP and previewed notes.txt through Wine Notepad. Exactly one content file was written, and its 40 bytes exactly matched the independent source fixture. After closing Notepad and Fawusk, the owned preview directory was removed. The text association was configured only within the isolated Wine prefix.

Existing round-trip, bounded pipeline, corruption, cancellation, staged publication, path validation, quotas and no-overwrite tests were retained. Existing preview policy and owned Temp cleanup tests remain: foreign Temp files are preserved, active owners protected, locked files retained and retried. GOMAXPROCS=4 scheduling correctness is exercised with mixed STORE/Zstandard groups; this is not a test on four physical cores.

## Remaining gaps
Native Windows, representative mixed-file performance/RAM benchmarks, four-core hardware, multiple DPI/monitors, network and NTFS reparse-point policies, installed media/Office/PDF viewers, sustained fuzzing and independent review remain necessary. The source symlink case is covered on Linux and skipped under Wine. External viewers are not sandboxed; the preview policy is not antivirus. Cleanup is scoped, best-effort normal deletion, not secure erasure. See TEMP_CLEANUP.md and ZIP_SUPPORT.md. The GitHub Actions configuration is supplied but was not run in a published repository here.
