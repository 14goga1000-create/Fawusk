# Alpha 0.7 delivery checks

## Environment and totals
Go 1.27.2, Linux sandbox with 2 vCPU. Windows x64 CGO-disabled build with icon, version resource and long-path/as-invoker manifest. Native GUI EXE checked through Wine 10.0/Xvfb, UTF-8 locale. No actual Windows 10/11 or physical four-core computer was available. EXE is unsigned.

- **77 top-level Linux tests passed** with race detector; zero failed. 3 opt-in/demo tests skipped.
- **82 top-level Windows/Wine tests passed**, including real GUI clear/suspicious/test status and extraction-button checks; zero failed. 4 opt-in/unsupported-environment tests skipped.
- Linux and Windows go vet passed.
- CustomAV byte-parser fuzzing: 10,018 executions, 48 new interesting inputs, no crash, 0.798 seconds. This is short fuzzing, not an independent security audit or malware-detection benchmark.
- Fuzz seeds are separate from top-level Test counts. Final suite/vet/fuzz logs included in test-logs/.

## CustomAV and FawReader
EICAR exact/optional CRLF classification remains test-only with malware/test/review scores separate. Merely mentioning its marker in ordinary documentation is not the exact test file. Additional signature database errors, malformed RE2 rules, scanner file/byte/depth/sample/report limits, cancellation, source changes and corruption cannot yield archive approval.

Tests cover every FAW representation (1/2/continuous-3/indexed-3), EICAR inside each, ordinary byte-preserving streams, nested FAW and ZIP, bad header/version/checksum, Unicode parent-name masking, selected-entry coverage, independent ZIP fixtures, CRC failures and blocked extraction/new-archive publication. Suspicious originals are unchanged; staging results are not published on failure. FawReader supplies existing validated decoder streams; it is not a second antivirus. Scanner archive-open path does not extract ordinary targets to disk. Nested FAW uses an owned temporary compressed-container file and removes it normally.

FawReader.OpenEntry uses a pipe with final decoder completion/error; callers must read to EOF and check the error. List validates format/catalogue/paths and legacy content as appropriate. Existing unsafe-path/name/collision/quota/index/corruption/no-overwrite tests remain in the full suite.

The standalone Windows EXE scanner mode was run through Wine and wrote a JSON all-entry report for the ordinary FAW sample: complete, format=faw, 7 file records. The Linux validation executable returned 0 for the ordinary FAW and 3 for the deliberately checksum-damaged copy, which reported incomplete. Delivered sample pack has both archives and reports, **no live malware/EICAR test file**. EICAR is generated only during tests/manual isolated inspection.

## GUI and preview inspection
Actual native clear, red suspicious, amber EICAR, yellow review/confirmation and grey corrupted-archive states were inspected. Red/grey/test extraction was disabled; catalogue remained inspectable when available. Native video frame/play, audio note, image landscape, PDF and table pictograms were inspected with real short MP4/WAV/PNG/PDF/CSV files. No emoji, shell icon handlers or thumbnails are used. Three table headers, size/date semantics, one path per window and no-overwrite remain.

Manual FAW preview after full CustomAV approval wrote exactly one content TXT, its bytes matched the original UTF-8-BOM document, and Wine Notepad displayed Cyrillic correctly. Viewer/Fawusk close removed the owned preview root. The TXT association was configured only inside the isolated Wine prefix. Review preview presented an explicit confirmation dialog; declining did not extract or launch the file. External viewers are not sandboxed.

GUI integration waits for background folder navigation/scan completion before posting commands or inspecting final button permissions; a changed path/label alone is not an idle signal. Windows are matched by owning PID, avoiding another demo window.

## Retained checks and limits
Existing FAW 3 mixed STORE/Zstandard worker-budget and GOMAXPROCS=4 correctness tests, buffer ownership, cancellation, staged publication, SHA/CRC, safe preview type policy and scoped Temp cleanup/Windows deletion-lock retries remain. These are not tests on four physical CPU cores. Linux source-symlink case is covered; skipped under Wine.

No new throughput/peak-RSS benchmark, competitor comparison, real malware corpus validation, commercial AV parity or independent security audit is claimed. Scanner can miss threats or flag benign programs/text. Only EICAR is in the built-in signature database. Important strict-alpha coverage limit: analysis sample 16 MiB/file; larger files and unsupported/incomplete containers block operations instead of being reported green. Full scanning adds decompression/hashing/legacy passes, so earlier compression/extraction observations do not measure this path.

Actual Windows/DPI/monitors, installed media/Office/PDF software, storage/network/reparse policies, representative large-file resource measurements, sustained fuzzing and independent review remain required. GitHub Actions is supplied but has not run in a published repository. See CUSTOMAV.md, TEMP_CLEANUP.md and ZIP_SUPPORT.md for scope, adapted rules, cleanup best-effort behaviour and unsupported formats.
