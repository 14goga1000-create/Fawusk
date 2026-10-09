# Alpha 0.7.1 delivery checks

## Environment
Go 1.27.2, Linux sandbox with 2 vCPU. Windows x64 CGO-disabled EXE with icon, version resource and long-path/as-invoker manifest. Windows executable/GUI tests run through Wine 10.0/Xvfb with UTF-8 locale, not a real Windows 10/11 computer. EXE is unsigned. No physical four-core or competitor performance benchmark, independent security audit or malware corpus validation is claimed.

## Results
Recorded full-release test results are listed below; generated logs are not bundled in the source-only archive. Counts below include top-level Test functions only; fuzz seed cases and subtests are separate.

- Linux: 82 main-package tests plus 5 Faw Edition SDK tests passed with race detector; zero failed. 3 opt-in/demo tests skipped.
- Windows/Wine: 88 main-package tests plus 5 SDK tests passed; zero failed. 4 opt-in/unsupported-environment tests skipped.
- Linux and Windows go vet passed.
- The final native EXE CLI produced a complete all-entry ordinary-FAW report with outer_integrity_ok=true and user_override=false.

Historical alpha 0.7 results describe the earlier strict policy. Short prior fuzzing is not an audit.

## Added 0.7.1 regressions
- Actual FawReader.Entries interface on FAW 1/2/indexed-3; exact bytes/size and checked EOF; optional SDK bridge uses the existing detector.
- Default refusal of harmless suspicious command documentation; explicit SHA/size-bound consent permits extraction and TXT preview while preserving blocked verdict, malware score and override audit fields.
- Consent rejects changed sources; partial-only approval cannot grant a whole archive. Damaged checksums and traversal still reject publication, including a forged internal consent test. Executable/script preview remains forbidden.
- An intact 17 MiB file reports incomplete content analysis; explicit risk permits byte-preserving extraction without marking its scan complete.
- SDK preflights all entries before opening any stream: directories, invalid Windows/traversal/Unicode-control paths, links, size, duplicates and file/parent collisions.
- Exact stream consumption, unexpected extra bytes, EOF/checksum errors, supplied SHA mismatch, nil reader and cancellation cannot produce a clean SDK result. JSON serialization excludes reader functions.
- Unknown/incomplete/test/review/malware statuses remain distinct. Review points below blocking thresholds cannot silently become green.
- SDK ZIP convenience API checks central-directory bounds before zip.NewReader allocation; ordinary ZIP and malformed count/truncation tests.
- Private-report envelope helpers: round trip, different random salt/nonce, wrong password, authentication tamper, truncation and empty password. Library helpers only; no encrypted-report GUI or quarantine claim.

## GUI and visual inspection
Automated real native GUI checks cover clear/red/test status, disabled default extraction, risk confirmation decline/accept, enabled extraction after acceptance, retained warning and revocation. Windows are matched by process ID and tests wait for background completion.

Manual inspection: red suspicion has a visible “Всё равно” button and disabled extraction. Risk dialog defaults to No and explains unchanged structural/type protections. Accepting retains the red state and shows “Снять риск”; damaged archive stays grey with no risk button. No checked archive contents were executed. Harmless fixtures only; no live malware shipped. Prior video/audio/image/PDF/table vector icons, three columns, path navigation and one path per window remain.

Release cover uses an actual native-window capture. All three signed memorandum PDF pages and the cover were individually inspected for legibility, margins and overflow. Project signature is typed ceremonial confirmation, not a handwritten or qualified electronic signature.

## Retained checks and limitations
Full inherited tests cover all FAW variants, nested FAW/ZIP, EICAR test classification, rules/database errors, original byte preservation, publication refusal, CRC/SHA corruption, metadata/date/size and empty entries, independent ZIP/ZIP64/BZip2/Zstandard fixtures, source mutation, safe preview and owned Temp cleanup. Core staging/no-overwrite and capped codec scheduling remain.

Content analysis is still bounded to 16 MiB/file, with full file hashing. Default signature database contains EICAR only; broad heuristics can miss threats or flag legitimate files. Unsupported or encrypted nested data remain incomplete, even after explicit operation consent. Actual Windows/DPI/installed viewers, representative large-file speed/RSS, sustained fuzzing and independent review are still required. See CUSTOMAV.md and THIRD_PARTY_NOTICES.md, including the now-supplied CustomAV Faw Edition MIT licence and upstream notice.

Source-only cleanup: runtime code and EXE unchanged; independent ZIP and alpha 0.4 FAW fixtures moved byte-for-byte into test source literals. Clean-tree go test ./... and go vet ./... were rerun. Native Windows tests above refer to the previously checked unchanged release binary.
