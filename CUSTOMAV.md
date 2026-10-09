# CustomAV 0.5 integration — Fawusk alpha 0.7.1

The mandatory user-supplied instruction was read before implementation. This is a **native adapted port of CustomAV 0.5**, not a commercial antivirus, sandbox, neural classifier or an interchangeable second detector. Original reference code and instruction are retained under reference/customav/. The Python runtime and its external extraction utilities are not executed by Fawusk.

## FawReader adapter
`faw_reader.go` recognises the FAW header/version and provides List, ReadAll and OpenEntry. The existing FAW 1, FAW 2, continuous FAW 3 and indexed FAW 3 decoders remain the sole format authority. They enforce path/type/size/catalogue limits and validate CRC/SHA before successful stream completion. OpenEntry returns an io.ReadCloser; callers must read to EOF and check errors. The pipe is closed with the final decoder error, not before checksum validation.

CustomAV receives each decoded entry as a stream. Ordinary archive-open scanning writes **no target entries** to disk. For nested FAW, only the inert compressed container (at most 16 MiB here) is materialised in a private marked Temp directory so the same ReaderAt decoders can be reused; its entries stay streams. This directory is cleaned after scanning and is eligible for the existing scoped orphan recovery. Nothing from the archive is executed.

Nested FAW/ZIP/JAR/Office-ZIP use the same CustomAV run, scores, budgets and report. ZIP may use Store/Deflate/BZip2/Zstandard. Nested unsupported RAR/7z/TAR/gzip/bzip2/xz, encrypted entries, corruption, unsupported versions, timeouts and limits give an incomplete report, never a green archive result. Unknown threats and unrecognised container types can still evade static rules.

## Preserved and adapted rules
- Exact EICAR test classification, separate test/malware/review scores; optional CR/LF normalisation. Mentioning EICAR in ordinary documentation is not the exact test file.
- User exact/contains/regex signatures, UTF-8/base64/hex patterns. Built-in EICAR cannot be removed by replacing the sidecar database. Invalid database fails closed. Optional customav_signatures.json next to the EXE supplements the embedded database. RE2 regex is bounded/linear-time; Python-specific unsupported syntax is rejected rather than silently ignored.
- CustomAV filename Unicode/disguise, script capability, high-risk text/PE strings, PDF/ELF hints, URLs, active Office content and nested executable rules. These are broad **heuristics** and can block legitimate developer files, installers or documents mentioning commands.
- Native debug/pe import parsing replaces objdump; bounded Java constant-pool reading replaces executable class loading. PE parsing failure is incomplete, not clean.
- Review findings always produce a yellow warning, even below the reference aggregate threshold. Existing scores/verdicts are not downgraded by a friendly filename, allowlist, user confirmation or a language model. The user may grant an explicit operation-policy exception without changing those verdicts.

Not ported: entropy/packer scoring, Minecraft SHA-1 manifest validation, local allowlist/blocklist reputation, full embedded-payload extraction or external commercial reputation. Do not describe this port as byte-for-byte equivalent to all Python 0.5 heuristics. Default signature database contains **only EICAR**, not a broad real-malware signature collection. Detection quality has not been validated on a malware corpus or independently audited.

## Coverage and limits
- 10,000 file records, including recursively inspected members; 100,000 structural archive paths remain the parser ceiling.
- 20 GiB cumulative bytes consumed, 1 GiB nested decoded bytes, nested depth 3, 10-minute operation deadline.
- A file's complete SHA-256 is calculated, but content rules buffer at most **16 MiB**. Larger files are marked incomplete. Script heuristics use 2 MB and text heuristics 10 MB; exceeding these specific analysis limits is also incomplete.
- At most 2,000 findings retained. Truncation is explicit and cannot erase blocking scores. No unlimited worker/process fan-out.

**Important:** common videos/large binary files above 16 MiB can therefore make the whole archive incomplete. By default this blocks preview/extraction/publication. An explicit risk exception may permit extraction/allowed preview for an intact archive, without pretending analysis was complete. Creation publication remains strict. Raising this coverage safely is future work, not an implemented streaming commercial AV claim. Antivirus mode adds decompression, hashing and possible extra legacy-format passes; old speed observations no longer describe this full security path.

## Policy and UI
- Grey: scanning/not checked/incomplete. Archive preview and extraction disabled.
- Red: suspicious rules/signatures; archive preview, extraction and creation publication blocked.
- Amber test: EICAR/test signature, **not a real infection**; strict testing policy blocks publication.
- Yellow review: warnings; allowed only after explicit GUI confirmation for extraction/preview.
- Green: all available entries finished under configured rules with no positive indicators. Text is “Угрозы не обнаружены”, never “guaranteed virus-free”.

Opening scans before enabling operations. New archives are scanned in their closed temporary .part state before publication. Extraction rescans its decoded streams before publishing a staging directory. Preview requires an approved whole-archive report, matches the archive SHA/size, rescans the selected content and checks source identity before publication/opening. Originals are not deleted, quarantined, executed or uploaded. Existing no-overwrite, staged output, safe preview type policy and scoped Temp cleanup remain.

## Report and standalone mode
The same pipeline can run without opening the GUI:
```
Fawusk-alpha-0.7.1.exe --scan-customav archive.faw --report new-report.json
```
When invoking it from a program, use an argument array with no shell, wait for process completion, and inspect both exit code and JSON. Code 0 = completed clear/review (read the verdict); 2 = blocking malware/test signal; 3 = incomplete/error; 64 = invalid arguments. Report filenames are not overwritten. Missing report is a failure, never clear. Existing encrypted/unsafe archives are not made readable by this mode.

Fields include container_format, format_version, archive_sha256/size, scan_scope, scan_complete, complete, verdict, score and separate malware_signal_score/test_signal_score/review_signal_score. Each file includes entry/path, container_format, size, sha256, scan_complete, state and verdict; findings retain rule/path/detail/category/points. Paths include `outer.faw!/entry` for nested members. `no_positive_indicators` is the file verdict, not a safety guarantee. The report contains local paths/hashes; it is saved only on request and is never uploaded.

A selected-entry scan cannot provide whole-archive approval. Green archive state needs all_entries scope and scan_complete. Findings explain decisions; a total score alone is insufficient. Full reports may be exported from “…”; the on-screen report is intentionally shortened.

## Validation
Tests cover EICAR in every FAW representation, nested FAW/ZIP, corruption, invalid signature/version, blocked publication/no original alteration, parser path/quota checks, Unicode parent masking, selected-entry coverage, ordinary file streams, immutable-source preview, JSON CLI and GUI clear/suspicious/test states. Test payloads are harmless and generated at test runtime. The delivery sample pack has one ordinary FAW and one intentionally checksum-damaged FAW, with JSON reports; it contains no live malware or EICAR file. Real Windows, sustained fuzzing, representative performance and independent review remain required.

## Faw Edition integration and risk consent in 0.7.1
The additional mandatory Faw Edition instruction was read before integration. `security/fawsecurity` is a hardened adaptation of the supplied Go policy API, not a new independent malware engine. The unchanged upstream package, Python reference, Go client and JSON schemas remain in `reference/customav_faw_edition/`; the executable does not launch Python or reference extraction tools.

The actual FawReader.Entries adapter implements the supplied interface using checked format decoders: paths, original sizes, directory/encryption flags, reader closures and available indexed SHA-256. Compressed entry size is unknown/zero for shared solid data; it is not invented. Unsupported encrypted FAW versions fail instead of returning falsely unencrypted readable entries. Optional NativeFawEntryScanner uses the existing CustomAV rules. Production uses sequential ReadAll for legacy solid archives to avoid quadratic decoding.

Hardening includes preflight of every path (including directories), Windows device/absolute/traversal/control/Unicode-format names, link rejection, duplicate/case/file-directory collision checks, bounds before ZIP central allocation, exact stream byte consumption, EOF/checksum and close errors, cancellation, and unknown/incomplete verdicts that cannot turn green. SDK policy metadata ceiling: 10,000 entries including directories; native scanner record ceiling also includes recursively scanned files. Core structural quotas remain in effect.

“Всё равно” requires a whole-archive scan with successful outer decoder integrity checks and unchanged SHA-256/size, plus explicit user confirmation (default No). The grant lasts only for that window/archive identity; reopen or “Снять риск” clears it. Red/amber/grey verdicts and findings are retained. JSON records `outer_integrity_ok`, `user_override`, `override_at`. An intact outer archive containing unsupported nested data may still be incomplete: consenting means accepting that limitation, not making its nested content safe. Extraction does not launch files. The existing preview allowlist, executable/script/macro/disguise checks, preview quotas, source checks and safe staging remain mandatory. Corrupt/encrypted/unsafe outer archives, structural quota failures and partial-only reports cannot obtain a UI grant. Pack publication and CLI scanning remain strict; no command-line bypass was added.

The SDK contains tested AES-256-GCM/PBKDF2-HMAC-SHA256 FAWSEC1 private-report envelope helpers (200,000 iterations, fresh salt/nonce, authentication and bounded sizes). They are **library helpers only**: encrypted-report UI, quarantine and archive password/encryption are not implemented in this release. Do not imply that ordinary exported JSON is encrypted.

The memorandum is ceremonial project documentation supplied/authorised by the owner. CustomAV's provided signature was not independently verified. No legal entity, qualified electronic signature, independent audit or security certification is asserted.

## Licensed distribution update (still alpha 0.7.1)
The subsequently supplied licensed Faw Edition v0.5 package contains MIT LICENSE and NOTICE.md with explicit permission for Fawusk inclusion/modification/redistribution. Functional source files are unchanged relative to the earlier Faw Edition package. Licence/copyright and upstream notice are preserved under reference/customav_faw_edition, docs/licenses and security/fawsecurity/LICENSE. This update changes packaging and licence documentation only, not the EXE, scanner or version.
