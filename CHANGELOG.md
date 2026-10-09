# Alpha 0.7
- CustomAV 0.5 adapted native port; mandatory reference instruction retained.
- Read-only FawReader adapter and bounded nested FAW/ZIP scanning; whole-archive coverage fields.
- Fail-closed publication/preview/extraction gates, explanatory JSON report and standalone scanner mode.
- Dedicated media/document/code/application vector icons and top security strip.
- Explicit incomplete status for coverage limits, errors and unsupported containers; no claim of commercial AV parity.

# Changelog

## Alpha 0.6
- Native virtual report table: Name/Size/Modified, graphical icons, column sorting, folders first.
- Background cancellable folder metadata; compact FAW 3 sizes/dates projected without format change; missing metadata not fabricated.
- Broader ZIP support: CP437/Unicode Path, safe path normalization, ZIP64, BZip2 and Zstandard; catalogue-only listing and selected-entry extraction.
- Empty files/directories and directory-record deduplication; directories excluded from payload sums; directory timestamps restored after contents.
- Independent ZIP fixtures and expanded metadata/CRC/path/empty-table/fuzz tests. No native Windows or four-core performance claim.

## Alpha 0.5
- Human FAW 2 Classic label; native vector folder/archive/file pictograms, larger owner-drawn rows, no emoji.
- Four-core-oriented capped codec budget: up to three workers plus I/O/file hashing; buffers reused in both compression and prefetch/decode pipelines.
- Marked per-window preview Temp directories; normal-close cleanup, two-minute retry helper for locked files, next-start orphan recovery. No arbitrary Temp purge or forced viewer termination.
- FAW 3 flags=1 format unchanged; alpha 0.4 compatibility retained.
- Expanded parallel-group, worker-budget, cancellation, owned/foreign/orphan Temp and Windows deletion-lock tests.

## Alpha 0.4
- Indexed FAW 3 flags=1: compact catalogue, 8 MiB solid groups, bounded two-task compression pipeline, adaptive STORE, SHA-256 per group/file.
- Fast catalogue-only listing; selected-file extraction reads only required groups for flags=1. Legacy FAW 1/2/3 and ZIP remain readable.
- Restricted archive media/document preview to isolated Temp directories, launched with the Windows association only after verification; forbidden executables/scripts/shortcuts/macros and misleading names.
- Fast / Good / Maximum presets and FAW 3/2/1/ZIP selectors shown directly in the spacious single-path window.
- Expanded round-trip, multi-group, malicious-index, cancellation, viewer-policy, office active-content and fuzz tests. Synthetic 5 GiB round-trip SHA-256 passed; 5–6 second goal not reached.
- New FAW 3 requires alpha 0.4; choose old formats for older recipients.

## Alpha 0.3
Single-path browser, archive/folder navigation, legacy continuous FAW 3 solid stream, long Unicode paths, optional FAW Open With registration.

## Alpha 0.2
Minimal interface and independent FAW 2 blocks.

## Alpha 0.1
Initial FAW 1 ZIP-based container and ZIP archiving.
