# Changelog

## alpha 0.2

- Reduced visible controls and default window dimensions; secondary actions in menus.
- Destination chosen in a save dialog only when creating an archive.
- New FAW 2 streaming container: 1 MiB Zstandard / STORE blocks, one codec worker, reusable buffers.
- Per-block raw CRC-32 and single-pass whole-container SHA-256.
- Bounded decoder window/output, names and path-depth limits, streaming conflict validation.
- Read compatibility with FAW 1. Alpha 0.1 cannot read FAW 2.
- Added mixed-size/multi-block/random-data round trips, corruption/truncation/path/decoder-bound tests and parser fuzz target.
- Added reproducible fast-preset FAW 1/2 synthetic microbenchmark.

## alpha 0.1

- Initial native Windows UI, ZIP and FAW 1 (ZIP/DEFLATE payload), integrity checks and no-overwrite extraction.
