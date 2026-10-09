# FAW 3 indexed solid groups — alpha 0.4

This extension keeps magic/version 3 and uses **flags=1**. Alpha 0.3 accepts flags=0 only and cannot read flags=1. Alpha 0.4 reads both. Original flags=0 specification remains in FAW_FORMAT.md. The format is experimental; flags=1 is not a claim of compatibility with third-party archivers.

All fixed-width integers are little-endian. U = unsigned LEB128/uvarint (at most 10 bytes). Times are Unix seconds, zig-zag encoded as U. SHA-256 is unkeyed corruption detection, not authentication.

## Header: 32 bytes
- 0:8 magic `FAWUSK\r\n`
- 8:10 version uint16 = 3
- 10:12 flags uint16 = 1
- 12:16 group size uint32 = 8 MiB
- 16:24 total file bytes uint64
- 24:28 explicit entry count uint32
- 28:32 IEEE CRC-32 over bytes 0:28

## Data
Starting at byte 32, stored groups are contiguous, in catalogue order. Uncompressed groups concatenate file bytes in entry order, excluding directory metadata. A file may span groups; small files share a group. All groups except the last contain exactly 8 MiB raw bytes. Each group is an independent Zstandard frame (codec=1) or raw STORE bytes (codec=0). STORE is chosen when compression would not shrink the group. Alpha 0.4 uses two concurrent EncodeAll tasks; alpha 0.5 uses an available-CPU-aware ceiling of three with reused buffers. Tasks are bounded by an ordered pipeline; no full-archive buffer.

## Catalogue (raw before optional compression)
- 8-byte magic `FWIX0001`
- U group count = ceil(total/8 MiB)
- For each group: U stored size, U raw size, byte codec, 32-byte SHA-256 of stored bytes
- U entry count = header count
- For each entry: byte kind (1 directory / 2 regular file), U UTF-8 name length, U file size (0 for directory), U zig-zag mtime, name bytes, followed by 32-byte SHA-256 of raw file bytes for kind=2

Group offsets are implicit prefix sums of stored sizes, beginning at 32. File positions are implicit prefix sums of file sizes in entry order. This avoids storing a segment list for every file while retaining O(groups + entries) indexing. Group sizes must cover exactly the header total and end exactly at catalogue offset. Entry file sizes must sum to total. Empty files carry SHA-256(empty); empty archives have no groups.

The catalogue is optionally Zstandard compressed, or STORE when compression does not shrink it. Both stored and raw catalogue sizes are at most 32 MiB. Decoder output is cap-limited. Names are bounded to 16 MiB total, 3,000 bytes per name and 128 components, with 100,000 explicit/derived nodes. Duplicate case-insensitive paths, ambiguous parent casing, traversal, absolute/device names, alternate streams, trailing spaces/dots and invalid UTF-8 are rejected.

## Trailer: final 72 bytes
- 0:8 magic `FAWIDX04`
- 8:16 catalogue offset uint64
- 16:24 catalogue stored size uint64
- 24:32 catalogue raw size uint64
- 32:36 catalogue codec uint32 (0 STORE / 1 Zstandard)
- 36:40 reserved uint32 = 0
- 40:72 SHA-256(header || stored catalogue || trailer[0:40])

No padding/trailing bytes are allowed. The catalogue starts after the groups and ends immediately before this trailer. Bounds are checked before allocating or decoding. Maximum decoded group/window is 8 MiB. Header total <=20 GiB, each file <=8 GiB.

## Reading and integrity
Listing validates header/trailer/catalogue checksums, bounds and names, **not payload**. Selected-file extraction verifies stored SHA-256 before decoding each needed group, then verifies the selected file's raw SHA-256. Full extraction verifies every file/group and publishes a staged new directory only after success. No overwritten destination. Selected previews write only that file and required directories; other files in shared groups exist in memory only.

A catalogue hash is not a trust signature. An attacker can generate valid hashes for malicious content. Preview policy and updated external viewers remain necessary. Limited solid groups deliberately trade some cross-group compression history for parallelism, bounded memory and efficient random access.

Alpha 0.5 changes execution scheduling and buffers only, not these bytes or validation rules. Its reader prefetches a bounded set of necessary groups with per-worker reusable buffers; it never decodes outside a selected file's group range.
