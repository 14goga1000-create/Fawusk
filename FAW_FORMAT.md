# FAW 2 binary format

FAW 2 is a sequential streaming container using independent Zstandard / STORE blocks. It is not ZIP with another extension. All integers are little-endian. The writer uses bounded reused buffers and writes the integrity digest in the same pass. The reader extracts to a temporary directory and publishes only after complete validation.

## Header (32 bytes)

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | ASCII `FAWUSK` + CR LF, bytes `46 41 57 55 53 4b 0d 0a` |
| 8 | 2 | Version = 2 |
| 10 | 2 | Flags = 0; nonzero rejected |
| 12 | 4 | Block-size bound = 1,048,576 bytes; other values rejected |
| 16 | 8 | Sum of original regular-file sizes |
| 24 | 4 | Number of file and directory entries |
| 28 | 4 | IEEE CRC-32 of header bytes 0–27 |

## Entries

Each entry begins with a one-byte kind: `1` = directory, `2` = regular file. It is followed by:

| Size | Field |
| --- | --- |
| 4 | UTF-8 name length, 1…3,000 bytes |
| 8 | Original size; zero for directories |
| 8 | Signed Unix modification timestamp in seconds, encoded as its two's-complement uint64 bit pattern |
| name length | Relative UTF-8 path, `/` separators, no trailing slash |

No link, device, stream, permission or arbitrary metadata records are defined. Paths undergo portable Windows-oriented validation. Explicit duplicates and file/directory conflicts are rejected; parent directories may be implicitly created. Inconsistent casing of path ancestors is rejected.

File data is a sequence of blocks that must sum exactly to the original size. An empty file has no blocks. A directory has no blocks.

## Block

| Size | Field |
| --- | --- |
| 4 | Raw size: 1…1,048,576, no greater than the file's remaining size |
| 4 | Stored size: 1…raw size |
| 1 | Codec: `0` STORE, `1` Zstandard |
| 4 | IEEE CRC-32 of raw data |
| stored size | Data |

STORE requires stored size = raw size. Zstandard is decoded into a capacity-limited buffer of exactly the declared raw-size allowance, with one decoder worker, a 1 MiB maximum window and an 8 MiB configured decoder memory ceiling. This ceiling is a decoder option, **not** the complete process's RSS limit. The decoded length and raw CRC must match. External dictionaries are not defined.

The writer tries Zstandard at the chosen speed preset and uses STORE when compressed size is not smaller. Each block is independent; there is no cross-block/solid dictionary or deduplication in this version.

## End and digest

After the declared number of entries, a one-byte `0` ends the entry stream. A raw 32-byte SHA-256 follows. SHA-256 covers **all bytes from the header through the terminating `0`**, excluding the digest itself. No trailing bytes are permitted.

The reader must validate total original sizes and entry count against the header, checksums, all paths and all quotas before publishing the temporary destination. Corruption detection is not authenticity: an attacker can recompute SHA-256 and CRC. There is no encryption or signature.

## Alpha quotas and compatibility

At most 100,000 entries, 8 GiB/file, 20 GiB total original data, 16 MiB aggregate name bytes and 128 path components. Limits are enforced regardless of the header's claims. The archive file itself is bounded to 21 GiB. There is no arbitrary-access index, split volume or encrypted extension.

Alpha 0.2 reads [FAW 1](FAW_V1.md) and FAW 2; it creates FAW 2 from the GUI. Alpha 0.1 reads only FAW 1, not FAW 2. ZIP remains the compatible interchange option.

## Русский

FAW 2 — потоковый контейнер с собственным заголовком и независимыми блоками Zstandard/STORE по 1 МиБ. Несжимаемый блок записывается без сжатия. CRC-32 проверяет распакованный блок, SHA-256 — весь контейнер до завершающей записи. Хеш считается в процессе записи/чтения, без отдельного прохода по архиву. До окончания проверки данные находятся во временной папке.

Это не новый алгоритм сжатия и не шифрование. Alpha 0.2 читает старые FAW 1; alpha 0.1 не читает новые FAW 2. Формат пока не содержит solid-сжатия, дедупликации и индекса произвольного доступа.
