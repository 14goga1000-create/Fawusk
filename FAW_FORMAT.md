# FAW 3 Solid Stream

FAW 3 uses a versioned container and a streaming Zstandard payload with shared history across file boundaries. It is not an invented codec or ZIP renamed. All fixed integers are little-endian. Variable integers use unsigned LEB128 (Go `binary.PutUvarint` / `ReadUvarint`, maximum 10 bytes).

## Header (32 bytes)

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | ASCII `FAWUSK` + CR LF |
| 8 | 2 | Version = 3 |
| 10 | 2 | Flags = 0; nonzero rejected |
| 12 | 4 | Window bound = 8,388,608 bytes; other values rejected |
| 16 | 8 | Total original regular-file size |
| 24 | 4 | Entry count (files + directories) |
| 28 | 4 | IEEE CRC-32 of header bytes 0–27 |

## Compressed stream

Between the header and the last 32 bytes is a Zstandard stream. The writer emits one frame with an 8 MiB configured history and one codec worker. The reader supports a Zstandard stream with the same window bound, one decoder worker and a configured 32 MiB decoder memory ceiling (not total RSS). Zstandard may internally store incompressible blocks. External dictionaries are not defined.

Decoded entries:

1. One byte: `1` directory, `2` regular file, `0` end.
2. Uvarint: UTF-8 name length (1…3,000).
3. Uvarint: original size (0 for directories).
4. Uvarint: ZigZag-encoded signed Unix modification timestamp in seconds: `uint64(seconds<<1) ^ uint64(seconds>>63)`.
5. Exactly name-length UTF-8 bytes, relative path with `/`, no trailing slash.
6. For a file only: exactly original-size bytes, then 4-byte IEEE CRC-32 of those bytes. Empty-file CRC is 0.

Directories have no data or CRC trailer. The terminating `0` has no additional fields. There must be no further decoded data.

## Footer

The final 32 bytes are raw SHA-256 of **every preceding container byte**, including the header and complete compressed stream. The footer itself is excluded. Hashing is streamed during writing/reading, with no second full pass. Checksums do not provide authentication, encryption or malicious-content protection.

Readers enforce exact entry count and total file sizes, path/duplicate/conflict checks, file CRCs, valid Zstandard termination and SHA-256 before publishing a temporary destination. Browsing uses the same validation path with an in-memory manifest and discarded file bytes, not automatic extraction/execution.

## Limits

100,000 entries and unique path nodes (including implied parents); 8 GiB/file; 20 GiB total file data; 16 MiB aggregate name bytes; 128 path components. The decoded logical stream is additionally bounded to `header_total + 16 MiB + entry_count*35 + 1` bytes: worst-case compact record fields, file CRCs and end marker. Untrusted fields do not define unbounded allocations. Archive file size is limited to 21 GiB.

No random-access index, encrypted extension, password, multi-volume record or link/device record is defined. Solid history can improve related files but has memory, scan-time and damage-recovery trade-offs. Do not promise all inputs will shrink.

## Compatibility

Alpha 0.3 reads [FAW 1](FAW_V1.md), [FAW 2](FAW_V2.md), FAW 3 and supported ZIP. It writes FAW 3 from the GUI. Older alpha 0.1/0.2 do not read FAW 3; use ZIP for interchange with them.

## Русский

FAW 3 Solid Stream — контейнер с общей историей потокового Zstandard до 8 МиБ между файлами. Метаданные тоже сжимаются, записи используют компактные varint-поля. CRC-32 проверяет каждый файл, SHA-256 — заголовок и весь сжатый поток. Старые FAW 1/2 читаются, но старые приложения не читают FAW 3.

Это не новый алгоритм и не шифрование. Solid помогает похожим данным, но требует истории и последовательного чтения; уменьшение всех архивов не гарантируется. Произвольного доступа и автоматического восстановления повреждённого потока пока нет.
