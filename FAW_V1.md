# FAW container version 1

FAW is an experimental Fawusk container, not a new compression codec. Integers are little-endian. A file is exactly `32-byte header + ZIP payload + 32-byte SHA-256 digest`.

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | Magic: ASCII `FAWUSK` followed by CR LF (`46 41 57 55 53 4b 0d 0a`) |
| 8 | 2 | Container version: 1 |
| 10 | 2 | Flags: 0; nonzero values rejected |
| 12 | 4 | Reserved: 0 |
| 16 | 8 | ZIP payload length, excluding header and digest |
| 24 | 4 | IEEE CRC-32 of bytes 0–23 |
| 28 | 4 | Reserved: 0 |
| 32 | payload length | A standalone ZIP stream, with ZIP offsets relative to the start of this payload |
| 32 + payload length | 32 | Raw SHA-256 of the ZIP payload |

ZIP uses STORE for directories and DEFLATE for files. Fawusk's preset DEFLATE levels are 1, 6, and 9. ZIP CRC-32 checks still apply. The payload can be ZIP64 where supported by the standard library and alpha limits.

Readers must check the header, exact file length, payload hash, directory allocation bounds, permitted entry names, types and methods, and extraction limits. Do not interpret a `.faw` extension as sufficient validation.

SHA-256 here is unkeyed. An attacker can change an archive and recompute it. Neither the digest nor CRC provides authentication, confidentiality, or protection from malicious file contents. No passwords, encrypted payloads, signatures, multi-volume extensions, or arbitrary trailing bytes are defined in version 1.

## Русский

FAW версии 1 состоит из собственного 32-байтного заголовка, самостоятельного ZIP-потока и 32-байтной контрольной суммы SHA-256. Все целые числа записаны младшим байтом вперёд. Смещения ZIP отсчитываются от начала ZIP-потока, а не от начала файла FAW.

Формат использует DEFLATE, а не новый алгоритм сжатия. Перед распаковкой проверяются заголовок, точная длина, контрольная сумма и безопасные пути. SHA-256 обнаруживает повреждение, но не подтверждает автора архива и не обеспечивает шифрование. Формат экспериментальный.
