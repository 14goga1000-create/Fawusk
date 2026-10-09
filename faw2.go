package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

const fawBlockSize = 1 << 20
const fawMaxNames = 16 << 20

func faw2Header(total uint64, count int) []byte {
	h := make([]byte, 32)
	copy(h, fawMagic[:])
	binary.LittleEndian.PutUint16(h[8:10], 2)
	binary.LittleEndian.PutUint32(h[12:16], fawBlockSize)
	binary.LittleEndian.PutUint64(h[16:24], total)
	binary.LittleEndian.PutUint32(h[24:28], uint32(count))
	binary.LittleEndian.PutUint32(h[28:32], crc32.ChecksumIEEE(h[:28]))
	return h
}
func packFAW2(ctx context.Context, inputs []string, output string, level int, progress report) (err error) {
	if progress == nil {
		progress = func(int, string) {}
	}
	if !strings.EqualFold(filepath.Ext(output), ".faw") {
		return errors.New(tr("Имя архива должно заканчиваться на .faw"))
	}
	if _, e := os.Lstat(output); e == nil {
		return errors.New(tr("Файл назначения уже существует; выберите другое имя"))
	} else if !os.IsNotExist(e) {
		return e
	}
	progress(0, tr("Проверка файлов…"))
	entries, total, e := plan(ctx, inputs, output)
	if e != nil {
		return e
	}
	names := 0
	for _, it := range entries {
		names += len(strings.TrimSuffix(it.name, "/"))
		if names > fawMaxNames {
			return errors.New(tr("Слишком много данных имён: лимит 16 МиБ"))
		}
	}
	quality := zstd.SpeedFastest
	if level == 6 {
		quality = zstd.SpeedDefault
	}
	if level == 9 {
		quality = zstd.SpeedBestCompression
	}
	enc, e := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(quality), zstd.WithWindowSize(fawBlockSize), zstd.WithLowerEncoderMem(true))
	if e != nil {
		return e
	}
	defer enc.Close()
	tmp, e := os.CreateTemp(filepath.Dir(output), ".fawusk-*.tmp")
	if e != nil {
		return e
	}
	tempName := tmp.Name()
	defer func() { tmp.Close(); os.Remove(tempName) }()
	buffered := bufio.NewWriterSize(tmp, 128*1024)
	digest := sha256.New()
	writer := io.MultiWriter(buffered, digest)
	if _, e = writer.Write(faw2Header(uint64(total), len(entries))); e != nil {
		return e
	}
	raw := make([]byte, fawBlockSize)
	encoded := make([]byte, 0, fawBlockSize+65536)
	counter := &copying{ctx: ctx, total: total, report: progress}
	for _, it := range entries {
		if e = check(ctx); e != nil {
			return e
		}
		name := strings.TrimSuffix(it.name, "/")
		kind := byte(2)
		if it.info.IsDir() {
			kind = 1
		}
		meta := make([]byte, 21)
		meta[0] = kind
		binary.LittleEndian.PutUint32(meta[1:5], uint32(len(name)))
		if kind == 2 {
			binary.LittleEndian.PutUint64(meta[5:13], uint64(it.info.Size()))
		}
		binary.LittleEndian.PutUint64(meta[13:21], uint64(it.info.ModTime().Unix()))
		if _, e = writer.Write(meta); e != nil {
			return e
		}
		if _, e = io.WriteString(writer, name); e != nil {
			return e
		}
		if kind == 1 {
			continue
		}
		f, e := os.Open(it.path)
		if e != nil {
			return e
		}
		e = func() error {
			defer f.Close()
			st, e := f.Stat()
			if e != nil {
				return e
			}
			if !st.Mode().IsRegular() || st.Size() != it.info.Size() || !st.ModTime().Equal(it.info.ModTime()) || !os.SameFile(st, it.info) {
				return errors.New(tr("Исходный файл изменился во время упаковки"))
			}
			remaining := it.info.Size()
			counter.label = tr("Упаковка: ") + name
			for remaining > 0 {
				if e = check(ctx); e != nil {
					return e
				}
				size := len(raw)
				if remaining < int64(size) {
					size = int(remaining)
				}
				if _, e = io.ReadFull(f, raw[:size]); e != nil {
					return e
				}
				encoded = enc.EncodeAll(raw[:size], encoded[:0])
				codec := byte(1)
				payload := encoded
				if len(payload) >= size {
					codec = 0
					payload = raw[:size]
				}
				block := [13]byte{}
				binary.LittleEndian.PutUint32(block[:4], uint32(size))
				binary.LittleEndian.PutUint32(block[4:8], uint32(len(payload)))
				block[8] = codec
				binary.LittleEndian.PutUint32(block[9:13], crc32.ChecksumIEEE(raw[:size]))
				if _, e = writer.Write(block[:]); e != nil {
					return e
				}
				if _, e = writer.Write(payload); e != nil {
					return e
				}
				if _, e = counter.Write(raw[:size]); e != nil {
					return e
				}
				remaining -= int64(size)
			}
			var extra [1]byte
			n, e := f.Read(extra[:])
			if n != 0 || e != io.EOF {
				return errors.New(tr("Исходный файл изменился во время упаковки"))
			}
			after, e := f.Stat()
			if e != nil {
				return e
			}
			if after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) {
				return errors.New(tr("Исходный файл изменился во время упаковки"))
			}
			return nil
		}()
		if e != nil {
			return e
		}
	}
	if e = check(ctx); e != nil {
		return e
	}
	if _, e = writer.Write([]byte{0}); e != nil {
		return e
	}
	if _, e = buffered.Write(digest.Sum(nil)); e != nil {
		return e
	}
	if e = buffered.Flush(); e != nil {
		return e
	}
	if e = tmp.Sync(); e != nil {
		return e
	}
	if e = tmp.Close(); e != nil {
		return e
	}
	if e = check(ctx); e != nil {
		return e
	}
	if e = beforeArchivePublish(ctx, tempName); e != nil {
		return e
	}
	if e = publishFile(tempName, output); e != nil {
		return e
	}
	progress(100, tr("Готово: ")+output)
	return nil
}

// All allocations controlled by format constants, not arbitrary archive fields.
func unpackFAW2(ctx context.Context, p, dest string, progress report) error {
	return walkFAW2(ctx, p, dest, progress, nil)
}
func walkFAW2(ctx context.Context, archivePath, dest string, progress report, visit entryVisitor) (err error) {
	if progress == nil {
		progress = func(int, string) {}
	}
	f, e := os.Open(archivePath)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Size() < 65 || uint64(info.Size()) > maxTotal+(1<<30) {
		return errors.New(tr("Неверный размер FAW"))
	}
	digest := sha256.New()
	base := bufio.NewReaderSize(f, 128*1024)
	reader := io.TeeReader(base, digest)
	header := make([]byte, 32)
	if _, e = io.ReadFull(reader, header); e != nil {
		return e
	}
	if !equalBytes(header[:8], fawMagic[:]) || binary.LittleEndian.Uint16(header[8:10]) != 2 || binary.LittleEndian.Uint16(header[10:12]) != 0 || binary.LittleEndian.Uint32(header[12:16]) != fawBlockSize || binary.LittleEndian.Uint32(header[28:32]) != crc32.ChecksumIEEE(header[:28]) {
		return errors.New(tr("Повреждён заголовок FAW 2"))
	}
	expectedTotal := binary.LittleEndian.Uint64(header[16:24])
	expectedCount := binary.LittleEndian.Uint32(header[24:28])
	if expectedTotal > maxTotal || expectedCount > maxFiles {
		return errors.New(tr("Превышен безопасный лимит FAW"))
	}
	sink, e := newExtractionSink(ctx, dest)
	if e != nil {
		return e
	}
	sink.selected = selectedName(ctx)
	defer sink.cleanup()
	decoder, e := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(8<<20), zstd.WithDecoderMaxWindow(fawBlockSize), zstd.WithDecodeAllCapLimit(true))
	if e != nil {
		return e
	}
	defer decoder.Close()
	stored := make([]byte, fawBlockSize)
	raw := make([]byte, 0, fawBlockSize)
	explicit := map[string]bool{}
	types := map[string]bool{}
	canonical := map[string]string{}
	var total uint64
	count := uint32(0)
	names := uint64(0)
	counter := &copying{ctx: ctx, total: int64(expectedTotal), report: progress}
	progress(0, tr("Распаковка FAW 2…"))
	for {
		if e = check(ctx); e != nil {
			return e
		}
		var kind [1]byte
		if _, e = io.ReadFull(reader, kind[:]); e != nil {
			return fmt.Errorf(tr("Не завершён FAW: %w"), e)
		}
		if kind[0] == 0 {
			break
		}
		if kind[0] != 1 && kind[0] != 2 {
			return errors.New(tr("Неизвестный тип записи FAW"))
		}
		if count >= expectedCount {
			return errors.New(tr("Лишние записи FAW"))
		}
		count++
		var meta [20]byte
		if _, e = io.ReadFull(reader, meta[:]); e != nil {
			return e
		}
		nameSize := binary.LittleEndian.Uint32(meta[:4])
		size := binary.LittleEndian.Uint64(meta[4:12])
		seconds := int64(binary.LittleEndian.Uint64(meta[12:20]))
		names += uint64(nameSize)
		if nameSize == 0 || nameSize > 3000 || names > fawMaxNames {
			return errors.New(tr("Превышен лимит имён FAW"))
		}
		if (kind[0] == 1 && size != 0) || size > maxSingle || size > maxTotal-total {
			return errors.New(tr("Превышен безопасный лимит распаковки FAW"))
		}
		total += size
		if total > expectedTotal {
			return errors.New(tr("Размеры записей не совпадают с заголовком FAW"))
		}
		nameBytes := make([]byte, nameSize)
		if _, e = io.ReadFull(reader, nameBytes); e != nil {
			return e
		}
		name, e := safeName(string(nameBytes))
		if e != nil {
			return e
		}
		if strings.HasSuffix(string(nameBytes), "/") {
			return errors.New(tr("FAW 2 не допускает завершающий слеш в имени"))
		}
		key := strings.ToLower(name)
		isDir := kind[0] == 1
		if explicit[key] {
			return errors.New(tr("Дублирующийся путь FAW"))
		}
		if old, exists := types[key]; exists && old != isDir {
			return errors.New(tr("Конфликт файлов и папок FAW"))
		}
		explicit[key] = true
		types[key] = isDir
		// Reject inconsistent casing of ancestors, even on case-sensitive test systems.
		for p := name; p != "."; p = path.Dir(p) {
			k := strings.ToLower(p)
			if old, exists := canonical[k]; exists && old != p {
				return errors.New(tr("Неоднозначный регистр пути FAW"))
			}
			if _, exists := canonical[k]; !exists && len(canonical) >= maxFiles {
				return errors.New(tr("Превышен лимит компонентов путей"))
			}
			canonical[k] = p
			if p != name {
				if directory, exists := types[k]; exists && !directory {
					return errors.New(tr("Файл используется как папка FAW"))
				}
				types[k] = true
			}
		}
		if visit != nil {
			visit(archiveEntry{Name: name, Size: size, Directory: isDir, SizeKnown: !isDir, Modified: seconds, DateKnown: true})
		}
		if isDir {
			if e = sink.directory(name); e != nil {
				return e
			}
			sink.directoryTimestamp(name, time.Unix(seconds, 0))
			continue
		}
		out, e := sink.file(name)
		if e != nil {
			return e
		}
		e = func() error {
			defer out.Close()
			left := size
			counter.label = tr("Распаковка: ") + name
			for left > 0 {
				if e = check(ctx); e != nil {
					return e
				}
				var block [13]byte
				if _, e = io.ReadFull(reader, block[:]); e != nil {
					return e
				}
				rawSize := binary.LittleEndian.Uint32(block[:4])
				storedSize := binary.LittleEndian.Uint32(block[4:8])
				codec := block[8]
				if rawSize == 0 || rawSize > fawBlockSize || uint64(rawSize) > left || storedSize == 0 || storedSize > rawSize || codec > 1 || (codec == 0 && storedSize != rawSize) {
					return errors.New(tr("Неверные размеры или кодек блока FAW"))
				}
				if _, e = io.ReadFull(reader, stored[:storedSize]); e != nil {
					return e
				}
				var data []byte
				if codec == 0 {
					data = stored[:storedSize]
				} else {
					data, e = decoder.DecodeAll(stored[:storedSize], raw[:0:rawSize])
					if e != nil {
						return fmt.Errorf(tr("Повреждён блок Zstandard: %w"), e)
					}
				}
				if len(data) != int(rawSize) || crc32.ChecksumIEEE(data) != binary.LittleEndian.Uint32(block[9:13]) {
					return errors.New(tr("Контрольная сумма или размер блока FAW не совпадает"))
				}
				if _, e = out.Write(data); e != nil {
					return e
				}
				if _, e = counter.Write(data); e != nil {
					return e
				}
				left -= uint64(rawSize)
			}
			return out.Close()
		}()
		if e != nil {
			return e
		}
		if seconds >= 0 && seconds <= 253402300799 {
			stamp := time.Unix(seconds, 0)
			sink.timestamp(name, stamp)
		}
	}
	if total != expectedTotal || count != expectedCount {
		return errors.New(tr("Неполный каталог FAW"))
	}
	sum := digest.Sum(nil)
	footer := make([]byte, 32)
	if _, e = io.ReadFull(base, footer); e != nil {
		return e
	}
	if !equalBytes(sum, footer) {
		return errors.New(tr("FAW повреждён: SHA-256 не совпадает"))
	}
	if _, e = base.ReadByte(); e != io.EOF {
		return errors.New(tr("Лишние данные после FAW"))
	}
	if e = check(ctx); e != nil {
		return e
	}
	if e = sink.publish(ctx); e != nil {
		return e
	}
	progress(100, tr("Готово: ")+dest)
	return nil
}
