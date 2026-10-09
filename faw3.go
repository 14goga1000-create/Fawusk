package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/klauspost/compress/zstd"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const faw3Window = 8 << 20

func faw3Header(total uint64, count int) []byte {
	h := faw2Header(total, count)
	binary.LittleEndian.PutUint16(h[8:10], 3)
	binary.LittleEndian.PutUint32(h[12:16], faw3Window)
	binary.LittleEndian.PutUint32(h[28:32], crc32.ChecksumIEEE(h[:28]))
	return h
}
func putU(w io.Writer, n uint64) error {
	var b [10]byte
	k := binary.PutUvarint(b[:], n)
	_, e := w.Write(b[:k])
	return e
}
func packFAW3Legacy(ctx context.Context, inputs []string, output string, level int, progress report) (err error) {
	if progress == nil {
		progress = func(int, string) {}
	}
	if !strings.EqualFold(filepath.Ext(output), ".faw") {
		return errors.New("Имя архива должно заканчиваться на .faw")
	}
	if _, e := os.Lstat(output); e == nil {
		return errors.New("Файл назначения уже существует; выберите другое имя")
	} else if !os.IsNotExist(e) {
		return e
	}
	if e := ensureParents(filepath.Dir(output)); e != nil {
		return e
	}
	progress(0, "Проверка файлов…")
	entries, total, e := plan(ctx, inputs, output)
	if e != nil {
		return e
	}
	names := 0
	for _, it := range entries {
		names += len(strings.TrimSuffix(it.name, "/"))
		if names > fawMaxNames {
			return errors.New("Превышен лимит имён FAW")
		}
	}
	tmp, e := os.CreateTemp(filepath.Dir(output), ".fawusk-*.tmp")
	if e != nil {
		return e
	}
	temp := tmp.Name()
	defer func() { tmp.Close(); os.Remove(temp) }()
	buffered := bufio.NewWriterSize(tmp, 128*1024)
	digest := sha256.New()
	compressed := io.MultiWriter(buffered, digest)
	if _, e = compressed.Write(faw3Header(uint64(total), len(entries))); e != nil {
		return e
	}
	quality := zstd.SpeedFastest
	if level == 6 {
		quality = zstd.SpeedDefault
	}
	if level == 9 {
		quality = zstd.SpeedBestCompression
	}
	enc, e := zstd.NewWriter(compressed, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(quality), zstd.WithWindowSize(faw3Window), zstd.WithLowerEncoderMem(true))
	if e != nil {
		return e
	}
	defer enc.Close()
	raw := make([]byte, 128*1024)
	counter := &copying{ctx: ctx, total: total, report: progress}
	for _, it := range entries {
		if e = check(ctx); e != nil {
			return e
		}
		name := strings.TrimSuffix(it.name, "/")
		kind := byte(2)
		size := uint64(it.info.Size())
		if it.info.IsDir() {
			kind = 1
			size = 0
		}
		if _, e = enc.Write([]byte{kind}); e != nil {
			return e
		}
		if e = putU(enc, uint64(len(name))); e != nil {
			return e
		}
		if e = putU(enc, size); e != nil {
			return e
		}
		stamp := it.info.ModTime().Unix()
		zigzag := uint64(stamp<<1) ^ uint64(stamp>>63)
		if e = putU(enc, zigzag); e != nil {
			return e
		}
		if _, e = io.WriteString(enc, name); e != nil {
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
			if !st.Mode().IsRegular() || !os.SameFile(st, it.info) || st.Size() != it.info.Size() || !st.ModTime().Equal(it.info.ModTime()) {
				return errors.New("Исходный файл изменился во время упаковки")
			}
			crc := crc32.NewIEEE()
			counter.label = "Упаковка: " + name
			n, e := io.CopyBuffer(io.MultiWriter(enc, crc, counter), io.LimitReader(f, it.info.Size()+1), raw)
			if e != nil {
				return e
			}
			after, e := f.Stat()
			if e != nil {
				return e
			}
			if n != it.info.Size() || after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) {
				return errors.New("Исходный файл изменился во время упаковки")
			}
			var b [4]byte
			binary.LittleEndian.PutUint32(b[:], crc.Sum32())
			_, e = enc.Write(b[:])
			return e
		}()
		if e != nil {
			return e
		}
	}
	if e = check(ctx); e != nil {
		return e
	}
	if _, e = enc.Write([]byte{0}); e != nil {
		return e
	}
	if e = enc.Close(); e != nil {
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
	if e = publishFile(temp, output); e != nil {
		return e
	}
	progress(100, "Готово: "+output)
	return nil
}
func unpackFAW3(ctx context.Context, p, dest string, progress report) error {
	if indexed(p) {
		return walkIndexed(ctx, p, dest, progress, nil)
	}
	return walkFAW3(ctx, p, dest, progress, nil)
}
func walkFAW3(ctx context.Context, p, dest string, progress report, visit entryVisitor) (err error) {
	if progress == nil {
		progress = func(int, string) {}
	}
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Size() < 65 || uint64(info.Size()) > maxTotal+(1<<30) {
		return errors.New("Неверный размер FAW 3")
	}
	digest := sha256.New()
	container := io.TeeReader(io.NewSectionReader(f, 0, info.Size()-32), digest)
	header := make([]byte, 32)
	if _, e = io.ReadFull(container, header); e != nil {
		return e
	}
	if !equalBytes(header[:8], fawMagic[:]) || binary.LittleEndian.Uint16(header[8:10]) != 3 || binary.LittleEndian.Uint16(header[10:12]) != 0 || binary.LittleEndian.Uint32(header[12:16]) != faw3Window || binary.LittleEndian.Uint32(header[28:32]) != crc32.ChecksumIEEE(header[:28]) {
		return errors.New("Повреждён заголовок FAW 3")
	}
	totalExpected := binary.LittleEndian.Uint64(header[16:24])
	countExpected := binary.LittleEndian.Uint32(header[24:28])
	if totalExpected > maxTotal || countExpected > maxFiles {
		return errors.New("Превышен безопасный лимит FAW 3")
	}
	decoder, e := zstd.NewReader(container, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(32<<20), zstd.WithDecoderMaxWindow(faw3Window))
	if e != nil {
		return e
	}
	defer decoder.Close()
	limit := int64(totalExpected) + fawMaxNames + int64(countExpected)*35 + 1
	reader := bufio.NewReaderSize(io.LimitReader(decoder, limit), 128*1024)
	sink, e := newExtractionSink(dest)
	if e != nil {
		return e
	}
	sink.selected = selectedName(ctx)
	defer sink.cleanup()
	guard := newNameGuard()
	var total uint64
	count := uint32(0)
	buffer := make([]byte, 128*1024)
	counter := &copying{ctx: ctx, total: int64(totalExpected), report: progress}
	progress(0, "Чтение FAW 3…")
	for {
		if e = check(ctx); e != nil {
			return e
		}
		kind, e := reader.ReadByte()
		if e != nil {
			return fmt.Errorf("Не завершён FAW 3: %w", e)
		}
		if kind == 0 {
			break
		}
		if kind != 1 && kind != 2 {
			return errors.New("Неизвестный тип записи FAW 3")
		}
		if count >= countExpected {
			return errors.New("Лишние записи FAW 3")
		}
		count++
		nameLength, e := binary.ReadUvarint(reader)
		if e != nil {
			return e
		}
		size, e := binary.ReadUvarint(reader)
		if e != nil {
			return e
		}
		zigzag, e := binary.ReadUvarint(reader)
		if e != nil {
			return e
		}
		seconds := int64(zigzag>>1) ^ -int64(zigzag&1)
		if nameLength == 0 || nameLength > 3000 {
			return errors.New("Неверная длина имени FAW 3")
		}
		if (kind == 1 && size != 0) || size > maxSingle || size > maxTotal-total {
			return errors.New("Превышен безопасный лимит распаковки FAW 3")
		}
		total += size
		if total > totalExpected {
			return errors.New("Размеры FAW 3 не совпадают")
		}
		nameBytes := make([]byte, int(nameLength))
		if _, e = io.ReadFull(reader, nameBytes); e != nil {
			return e
		}
		name := string(nameBytes)
		if e = guard.validate(name, kind == 1); e != nil {
			return e
		}
		if visit != nil {
			visit(archiveEntry{Name: name, Size: size, Directory: kind == 1, SizeKnown: kind == 2, Modified: seconds, DateKnown: true})
		}
		if kind == 1 {
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
			crc := crc32.NewIEEE()
			counter.label = "Распаковка: " + name
			n, e := io.CopyBuffer(io.MultiWriter(out, crc, counter), io.LimitReader(reader, int64(size)), buffer)
			if e != nil {
				return e
			}
			if uint64(n) != size {
				return errors.New("Файл FAW 3 обрезан")
			}
			var stored [4]byte
			if _, e = io.ReadFull(reader, stored[:]); e != nil {
				return e
			}
			if crc.Sum32() != binary.LittleEndian.Uint32(stored[:]) {
				return errors.New("CRC файла FAW 3 не совпадает")
			}
			return out.Close()
		}()
		if e != nil {
			return e
		}
		if seconds >= 0 && seconds <= 253402300799 {
			sink.timestamp(name, time.Unix(seconds, 0))
		}
	}
	if total != totalExpected || count != countExpected {
		return errors.New("Неполный каталог FAW 3")
	}
	if _, e = reader.ReadByte(); e != io.EOF {
		return errors.New("Лишние данные или повреждённый поток FAW 3")
	}
	var extra [1]byte
	if n, e := decoder.Read(extra[:]); n != 0 || e != io.EOF {
		return errors.New("Превышен лимит распакованного потока FAW 3")
	}
	if _, e = io.Copy(io.Discard, container); e != nil {
		return e
	}
	stored := make([]byte, 32)
	if _, e = f.ReadAt(stored, info.Size()-32); e != nil {
		return e
	}
	if !equalBytes(stored, digest.Sum(nil)) {
		return errors.New("SHA-256 FAW 3 не совпадает")
	}
	if e = sink.publish(ctx); e != nil {
		return e
	}
	progress(100, "Готово: "+dest)
	return nil
}
