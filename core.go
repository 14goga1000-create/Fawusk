package main

import (
	"archive/zip"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const appVersion = "alpha 0.6"
const maxFiles = 100000
const maxTotal = uint64(20) << 30
const maxSingle = uint64(8) << 30
const maxDirectory = uint64(64) << 20

var fawMagic = [8]byte{'F', 'A', 'W', 'U', 'S', 'K', '\r', '\n'}

type report func(int, string)
type item struct {
	path, name string
	info       os.FileInfo
}

func check(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
func isLink(info os.FileInfo) bool {
	return info.Mode()&(os.ModeSymlink|os.ModeDevice|os.ModeNamedPipe|os.ModeSocket) != 0
}

// Portable paths deliberately reject Windows aliases and ambiguous names.
func safeName(name string) (string, error) {
	if !utf8.ValidString(name) || strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") || len(name) > 3000 {
		return "", errors.New("Недопустимый путь в архиве")
	}
	trimmed := strings.TrimSuffix(name, "/")
	if strings.Count(trimmed, "/") > 127 {
		return "", errors.New("Слишком глубокий путь")
	}
	if trimmed == "" {
		return "", errors.New("Пустой путь в архиве")
	}
	for _, p := range strings.Split(trimmed, "/") {
		if p == "" || p == "." || p == ".." || strings.HasSuffix(p, ".") || strings.HasSuffix(p, " ") || strings.ContainsAny(p, "<>\"|?*") {
			return "", fmt.Errorf("Опасное имя: %q", name)
		}
		for _, r := range p {
			if r < 32 || r == 127 {
				return "", fmt.Errorf("Управляющий символ: %q", name)
			}
		}
		base := strings.ToUpper(strings.TrimRight(strings.SplitN(p, ".", 2)[0], " ."))
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CONIN$" || base == "CONOUT$" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9') || base == "COM¹" || base == "COM²" || base == "COM³" || base == "LPT¹" || base == "LPT²" || base == "LPT³" {
			return "", fmt.Errorf("Зарезервированное имя Windows: %q", name)
		}
	}
	return trimmed, nil
}

func plan(ctx context.Context, inputs []string, output string) ([]item, int64, error) {
	if len(inputs) == 0 {
		return nil, 0, errors.New("Добавьте файлы или папку")
	}
	out, _ := filepath.Abs(output)
	seen := map[string]bool{}
	roots := map[string]bool{}
	var entries []item
	var total int64
	for _, p := range inputs {
		abs, e := filepath.Abs(p)
		if e != nil {
			return nil, 0, e
		}
		key := strings.ToLower(abs)
		if roots[key] {
			continue
		}
		roots[key] = true
		root := filepath.Base(abs)
		if root == "." || root == string(filepath.Separator) {
			return nil, 0, errors.New("Выберите папку, а не корень диска")
		}
		e = filepath.Walk(abs, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if e := check(ctx); e != nil {
				return e
			}
			if strings.EqualFold(path, out) {
				return errors.New("Архив нельзя создавать внутри выбранной папки или поверх исходного файла")
			}
			if isLink(info) || platformUnsafe(path, info) {
				return fmt.Errorf("Ссылки, junction и специальные файлы не поддерживаются: %s", path)
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				return fmt.Errorf("Необычный тип файла: %s", path)
			}
			rel, e := filepath.Rel(abs, path)
			if e != nil {
				return e
			}
			name := root
			if rel != "." {
				name += "/" + filepath.ToSlash(rel)
			}
			clean, e := safeName(name)
			if e != nil {
				return e
			}
			key := strings.ToLower(clean)
			if seen[key] {
				return fmt.Errorf("Совпадающие имена в архиве: %s", name)
			}
			seen[key] = true
			if len(entries) >= maxFiles {
				return errors.New("Лимит alpha: 100 000 элементов")
			}
			if !info.IsDir() {
				if uint64(info.Size()) > maxSingle {
					return errors.New("Лимит alpha: 8 ГиБ на один файл")
				}
				total += info.Size()
				if uint64(total) > maxTotal {
					return errors.New("Лимит alpha: 20 ГиБ исходных данных")
				}
			}
			if info.IsDir() {
				name += "/"
			}
			entries = append(entries, item{path, name, info})
			return nil
		})
		if e != nil {
			return nil, 0, e
		}
		if st, e := os.Stat(abs); e == nil && st.IsDir() {
			rel, e := filepath.Rel(abs, out)
			if e == nil && (rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")) {
				return nil, 0, errors.New("Сохраните архив вне выбранной папки")
			}
		}
	}
	return entries, total, nil
}

type copying struct {
	ctx         context.Context
	done, total int64
	label       string
	report      report
	last        time.Time
}

func (c *copying) Write(p []byte) (int, error) {
	if e := check(c.ctx); e != nil {
		return 0, e
	}
	c.done += int64(len(p))
	if time.Since(c.last) > 120*time.Millisecond {
		n := 0
		if c.total > 0 {
			n = int(c.done * 100 / c.total)
		}
		if n > 99 {
			n = 99
		}
		c.report(n, c.label)
		c.last = time.Now()
	}
	return len(p), nil
}
func pack(ctx context.Context, inputs []string, output, format string, level int, progress report) (err error) {
	if format == "faw" || format == "faw3" {
		return packFAW3(ctx, inputs, output, level, progress)
	}
	if format == "faw2" {
		return packFAW2(ctx, inputs, output, level, progress)
	}
	if format == "faw1" {
		format = "faw"
	}
	return packLegacy(ctx, inputs, output, format, level, progress)
}

func packLegacy(ctx context.Context, inputs []string, output, format string, level int, progress report) (err error) {
	if progress == nil {
		progress = func(int, string) {}
	}
	if format != "zip" && format != "faw" {
		return errors.New("Создание RAR не поддерживается: нужен лицензированный RAR. Выберите ZIP или FAW")
	}
	if !strings.EqualFold(filepath.Ext(output), "."+format) {
		return fmt.Errorf("Имя архива должно заканчиваться на .%s", format)
	}
	if _, e := os.Lstat(output); e == nil {
		return errors.New("Файл назначения уже существует; выберите другое имя")
	} else if !os.IsNotExist(e) {
		return e
	}
	progress(0, "Проверка исходных файлов…")
	entries, total, e := plan(ctx, inputs, output)
	if e != nil {
		return e
	}
	tmp, e := os.CreateTemp(filepath.Dir(output), ".fawusk-*.tmp")
	if e != nil {
		return e
	}
	tmpName := tmp.Name()
	defer func() { tmp.Close(); os.Remove(tmpName) }()
	offset := int64(0)
	if format == "faw" {
		offset = 32
		if _, e = tmp.Write(make([]byte, 32)); e != nil {
			return e
		}
	}
	zw := zip.NewWriter(tmp)
	zw.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) { return flate.NewWriter(w, level) })
	counter := &copying{ctx: ctx, total: total, report: progress}
	buffer := make([]byte, 128*1024)
	for _, it := range entries {
		if e = check(ctx); e != nil {
			zw.Close()
			return e
		}
		h, e := zip.FileInfoHeader(it.info)
		if e != nil {
			zw.Close()
			return e
		}
		h.Name = it.name
		h.Method = zip.Deflate
		h.NonUTF8 = false
		h.SetMode(it.info.Mode().Perm())
		if it.info.IsDir() {
			h.Method = zip.Store
			h.SetMode(os.ModeDir | 0755)
		}
		w, e := zw.CreateHeader(h)
		if e != nil {
			zw.Close()
			return e
		}
		if it.info.IsDir() {
			continue
		}
		f, e := os.Open(it.path)
		if e != nil {
			zw.Close()
			return e
		}
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() != it.info.Size() || !st.ModTime().Equal(it.info.ModTime()) || !os.SameFile(st, it.info) {
			f.Close()
			zw.Close()
			return errors.New("Исходный файл изменился во время упаковки")
		}
		counter.label = "Упаковка: " + it.name
		n, e := io.CopyBuffer(io.MultiWriter(w, counter), io.LimitReader(f, it.info.Size()+1), buffer)
		after, se := f.Stat()
		f.Close()
		if e != nil {
			zw.Close()
			return e
		}
		if se != nil || n != it.info.Size() || !after.ModTime().Equal(st.ModTime()) {
			zw.Close()
			return errors.New("Исходный файл изменился во время упаковки")
		}
	}
	if e = zw.Close(); e != nil {
		return e
	}
	if format == "faw" {
		end, e := tmp.Seek(0, io.SeekCurrent)
		if e != nil {
			return e
		}
		payload := uint64(end - offset)
		header := make([]byte, 32)
		copy(header, fawMagic[:])
		binary.LittleEndian.PutUint16(header[8:10], 1)
		binary.LittleEndian.PutUint64(header[16:24], payload)
		binary.LittleEndian.PutUint32(header[24:28], crc32.ChecksumIEEE(header[:24]))
		if _, e = tmp.WriteAt(header, 0); e != nil {
			return e
		}
		progress(99, "Проверка целостности FAW…")
		hash := sha256.New()
		c := &copying{ctx: ctx, total: int64(payload), report: func(int, string) {}}
		if _, e = io.CopyBuffer(io.MultiWriter(hash, c), io.NewSectionReader(tmp, 32, int64(payload)), make([]byte, 128*1024)); e != nil {
			return e
		}
		if _, e = tmp.Write(hash.Sum(nil)); e != nil {
			return e
		}
	}
	if e = check(ctx); e != nil {
		return e
	}
	if e = tmp.Sync(); e != nil {
		return e
	}
	if e = tmp.Close(); e != nil {
		return e
	}
	if e = publishFile(tmpName, output); e != nil {
		return e
	}
	progress(100, "Готово: "+output)
	return nil
}

// Bound central-directory allocation before archive/zip parses untrusted data.
func inspectDirectory(r io.ReaderAt, size int64) error {
	if size < 22 {
		return errors.New("Слишком короткий ZIP")
	}
	n := int64(65557)
	if size < n {
		n = size
	}
	tail := make([]byte, n)
	if _, e := r.ReadAt(tail, size-n); e != nil {
		return e
	}
	pos := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:i+4]) == 0x06054b50 && i+22+int(binary.LittleEndian.Uint16(tail[i+20:i+22])) == len(tail) {
			pos = i
			break
		}
	}
	if pos < 0 {
		return errors.New("Повреждено окончание ZIP")
	}
	b := tail[pos:]
	if binary.LittleEndian.Uint16(b[4:6]) != 0 || binary.LittleEndian.Uint16(b[6:8]) != 0 {
		return errors.New("Многотомные архивы не поддерживаются")
	}
	count := uint64(binary.LittleEndian.Uint16(b[10:12]))
	length := uint64(binary.LittleEndian.Uint32(b[12:16]))
	off := uint64(binary.LittleEndian.Uint32(b[16:20]))
	eocd := size - n + int64(pos)
	if count == 65535 || length == 0xffffffff || off == 0xffffffff {
		if eocd < 20 {
			return errors.New("Повреждён ZIP64")
		}
		loc := make([]byte, 20)
		if _, e := r.ReadAt(loc, eocd-20); e != nil {
			return e
		}
		if binary.LittleEndian.Uint32(loc[:4]) != 0x07064b50 || binary.LittleEndian.Uint32(loc[4:8]) != 0 || binary.LittleEndian.Uint32(loc[16:20]) != 1 {
			return errors.New("Неподдерживаемый ZIP64")
		}
		zoff := binary.LittleEndian.Uint64(loc[8:16])
		if zoff > uint64(size-56) {
			return errors.New("Неверный адрес ZIP64")
		}
		z := make([]byte, 56)
		if _, e := r.ReadAt(z, int64(zoff)); e != nil {
			return e
		}
		if binary.LittleEndian.Uint32(z[:4]) != 0x06064b50 || binary.LittleEndian.Uint32(z[16:20]) != 0 || binary.LittleEndian.Uint32(z[20:24]) != 0 {
			return errors.New("Неподдерживаемый ZIP64")
		}
		count = binary.LittleEndian.Uint64(z[32:40])
		length = binary.LittleEndian.Uint64(z[40:48])
		off = binary.LittleEndian.Uint64(z[48:56])
	}
	if count > maxFiles || length > maxDirectory || off > uint64(size) || length > uint64(size)-off {
		return errors.New("Превышен лимит или повреждён каталог ZIP")
	}
	return nil
}
func archive(ctx context.Context, path string, progress report) (*os.File, *zip.Reader, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, nil, e
	}
	fail := func(e error) (*os.File, *zip.Reader, error) { f.Close(); return nil, nil, e }
	st, e := f.Stat()
	if e != nil {
		return fail(e)
	}
	size := st.Size()
	if !st.Mode().IsRegular() || size > int64(maxTotal)+(1<<30) {
		return fail(errors.New("Слишком большой или неподдерживаемый файл"))
	}
	var reader io.ReaderAt = f
	var magic [8]byte
	f.ReadAt(magic[:], 0)
	if magic == fawMagic {
		h := make([]byte, 32)
		if _, e = f.ReadAt(h, 0); e != nil {
			return fail(e)
		}
		if binary.LittleEndian.Uint16(h[8:10]) != 1 || binary.LittleEndian.Uint16(h[10:12]) != 0 || binary.LittleEndian.Uint32(h[12:16]) != 0 || binary.LittleEndian.Uint32(h[28:32]) != 0 || crc32.ChecksumIEEE(h[:24]) != binary.LittleEndian.Uint32(h[24:28]) {
			return fail(errors.New("Повреждён заголовок или неподдерживаемая версия FAW"))
		}
		length := binary.LittleEndian.Uint64(h[16:24])
		if size < 64 || length != uint64(size-64) {
			return fail(errors.New("Неверный размер FAW"))
		}
		progress(0, "Проверка SHA-256…")
		hash := sha256.New()
		c := &copying{ctx: ctx, total: int64(length), report: func(int, string) {}}
		if _, e = io.CopyBuffer(io.MultiWriter(hash, c), io.NewSectionReader(f, 32, int64(length)), make([]byte, 128*1024)); e != nil {
			return fail(e)
		}
		stored := make([]byte, 32)
		if _, e = f.ReadAt(stored, 32+int64(length)); e != nil {
			return fail(e)
		}
		if !equalBytes(stored, hash.Sum(nil)) {
			return fail(errors.New("FAW повреждён: SHA-256 не совпадает"))
		}
		reader = io.NewSectionReader(f, 32, int64(length))
		size = int64(length)
	} else if strings.EqualFold(filepath.Ext(path), ".faw") {
		return fail(errors.New("Этот файл не является архивом FAW"))
	}
	if e = inspectDirectory(reader, size); e != nil {
		return fail(e)
	}
	zr, e := zip.NewReader(reader, size)
	if e != nil && !(e == zip.ErrInsecurePath && zr != nil) {
		return fail(e)
	}
	registerZipCodecs(zr)
	return f, zr, nil
}
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
func unpack(ctx context.Context, path, dest string, progress report) (err error) {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	var prefix [10]byte
	_, e = f.ReadAt(prefix[:], 0)
	f.Close()
	if e == nil && equalBytes(prefix[:8], fawMagic[:]) {
		switch binary.LittleEndian.Uint16(prefix[8:10]) {
		case 2:
			return unpackFAW2(ctx, path, dest, progress)
		case 3:
			return unpackFAW3(ctx, path, dest, progress)
		}
	}
	return unpackLegacy(ctx, path, dest, progress)
}

func unpackLegacy(ctx context.Context, path, dest string, progress report) error {
	return walkLegacy(ctx, path, dest, progress, nil)
}
func walkLegacy(ctx context.Context, path, dest string, progress report, visit entryVisitor) (err error) {
	if progress == nil {
		progress = func(int, string) {}
	}
	if strings.EqualFold(filepath.Ext(path), ".rar") {
		return errors.New("RAR в alpha 0.6 не поддерживается. Для тестирования используйте ZIP или FAW")
	}
	f, zr, e := archive(ctx, path, progress)
	if e != nil {
		return e
	}
	defer f.Close()
	records, total, e := zipRecords(ctx, zr)
	if e != nil {
		return e
	}
	selected := selectedName(ctx)
	if selected != "" {
		found := false
		for _, r := range records {
			if r.entry.Name == selected && !r.entry.Directory {
				found = true
				if r.entry.Size > previewLimit {
					return errors.New("Просмотр ограничен 1 ГиБ")
				}
			}
		}
		if !found {
			return errors.New("Файл отсутствует в ZIP")
		}
	}
	sink, e := newExtractionSink(dest)
	if e != nil {
		return e
	}
	sink.selected = selectedName(ctx)
	defer sink.cleanup()
	counter := &copying{ctx: ctx, total: int64(total), report: progress}
	buffer := make([]byte, 128*1024)
	for _, record := range records {
		z := record.file
		meta := record.entry
		if selected != "" && meta.Name != selected {
			continue
		}
		if e = check(ctx); e != nil {
			return e
		}
		name := meta.Name
		if visit != nil {
			visit(meta)
		}
		if meta.Directory {
			if e = sink.directory(name); e != nil {
				return e
			}
			if meta.DateKnown {
				sink.directoryTimestamp(name, z.Modified)
			}
			continue
		}
		r, e := z.Open()
		if e != nil {
			return e
		}
		w, e := sink.file(name)
		if e != nil {
			r.Close()
			return e
		}
		counter.label = "Распаковка: " + z.Name
		n, e := io.CopyBuffer(io.MultiWriter(w, counter), io.LimitReader(r, int64(z.UncompressedSize64)+1), buffer)
		ce := w.Close()
		r.Close()
		if e != nil {
			return fmt.Errorf("%s: %w", z.Name, e)
		}
		if ce != nil {
			return ce
		}
		if uint64(n) != z.UncompressedSize64 {
			return errors.New("Размер файла не совпадает с каталогом архива")
		}
		if !z.Modified.IsZero() {
			sink.timestamp(name, z.Modified)
		}
	}
	if e = check(ctx); e != nil {
		return e
	}
	if e = sink.publish(ctx); e != nil {
		return e
	}
	progress(100, "Готово: "+dest)
	return nil
}
func ensureParents(path string) error {
	abs, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	for p := abs; ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if !info.IsDir() || isLink(info) || platformUnsafe(p, info) {
			return errors.New("Папка назначения или родитель — ссылка / junction")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
