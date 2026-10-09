package main

import (
	"archive/zip"
	"compress/bzip2"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/klauspost/compress/zstd"
	"hash/crc32"
	"io"
	"strings"
	"unicode/utf8"
)

const cp437High = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "

var cp437Runes = []rune(cp437High)

func zipName(z *zip.File) (string, error) {
	raw := z.Name
	name := raw
	if z.Flags&0x800 != 0 {
		if !utf8.ValidString(name) {
			return "", errors.New(tr("Некорректное UTF-8 имя ZIP"))
		}
	} else {
		var b strings.Builder
		for _, c := range []byte(raw) {
			if c < 128 {
				b.WriteByte(c)
			} else {
				b.WriteRune(cp437Runes[int(c)-128])
			}
		}
		name = b.String()
	}
	for extra := z.Extra; len(extra) >= 4; {
		tag := binary.LittleEndian.Uint16(extra)
		n := int(binary.LittleEndian.Uint16(extra[2:]))
		extra = extra[4:]
		if n > len(extra) {
			break
		}
		v := extra[:n]
		if tag == 0x7075 && n >= 5 && v[0] == 1 && binary.LittleEndian.Uint32(v[1:]) == crc32.ChecksumIEEE([]byte(raw)) && utf8.Valid(v[5:]) {
			name = string(v[5:])
			break
		}
		extra = extra[n:]
	}
	name = strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(name, "/") {
		return "", errors.New(tr("Абсолютный путь ZIP запрещён"))
	}
	directory := strings.HasSuffix(name, "/")
	parts := strings.Split(name, "/")
	clean := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == ".." {
			return "", errors.New(tr("Выход из папки ZIP запрещён"))
		}
		if p == "" || p == "." {
			continue
		}
		clean = append(clean, p)
	}
	name = strings.Join(clean, "/")
	if directory {
		name += "/"
	}
	return name, nil
}

type zipRecord struct {
	file  *zip.File
	entry archiveEntry
}

func zipRecords(ctx context.Context, zr *zip.Reader) ([]zipRecord, uint64, error) {
	if len(zr.File) > maxFiles {
		return nil, 0, errors.New(tr("Слишком много элементов ZIP"))
	}
	guard := newNameGuard()
	guard.byteLimit = maxDirectory
	seen := map[string]archiveEntry{}
	records := make([]zipRecord, 0, len(zr.File))
	var total uint64
	for _, z := range zr.File {
		if e := check(ctx); e != nil {
			return nil, 0, e
		}
		name, e := zipName(z)
		if e != nil {
			return nil, 0, e
		}
		directory := z.FileInfo().IsDir() || strings.HasSuffix(name, "/")
		name, e = safeName(name)
		if e != nil {
			return nil, 0, e
		}
		a := archiveEntry{Name: name, Size: z.UncompressedSize64, Directory: directory, SizeKnown: !directory, DateKnown: zipDateKnown(z), Modified: z.Modified.Unix()}
		if isLink(z.FileInfo()) || (!directory && !z.Mode().IsRegular()) {
			return nil, 0, errors.New(tr("ZIP содержит ссылку или специальный файл"))
		}
		if z.Flags&0x41 != 0 || z.Method == 99 {
			return nil, 0, errors.New(tr("ZIP с паролем пока не поддерживается"))
		}
		switch z.Method {
		case zip.Store, zip.Deflate, 12, 20, 93:
		default:
			return nil, 0, fmt.Errorf(tr("Метод ZIP %d не поддерживается; доступны Store, Deflate, BZip2 и Zstandard"), z.Method)
		}
		if directory && a.Size != 0 {
			return nil, 0, errors.New(tr("ZIP-папка содержит ненулевой размер данных"))
		}
		if a.Size > maxSingle || a.Size > maxTotal-total {
			return nil, 0, errors.New(tr("Превышен безопасный лимит распаковки: 8 ГиБ/файл, 20 ГиБ/архив"))
		}
		key := strings.ToLower(name)
		if old, ok := seen[key]; ok {
			if old.Directory && a.Directory && old.Name == name {
				continue
			}
			return nil, 0, errors.New(tr("Дублирующийся или неоднозначный путь ZIP"))
		}
		if e = guard.validate(name, directory); e != nil {
			return nil, 0, e
		}
		seen[key] = a
		if !directory {
			total += a.Size
		}
		records = append(records, zipRecord{z, a})
	}
	return records, total, nil
}
func registerZipCodecs(zr *zip.Reader) {
	zr.RegisterDecompressor(12, func(r io.Reader) io.ReadCloser { return io.NopCloser(bzip2.NewReader(r)) })
	z := func(r io.Reader) io.ReadCloser {
		d, e := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(64<<20), zstd.WithDecoderMaxWindow(64<<20))
		if e != nil {
			return errorZipReader{e}
		}
		return d.IOReadCloser()
	}
	zr.RegisterDecompressor(20, z)
	zr.RegisterDecompressor(93, z)
}

type errorZipReader struct{ err error }

func (r errorZipReader) Read([]byte) (int, error) { return 0, r.err }
func (errorZipReader) Close() error               { return nil }
func scanZipCatalogue(ctx context.Context, p string, progress report) ([]archiveEntry, error) {
	if progress == nil {
		progress = func(int, string) {}
	}
	f, z, e := archive(ctx, p, progress)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	records, _, e := zipRecords(ctx, z)
	if e != nil {
		return nil, e
	}
	a := make([]archiveEntry, 0, len(records))
	for _, r := range records {
		a = append(a, r.entry)
	}
	return a, nil
}

func zipDateKnown(z *zip.File) bool {
	if z.Modified.IsZero() {
		return false
	}
	if z.ModifiedDate != 0 || z.ModifiedTime != 0 {
		return true
	}
	for extra := z.Extra; len(extra) >= 4; {
		tag := binary.LittleEndian.Uint16(extra)
		n := int(binary.LittleEndian.Uint16(extra[2:]))
		extra = extra[4:]
		if n > len(extra) {
			break
		}
		if tag == 0x5455 && n >= 5 && extra[0]&1 != 0 || tag == 0x000a && n >= 32 {
			return true
		}
		extra = extra[n:]
	}
	return false
}
