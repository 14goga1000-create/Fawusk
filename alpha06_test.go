package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"github.com/klauspost/compress/zstd"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMetadataAllFormats(t *testing.T) {
	stamp := time.Date(2024, 5, 17, 12, 34, 56, 0, time.UTC)
	for _, format := range []string{"faw1", "faw2", "faw3", "zip", "old3"} {
		t.Run(format, func(t *testing.T) {
			root := t.TempDir()
			src := filepath.Join(root, "source")
			os.MkdirAll(filepath.Join(src, "empty"), 0700)
			p := filepath.Join(src, "notes.txt")
			os.WriteFile(p, bytes.Repeat([]byte("metadata"), 128), 0600)
			os.Chtimes(p, stamp, stamp)
			os.Chtimes(filepath.Join(src, "empty"), stamp, stamp)
			out := filepath.Join(root, "archive.faw")
			if format == "zip" {
				out = filepath.Join(root, "archive.zip")
			}
			var e error
			if format == "old3" {
				e = packFAW3Legacy(context.Background(), []string{src}, out, 1, nil)
			} else {
				e = pack(context.Background(), []string{src}, out, format, 1, nil)
			}
			if e != nil {
				t.Fatal(e)
			}
			list, e := scanArchive(context.Background(), out, nil)
			if e != nil {
				t.Fatal(e)
			}
			found := false
			for _, a := range list {
				if a.Name == "source/notes.txt" {
					found = true
					if !a.SizeKnown || a.Size != 1024 || !a.DateKnown || a.Modified != stamp.Unix() {
						t.Fatal("lost metadata", a)
					}
				}
			}
			if !found {
				t.Fatal("missing file")
			}
			for _, a := range archiveChildren(list, "source/") {
				if a.Name == "source/empty" && !a.DateKnown {
					t.Fatal("explicit folder date lost")
				}
			}
		})
	}
}
func TestFolderMetadataAndEmptyAccounting(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "empty"), 0700)
	os.WriteFile(filepath.Join(root, "zero.txt"), nil, 0600)
	os.WriteFile(filepath.Join(root, "data.bin"), make([]byte, 2048), 0600)
	rows, e := readFolder(context.Background(), root, nil)
	if e != nil {
		t.Fatal(e)
	}
	sum := totals(rows)
	if sum.Bytes != 2048 || sum.Files != 2 || sum.Directories != 1 {
		t.Fatal(sum)
	}
	for _, a := range rows {
		if !a.DateKnown {
			t.Fatal("folder date absent")
		}
		if a.Directory && sizeText(a) != "—" {
			t.Fatal("directory adds bytes")
		}
		if strings.HasSuffix(a.Name, "zero.txt") && sizeText(a) != "0 КБ" {
			t.Fatal("zero file misreported")
		}
	}
	empty, e := readFolder(context.Background(), filepath.Join(root, "empty"), nil)
	if e != nil || len(empty) != 0 || totals(empty).Bytes != 0 {
		t.Fatal("empty folder failed", e)
	}
}
func TestSizeFormattingAndOrdering(t *testing.T) {
	for _, c := range []struct {
		n    uint64
		want string
	}{{0, "0 КБ"}, {1, "<0,01 КБ"}, {1024, "1,00 КБ"}, {1 << 20, "1,00 МБ"}, {1 << 30, "1,00 ГБ"}} {
		if got := formatBytes(c.n); got != c.want {
			t.Fatal(c, got)
		}
	}
	a := []archiveEntry{{Name: "big", Size: 4096, SizeKnown: true}, {Name: "empty", Directory: true, Size: 999999, SizeKnown: true}, {Name: "zero", SizeKnown: true}}
	orderRows(a, 1, false)
	if !a[0].Directory || a[1].Name != "zero" {
		t.Fatal("size sort")
	}
	if totals(a).Bytes != 4096 {
		t.Fatal("folder metadata counted as data")
	}
}
func TestExternalZIPFixtures(t *testing.T) {
	for _, name := range []string{"external-store.zip", "external-deflate.zip", "external-bzip2.zip"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join("testdata", name)
			list, e := scanArchive(context.Background(), p, nil)
			if e != nil || len(list) != 3 {
				t.Fatal("external listing", e)
			}
			if totals(list).Bytes != uint64(len("An independently generated ZIP fixture.\n")) {
				t.Fatal("payload size", totals(list))
			}
			dest := filepath.Join(t.TempDir(), "out")
			if e = unpack(context.Background(), p, dest, nil); e != nil {
				t.Fatal(e)
			}
			b, e := os.ReadFile(filepath.Join(dest, "Документы", "notes.txt"))
			if e != nil || string(b) != "An independently generated ZIP fixture.\n" {
				t.Fatal("external bytes", e)
			}
			if st, e := os.Stat(filepath.Join(dest, "Документы", "пусто")); e != nil || !st.IsDir() {
				t.Fatal("empty directory")
			}
			temp := t.TempDir()
			if _, e = extractSelected(context.Background(), p, "Документы/notes.txt", temp, nil); e != nil {
				t.Fatal("ZIP selected preview", e)
			}
		})
	}
}
func zipRawFixture(t *testing.T, name string, extra []byte, method uint16, body []byte, plain []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "raw.zip")
	f, _ := os.Create(p)
	w := zip.NewWriter(f)
	h := zip.FileHeader{Name: name, NonUTF8: true, Method: method, Extra: extra, CRC32: crc32.ChecksumIEEE(plain), UncompressedSize64: uint64(len(plain)), CompressedSize64: uint64(len(body))}
	h.SetModTime(time.Date(2024, 5, 17, 12, 34, 56, 0, time.UTC))
	r, e := w.CreateRaw(&h)
	if e != nil {
		t.Fatal(e)
	}
	r.Write(body)
	w.Close()
	f.Close()
	return p
}
func TestZIPCP437UnicodeAndWindowsPaths(t *testing.T) {
	if len(cp437Runes) != 128 {
		t.Fatal("CP437 map length")
	}
	raw := "caf\x82.txt"
	p := zipRawFixture(t, raw, nil, zip.Store, []byte("data"), []byte("data"))
	a, e := scanArchive(context.Background(), p, nil)
	if e != nil || a[0].Name != "café.txt" {
		t.Fatal(a, e)
	}
	u := []byte("Документы/данные.txt")
	v := append([]byte{1, 0, 0, 0, 0}, u...)
	binary.LittleEndian.PutUint32(v[1:], crc32.ChecksumIEEE([]byte(raw)))
	extra := make([]byte, 4)
	binary.LittleEndian.PutUint16(extra, 0x7075)
	binary.LittleEndian.PutUint16(extra[2:], uint16(len(v)))
	extra = append(extra, v...)
	p = zipRawFixture(t, raw, extra, zip.Store, []byte("data"), []byte("data"))
	a, e = scanArchive(context.Background(), p, nil)
	if e != nil || a[0].Name != string(u) {
		t.Fatal(a, e)
	}
	p = zipRawFixture(t, "dir\\notes.txt", nil, zip.Store, []byte("data"), []byte("data"))
	dest := filepath.Join(t.TempDir(), "out")
	if e = unpack(context.Background(), p, dest, nil); e != nil {
		t.Fatal(e)
	}
	if b, e := os.ReadFile(filepath.Join(dest, "dir", "notes.txt")); e != nil || string(b) != "data" {
		t.Fatal("Windows path failed", e)
	}
}
func TestZIPZstandardAndCRC(t *testing.T) {
	plain := bytes.Repeat([]byte("Zstandard ZIP data\n"), 10000)
	enc, _ := zstd.NewWriter(nil)
	stored := enc.EncodeAll(plain, nil)
	enc.Close()
	for _, method := range []uint16{20, 93} {
		p := zipRawFixture(t, "notes.txt", nil, method, stored, plain)
		dest := filepath.Join(t.TempDir(), "out")
		if e := unpack(context.Background(), p, dest, nil); e != nil {
			t.Fatal(method, e)
		}
		b, _ := os.ReadFile(filepath.Join(dest, "notes.txt"))
		if !bytes.Equal(b, plain) {
			t.Fatal("Zstandard ZIP bytes")
		}
	}
	p := zipRawFixture(t, "notes.txt", nil, zip.Store, []byte("CORRUPT"), []byte("correct"))
	if _, e := scanArchive(context.Background(), p, nil); e != nil {
		t.Fatal("catalogue unexpectedly decoded payload", e)
	}
	dest := filepath.Join(t.TempDir(), "out")
	if e := unpack(context.Background(), p, dest, nil); e == nil {
		t.Fatal("CRC error accepted")
	}
	if _, e := os.Stat(dest); !os.IsNotExist(e) {
		t.Fatal("published CRC failure")
	}
}
func TestZIP64AndEmptyZIP(t *testing.T) {
	p := zipRawFixture(t, "notes.txt", nil, zip.Store, []byte("zip64"), []byte("zip64"))
	b, _ := os.ReadFile(p)
	end := len(b) - 22
	eocd := bytes.Clone(b[end:])
	off := binary.LittleEndian.Uint32(eocd[16:])
	length := binary.LittleEndian.Uint32(eocd[12:])
	z := make([]byte, 56)
	binary.LittleEndian.PutUint32(z, 0x06064b50)
	binary.LittleEndian.PutUint64(z[4:], 44)
	binary.LittleEndian.PutUint16(z[12:], 45)
	binary.LittleEndian.PutUint16(z[14:], 45)
	binary.LittleEndian.PutUint64(z[24:], 1)
	binary.LittleEndian.PutUint64(z[32:], 1)
	binary.LittleEndian.PutUint64(z[40:], uint64(length))
	binary.LittleEndian.PutUint64(z[48:], uint64(off))
	loc := make([]byte, 20)
	binary.LittleEndian.PutUint32(loc, 0x07064b50)
	binary.LittleEndian.PutUint64(loc[8:], uint64(end))
	binary.LittleEndian.PutUint32(loc[16:], 1)
	binary.LittleEndian.PutUint16(eocd[8:], 65535)
	binary.LittleEndian.PutUint16(eocd[10:], 65535)
	binary.LittleEndian.PutUint32(eocd[12:], 0xffffffff)
	binary.LittleEndian.PutUint32(eocd[16:], 0xffffffff)
	all := append(append(append(bytes.Clone(b[:end]), z...), loc...), eocd...)
	os.WriteFile(p, all, 0600)
	if _, e := scanArchive(context.Background(), p, nil); e != nil {
		t.Fatal("ZIP64", e)
	}
	if e := unpack(context.Background(), p, filepath.Join(t.TempDir(), "out"), nil); e != nil {
		t.Fatal(e)
	}
	p = filepath.Join(t.TempDir(), "empty.zip")
	f, _ := os.Create(p)
	w := zip.NewWriter(f)
	w.Close()
	f.Close()
	list, e := scanArchive(context.Background(), p, nil)
	if e != nil || len(list) != 0 {
		t.Fatal("empty ZIP", e)
	}
	if e = unpack(context.Background(), p, filepath.Join(t.TempDir(), "empty"), nil); e != nil {
		t.Fatal(e)
	}
}
func TestZIPRepeatedDirectoriesAndUnsafeNames(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dirs.zip")
	f, _ := os.Create(p)
	w := zip.NewWriter(f)
	w.Create("dir/")
	w.Create("dir/")
	r, _ := w.Create("dir/empty.txt")
	r.Write(nil)
	w.Close()
	f.Close()
	list, e := scanArchive(context.Background(), p, nil)
	if e != nil || len(list) != 2 || totals(list).Bytes != 0 {
		t.Fatal("duplicate empty folders", e)
	}
	if e = unpack(context.Background(), p, filepath.Join(t.TempDir(), "out"), nil); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"..\\escape.txt", "C:\\evil.txt", "\\\\server\\share\\x", "/absolute", "dir\\..\\x"} {
		p = zipRawFixture(t, name, nil, zip.Store, nil, nil)
		if _, e = scanArchive(context.Background(), p, nil); e == nil {
			t.Fatal("unsafe ZIP accepted", name)
		}
	}
}
func TestZIPUnsupportedAndEncrypted(t *testing.T) {
	for _, method := range []uint16{9, 99} {
		p := zipRawFixture(t, "notes.txt", nil, method, nil, nil)
		if _, e := scanArchive(context.Background(), p, nil); e == nil {
			t.Fatal("unsupported method accepted")
		}
	}
	p := zipRawFixture(t, "notes.txt", nil, zip.Store, nil, nil)
	b, _ := os.ReadFile(p)
	idx := bytes.Index(b, []byte("PK\x01\x02"))
	binary.LittleEndian.PutUint16(b[idx+8:], 1)
	os.WriteFile(p, b, 0600)
	if _, e := scanArchive(context.Background(), p, nil); e == nil {
		t.Fatal("encrypted accepted")
	}
}

func TestZIPStrictPathModeAndUnknownDate(t *testing.T) {
	t.Setenv("GODEBUG", "zipinsecurepath=0")
	p := zipRawFixture(t, "dir\\notes.txt", nil, zip.Store, nil, nil)
	if _, e := scanArchive(context.Background(), p, nil); e != nil {
		t.Fatal("safe normalized path in strict mode", e)
	}
	bad := zipRawFixture(t, "..\\notes.txt", nil, zip.Store, nil, nil)
	if _, e := scanArchive(context.Background(), bad, nil); e == nil {
		t.Fatal("unsafe path accepted in strict mode")
	}
	z := &zip.File{FileHeader: zip.FileHeader{Modified: time.Date(1979, 11, 30, 0, 0, 0, 0, time.UTC)}}
	if zipDateKnown(z) {
		t.Fatal("invented date from zero DOS fields")
	}
}

func TestZIPHarmlessDotPrefixes(t *testing.T) {
	p := zipRawFixture(t, "./dir//notes.txt", nil, zip.Store, []byte("data"), []byte("data"))
	a, e := scanArchive(context.Background(), p, nil)
	if e != nil || a[0].Name != "dir/notes.txt" {
		t.Fatal(a, e)
	}
	dest := filepath.Join(t.TempDir(), "out")
	if e = unpack(context.Background(), p, dest, nil); e != nil {
		t.Fatal(e)
	}
	p = zipRawFixture(t, "./dir/../escape.txt", nil, zip.Store, nil, nil)
	if _, e = scanArchive(context.Background(), p, nil); e == nil {
		t.Fatal("traversal normalization accepted")
	}
}

func FuzzZIPCatalogue(f *testing.F) {
	b, e := os.ReadFile(filepath.Join("testdata", "external-deflate.zip"))
	if e != nil {
		f.Fatal(e)
	}
	f.Add(b)
	f.Add([]byte("PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		p := filepath.Join(t.TempDir(), "fuzz.zip")
		os.WriteFile(p, data, 0600)
		_, _ = scanArchive(context.Background(), p, nil)
	})
}
