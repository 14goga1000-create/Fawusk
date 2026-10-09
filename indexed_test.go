package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIndexedMultiGroupExact(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "исходники")
	os.Mkdir(src, 0700)
	data := make([]byte, 19<<20)
	rand.Read(data)
	data[0] = 'x'
	for _, name := range []string{"a.bin", "b.bin"} {
		os.WriteFile(filepath.Join(src, name), data, 0600)
	}
	os.WriteFile(filepath.Join(src, "notes.txt"), []byte("только выбранный документ\n"), 0600)
	os.WriteFile(filepath.Join(src, "empty.txt"), nil, 0600)
	out := filepath.Join(root, "x.faw")
	if e := pack(context.Background(), []string{src}, out, "faw3", 1, nil); e != nil {
		t.Fatal(e)
	}
	cat, e := readCatalogue(context.Background(), out)
	if e != nil || len(cat.Groups) < 4 {
		t.Fatal(e)
	}
	dest := filepath.Join(root, "out")
	if e = unpack(context.Background(), out, dest, nil); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"a.bin", "b.bin", "notes.txt", "empty.txt"} {
		a, _ := os.ReadFile(filepath.Join(src, name))
		b, e := os.ReadFile(filepath.Join(dest, "исходники", name))
		if e != nil || sha256.Sum256(a) != sha256.Sum256(b) {
			t.Fatal("lost data", name, e)
		}
	}
	temp := filepath.Join(root, "temp")
	os.Mkdir(temp, 0700)
	p, e := extractSelected(context.Background(), out, "исходники/notes.txt", temp, nil)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "выбранный") {
		t.Fatal("preview")
	}
	files := 0
	filepath.Walk(filepath.Join(temp, "content"), func(p string, st os.FileInfo, e error) error {
		if e == nil && !st.IsDir() {
			files++
		}
		return e
	})
	if files != 1 {
		t.Fatal("wrote other files", files)
	}
	// Corrupt an unrelated group: fast listing and selected last-file preview work,
	// but complete extraction must reject corruption, without publishing output.
	f, _ := os.OpenFile(out, os.O_RDWR, 0600)
	b = make([]byte, 1)
	f.ReadAt(b, int64(cat.Groups[0].Offset))
	b[0] ^= 1
	f.WriteAt(b, int64(cat.Groups[0].Offset))
	f.Close()
	if _, e = scanArchive(context.Background(), out, nil); e != nil {
		t.Fatal("listing unnecessarily decoded payload", e)
	}
	temp2 := filepath.Join(root, "temp2")
	os.Mkdir(temp2, 0700)
	if _, e = extractSelected(context.Background(), out, "исходники/notes.txt", temp2, nil); e != nil {
		t.Fatal("unrelated group decoded", e)
	}
	bad := filepath.Join(root, "badout")
	if e = unpack(context.Background(), out, bad, nil); e == nil {
		t.Fatal("corruption accepted")
	}
	if _, e = os.Stat(bad); !os.IsNotExist(e) {
		t.Fatal("published corruption")
	}
}
func TestPreviewAllFormats(t *testing.T) {
	for _, format := range []string{"faw1", "faw2", "faw3", "zip", "old3"} {
		t.Run(format, func(t *testing.T) {
			root := t.TempDir()
			src := filepath.Join(root, "source")
			os.Mkdir(src, 0700)
			os.WriteFile(filepath.Join(src, "notes.txt"), []byte("hello"), 0600)
			os.WriteFile(filepath.Join(src, "blocked.exe"), []byte("MZ"), 0600)
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
			temp := filepath.Join(root, "temp")
			os.Mkdir(temp, 0700)
			p, e := extractSelected(context.Background(), out, "source/notes.txt", temp, nil)
			if e != nil {
				t.Fatal(e)
			}
			b, _ := os.ReadFile(p)
			if string(b) != "hello" {
				t.Fatal("mismatch")
			}
			if _, e = os.Stat(filepath.Join(temp, "content", "source", "blocked.exe")); !os.IsNotExist(e) {
				t.Fatal("other file written")
			}
			if _, e = extractSelected(context.Background(), out, "source/blocked.exe", temp, nil); e == nil {
				t.Fatal("executable opened")
			}
		})
	}
}
func TestPreviewPolicy(t *testing.T) {
	for _, name := range []string{"x.exe", "x.bat", "x.cmd", "x.ps1", "x.vbs", "x.lnk", "x.url", "x.docm", "x.exe.txt", "x.\u202eexe.txt", "../x.txt", "x.jar", "x.js"} {
		if e := previewAllowed(name); e == nil {
			t.Fatal("allowed", name)
		}
	}
	for _, name := range []string{"x.txt", "фото.jpg", "clip.mp4", "x.pdf", "x.docx"} {
		if e := previewAllowed(name); e != nil {
			t.Fatal(e)
		}
	}
	root := t.TempDir()
	p := filepath.Join(root, "fake.txt")
	os.WriteFile(p, []byte("MZ fake PE"), 0600)
	if e := validatePreview(p); e == nil {
		t.Fatal("disguised PE")
	}
}
func TestIndexedMetadataTamper(t *testing.T) {
	root, src := fixtures(t)
	out := filepath.Join(root, "a.faw")
	packFAW3(context.Background(), []string{src}, out, 1, nil)
	b, _ := os.ReadFile(out)
	for _, at := range []int{8, 10, 28, len(b) - 1, len(b) - 64, len(b) - 40} {
		v := bytes.Clone(b)
		v[at] ^= 1
		p := filepath.Join(root, "bad.faw")
		os.WriteFile(p, v, 0600)
		if _, e := scanArchive(context.Background(), p, nil); e == nil {
			t.Fatal("accepted", at)
		}
	}
	// Valid checksum on malicious offsets must still be rejected.
	v := bytes.Clone(b)
	tr := v[len(v)-72:]
	binary.LittleEndian.PutUint64(tr[8:], ^uint64(0))
	d := sha256.New()
	d.Write(v[:32])
	off := binary.LittleEndian.Uint64(b[len(b)-64:])
	d.Write(v[off : len(v)-72])
	d.Write(tr[:40])
	copy(tr[40:], d.Sum(nil))
	p := filepath.Join(root, "overflow.faw")
	os.WriteFile(p, v, 0600)
	if _, e := readCatalogue(context.Background(), p); e == nil {
		t.Fatal("overflow accepted")
	}
}
func TestIndexedCancelPipeline(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "large.bin")
	f, _ := os.Create(p)
	f.Truncate(64 << 20)
	f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	out := filepath.Join(root, "x.faw")
	e := packFAW3(ctx, []string{p}, out, 1, func(n int, s string) {
		if n > 10 {
			cancel()
		}
	})
	if e == nil {
		t.Fatal("cancellation ignored")
	}
	if _, e = os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("cancel published")
	}
	matches, _ := filepath.Glob(filepath.Join(root, ".fawusk-*"))
	if len(matches) != 0 {
		t.Fatal("temporary leak")
	}
}
func TestFiveGiBOptIn(t *testing.T) {
	if os.Getenv("FAWUSK_5G_BENCH") != "1" {
		t.Skip("opt-in engineering stress test")
	}
	root := t.TempDir()
	src := filepath.Join(root, "zeros.bin")
	f, _ := os.Create(src)
	f.Truncate(5 << 30)
	f.Close()
	out := filepath.Join(root, "five.faw")
	started := time.Now()
	if e := packFAW3(context.Background(), []string{src}, out, 1, nil); e != nil {
		t.Fatal(e)
	}
	elapsed := time.Since(started)
	st, _ := os.Stat(out)
	t.Logf("SYNTHETIC sparse zero input: bytes=%d archive_bytes=%d pack_seconds=%.3f; Linux 2 vCPU; not Windows or mixed-file performance", uint64(5<<30), st.Size(), elapsed.Seconds())
	dest := filepath.Join(root, "out")
	if e := unpack(context.Background(), out, dest, nil); e != nil {
		t.Fatal(e)
	}
	hashFile := func(p string) [32]byte {
		f, e := os.Open(p)
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		h := sha256.New()
		if _, e = io.Copy(h, f); e != nil {
			t.Fatal(e)
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		return sum
	}
	if hashFile(src) != hashFile(filepath.Join(dest, "zeros.bin")) {
		t.Fatal("5GiB roundtrip differs")
	}
	t.Log("5GiB original and restored SHA-256 match")
}
func FuzzIndexedCatalogue(f *testing.F) {
	f.Add([]byte("FAWUSK\r\n"))
	root := f.TempDir()
	src := filepath.Join(root, "notes.txt")
	os.WriteFile(src, []byte("seed"), 0600)
	p := filepath.Join(root, "seed.faw")
	if e := packFAW3(context.Background(), []string{src}, p, 1, nil); e != nil {
		f.Fatal(e)
	}
	b, _ := os.ReadFile(p)
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		p := filepath.Join(t.TempDir(), "bad.faw")
		os.WriteFile(p, b, 0600)
		_, _ = readCatalogue(context.Background(), p)
	})
}

func TestPreviewOfficePolicy(t *testing.T) {
	for _, scenario := range []string{"normal", "macro", "external"} {
		t.Run(scenario, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "doc.docx")
			f, _ := os.Create(p)
			z := zip.NewWriter(f)
			w, _ := z.Create("[Content_Types].xml")
			io.WriteString(w, `<Types><Override ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml" /></Types>`)
			if scenario == "macro" {
				w, _ = z.Create("word/vbaProject.bin")
				w.Write([]byte("macro"))
			}
			if scenario == "external" {
				w, _ = z.Create("word/_rels/document.xml.rels")
				io.WriteString(w, `<Relationships><Relationship TargetMode = "External" Target="https://example.com/" /></Relationships>`)
			}
			z.Close()
			f.Close()
			e := validatePreview(p)
			if scenario == "normal" && e != nil || scenario != "normal" && e == nil {
				t.Fatal(scenario, e)
			}
		})
	}
}

func TestMakeReleaseDemo(t *testing.T) {
	root := os.Getenv("FAWUSK_DEMO_ROOT")
	if root == "" {
		t.Skip("release helper")
	}
	root, e := filepath.EvalSymlinks(root)
	if e != nil {
		t.Fatal(e)
	}
	src := filepath.Join(root, "Пример")
	os.MkdirAll(filepath.Join(src, "Документы"), 0700)
	os.WriteFile(filepath.Join(src, "Заметки.txt"), []byte("\xef\xbb\xbfFawusk alpha 0.6\nОткрыт только выбранный файл.\nИсходники остаются без изменений.\n"), 0600)
	os.WriteFile(filepath.Join(src, "Документы", "Прочитай.txt"), []byte("Тестовая папка для навигации."), 0600)
	stamp := time.Date(2026, 10, 8, 12, 34, 0, 0, time.UTC)
	i := 0
	filepath.Walk(src, func(p string, st os.FileInfo, e error) error {
		if e == nil {
			t := stamp.Add(time.Duration(i) * time.Hour)
			os.Chtimes(p, t, t)
			i++
		}
		return e
	})
	out := filepath.Join(root, "Пример.faw")
	os.Remove(out)
	if e = packFAW3(context.Background(), []string{src}, out, 1, nil); e != nil {
		t.Fatal(e)
	}
}

func TestIndexedDeepValidation(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "CON", "a:stream", "a\\b", "a/../x", "trailing.\u0020", "good.txt"} {
		t.Run(name, func(t *testing.T) {
			h := faw3Header(0, 1)
			binary.LittleEndian.PutUint16(h[10:], 1)
			binary.LittleEndian.PutUint32(h[28:], crc32.ChecksumIEEE(h[:28]))
			var ix bytes.Buffer
			ix.WriteString("FWIX0001")
			putU(&ix, 0)
			putU(&ix, 1)
			ix.WriteByte(2)
			putU(&ix, uint64(len(name)))
			putU(&ix, 0)
			putU(&ix, 0)
			ix.WriteString(name)
			sum := sha256.Sum256(nil)
			ix.Write(sum[:])
			tr := make([]byte, 72)
			copy(tr, "FAWIDX04")
			binary.LittleEndian.PutUint64(tr[8:], 32)
			binary.LittleEndian.PutUint64(tr[16:], uint64(ix.Len()))
			binary.LittleEndian.PutUint64(tr[24:], uint64(ix.Len()))
			d := sha256.New()
			d.Write(h)
			d.Write(ix.Bytes())
			d.Write(tr[:40])
			copy(tr[40:], d.Sum(nil))
			b := append(append(h, ix.Bytes()...), tr...)
			p := filepath.Join(t.TempDir(), "a.faw")
			os.WriteFile(p, b, 0600)
			_, e := readCatalogue(context.Background(), p)
			if name == "good.txt" && e != nil || name != "good.txt" && e == nil {
				t.Fatal("deep path guard", name, e)
			}
		})
	}
}
