package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixtures(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(root, "Данные")
	if e := os.MkdirAll(filepath.Join(src, "пустая папка"), 0700); e != nil {
		t.Fatal(e)
	}
	for n, d := range map[string][]byte{"hello.txt": bytes.Repeat([]byte("Fawusk alpha — привет!\n"), 12000), "zero.bin": {}, "random.bin": func() []byte {
		b := make([]byte, 8192)
		for i := range b {
			b[i] = byte(i * 17)
		}
		return b
	}()} {
		if e := os.WriteFile(filepath.Join(src, n), d, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return root, src
}
func TestRoundTrip(t *testing.T) {
	for _, format := range []string{"zip", "faw"} {
		for _, level := range []int{1, 6, 9} {
			t.Run(fmt.Sprintf("%s-level-%d", format, level), func(t *testing.T) {
				root, src := fixtures(t)
				out := filepath.Join(root, "archive."+format)
				if e := pack(context.Background(), []string{src}, out, format, level, nil); e != nil {
					t.Fatal(e)
				}
				dest := filepath.Join(root, "result")
				if e := unpack(context.Background(), out, dest, nil); e != nil {
					t.Fatal(e)
				}
				filepath.Walk(src, func(p string, st os.FileInfo, e error) error {
					if e != nil {
						t.Fatal(e)
					}
					rel, _ := filepath.Rel(src, p)
					actual := filepath.Join(dest, filepath.Base(src), rel)
					if st.IsDir() {
						if a, e := os.Stat(actual); e != nil || !a.IsDir() {
							t.Errorf("missing directory %s", actual)
						}
					} else {
						a, _ := os.ReadFile(p)
						b, e := os.ReadFile(actual)
						if e != nil || !bytes.Equal(a, b) {
							t.Errorf("mismatch %s", actual)
						}
					}
					return nil
				})
			})
		}
	}
}
func TestNoOverwrite(t *testing.T) {
	root, src := fixtures(t)
	out := filepath.Join(root, "a.zip")
	old := []byte("existing")
	os.WriteFile(out, old, 0600)
	if e := pack(context.Background(), []string{src}, out, "zip", 1, nil); e == nil {
		t.Fatal("overwrite allowed")
	}
	b, _ := os.ReadFile(out)
	if !bytes.Equal(b, old) {
		t.Fatal("modified original output")
	}
}
func TestInsideSource(t *testing.T) {
	_, src := fixtures(t)
	if e := pack(context.Background(), []string{src}, filepath.Join(src, "a.faw"), "faw", 1, nil); e == nil {
		t.Fatal("output inside source accepted")
	}
}
func TestBadNames(t *testing.T) {
	for _, n := range []string{"../x", "/absolute", "a/../../x", "C:/x", "a\\x", "CON", "aux.txt", "LPT1.log", "nul", "a.", "a ", "a//b", "a/./b", "a:stream", "foo\x00bar", "COM¹.txt", "a/CONOUT$"} {
		if _, e := safeName(n); e == nil {
			t.Errorf("accepted %q", n)
		}
	}
	for _, n := range []string{"привет/мир.txt", "test.txt", "dir/", "a/b/c", "COMPUTER.txt"} {
		if _, e := safeName(n); e != nil {
			t.Errorf("rejected %q", n)
		}
	}
}
func malicious(t *testing.T, entries []string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bad.zip")
	f, _ := os.Create(p)
	w := zip.NewWriter(f)
	for _, n := range entries {
		a, _ := w.Create(n)
		a.Write([]byte("payload"))
	}
	w.Close()
	f.Close()
	return p
}
func TestTraversal(t *testing.T) {
	for _, n := range []string{"../escape.txt", "/escape.txt", "C:/escape.txt", "..\\escape.txt", "C:\\escape.txt", "CON.txt"} {
		p := malicious(t, []string{n})
		dest := filepath.Join(filepath.Dir(p), "result")
		if e := unpack(context.Background(), p, dest, nil); e == nil {
			t.Errorf("accepted %q", n)
		}
		if _, e := os.Stat(dest); !os.IsNotExist(e) {
			t.Error("created destination on validation failure")
		}
	}
}
func TestDuplicatesAndConflicts(t *testing.T) {
	for _, ns := range [][]string{{"a.txt", "A.TXT"}, {"a", "a/b"}, {"x", "x"}} {
		p := malicious(t, ns)
		if e := unpack(context.Background(), p, filepath.Join(filepath.Dir(p), "result"), nil); e == nil {
			t.Errorf("accepted %v", ns)
		}
	}
}
func TestLegacyFAWIntegrity(t *testing.T) {
	root, src := fixtures(t)
	p := filepath.Join(root, "a.faw")
	if e := packLegacy(context.Background(), []string{src}, p, "faw", 1, nil); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(p)
	if string(b[:8]) != string(fawMagic[:]) {
		t.Fatal("wrong magic")
	}
	if binary.LittleEndian.Uint64(b[16:24]) != uint64(len(b)-64) {
		t.Fatal("bad length")
	}
	s := sha256.Sum256(b[32 : len(b)-32])
	if !bytes.Equal(s[:], b[len(b)-32:]) {
		t.Fatal("bad hash")
	}
	for _, at := range []int{10, 25, 40, len(b) - 1} {
		v := append([]byte(nil), b...)
		v[at] ^= 1
		bad := filepath.Join(root, fmt.Sprintf("corrupt-%d.faw", at))
		os.WriteFile(bad, v, 0600)
		if e := unpackLegacy(context.Background(), bad, filepath.Join(root, fmt.Sprintf("d-%d", at)), nil); e == nil {
			t.Errorf("corruption accepted at %d", at)
		}
	}
}
func TestCRC(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.zip")
	f, _ := os.Create(p)
	w := zip.NewWriter(f)
	a, _ := w.CreateHeader(&zip.FileHeader{Name: "a.txt", Method: zip.Store})
	a.Write([]byte("payload-unique-123"))
	w.Close()
	f.Close()
	b, _ := os.ReadFile(p)
	i := bytes.Index(b, []byte("payload-unique-123"))
	b[i] ^= 1
	os.WriteFile(p, b, 0600)
	dest := filepath.Join(filepath.Dir(p), "out")
	if e := unpack(context.Background(), p, dest, nil); e == nil {
		t.Fatal("CRC corruption accepted")
	}
	if _, e := os.Stat(dest); !os.IsNotExist(e) {
		t.Fatal("partial destination published")
	}
}
func TestCancel(t *testing.T) {
	root, src := fixtures(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := filepath.Join(root, "a.faw")
	if e := pack(ctx, []string{src}, p, "faw", 1, nil); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("cancelled output exists")
	}
}
func TestSymlink(t *testing.T) {
	if runtime.GOOS == "windows" && os.Getenv("WINEPREFIX") != "" {
		t.Skip("Wine does not reliably expose native Windows reparse-point semantics; requires native Windows validation")
	}
	root, src := fixtures(t)
	if e := os.Symlink("hello.txt", filepath.Join(src, "link")); e != nil {
		t.Skip(e)
	}
	linkPath := filepath.Join(src, "link")
	info, e := os.Lstat(linkPath)
	if e != nil {
		t.Fatal(e)
	}
	if !isLink(info) && !platformUnsafe(linkPath, info) {
		t.Skip("This environment does not expose the created link as a symlink/reparse point; native Windows validation remains required")
	}
	if e := pack(context.Background(), []string{src}, filepath.Join(root, "a.zip"), "zip", 1, nil); e == nil {
		t.Fatal("symlink accepted")
	}
}
func TestZipSymlink(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "bad.zip")
	f, _ := os.Create(p)
	w := zip.NewWriter(f)
	h := &zip.FileHeader{Name: "link"}
	h.SetMode(os.ModeSymlink | 0777)
	a, _ := w.CreateHeader(h)
	a.Write([]byte("../target"))
	w.Close()
	f.Close()
	if e := unpack(context.Background(), p, filepath.Join(root, "dest"), nil); e == nil {
		t.Fatal("archived symlink accepted")
	}
}
func TestExistingDestination(t *testing.T) {
	p := malicious(t, []string{"a.txt"})
	dest := filepath.Join(filepath.Dir(p), "out")
	os.Mkdir(dest, 0700)
	os.WriteFile(filepath.Join(dest, "keep.txt"), []byte("keep"), 0600)
	if e := unpack(context.Background(), p, dest, nil); e == nil {
		t.Fatal("existing destination accepted")
	}
	b, _ := os.ReadFile(filepath.Join(dest, "keep.txt"))
	if string(b) != "keep" {
		t.Fatal("original modified")
	}
}
func TestCentralDirectoryLimit(t *testing.T) {
	p := malicious(t, []string{"a.txt"})
	b, _ := os.ReadFile(p)
	binary.LittleEndian.PutUint32(b[len(b)-22+12:], uint32(maxDirectory+1))
	os.WriteFile(p, b, 0600)
	if e := unpack(context.Background(), p, filepath.Join(filepath.Dir(p), "out"), nil); e == nil {
		t.Fatal("oversize directory accepted")
	}
}
func TestEmptyZIP(t *testing.T) {
	p := malicious(t, nil)
	if e := unpack(context.Background(), p, filepath.Join(filepath.Dir(p), "out"), nil); e != nil {
		t.Fatal(e)
	}
}
func TestExtractionLimit(t *testing.T) {
	p := malicious(t, []string{"x"})
	b, _ := os.ReadFile(p)
	i := bytes.Index(b, []byte{'P', 'K', 1, 2})
	binary.LittleEndian.PutUint32(b[i+24:i+28], 0xffffffff) // Force inconsistent ZIP64 metadata; must not succeed.
	os.WriteFile(p, b, 0600)
	if e := unpack(context.Background(), p, filepath.Join(filepath.Dir(p), "out"), nil); e == nil {
		t.Fatal("invalid size accepted")
	}
}
func FuzzSafeName(f *testing.F) {
	for _, s := range []string{"hello.txt", "../bad", "a/b", "CON"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = safeName(s) })
}

func TestMidOperationCancel(t *testing.T) {
	root, src := fixtures(t)
	ctx, cancel := context.WithCancel(context.Background())
	out := filepath.Join(root, "cancel.faw")
	e := pack(ctx, []string{src}, out, "faw", 1, func(_ int, s string) {
		if strings.HasPrefix(s, "Упаковка:") {
			cancel()
		}
	})
	if !errors.Is(e, context.Canceled) {
		t.Fatalf("pack cancellation: %v", e)
	}
	if _, e = os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("cancelled archive published")
	}
	good := filepath.Join(root, "good.zip")
	if e = pack(context.Background(), []string{src}, good, "zip", 1, nil); e != nil {
		t.Fatal(e)
	}
	ctx, cancel = context.WithCancel(context.Background())
	dest := filepath.Join(root, "cancelled-result")
	e = unpack(ctx, good, dest, func(_ int, s string) {
		if strings.HasPrefix(s, "Распаковка:") {
			cancel()
		}
	})
	if !errors.Is(e, context.Canceled) {
		t.Fatalf("extract cancellation: %v", e)
	}
	if _, e = os.Stat(dest); !os.IsNotExist(e) {
		t.Fatal("partial extraction published")
	}
	temps, _ := filepath.Glob(filepath.Join(root, ".fawusk-*"))
	if len(temps) != 0 {
		t.Fatal("temporary data remains", temps)
	}
}
func TestDeclaredSizeLimit(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "bomb.zip")
	f, e := os.Create(p)
	if e != nil {
		t.Fatal(e)
	}
	w := zip.NewWriter(f)
	_, e = w.CreateRaw(&zip.FileHeader{Name: "large.bin", Method: zip.Store, UncompressedSize64: maxSingle + 1, CompressedSize64: 0})
	if e != nil {
		t.Fatal(e)
	}
	w.Close()
	f.Close()
	e = unpack(context.Background(), p, filepath.Join(root, "out"), nil)
	if e == nil || !strings.Contains(e.Error(), "Превышен безопасный лимит") {
		t.Fatalf("expected extraction limit, got %v", e)
	}
}
