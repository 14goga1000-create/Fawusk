package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/klauspost/compress/zstd"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

func TestFAW3SolidAndView(t *testing.T) {
	for _, level := range []int{1, 6, 9} {
		root := t.TempDir()
		src := filepath.Join(root, "files")
		os.MkdirAll(filepath.Join(src, "empty"), 0700)
		base := make([]byte, 50000)
		rand.Read(base)
		for i := 0; i < 20; i++ {
			name := filepath.Join(src, string(rune('a'+i))+".bin")
			os.WriteFile(name, append(append([]byte{}, base...), byte(i)), 0600)
		}
		out := filepath.Join(root, "solid.faw")
		if e := pack(context.Background(), []string{src}, out, "faw", level, nil); e != nil {
			t.Fatal(e)
		}
		listed, e := scanArchive(context.Background(), out, nil)
		if e != nil {
			t.Fatal(e)
		}
		if len(listed) != 22 {
			t.Fatal("wrong listing", len(listed))
		}
		dest := filepath.Join(root, "out")
		if e = unpack(context.Background(), out, dest, nil); e != nil {
			t.Fatal(e)
		}
		for i := 0; i < 20; i++ {
			name := string(rune('a'+i)) + ".bin"
			original, _ := os.ReadFile(filepath.Join(src, name))
			got, e := os.ReadFile(filepath.Join(dest, "files", name))
			if e != nil || !bytes.Equal(original, got) {
				t.Fatal("solid mismatch", e)
			}
		}
		data, _ := os.ReadFile(out)
		if binary.LittleEndian.Uint16(data[8:10]) != 3 {
			t.Fatal("wrong version")
		}
		sum := sha256.Sum256(data[:len(data)-32])
		if !bytes.Equal(sum[:], data[len(data)-32:]) {
			t.Fatal("wrong digest")
		}
	}
}
func TestArchiveViewCompatibility(t *testing.T) {
	for _, version := range []int{-1, 1, 2, 3} {
		root, src := fixtures(t)
		out := filepath.Join(root, "test.faw")
		var e error
		switch version {
		case -1:
			out = filepath.Join(root, "test.zip")
			e = packLegacy(context.Background(), []string{src}, out, "zip", 1, nil)
		case 1:
			e = packLegacy(context.Background(), []string{src}, out, "faw", 1, nil)
		case 2:
			e = packFAW2(context.Background(), []string{src}, out, 1, nil)
		case 3:
			e = packFAW3(context.Background(), []string{src}, out, 1, nil)
		}
		if e != nil {
			t.Fatal(e)
		}
		a, e := scanArchive(context.Background(), out, nil)
		if e != nil || len(a) != 5 {
			t.Fatal("view failed", version, len(a), e)
		}
		children := archiveChildren(a, "Данные/")
		if len(children) != 4 {
			t.Fatal("bad directory listing", version, len(children))
		}
	}
}
func makeFAW3Test(t *testing.T, payload []byte, total uint64, count int) string {
	t.Helper()
	var b bytes.Buffer
	h := faw3Header(total, count)
	b.Write(h)
	enc, e := zstd.NewWriter(&b, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(faw3Window))
	if e != nil {
		t.Fatal(e)
	}
	enc.Write(payload)
	enc.Close()
	sum := sha256.Sum256(b.Bytes())
	b.Write(sum[:])
	p := filepath.Join(t.TempDir(), "bad.faw")
	os.WriteFile(p, b.Bytes(), 0600)
	return p
}
func faw3Entry(name string, size uint64, kind byte) []byte {
	var b bytes.Buffer
	b.WriteByte(kind)
	putU(&b, uint64(len(name)))
	putU(&b, size)
	putU(&b, 0)
	b.WriteString(name)
	return b.Bytes()
}
func TestFAW3MaliciousRecords(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "a:stream", "CON", "a\\b"} {
		p := makeFAW3Test(t, append(faw3Entry(name, 0, 2), 0, 0, 0, 0, 0), 0, 1)
		if _, e := scanArchive(context.Background(), p, nil); e == nil {
			t.Fatal("accepted path", name)
		}
	}
	for _, pair := range [][2]string{{"a", "A"}, {"a", "a/b"}, {"a/b", "a"}, {"a/b", "A/c"}} {
		payload := append(faw3Entry(pair[0], 0, 2), 0, 0, 0, 0)
		payload = append(payload, faw3Entry(pair[1], 0, 2)...)
		payload = append(payload, 0, 0, 0, 0, 0)
		p := makeFAW3Test(t, payload, 0, 2)
		if e := unpack(context.Background(), p, filepath.Join(filepath.Dir(p), "out"), nil); e == nil {
			t.Fatal("accepted conflict", pair)
		}
	}
	p := makeFAW3Test(t, append(faw3Entry("big", maxSingle+1, 2), 0), maxSingle+1, 1)
	if _, e := scanArchive(context.Background(), p, nil); e == nil {
		t.Fatal("accepted oversized file")
	}
	p = makeFAW3Test(t, append(faw3Entry("x", 1, 2), byte('x'), 0, 0, 0, 0, 0), 1, 1)
	if _, e := scanArchive(context.Background(), p, nil); e == nil {
		t.Fatal("accepted bad CRC")
	}
	p = makeFAW3Test(t, []byte{0, 99}, 0, 0)
	if _, e := scanArchive(context.Background(), p, nil); e == nil {
		t.Fatal("accepted trailing raw bytes")
	}
}
func TestFAW3Corruption(t *testing.T) {
	root, src := fixtures(t)
	out := filepath.Join(root, "a.faw")
	if e := packFAW3(context.Background(), []string{src}, out, 1, nil); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(out)
	for _, at := range []int{8, 16, 28, 36, len(b) - 33, len(b) - 1} {
		v := append([]byte(nil), b...)
		v[at] ^= 1
		p := filepath.Join(root, "bad.faw")
		os.WriteFile(p, v, 0600)
		dest := filepath.Join(root, "out")
		if e := unpack(context.Background(), p, dest, nil); e == nil {
			t.Fatal("accepted corrupt archive", at)
		}
		if _, e := os.Stat(dest); !os.IsNotExist(e) {
			t.Fatal("published corrupt destination")
		}
	}
	for _, n := range []int{10, 32, 64, len(b) - 1} {
		p := filepath.Join(root, "short.faw")
		os.WriteFile(p, b[:n], 0600)
		if _, e := scanArchive(context.Background(), p, nil); e == nil {
			t.Fatal("accepted truncated", n)
		}
	}
}
func TestRemoteLongUnicodePaths(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source")
	os.Mkdir(src, 0700)
	os.WriteFile(filepath.Join(src, "пример.txt"), []byte("remote destination"), 0600)
	remote := filepath.Join(root, "far-away")
	for i := 0; i < 16; i++ {
		remote = filepath.Join(remote, "длинная-папка-123456")
	}
	if e := os.MkdirAll(remote, 0700); e != nil {
		t.Fatal(e)
	}
	for _, format := range []string{"faw", "zip"} {
		out := filepath.Join(remote, "archive."+format)
		if e := pack(context.Background(), []string{src}, out, format, 1, nil); e != nil {
			t.Fatalf("long destination %s: %v", format, e)
		}
		dest := filepath.Join(remote, "extracted-"+format)
		if e := unpack(context.Background(), out, dest, nil); e != nil {
			t.Fatalf("long extraction %s: %v", format, e)
		}
		b, e := os.ReadFile(filepath.Join(dest, "source", "пример.txt"))
		if e != nil || string(b) != "remote destination" {
			t.Fatal(e)
		}
	}
}
func TestFAW3HeaderQuotas(t *testing.T) {
	p := makeFAW3Test(t, []byte{0}, 0, 0)
	b, _ := os.ReadFile(p)
	binary.LittleEndian.PutUint64(b[16:24], maxTotal+1)
	binary.LittleEndian.PutUint32(b[28:32], crc32.ChecksumIEEE(b[:28]))
	s := sha256.Sum256(b[:len(b)-32])
	copy(b[len(b)-32:], s[:])
	os.WriteFile(p, b, 0600)
	if _, e := scanArchive(context.Background(), p, nil); e == nil {
		t.Fatal("oversized quota accepted")
	}
}
func FuzzFAW3Parser(f *testing.F) {
	var b bytes.Buffer
	b.Write(faw3Header(0, 0))
	enc, _ := zstd.NewWriter(&b, zstd.WithEncoderConcurrency(1))
	enc.Write([]byte{0})
	enc.Close()
	sum := sha256.Sum256(b.Bytes())
	f.Add(append(b.Bytes(), sum[:]...))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		p := filepath.Join(t.TempDir(), "fuzz.faw")
		os.WriteFile(p, b, 0600)
		_, _ = scanArchive(context.Background(), p, nil)
	})
}

func TestSolidSimilarFilesBenefit(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "similar")
	os.Mkdir(src, 0700)
	seed := make([]byte, 60000)
	rand.Read(seed)
	for i := 0; i < 30; i++ {
		os.WriteFile(filepath.Join(src, fmt.Sprintf("%02d.bin", i)), append(append([]byte{}, seed...), byte(i)), 0600)
	}
	v2 := filepath.Join(root, "v2.faw")
	v3 := filepath.Join(root, "v3.faw")
	if e := packFAW2(context.Background(), []string{src}, v2, 1, nil); e != nil {
		t.Fatal(e)
	}
	if e := packFAW3(context.Background(), []string{src}, v3, 1, nil); e != nil {
		t.Fatal(e)
	}
	a, _ := os.Stat(v2)
	b, _ := os.Stat(v3)
	if b.Size() >= a.Size() {
		t.Fatalf("solid did not help this repeated synthetic fixture: v2=%d,v3=%d", a.Size(), b.Size())
	}
	t.Log("Similar-file synthetic fixture only; not a universal ratio or competitor claim")
}
func TestFAW3NonOverwrite(t *testing.T) {
	root, src := fixtures(t)
	out := filepath.Join(root, "x.faw")
	os.WriteFile(out, []byte("keep"), 0600)
	if e := pack(context.Background(), []string{src}, out, "faw", 1, nil); e == nil {
		t.Fatal("overwritten")
	}
	b, _ := os.ReadFile(out)
	if string(b) != "keep" {
		t.Fatal("changed existing archive")
	}
}
