package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/klauspost/compress/zstd"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFAW2LargeMixedBlocks(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source")
	os.Mkdir(src, 0700)
	fixtures := map[string][]byte{"a-small.txt": []byte("small small small"), "b-large.txt": bytes.Repeat([]byte("Fawusk Fawusk Fawusk\n"), 150000), "c-noise.bin": make([]byte, fawBlockSize+317), "d-medium.txt": bytes.Repeat([]byte("abc"), 70000)}
	rand.Read(fixtures["c-noise.bin"])
	for name, b := range fixtures {
		os.WriteFile(filepath.Join(src, name), b, 0600)
	}
	archive := filepath.Join(root, "a.faw")
	if e := pack(context.Background(), []string{src}, archive, "faw", 6, nil); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(root, "out")
	if e := unpack(context.Background(), archive, dest, nil); e != nil {
		t.Fatal(e)
	}
	for name, b := range fixtures {
		a, e := os.ReadFile(filepath.Join(dest, "source", name))
		if e != nil || !bytes.Equal(a, b) {
			t.Fatalf("mismatch %s: %v", name, e)
		}
	}
	data, _ := os.ReadFile(archive)
	if binary.LittleEndian.Uint16(data[8:10]) != 2 {
		t.Fatal("not FAW 2")
	}
	sum := sha256.Sum256(data[:len(data)-32])
	if !bytes.Equal(sum[:], data[len(data)-32:]) {
		t.Fatal("global hash mismatch")
	}
}
func TestFAW2IntegrityAndTruncation(t *testing.T) {
	root, src := fixtures(t)
	p := filepath.Join(root, "a.faw")
	if e := pack(context.Background(), []string{src}, p, "faw", 1, nil); e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(p)
	for _, at := range []int{10, 28, 40, 70, len(data) - 33, len(data) - 1} {
		bad := append([]byte(nil), data...)
		bad[at] ^= 1
		q := filepath.Join(root, "bad.faw")
		os.WriteFile(q, bad, 0600)
		dest := filepath.Join(root, "out")
		if e := unpack(context.Background(), q, dest, nil); e == nil {
			t.Fatalf("accepted corruption at %d", at)
		}
		if _, e := os.Stat(dest); !os.IsNotExist(e) {
			t.Fatal("published corrupt archive")
		}
	}
	for _, n := range []int{0, 9, 32, 64, len(data) - 1} {
		q := filepath.Join(root, "short.faw")
		os.WriteFile(q, data[:n], 0600)
		if e := unpack(context.Background(), q, filepath.Join(root, "short-out"), nil); e == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	os.WriteFile(filepath.Join(root, "tail.faw"), append(data, 99), 0600)
	if e := unpack(context.Background(), filepath.Join(root, "tail.faw"), filepath.Join(root, "tail-out"), nil); e == nil {
		t.Fatal("accepted trailing byte")
	}
}

type fakeFAWEntry struct {
	name      string
	directory bool
	data      []byte
}

func makeTestFAW(t *testing.T, entries []fakeFAWEntry) string {
	t.Helper()
	var total uint64
	for _, a := range entries {
		total += uint64(len(a.data))
	}
	var b bytes.Buffer
	b.Write(faw2Header(total, len(entries)))
	for _, a := range entries {
		meta := make([]byte, 21)
		meta[0] = 2
		if a.directory {
			meta[0] = 1
		}
		binary.LittleEndian.PutUint32(meta[1:5], uint32(len(a.name)))
		binary.LittleEndian.PutUint64(meta[5:13], uint64(len(a.data)))
		b.Write(meta)
		b.WriteString(a.name)
		if len(a.data) > 0 {
			block := make([]byte, 13)
			binary.LittleEndian.PutUint32(block[:4], uint32(len(a.data)))
			binary.LittleEndian.PutUint32(block[4:8], uint32(len(a.data)))
			binary.LittleEndian.PutUint32(block[9:13], crc32.ChecksumIEEE(a.data))
			b.Write(block)
			b.Write(a.data)
		}
	}
	b.WriteByte(0)
	sum := sha256.Sum256(b.Bytes())
	b.Write(sum[:])
	p := filepath.Join(t.TempDir(), "test.faw")
	os.WriteFile(p, b.Bytes(), 0600)
	return p
}
func TestFAW2MaliciousNames(t *testing.T) {
	for _, entries := range [][]fakeFAWEntry{{{name: "../escape"}}, {{name: "/absolute"}}, {{name: "CON.txt"}}, {{name: "a:stream"}}, {{name: "a\\b"}}, {{name: "a"}, {name: "A"}}, {{name: "a"}, {name: "a/b"}}, {{name: "a/b"}, {name: "a"}}, {{name: "a/b"}, {name: "A/c"}}, {{name: "a/", directory: true}}} {
		p := makeTestFAW(t, entries)
		dest := filepath.Join(filepath.Dir(p), "out")
		if e := unpack(context.Background(), p, dest, nil); e == nil {
			t.Fatalf("accepted %+v", entries)
		}
		if _, e := os.Stat(dest); !os.IsNotExist(e) {
			t.Fatal("published invalid archive")
		}
	}
}
func rehashFAW(b []byte) { sum := sha256.Sum256(b[:len(b)-32]); copy(b[len(b)-32:], sum[:]) }
func TestFAW2DeclaredLimitsAndChunkBounds(t *testing.T) {
	p := makeTestFAW(t, []fakeFAWEntry{{name: "x", data: []byte("hello")}})
	original, _ := os.ReadFile(p)
	for _, which := range []string{"total", "count", "name", "file", "raw", "stored", "codec", "crc"} {
		b := append([]byte(nil), original...)
		switch which {
		case "total":
			binary.LittleEndian.PutUint64(b[16:24], maxTotal+1)
			binary.LittleEndian.PutUint32(b[28:32], crc32.ChecksumIEEE(b[:28]))
		case "count":
			binary.LittleEndian.PutUint32(b[24:28], maxFiles+1)
			binary.LittleEndian.PutUint32(b[28:32], crc32.ChecksumIEEE(b[:28]))
		case "name":
			binary.LittleEndian.PutUint32(b[33:37], 0xffffffff)
		case "file":
			binary.LittleEndian.PutUint64(b[37:45], maxSingle+1)
		case "raw":
			binary.LittleEndian.PutUint32(b[54:58], fawBlockSize+1)
		case "stored":
			binary.LittleEndian.PutUint32(b[58:62], 0xffffffff)
		case "codec":
			b[62] = 2
		case "crc":
			b[63] ^= 1
		}
		rehashFAW(b)
		q := filepath.Join(filepath.Dir(p), which+".faw")
		os.WriteFile(q, b, 0600)
		if e := unpack(context.Background(), q, filepath.Join(filepath.Dir(p), which+"-out"), nil); e == nil {
			t.Fatalf("accepted bad %s", which)
		}
	}
}
func TestFAW2ImplicitDirectories(t *testing.T) {
	p := makeTestFAW(t, []fakeFAWEntry{{name: "a/b.txt", data: []byte("hello")}, {name: "a", directory: true}})
	dest := filepath.Join(filepath.Dir(p), "out")
	if e := unpack(context.Background(), p, dest, nil); e != nil {
		t.Fatal(e)
	}
}
func TestFAW2DecoderBounds(t *testing.T) {
	p := makeTestFAW(t, []fakeFAWEntry{{name: "x", data: []byte("uncompressed")}})
	b, _ := os.ReadFile(p)
	b[62] = 1
	rehashFAW(b)
	os.WriteFile(p, b, 0600)
	if e := unpack(context.Background(), p, filepath.Join(filepath.Dir(p), "out"), nil); e == nil {
		t.Fatal("invalid Zstandard accepted")
	}
}
func FuzzFAW2Parser(f *testing.F) {
	p := makeFuzzSeed()
	f.Add(p)
	f.Add(makeFuzzFileSeed())
	f.Add([]byte("FAWUSK\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			t.Skip()
		}
		root := t.TempDir()
		p := filepath.Join(root, "fuzz.faw")
		os.WriteFile(p, data, 0600)
		_ = unpack(context.Background(), p, filepath.Join(root, "result"), nil)
	})
}
func makeFuzzSeed() []byte {
	b := faw2Header(0, 0)
	b = append(b, 0)
	s := sha256.Sum256(b)
	return append(b, s[:]...)
}
func TestDeepPathRejected(t *testing.T) {
	if _, e := safeName(strings.Repeat("a/", 128) + "x"); e == nil {
		t.Fatal("deep path accepted")
	}
}

func TestFAW2ZstdOutputCap(t *testing.T) {
	enc, e := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(fawBlockSize))
	if e != nil {
		t.Fatal(e)
	}
	defer enc.Close()
	compressed := enc.EncodeAll(bytes.Repeat([]byte("Z"), 100000), nil)
	var b bytes.Buffer
	b.Write(faw2Header(1000, 1))
	meta := make([]byte, 21)
	meta[0] = 2
	binary.LittleEndian.PutUint32(meta[1:5], 1)
	binary.LittleEndian.PutUint64(meta[5:13], 1000)
	b.Write(meta)
	b.WriteByte('x')
	block := make([]byte, 13)
	binary.LittleEndian.PutUint32(block[:4], 1000)
	binary.LittleEndian.PutUint32(block[4:8], uint32(len(compressed)))
	block[8] = 1
	b.Write(block)
	b.Write(compressed)
	b.WriteByte(0)
	sum := sha256.Sum256(b.Bytes())
	b.Write(sum[:])
	root := t.TempDir()
	p := filepath.Join(root, "bomb.faw")
	os.WriteFile(p, b.Bytes(), 0600)
	e = unpack(context.Background(), p, filepath.Join(root, "out"), nil)
	if !errors.Is(e, zstd.ErrDecoderSizeExceeded) {
		t.Fatalf("expected decoder capacity rejection, got %v", e)
	}
}

func makeFuzzFileSeed() []byte {
	var b bytes.Buffer
	data := []byte("hello")
	b.Write(faw2Header(5, 1))
	meta := make([]byte, 21)
	meta[0] = 2
	binary.LittleEndian.PutUint32(meta[1:5], 1)
	binary.LittleEndian.PutUint64(meta[5:13], 5)
	b.Write(meta)
	b.WriteByte('x')
	block := make([]byte, 13)
	binary.LittleEndian.PutUint32(block[:4], 5)
	binary.LittleEndian.PutUint32(block[4:8], 5)
	binary.LittleEndian.PutUint32(block[9:13], crc32.ChecksumIEEE(data))
	b.Write(block)
	b.Write(data)
	b.WriteByte(0)
	sum := sha256.Sum256(b.Bytes())
	return append(b.Bytes(), sum[:]...)
}
func TestFAW2NoOverwrite(t *testing.T) {
	root, src := fixtures(t)
	out := filepath.Join(root, "existing.faw")
	os.WriteFile(out, []byte("keep"), 0600)
	if e := pack(context.Background(), []string{src}, out, "faw", 1, nil); e == nil {
		t.Fatal("overwrite permitted")
	}
	b, _ := os.ReadFile(out)
	if string(b) != "keep" {
		t.Fatal("existing file modified")
	}
	good := filepath.Join(root, "good.faw")
	if e := pack(context.Background(), []string{src}, good, "faw", 1, nil); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(root, "result")
	os.Mkdir(dest, 0700)
	os.WriteFile(filepath.Join(dest, "keep"), []byte("keep"), 0600)
	if e := unpack(context.Background(), good, dest, nil); e == nil {
		t.Fatal("existing directory accepted")
	}
	b, _ = os.ReadFile(filepath.Join(dest, "keep"))
	if string(b) != "keep" {
		t.Fatal("existing directory modified")
	}
}
