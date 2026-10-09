package fawsecurity

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type drain struct{ under bool }

func (d drain) ScanReader(_ context.Context, _ string, r io.Reader) (ScanResult, error) {
	if !d.under {
		_, e := io.Copy(io.Discard, r)
		if e != nil {
			return ScanResult{}, e
		}
	}
	return ScanResult{Verdict: "clean"}, nil
}
func entry(p, b string) Entry {
	return Entry{Path: p, Size: int64(len(b)), Open: func(context.Context) (io.ReadCloser, error) { return io.NopCloser(bytes.NewBufferString(b)), nil }}
}
func TestPreflight(t *testing.T) {
	for _, p := range []string{"../bad", "C:/bad", "/root", "ok/../bad", "dir//bad", "nul.txt", "a\u202eb.txt", "dir. /f"} {
		if !UnsafePath(p) {
			t.Fatal(p)
		}
	}
	for _, es := range [][]Entry{{entry("../bad", "a")}, {entry("a", "a"), entry("A", "b")}, {entry("a", "a"), entry("a/b", "b")}, {{Path: "dir", Directory: true, Size: 1}}, {{Path: "link", Link: true}}, {entry("good", string(make([]byte, 11)))}} {
		if e := ValidateEntries(es, Config{MaxEntries: 10, MaxUnpackedBytes: 10, MaxEntryBytes: 10}); e == nil {
			t.Fatal(es)
		}
	}
}
func TestStreamsAndStatuses(t *testing.T) {
	for _, row := range []struct {
		e     Entry
		d     drain
		state string
	}{{entry("a", "hello"), drain{}, "clean"}, {entry("a", "hello"), drain{true}, "incomplete"}, {Entry{Path: "encrypted", Encrypted: true}, drain{}, "incomplete"}, {Entry{Path: "empty", Directory: true}, drain{}, "clean"}} {
		r, e := NewScanner(Config{EntryScanner: row.d}).ScanEntries(context.Background(), "faw", []Entry{row.e})
		if e != nil || r.Status != row.state {
			t.Fatal(r, e)
		}
		if _, e := json.Marshal(r); e != nil {
			t.Fatal(e)
		}
	}
	oversized := entry("a", "hello")
	oversized.Size = 1
	r, _ := NewScanner(Config{EntryScanner: drain{}}).ScanEntries(context.Background(), "faw", []Entry{oversized})
	if r.Status != "incomplete" {
		t.Fatal(r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, e := NewScanner(Config{EntryScanner: drain{}}).ScanEntries(ctx, "faw", []Entry{entry("a", "a")})
	if e == nil || r.Status != "incomplete" {
		t.Fatal(r, e)
	}
	for _, row := range []struct {
		r    ScanResult
		want string
	}{{ScanResult{Verdict: "clean", Incomplete: true}, "incomplete"}, {ScanResult{Verdict: "clean", ReviewSignal: 1}, "review"}, {ScanResult{Verdict: "unknown"}, "incomplete"}, {ScanResult{Verdict: "clean", TestSignal: 100}, "review"}, {ScanResult{Verdict: "clean", MalwareSignal: 1}, "blocked"}} {
		if StatusFor(row.r) != row.want {
			t.Fatal(row)
		}
	}
}
func TestPrivateReportEnvelope(t *testing.T) {
	plain := []byte("private report")
	pw := []byte("test password")
	a, e := Seal(plain, pw)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Seal(plain, pw)
	if e != nil || bytes.Equal(a, b) {
		t.Fatal("reused salt/nonce")
	}
	out, e := Open(a, pw)
	if e != nil || !bytes.Equal(out, plain) {
		t.Fatal(e)
	}
	if _, e := Open(a, []byte("wrong")); e == nil {
		t.Fatal("wrong password")
	}
	a[len(a)-1] ^= 1
	if _, e := Open(a, pw); e == nil {
		t.Fatal("tamper")
	}
	if _, e := Open(a[:10], pw); e == nil {
		t.Fatal("short")
	}
	if _, e := Seal(plain, nil); e == nil {
		t.Fatal("empty password")
	}
}
func TestChecksumAndPreflightBeforeOpen(t *testing.T) {
	e := entry("a", "ordinary")
	e.SHA256 = "wrong"
	r, _ := NewScanner(Config{EntryScanner: drain{}}).ScanEntries(context.Background(), "faw", []Entry{e})
	if r.Status != "incomplete" {
		t.Fatal(r)
	}
	opened := false
	good := entry("a", "ordinary")
	good.Open = func(context.Context) (io.ReadCloser, error) {
		opened = true
		return io.NopCloser(bytes.NewBufferString("ordinary")), nil
	}
	r, _ = NewScanner(Config{EntryScanner: drain{}}).ScanEntries(context.Background(), "faw", []Entry{good, {Path: "../bad", Directory: true}})
	if opened || r.Status != "blocked" {
		t.Fatal("preflight after open", r)
	}
	nilSrc := entry("a", "a")
	nilSrc.Open = func(context.Context) (io.ReadCloser, error) { return nil, nil }
	r, _ = NewScanner(Config{EntryScanner: drain{}}).ScanEntries(context.Background(), "faw", []Entry{nilSrc})
	if r.Status != "incomplete" {
		t.Fatal(r)
	}
}

func TestZIPConvenienceBounds(t *testing.T) {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, _ := z.Create("dir/notes.txt")
	w.Write([]byte("ordinary"))
	z.Close()
	p := filepath.Join(t.TempDir(), "normal.zip")
	os.WriteFile(p, b.Bytes(), 0600)
	s := NewScanner(Config{EntryScanner: drain{}})
	r, e := s.ScanZIP(context.Background(), p)
	if e != nil || r.Status != "clean" || r.Scanned != 1 {
		t.Fatal(r, e)
	}
	data := append([]byte{}, b.Bytes()...)
	binary.LittleEndian.PutUint16(data[len(data)-22+10:], 10001)
	os.WriteFile(p, data, 0600)
	r, e = s.ScanZIP(context.Background(), p)
	if e == nil || r.Status != "incomplete" {
		t.Fatal("directory preallocation bound", r, e)
	}
	os.WriteFile(p, b.Bytes()[:10], 0600)
	r, e = s.ScanZIP(context.Background(), p)
	if e == nil || r.Status != "incomplete" {
		t.Fatal("truncated accepted", r, e)
	}
}
