package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func avScanBytes(t *testing.T, name string, b, db []byte) avResult {
	t.Helper()
	if db == nil {
		db = avBuiltinDB
	}
	a := newAVRun(context.Background(), db, nil)
	w, e := a.file(name, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Write(b); e != nil {
		t.Fatal(e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	return a.finish()
}
func avEICAR(t *testing.T) []byte {
	t.Helper()
	var db struct{ Signatures []struct{ Pattern string } }
	if e := json.Unmarshal(avBuiltinDB, &db); e != nil {
		t.Fatal(e)
	}
	return []byte(db.Signatures[0].Pattern)
}
func TestCustomAVClearAndTestSignature(t *testing.T) {
	r := avScanBytes(t, "notes.txt", []byte("ordinary local document"), nil)
	if r.state() != "clear" || !r.permitted() || len(r.Files) != 1 || len(r.Files[0].SHA256) != 64 {
		t.Fatal(r)
	}
	for _, b := range [][]byte{avEICAR(t), append(avEICAR(t), '\r', '\n')} {
		r = avScanBytes(t, "eicar.txt", b, nil)
		if r.state() != "test" || r.MalwareSignal != 0 || r.TestSignal != 100 || r.permitted() {
			t.Fatal(r)
		}
	}
	r = avScanBytes(t, "documentation.txt", append([]byte("Documentation mentions: "), avEICAR(t)...), nil)
	if r.TestSignal != 0 {
		t.Fatal("non-exact EICAR false positive", r)
	}
}
func TestCustomAVNativeRules(t *testing.T) {
	for _, row := range []struct {
		name  string
		b     []byte
		rule  string
		state string
	}{
		{"download.cmd", []byte("curl https://example.org/a"), "SCRIPT_CAPABILITY", "blocked"},
		{"photo.jpg.exe", []byte{1, 0, 2}, "DOUBLE_EXTENSION", "blocked"},
		{"readme.txt", []byte("powershell -encodedcommand xyz"), "HIGH_RISK_TEXT", "blocked"},
		{"notes.txt", []byte("https://example.org"), "UNEXPECTED_URL", "review"},
		{"simple.sh", []byte("echo hello"), "SCRIPT_FILE", "review"},
		{"paper.pdf", []byte("%PDF-1.7 /OpenAction /JavaScript"), "PDF_ACTIVE_CONTENT", "review"},
		{"photo.jpg", []byte("%PDF-1.7 ordinary"), "FORMAT_EXTENSION_MISMATCH", "review"},
		{"native.exe", []byte("MZ bad"), "PE_PARSE_LIMITED", "incomplete"},
	} {
		t.Run(row.rule, func(t *testing.T) {
			r := avScanBytes(t, row.name, row.b, nil)
			if r.state() != row.state {
				t.Fatal(r)
			}
			found := false
			for _, f := range r.Findings {
				found = found || f.Rule == row.rule
			}
			if !found {
				t.Fatal(r)
			}
		})
	}
}
func TestCustomAVSignatureDatabase(t *testing.T) {
	db := []byte(`{"version":1,"signatures":[{"id":"LOCAL_TEST","type":"contains","pattern":"LOCAL-MARKER","classification":"test"},{"id":"RE_RULE","type":"regex","pattern":"danger[0-9]+","classification":"malware"}]}`)
	r := avScanBytes(t, "plain.txt", []byte("xx LOCAL-MARKER yy"), db)
	if r.TestSignal != 100 {
		t.Fatal(r)
	}
	r = avScanBytes(t, "plain.txt", []byte("danger123"), db)
	if r.MalwareSignal != 100 {
		t.Fatal(r)
	}
	for _, b := range [][]byte{[]byte("{broken"), []byte(`{"version":1,"signatures":[]}`), []byte(`{"version":1,"signatures":[{"id":"bad","type":"regex","pattern":"(?=foo)","classification":"malware"}]}`)} {
		r = avScanBytes(t, "plain.txt", []byte("ordinary"), b)
		if r.Complete || r.permitted() {
			t.Fatal("invalid DB reported clear", r)
		}
	}
}
func avZipBytes(t *testing.T, name string, b []byte) []byte {
	t.Helper()
	var dst bytes.Buffer
	z := zip.NewWriter(&dst)
	w, e := z.Create(name)
	if e != nil {
		t.Fatal(e)
	}
	w.Write(b)
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	return dst.Bytes()
}
func TestCustomAVNestedZIP(t *testing.T) {
	inner := avZipBytes(t, "eicar.txt", avEICAR(t))
	r := avScanBytes(t, "bundle.zip", inner, nil)
	if r.TestSignal != 100 || r.permitted() || len(r.Files) != 2 || r.Findings[0].Path != "bundle.zip!/eicar.txt" {
		t.Fatal(r)
	}
	r = avScanBytes(t, "bundle.zip", avZipBytes(t, "ordinary.txt", []byte("normal")), nil)
	if !r.permitted() || r.state() != "clear" {
		t.Fatal(r)
	}
	r = avScanBytes(t, "bundle.zip", avZipBytes(t, "../evil.txt", []byte("normal")), nil)
	if r.Complete || r.permitted() {
		t.Fatal(r)
	}
	r = avScanBytes(t, "bundle.zip", avZipBytes(t, "benign.exe", []byte{1, 0, 2}), nil)
	if !r.blocked() {
		t.Fatal(r)
	}
	deep := []byte("normal")
	for i := 0; i < 5; i++ {
		deep = avZipBytes(t, "nested.zip", deep)
	}
	r = avScanBytes(t, "outer.zip", deep, nil)
	if r.Complete || r.permitted() {
		t.Fatal("depth limit ignored", r)
	}
}
func TestCustomAVIncompleteFormatsAndLimits(t *testing.T) {
	for _, b := range [][]byte{fawMagic[:], []byte("Rar!\x1a\x07"), []byte("7z\xbc\xaf\x27\x1c"), []byte("\x1f\x8b")} {
		r := avScanBytes(t, "nested.dat", b, nil)
		if r.Complete || r.permitted() {
			t.Fatal(r)
		}
	}
	a := newAVRun(context.Background(), avBuiltinDB, nil)
	w, _ := a.file("big.bin", 0)
	chunk := make([]byte, 1<<20)
	for i := 0; i < 17; i++ {
		w.Write(chunk)
	}
	w.Close()
	r := a.finish()
	if r.Complete || r.Files[0].Size != 17<<20 || len(r.Files[0].SHA256) != 64 {
		t.Fatal(r)
	}
	a = newAVRun(context.Background(), avBuiltinDB, nil)
	a.count = avFileLimit
	if _, e := a.file("over.txt", 0); e == nil {
		t.Fatal("count limit")
	}
	a = newAVRun(context.Background(), avBuiltinDB, nil)
	a.consumed = avByteLimit
	w, _ = a.file("over.txt", 0)
	if _, e := w.Write([]byte{1}); e == nil {
		t.Fatal("byte limit")
	}
	a = newAVRun(context.Background(), avBuiltinDB, nil)
	for i := 0; i < avFindingLimit+1; i++ {
		a.add("medium", "R", string(rune(i+32)), "detail", "review", 1)
	}
	a.add("high", "BLOCK", "evil", "signal", "malware", 100)
	if !a.finish().blocked() || a.finish().Complete {
		t.Fatal("report limit erased block")
	}
}
func TestCustomAVAllFormatsAndPublication(t *testing.T) {
	for _, format := range []string{"faw1", "faw2", "faw3", "zip", "old3"} {
		t.Run(format, func(t *testing.T) {
			root := t.TempDir()
			src := filepath.Join(root, "source")
			os.Mkdir(src, 0700)
			os.WriteFile(filepath.Join(src, "notes.txt"), []byte("ordinary"), 0600)
			out := filepath.Join(root, "sample.faw")
			if format == "zip" {
				out = filepath.Join(root, "sample.zip")
			}
			var e error
			if format == "old3" {
				e = packFAW3Legacy(context.Background(), []string{src}, out, 1, nil)
			} else {
				_, e = securePack(context.Background(), []string{src}, out, format, 1, nil)
			}
			if e != nil {
				t.Fatal(e)
			}
			r := scanSecurity(context.Background(), out, nil)
			if !r.permitted() || len(r.Files) != 1 || r.ArchiveSHA256 == "" {
				t.Fatal(r)
			}
			dest := filepath.Join(root, "unpacked")
			r, e = secureUnpack(context.Background(), out, dest, nil)
			if e != nil || !r.permitted() {
				t.Fatal(r, e)
			}
			original, _ := os.ReadFile(filepath.Join(src, "notes.txt"))
			restored, _ := os.ReadFile(filepath.Join(dest, "source/notes.txt"))
			if !bytes.Equal(original, restored) {
				t.Fatal("bytes changed")
			}
			os.WriteFile(filepath.Join(src, "notes.txt"), avEICAR(t), 0600)
			unsafe := filepath.Join(root, "blocked.faw")
			if format == "zip" {
				unsafe = filepath.Join(root, "blocked.zip")
			}
			if format == "old3" {
				e = packFAW3Legacy(context.Background(), []string{src}, unsafe, 1, nil)
			} else {
				e = pack(context.Background(), []string{src}, unsafe, format, 1, nil)
			}
			if e != nil {
				t.Fatal(e)
			}
			before, _ := os.ReadFile(unsafe)
			r = scanSecurity(context.Background(), unsafe, nil)
			if !r.blocked() || r.MalwareSignal != 0 {
				t.Fatal(r)
			}
			blockedDest := filepath.Join(root, "not-published")
			r, e = secureUnpack(context.Background(), unsafe, blockedDest, nil)
			if e == nil || !r.blocked() {
				t.Fatal(r, e)
			}
			if _, e = os.Stat(blockedDest); !os.IsNotExist(e) {
				t.Fatal("unsafe destination published")
			}
			after, _ := os.ReadFile(unsafe)
			if !bytes.Equal(before, after) {
				t.Fatal("original modified")
			}
			if format != "old3" {
				created := filepath.Join(root, "creation-denied.faw")
				if format == "zip" {
					created = filepath.Join(root, "creation-denied.zip")
				}
				r, e = securePack(context.Background(), []string{src}, created, format, 1, nil)
				if e == nil || !r.blocked() {
					t.Fatal(r, e)
				}
				if _, e = os.Stat(created); !os.IsNotExist(e) {
					t.Fatal("unsafe pack published")
				}
			}
			stages, _ := filepath.Glob(filepath.Join(root, ".fawusk-unpack-*"))
			if len(stages) > 0 {
				t.Fatal("staging leak", stages)
			}
		})
	}
}
func TestCustomAVCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := newAVRun(ctx, avBuiltinDB, nil)
	w, _ := a.file("notes.txt", 0)
	if _, e := w.Write([]byte("x")); e == nil {
		t.Fatal("cancel ignored")
	}
	root := t.TempDir()
	src := filepath.Join(root, "x.txt")
	os.WriteFile(src, []byte("normal"), 0600)
	archive := filepath.Join(root, "x.zip")
	pack(context.Background(), []string{src}, archive, "zip", 1, nil)
	r := scanSecurity(ctx, archive, nil)
	if r.Complete || r.permitted() {
		t.Fatal(r)
	}
}
func TestCustomAVHashDoesNotWriteTargets(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "external.zip")
	os.WriteFile(p, avZipBytes(t, "notes.txt", []byte("ordinary")), 0600)
	r := scanSecurity(context.Background(), p, nil)
	if !r.permitted() {
		t.Fatal(r)
	}
	files, _ := os.ReadDir(root)
	if len(files) != 1 {
		t.Fatal("scanner extracted files to disk", files)
	}
}
func TestAlpha07FileKinds(t *testing.T) {
	for _, row := range []struct{ name, kind string }{{"clip.mp4", "video"}, {"clip.WMV", "video"}, {"music.opus", "audio"}, {"photo.png", "image"}, {"paper.pdf", "pdf"}, {"table.xlsx", "spreadsheet"}, {"slides.pptx", "presentation"}, {"program.exe", "application"}, {"script.ps1", "code"}, {"notes.txt", "text"}, {"unknown.xyz", "file"}} {
		if k := iconKind(archiveEntry{Name: row.name}); k != row.kind {
			t.Fatal(row, k)
		}
	}
	if iconKind(archiveEntry{Name: "fake.mp4", Directory: true}) != "folder" {
		t.Fatal("folder")
	}
}
func FuzzCustomAVBytes(f *testing.F) {
	f.Add("notes.txt", []byte("ordinary"))
	f.Add("sample.pdf", []byte("%PDF-1.7"))
	f.Add("app.exe", []byte("MZ"))
	f.Fuzz(func(t *testing.T, name string, b []byte) {
		if len(b) > 128<<10 || len(name) > 512 {
			return
		}
		a := newAVRun(context.Background(), avBuiltinDB, nil)
		w, e := a.file(name, 0)
		if e != nil {
			return
		}
		io.Copy(w, bytes.NewReader(b))
		w.Close()
		r := a.finish()
		if r.permitted() && (!r.Complete || r.blocked()) {
			t.Fatal("invalid policy")
		}
	})
}
func TestCustomAVInvalidDatabasePath(t *testing.T) {
	r := avScanBytes(t, "safe.txt", []byte("normal"), []byte(`{"version":8}`))
	if r.Complete || !strings.Contains(r.label(), "неполная") {
		t.Fatal(r)
	}
}
func TestCustomAVPreviewAndChangedArchive(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "notes.txt")
	os.WriteFile(src, []byte("ordinary"), 0600)
	p := filepath.Join(root, "preview.faw")
	pack(context.Background(), []string{src}, p, "faw3", 1, nil)
	r := scanSecurity(context.Background(), p, nil)
	temp := filepath.Join(root, "temp")
	os.Mkdir(temp, 0700)
	file, e := securePreview(context.Background(), p, "notes.txt", temp, r, nil)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(file)
	if string(b) != "ordinary" {
		t.Fatal("preview bytes")
	}
	os.WriteFile(p, avZipBytes(t, "notes.txt", []byte("changed")), 0600)
	temp2 := filepath.Join(root, "temp2")
	os.Mkdir(temp2, 0700)
	if _, e = securePreview(context.Background(), p, "notes.txt", temp2, r, nil); e == nil {
		t.Fatal("changed archive preview allowed")
	}
}
func TestCustomAVCorruptZIPIncomplete(t *testing.T) {
	p := zipRawFixture(t, "notes.txt", nil, zip.Store, []byte("corrupt"), []byte("correct"))
	r := scanSecurity(context.Background(), p, nil)
	if r.Complete || r.permitted() {
		t.Fatal("CRC failure reported green", r)
	}
}
func TestMakeReleaseDemo07(t *testing.T) {
	dest := os.Getenv("FAWUSK_DEMO07_ROOT")
	if dest == "" {
		t.Skip("release fixture opt-in")
	}
	dest, _ = filepath.EvalSymlinks(dest)
	src := filepath.Join(dest, "Пример")
	if _, e := os.Stat(src); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dest, "Пример.faw")
	r, e := securePack(context.Background(), []string{src}, p, "faw3", 1, nil)
	if e != nil || !r.permitted() {
		t.Fatal(r, e)
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	os.WriteFile(filepath.Join(dest, "clear-report.json"), b, 0600)
	testp := filepath.Join(dest, "Тест.txt")
	os.WriteFile(testp, avEICAR(t), 0600)
	testarchive := filepath.Join(dest, "Тест-EICAR.faw")
	if e := pack(context.Background(), []string{testp}, testarchive, "faw3", 1, nil); e != nil {
		t.Fatal(e)
	}
	sample := filepath.Join(dest, "Проверка.cmd")
	os.WriteFile(sample, []byte("REM Static demonstration only: powershell encodedcommand\r\n"), 0600)
	if e := pack(context.Background(), []string{sample}, filepath.Join(dest, "Подозрение.faw"), "faw3", 1, nil); e != nil {
		t.Fatal(e)
	}
}
func TestFawReaderStreamAndIntegrity(t *testing.T) {
	for _, format := range []string{"faw1", "faw2", "faw3", "old3"} {
		t.Run(format, func(t *testing.T) {
			root := t.TempDir()
			src := filepath.Join(root, "notes.txt")
			original := []byte("FawReader stream contents\n")
			os.WriteFile(src, original, 0600)
			p := filepath.Join(root, "sample.faw")
			var e error
			if format == "old3" {
				e = packFAW3Legacy(context.Background(), []string{src}, p, 1, nil)
			} else {
				e = pack(context.Background(), []string{src}, p, format, 1, nil)
			}
			if e != nil {
				t.Fatal(e)
			}
			reader, e := NewFawReader(p)
			if e != nil {
				t.Fatal(e)
			}
			entries, e := reader.List(context.Background())
			if e != nil || len(entries) != 1 || entries[0].Size != uint64(len(original)) {
				t.Fatal(entries, e)
			}
			r, e := reader.OpenEntry(context.Background(), "notes.txt")
			if e != nil {
				t.Fatal(e)
			}
			got, e := io.ReadAll(r)
			r.Close()
			if e != nil || !bytes.Equal(got, original) {
				t.Fatal(got, e)
			}
			if _, e = reader.OpenEntry(context.Background(), "absent.txt"); e == nil {
				t.Fatal("missing stream")
			}
			b, _ := os.ReadFile(p)
			b[len(b)-1] ^= 0xff
			os.WriteFile(p, b, 0600)
			result := scanSecurity(context.Background(), p, nil)
			if result.Complete || result.permitted() {
				t.Fatal("corrupt checksum green", result)
			}
		})
	}
}
func TestFawReaderNestedAndPartialCoverage(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "eicar.txt")
	os.WriteFile(src, avEICAR(t), 0600)
	inner := filepath.Join(root, "inner.faw")
	if e := pack(context.Background(), []string{src}, inner, "faw2", 1, nil); e != nil {
		t.Fatal(e)
	}
	outer := filepath.Join(root, "outer.faw")
	pack(context.Background(), []string{inner}, outer, "faw3", 1, nil)
	r := scanSecurity(context.Background(), outer, nil)
	if r.TestSignal != 100 || r.MalwareSignal != 0 || !r.blocked() {
		t.Fatal("nested EICAR missed", r)
	}
	found := false
	for _, f := range r.Findings {
		found = found || f.Path == "inner.faw!/eicar.txt"
	}
	if !found {
		t.Fatal(r)
	}
	os.WriteFile(src, []byte("ordinary"), 0600)
	p := filepath.Join(root, "clear.faw")
	pack(context.Background(), []string{src}, p, "faw3", 1, nil)
	ctx := context.WithValue(context.Background(), selectionKey{}, "eicar.txt")
	r = scanSecurity(ctx, p, nil)
	if r.Complete || r.ScanComplete || r.permitted() || r.ScanScope != "selected_entry" {
		t.Fatal("one entry made archive green", r)
	}
	all := scanSecurity(context.Background(), p, nil)
	if !all.ScanComplete || all.ContainerFormat != "faw" || all.FormatVersion != 3 || all.Files[0].Entry != "eicar.txt" || all.Files[0].ContainerFormat != "faw" || !all.Files[0].ScanComplete {
		t.Fatal(all)
	}
}
func TestFawReaderBadVersionAndSignature(t *testing.T) {
	root := t.TempDir()
	for i, b := range [][]byte{[]byte("not faw"), append(append([]byte{}, fawMagic[:]...), 0x63, 0)} {
		p := filepath.Join(root, string(rune('a'+i))+".faw")
		os.WriteFile(p, b, 0600)
		if _, e := NewFawReader(p); e == nil {
			t.Fatal("invalid FAW reader accepted")
		}
		r := scanSecurity(context.Background(), p, nil)
		if r.ScanComplete || r.Complete || r.permitted() {
			t.Fatal(r)
		}
	}
}
func TestCustomAVCLIReport(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "archive.zip")
	os.WriteFile(p, avZipBytes(t, "notes.txt", []byte("ordinary")), 0600)
	report := filepath.Join(root, "report.json")
	if code := runAVCLI([]string{"--scan-customav", p, "--report", report}); code != 0 {
		t.Fatal(code)
	}
	b, _ := os.ReadFile(report)
	var r avResult
	if e := json.Unmarshal(b, &r); e != nil || !r.ScanComplete {
		t.Fatal(r, e)
	}
	if code := runAVCLI([]string{"--scan-customav", p, "--report", report}); code != 3 {
		t.Fatal("report overwrite")
	}
}
func TestCustomAVUnicodeParentMask(t *testing.T) {
	r := avScanBytes(t, "folder\u202e/name.txt", []byte("ordinary"), nil)
	if !r.blocked() {
		t.Fatal("Unicode parent camouflage missed", r)
	}
}
func TestCustomAVCorruptEntryNotGreen(t *testing.T) {
	p := zipRawFixture(t, "notes.txt", nil, zip.Store, []byte("corrupt"), []byte("correct"))
	r := scanSecurity(context.Background(), p, nil)
	for _, file := range r.Files {
		if file.ScanComplete || file.State == "clear" {
			t.Fatal("corrupt file marked checked", file)
		}
	}
}
