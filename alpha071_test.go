package main

import (
	"bytes"
	"context"
	"fawusk/security/fawsecurity"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func fixture071(t *testing.T, name string, b []byte, format string) string {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(root, name)
	if e := os.WriteFile(src, b, 0600); e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(root, "sample.faw")
	if format == "zip" {
		out = filepath.Join(root, "sample.zip")
	}
	if e := pack(context.Background(), []string{src}, out, format, 1, nil); e != nil {
		t.Fatal(e)
	}
	return out
}
func TestFawEditionAdapter071(t *testing.T) {
	for _, format := range []string{"faw1", "faw2", "faw3"} {
		t.Run(format, func(t *testing.T) {
			p := fixture071(t, "notes.txt", []byte("ordinary"), format)
			r, e := NewFawReader(p)
			if e != nil {
				t.Fatal(e)
			}
			es, e := r.Entries(context.Background())
			if e != nil || len(es) != 1 || es[0].Size != 8 {
				t.Fatal(es, e)
			}
			src, e := es[0].Open(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			b, e := io.ReadAll(src)
			src.Close()
			if e != nil || string(b) != "ordinary" {
				t.Fatal(string(b), e)
			}
			cfg := fawEditionConfig()
			cfg.EntryScanner = NativeFawEntryScanner{}
			rep, e := fawsecurity.NewScanner(cfg).ScanFAW(context.Background(), r)
			if e != nil || rep.Status != "clean" || rep.Scanned != 1 {
				t.Fatal(rep, e)
			}
		})
	}
}
func TestRiskConsent071(t *testing.T) {
	for _, format := range []string{"faw1", "faw2", "faw3", "zip"} {
		t.Run(format, func(t *testing.T) {
			b := []byte("Documentation: powershell encodedcommand")
			p := fixture071(t, "notes.txt", b, format)
			r := scanSecurity(context.Background(), p, nil)
			if !r.blocked() || !r.overridePossible() {
				t.Fatal(r)
			}
			root := filepath.Dir(p)
			if _, e := secureUnpack(context.Background(), p, filepath.Join(root, "denied"), nil); e == nil {
				t.Fatal("default allowed")
			}
			c := riskConsent(r)
			rr, e := secureUnpackWithConsent(context.Background(), p, filepath.Join(root, "allowed"), c, nil)
			if e != nil || !rr.UserOverride || rr.MalwareSignal == 0 || rr.state() != "blocked" {
				t.Fatal(rr, e)
			}
			restored, _ := os.ReadFile(filepath.Join(root, "allowed/notes.txt"))
			if !bytes.Equal(restored, b) {
				t.Fatal("changed bytes")
			}
			temp := filepath.Join(root, "preview")
			os.Mkdir(temp, 0700)
			selected, e := securePreviewWithConsent(context.Background(), p, "notes.txt", temp, r, c, nil)
			if e != nil {
				t.Fatal(e)
			}
			viewed, _ := os.ReadFile(selected)
			if !bytes.Equal(viewed, b) {
				t.Fatal("preview changed")
			}
			partial := r
			partial.ScanScope = "selected_entry"
			if riskConsent(partial).Authorized {
				t.Fatal("partial grant")
			}
			if _, e := securePreviewWithConsent(context.Background(), p, "notes.txt", temp, partial, c, nil); e == nil {
				t.Fatal("partial approval")
			}
			os.WriteFile(p, []byte("changed"), 0600)
			if _, e := secureUnpackWithConsent(context.Background(), p, filepath.Join(root, "changed"), c, nil); e == nil {
				t.Fatal("changed archive allowed")
			}
		})
	}
}
func TestRiskHardChecks071(t *testing.T) {
	p := fixture071(t, "notes.cmd", []byte("REM powershell encodedcommand"), "faw3")
	r := scanSecurity(context.Background(), p, nil)
	temp := filepath.Join(filepath.Dir(p), "preview")
	os.Mkdir(temp, 0700)
	if _, e := securePreviewWithConsent(context.Background(), p, "notes.cmd", temp, r, riskConsent(r), nil); e == nil {
		t.Fatal("script preview allowed")
	}
	b, _ := os.ReadFile(p)
	b[len(b)-1] ^= 1
	os.WriteFile(p, b, 0600)
	broken := scanSecurity(context.Background(), p, nil)
	if broken.overridePossible() {
		t.Fatal("corrupt grant")
	}
	h, n, _ := hashArchive(context.Background(), p)
	forged := avConsent{Hash: h, Size: n, Authorized: true}
	dest := filepath.Join(filepath.Dir(p), "broken")
	if _, e := secureUnpackWithConsent(context.Background(), p, dest, forged, nil); e == nil {
		t.Fatal("corrupt extraction allowed")
	}
	if _, e := os.Stat(dest); !os.IsNotExist(e) {
		t.Fatal("published corrupt")
	}
}
func TestRiskCoverageIncomplete071(t *testing.T) {
	p := fixture071(t, "large.bin", make([]byte, 17<<20), "faw3")
	r := scanSecurity(context.Background(), p, nil)
	if r.Complete || r.state() != "incomplete" || !r.overridePossible() {
		t.Fatal(r)
	}
	dest := filepath.Join(filepath.Dir(p), "allowed")
	rr, e := secureUnpackWithConsent(context.Background(), p, dest, riskConsent(r), nil)
	if e != nil || !rr.UserOverride || rr.Complete {
		t.Fatal(rr, e)
	}
	st, e := os.Stat(filepath.Join(dest, "large.bin"))
	if e != nil || st.Size() != 17<<20 {
		t.Fatal(st, e)
	}
}
func TestRiskUnsafePaths071(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "unsafe.zip")
	os.WriteFile(p, avZipBytes(t, "../outside.txt", []byte("ordinary")), 0600)
	r := scanSecurity(context.Background(), p, nil)
	if r.overridePossible() {
		t.Fatal("unsafe grant")
	}
	h, n, _ := hashArchive(context.Background(), p)
	dest := filepath.Join(root, "dest")
	if _, e := secureUnpackWithConsent(context.Background(), p, dest, avConsent{Hash: h, Size: n, Authorized: true}, nil); e == nil {
		t.Fatal("unsafe extraction allowed")
	}
}
