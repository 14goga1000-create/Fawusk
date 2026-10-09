package main

import (
	"context"
	"encoding/hex"
	"fawusk/security/fawsecurity"
	"fmt"
	"io"
	"time"
)

// Actual Faw Edition API, backed by the existing checked FAW decoders.
func (r *FawReader) Entries(ctx context.Context) ([]fawsecurity.Entry, error) {
	entries, e := r.List(ctx)
	if e != nil {
		return nil, e
	}
	out := make([]fawsecurity.Entry, 0, len(entries))
	hashes := map[string]string{}
	if indexed(r.Path) {
		cat, e := readCatalogue(ctx, r.Path)
		if e != nil {
			return nil, e
		}
		for _, a := range cat.Entries {
			if !a.Directory {
				hashes[a.Name] = hex.EncodeToString(a.Hash[:])
			}
		}
	}
	for _, entry := range entries {
		a := entry
		item := fawsecurity.Entry{Path: a.Name, Size: int64(a.Size), Directory: a.Directory, Encrypted: false, SHA256: hashes[a.Name]}
		if !a.Directory {
			item.Open = func(ctx context.Context) (io.ReadCloser, error) { return r.OpenEntry(ctx, a.Name) }
		}
		out = append(out, item)
	}
	return out, nil
}

var _ fawsecurity.FawReader = (*FawReader)(nil)

func fawEditionConfig() fawsecurity.Config {
	return fawsecurity.Config{MaxEntries: avFileLimit, MaxUnpackedBytes: avByteLimit, MaxEntryBytes: int64(maxSingle)}
}
func validateEditionMetadata(entries []archiveEntry) error {
	converted := make([]fawsecurity.Entry, 0, len(entries))
	for _, a := range entries {
		converted = append(converted, fawsecurity.Entry{Path: a.Name, Size: int64(a.Size), Directory: a.Directory})
	}
	return fawsecurity.ValidateEntries(converted, fawEditionConfig())
}

// Optional SDK bridge. Production keeps the sequential ReadAll path to avoid
// re-decoding a legacy solid archive once per entry.
type NativeFawEntryScanner struct{}

func (NativeFawEntryScanner) ScanReader(ctx context.Context, name string, src io.Reader) (fawsecurity.ScanResult, error) {
	a := newRuntimeAV(ctx, nil)
	w, e := a.file(name, 0)
	if e != nil {
		return fawsecurity.ScanResult{}, e
	}
	_, e = io.CopyBuffer(w, src, make([]byte, 128<<10))
	ce := w.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return fawsecurity.ScanResult{}, e
	}
	r := a.finish()
	sr := fawsecurity.ScanResult{Verdict: r.Verdict, MalwareSignal: r.MalwareSignal, TestSignal: r.TestSignal, ReviewSignal: r.ReviewSignal, Incomplete: !r.Complete}
	for _, f := range r.Findings {
		sr.Findings = append(sr.Findings, fawsecurity.Finding{Severity: f.Severity, Rule: f.Rule, Path: f.Path, Detail: f.Detail, Points: f.Points, Category: f.Category})
	}
	return sr, nil
}

type avConsentKey struct{}
type avConsent struct {
	Hash       string
	Size       int64
	Authorized bool
	At         string
}

func riskConsent(r avResult) avConsent {
	return avConsent{Hash: r.ArchiveSHA256, Size: r.ArchiveSize, Authorized: r.overridePossible() && r.ScanScope == "all_entries", At: time.Now().UTC().Format(time.RFC3339)}
}
func (r avResult) overridePossible() bool {
	return r.IntegrityOK && r.ArchiveSHA256 != "" && r.ArchiveSize >= 0
}
func consentPermits(ctx context.Context, r avResult) bool {
	c, ok := ctx.Value(avConsentKey{}).(avConsent)
	return ok && c.Authorized && r.overridePossible() && c.Hash == r.ArchiveSHA256 && c.Size == r.ArchiveSize
}
func secureUnpackWithConsent(ctx context.Context, p, dest string, c avConsent, progress report) (avResult, error) {
	h, n, e := hashArchive(ctx, p)
	if e != nil {
		return avResult{}, e
	}
	if !c.Authorized || h != c.Hash || n != c.Size {
		return avResult{}, fmt.Errorf("%s", tr("Архив изменился после разрешения риска — откройте его заново"))
	}
	return secureUnpack(context.WithValue(ctx, avConsentKey{}, c), p, dest, progress)
}
func securePreviewWithConsent(ctx context.Context, p, name, root string, r avResult, c avConsent, progress report) (string, error) {
	return securePreview(context.WithValue(ctx, avConsentKey{}, c), p, name, root, r, progress)
}
