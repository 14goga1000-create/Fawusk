package fawsecurity

import (
    "archive/zip"
    "context"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
)

type Scanner struct { cfg Config }

func NewScanner(cfg Config) *Scanner {
    if cfg.MaxEntries == 0 { cfg.MaxEntries = 10000 }
    if cfg.MaxUnpackedBytes == 0 { cfg.MaxUnpackedBytes = 1_000_000_000 }
    if cfg.MaxEntryBytes == 0 { cfg.MaxEntryBytes = cfg.MaxUnpackedBytes }
    return &Scanner{cfg: cfg}
}

func (s *Scanner) ScanFAW(ctx context.Context, reader FawReader) (Report, error) {
    entries, err := reader.Entries(ctx)
    if err != nil { return Report{Format:"faw", Status:"incomplete", Errors:[]string{err.Error()}}, err }
    return s.scanEntries(ctx, "faw", entries)
}

func (s *Scanner) ScanZIP(ctx context.Context, path string) (Report, error) {
    z, err := zip.OpenReader(path)
    if err != nil { return Report{Format:"zip", Status:"incomplete", Errors:[]string{err.Error()}}, err }
    defer z.Close()
    entries := make([]Entry, 0, len(z.File))
    for _, f := range z.File {
        info := f.FileInfo()
        file := f
        entries = append(entries, Entry{
            Path: file.Name, Size: int64(file.UncompressedSize64), CompressedSize: int64(file.CompressedSize64),
            Encrypted: file.Flags&1 != 0, Directory: info.IsDir(),
            Open: func(ctx context.Context) (io.ReadCloser, error) {
                if err := ctx.Err(); err != nil { return nil, err }
                return file.Open()
            },
        })
    }
    return s.scanEntries(ctx, "zip", entries)
}

func (s *Scanner) scanEntries(ctx context.Context, format string, entries []Entry) (Report, error) {
    r := Report{Format:format, Status:"clean"}
    if len(entries) > s.cfg.MaxEntries { r.Status="blocked"; r.Blocked++; r.Errors=append(r.Errors,"entry count limit exceeded"); return r, nil }
    var total int64
    for _, e := range entries {
        if err := ctx.Err(); err != nil { r.Status="incomplete"; r.Errors=append(r.Errors,err.Error()); return r, err }
        if e.Directory { continue }
        er := EntryReport{Entry:e}
        if e.Size < 0 || e.Size > s.cfg.MaxEntryBytes || total > s.cfg.MaxUnpackedBytes-e.Size {
            er.Status="blocked"; er.Error="size limit exceeded"; r.Blocked++; r.Entries=append(r.Entries,er); r.Status="blocked"; continue
        }
        if unsafePath(e.Path) { er.Status="blocked"; er.Error="unsafe path"; r.Blocked++; r.Entries=append(r.Entries,er); r.Status="blocked"; continue }
        if e.Encrypted { er.Status="incomplete"; er.Error="encrypted entry requires password"; r.Incomplete++; r.Entries=append(r.Entries,er); if r.Status=="clean" { r.Status="incomplete" }; continue }
        if e.Open == nil || s.cfg.EntryScanner == nil { er.Status="incomplete"; er.Error="reader or scanner is missing"; r.Incomplete++; r.Entries=append(r.Entries,er); if r.Status=="clean" { r.Status="incomplete" }; continue }
        in, err := e.Open(ctx)
        if err != nil { er.Status="incomplete"; er.Error=err.Error(); r.Incomplete++; r.Entries=append(r.Entries,er); if r.Status=="clean" { r.Status="incomplete" }; continue }
        result, scanErr := s.cfg.EntryScanner.ScanReader(ctx, filepath.Base(e.Path), io.LimitReader(in, e.Size+1))
        in.Close()
        if scanErr != nil { er.Status="incomplete"; er.Error=scanErr.Error(); r.Incomplete++; r.Entries=append(r.Entries,er); if r.Status=="clean" { r.Status="incomplete" }; continue }
        er.Result=&result; er.Status=statusFor(result); r.Entries=append(r.Entries,er); r.Scanned++; total += e.Size
        if er.Status=="blocked" { r.Blocked++; r.Status="blocked" }
        if er.Status=="review" { r.Review++; if r.Status=="clean" { r.Status="review" } }
    }
    if r.Status=="clean" && r.Scanned==0 { r.Status="incomplete"; r.Incomplete++ }
    r.Verdict=r.Status
    return r, nil
}

func statusFor(r ScanResult) string {
    upper:=strings.ToUpper(r.Verdict)
    if r.MalwareSignal>0 || strings.Contains(upper,"SUSPICIOUS") { return "blocked" }
    if r.TestSignal>0 || strings.Contains(upper,"REVIEW") || strings.Contains(upper,"MODIFIED") { return "review" }
    return "clean"
}

func unsafePath(p string) bool {
    if p=="" || filepath.IsAbs(p) || strings.HasPrefix(p,"/") || strings.HasPrefix(p,"\\") { return true }
    clean:=filepath.Clean(filepath.FromSlash(p)); return clean==".." || strings.HasPrefix(clean,".."+string(os.PathSeparator))
}

var _ = fmt.Sprintf
