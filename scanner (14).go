package fawsecurity

// Fawusk integration hardening of the supplied Faw Edition policy.
// Preflight all entries, preserve paths, verify consumed bytes/EOF and fail closed.
import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Scanner struct{ cfg Config }

func NewScanner(cfg Config) *Scanner {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 10000
	}
	if cfg.MaxUnpackedBytes <= 0 {
		cfg.MaxUnpackedBytes = 1_000_000_000
	}
	if cfg.MaxEntryBytes <= 0 {
		cfg.MaxEntryBytes = cfg.MaxUnpackedBytes
	}
	return &Scanner{cfg}
}
func UnsafePath(p string) bool {
	if p == "" || !utf8.ValidString(p) || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") {
		return true
	}
	for _, r := range p {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimSuffix(p, "/")
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." || strings.TrimRight(part, " .") != part || strings.ContainsAny(part, `<>:"|?*`) {
			return true
		}
		base, _, _ := strings.Cut(strings.ToUpper(part), ".")
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CLOCK$" || base == "CONIN$" || base == "CONOUT$" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return true
		}
	}
	return false
}
func ValidateEntries(entries []Entry, cfg Config) error {
	s := NewScanner(cfg)
	if len(entries) > s.cfg.MaxEntries {
		return errors.New("entry count limit exceeded")
	}
	var total, names int64
	seen := map[string]bool{}
	types := map[string]bool{}
	spell := map[string]string{}
	for _, e := range entries {
		if UnsafePath(e.Path) || e.Link {
			return fmt.Errorf("unsafe path or link: %s", e.Path)
		}
		name := strings.TrimSuffix(strings.ReplaceAll(e.Path, "\\", "/"), "/")
		key := strings.ToLower(name)
		names += int64(len(e.Path))
		if names > 64<<20 {
			return errors.New("name storage limit exceeded")
		}
		if seen[key] {
			return fmt.Errorf("duplicate path: %s", e.Path)
		}
		seen[key] = true
		if e.Size < 0 || e.Size > s.cfg.MaxEntryBytes || total > s.cfg.MaxUnpackedBytes-e.Size {
			return fmt.Errorf("size limit exceeded: %s", e.Path)
		}
		if e.Directory && e.Size != 0 {
			return fmt.Errorf("directory has nonzero data size: %s", e.Path)
		}
		total += e.Size
		if old, ok := types[key]; ok && old != e.Directory {
			return fmt.Errorf("file/directory collision: %s", e.Path)
		}
		types[key] = e.Directory
		parts := strings.Split(name, "/")
		for i := range parts {
			prefix := strings.Join(parts[:i+1], "/")
			k := strings.ToLower(prefix)
			if old, ok := spell[k]; ok && old != prefix {
				return fmt.Errorf("ambiguous case: %s", e.Path)
			}
			spell[k] = prefix
			if i < len(parts)-1 {
				if isDir, ok := types[k]; ok && !isDir {
					return fmt.Errorf("parent is file: %s", e.Path)
				}
				types[k] = true
			}
		}
	}
	return nil
}
func StatusFor(r ScanResult) string {
	upper := strings.ToUpper(r.Verdict)
	if r.MalwareSignal > 0 || strings.Contains(upper, "SUSPICIOUS") {
		return "blocked"
	}
	if r.Incomplete || strings.Contains(upper, "INCOMPLETE") {
		return "incomplete"
	}
	if r.TestSignal > 0 || r.ReviewSignal > 0 || strings.Contains(upper, "REVIEW") || strings.Contains(upper, "MODIFIED") || strings.Contains(upper, "TEST SIGNATURE") {
		return "review"
	}
	if upper != "NO POSITIVE MALWARE INDICATORS" && upper != "CLEAN" {
		return "incomplete"
	}
	return "clean"
}
func (s *Scanner) ScanFAW(ctx context.Context, reader FawReader) (Report, error) {
	if reader == nil {
		return Report{Format: "faw", Status: "incomplete", Errors: []string{"missing FawReader"}}, errors.New("missing FawReader")
	}
	entries, e := reader.Entries(ctx)
	if e != nil {
		return Report{Format: "faw", Status: "incomplete", Errors: []string{e.Error()}}, e
	}
	return s.ScanEntries(ctx, "faw", entries)
}
func (s *Scanner) ScanZIP(ctx context.Context, p string) (Report, error) {
	// Production Fawusk uses its preflighted ZIP64/codec reader, not this convenience API.
	f, e := os.Open(p)
	if e != nil {
		return Report{Format: "zip", Status: "incomplete", Errors: []string{e.Error()}}, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e == nil && !st.Mode().IsRegular() {
		e = errors.New("not a regular archive")
	}
	if e == nil {
		e = s.preflightZIP(f, st.Size())
	}
	if e != nil {
		return Report{Format: "zip", Status: "incomplete", Errors: []string{e.Error()}}, e
	}
	z, e := zip.NewReader(f, st.Size())
	if e != nil {
		return Report{Format: "zip", Status: "incomplete", Errors: []string{e.Error()}}, e
	}
	if len(z.File) > s.cfg.MaxEntries {
		return Report{Format: "zip", Status: "blocked", Blocked: 1, Errors: []string{"entry count limit exceeded"}}, nil
	}
	entries := make([]Entry, 0, len(z.File))
	for _, f := range z.File {
		file := f
		mode := f.Mode()
		entries = append(entries, Entry{Path: f.Name, Size: int64(f.UncompressedSize64), CompressedSize: int64(f.CompressedSize64), Directory: f.FileInfo().IsDir(), Link: mode.Type() != 0 && !mode.IsDir(), Encrypted: f.Flags&0x41 != 0 || f.Method == 99, Open: func(ctx context.Context) (io.ReadCloser, error) {
			if e := ctx.Err(); e != nil {
				return nil, e
			}
			return file.Open()
		}})
	}
	return s.ScanEntries(ctx, "zip", entries)
}

type countedReader struct {
	ctx context.Context
	r   io.Reader
	n   int64
}

func (c *countedReader) Read(b []byte) (int, error) {
	if e := c.ctx.Err(); e != nil {
		return 0, e
	}
	n, e := c.r.Read(b)
	c.n += int64(n)
	return n, e
}
func (s *Scanner) ScanEntries(ctx context.Context, format string, entries []Entry) (Report, error) {
	report := Report{Format: format, Status: "clean", Entries: []EntryReport{}}
	if e := ValidateEntries(entries, s.cfg); e != nil {
		report.Status = "blocked"
		report.Verdict = "blocked"
		report.Blocked = 1
		report.Errors = []string{e.Error()}
		return report, nil
	}
	for _, entry := range entries {
		if e := ctx.Err(); e != nil {
			report.Status = "incomplete"
			report.Verdict = "incomplete"
			report.Errors = append(report.Errors, e.Error())
			return report, e
		}
		er := EntryReport{Entry: entry, Status: "clean"}
		if entry.Directory {
			report.Entries = append(report.Entries, er)
			continue
		}
		if entry.Encrypted || entry.Open == nil || s.cfg.EntryScanner == nil {
			er.Status = "incomplete"
			er.Error = "encrypted entry or reader/scanner missing"
		} else {
			src, e := entry.Open(ctx)
			if e == nil && src == nil {
				e = errors.New("entry reader is nil")
			}
			if e != nil {
				er.Status = "incomplete"
				er.Error = e.Error()
			} else {
				hash := sha256.New()
				cr := &countedReader{ctx: ctx, r: io.TeeReader(io.LimitReader(src, entry.Size+1), hash)}
				result, e := s.cfg.EntryScanner.ScanReader(ctx, entry.Path, cr)
				if e == nil && cr.n != entry.Size {
					e = fmt.Errorf("entry scanner did not consume exact size: %s", entry.Path)
				}
				if e == nil {
					var probe [1]byte
					n, end := cr.Read(probe[:])
					if n != 0 || end != io.EOF {
						e = fmt.Errorf("entry EOF/checksum not verified: %s (%v)", entry.Path, end)
					}
				}
				if e == nil && entry.SHA256 != "" && !strings.EqualFold(entry.SHA256, hex.EncodeToString(hash.Sum(nil))) {
					e = errors.New("entry SHA-256 mismatch")
				}
				ce := src.Close()
				if e == nil {
					e = ce
				}
				if e != nil {
					er.Status = "incomplete"
					er.Error = e.Error()
				} else {
					er.Result = &result
					er.Status = StatusFor(result)
					report.Scanned++
				}
			}
		}
		report.Entries = append(report.Entries, er)
		switch er.Status {
		case "blocked":
			report.Blocked++
		case "review":
			report.Review++
		case "incomplete":
			report.Incomplete++
		}
	}
	if report.Blocked > 0 {
		report.Status = "blocked"
	} else if report.Incomplete > 0 {
		report.Status = "incomplete"
	} else if report.Review > 0 {
		report.Status = "review"
	}
	report.Verdict = report.Status
	return report, nil
}

func (s *Scanner) preflightZIP(r io.ReaderAt, size int64) error {
	if size < 22 {
		return errors.New("Слишком короткий ZIP")
	}
	n := int64(65557)
	if size < n {
		n = size
	}
	tail := make([]byte, n)
	if _, e := r.ReadAt(tail, size-n); e != nil {
		return e
	}
	pos := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:i+4]) == 0x06054b50 && i+22+int(binary.LittleEndian.Uint16(tail[i+20:i+22])) == len(tail) {
			pos = i
			break
		}
	}
	if pos < 0 {
		return errors.New("Повреждено окончание ZIP")
	}
	b := tail[pos:]
	if binary.LittleEndian.Uint16(b[4:6]) != 0 || binary.LittleEndian.Uint16(b[6:8]) != 0 {
		return errors.New("Многотомные архивы не поддерживаются")
	}
	count := uint64(binary.LittleEndian.Uint16(b[10:12]))
	length := uint64(binary.LittleEndian.Uint32(b[12:16]))
	off := uint64(binary.LittleEndian.Uint32(b[16:20]))
	eocd := size - n + int64(pos)
	if count == 65535 || length == 0xffffffff || off == 0xffffffff {
		if eocd < 20 {
			return errors.New("Повреждён ZIP64")
		}
		loc := make([]byte, 20)
		if _, e := r.ReadAt(loc, eocd-20); e != nil {
			return e
		}
		if binary.LittleEndian.Uint32(loc[:4]) != 0x07064b50 || binary.LittleEndian.Uint32(loc[4:8]) != 0 || binary.LittleEndian.Uint32(loc[16:20]) != 1 {
			return errors.New("Неподдерживаемый ZIP64")
		}
		zoff := binary.LittleEndian.Uint64(loc[8:16])
		if zoff > uint64(size-56) {
			return errors.New("Неверный адрес ZIP64")
		}
		z := make([]byte, 56)
		if _, e := r.ReadAt(z, int64(zoff)); e != nil {
			return e
		}
		if binary.LittleEndian.Uint32(z[:4]) != 0x06064b50 || binary.LittleEndian.Uint32(z[16:20]) != 0 || binary.LittleEndian.Uint32(z[20:24]) != 0 {
			return errors.New("Неподдерживаемый ZIP64")
		}
		count = binary.LittleEndian.Uint64(z[32:40])
		length = binary.LittleEndian.Uint64(z[40:48])
		off = binary.LittleEndian.Uint64(z[48:56])
	}
	if count > uint64(s.cfg.MaxEntries) || length > 64<<20 || off > uint64(size) || length > uint64(size)-off {
		return errors.New("Превышен лимит или повреждён каталог ZIP")
	}
	return nil
}
