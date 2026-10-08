package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type archiveEntry struct {
	Name      string
	Size      uint64
	Directory bool
}
type entryVisitor func(archiveEntry)
type discardCloser struct{ io.Writer }

func (discardCloser) Close() error { return nil }

type extractionSink struct{ stage, dest string }

func newExtractionSink(dest string) (*extractionSink, error) {
	s := &extractionSink{dest: dest}
	if dest == "" {
		return s, nil
	}
	if _, e := os.Lstat(dest); e == nil {
		return nil, errors.New("Папка назначения уже существует; выберите новую")
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	parent := filepath.Dir(dest)
	if e := ensureParents(parent); e != nil {
		return nil, e
	}
	var e error
	s.stage, e = os.MkdirTemp(parent, ".fawusk-unpack-*")
	return s, e
}
func (s *extractionSink) cleanup() {
	if s.stage != "" {
		os.RemoveAll(s.stage)
	}
}
func (s *extractionSink) directory(name string) error {
	if s.stage == "" {
		return nil
	}
	return os.MkdirAll(filepath.Join(s.stage, filepath.FromSlash(name)), 0700)
}
func (s *extractionSink) file(name string) (io.WriteCloser, error) {
	if s.stage == "" {
		return discardCloser{io.Discard}, nil
	}
	target := filepath.Join(s.stage, filepath.FromSlash(name))
	if e := os.MkdirAll(filepath.Dir(target), 0700); e != nil {
		return nil, e
	}
	return os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}
func (s *extractionSink) timestamp(name string, t time.Time) {
	if s.stage != "" {
		os.Chtimes(filepath.Join(s.stage, filepath.FromSlash(name)), t, t)
	}
}
func (s *extractionSink) publish(ctx context.Context) error {
	if e := check(ctx); e != nil {
		return e
	}
	if s.stage == "" {
		return nil
	}
	return publishDirectory(s.stage, s.dest)
}
func archiveVersion(p string) (int, error) {
	f, e := os.Open(p)
	if e != nil {
		return 0, e
	}
	defer f.Close()
	var h [10]byte
	_, e = f.ReadAt(h[:], 0)
	if e == nil && equalBytes(h[:8], fawMagic[:]) {
		return int(binary.LittleEndian.Uint16(h[8:10])), nil
	}
	if strings.EqualFold(filepath.Ext(p), ".faw") {
		return 0, errors.New("Файл .faw не имеет корректной сигнатуры")
	}
	if strings.EqualFold(filepath.Ext(p), ".zip") {
		return -1, nil
	}
	return 0, nil
}
func scanArchive(ctx context.Context, p string, progress report) ([]archiveEntry, error) {
	version, e := archiveVersion(p)
	if e != nil {
		return nil, e
	}
	var result []archiveEntry
	visit := func(a archiveEntry) { result = append(result, a) }
	switch version {
	case 1, -1:
		e = walkLegacy(ctx, p, "", progress, visit)
	case 2:
		e = walkFAW2(ctx, p, "", progress, visit)
	case 3:
		e = walkFAW3(ctx, p, "", progress, visit)
	default:
		e = errors.New("Неподдерживаемая версия архива")
	}
	if e != nil {
		return nil, e
	}
	return result, nil
}
func archiveChildren(entries []archiveEntry, prefix string) []archiveEntry {
	rows := map[string]archiveEntry{}
	for _, a := range entries {
		if !strings.HasPrefix(a.Name, prefix) {
			continue
		}
		rel := strings.TrimPrefix(a.Name, prefix)
		if rel == "" {
			continue
		}
		first, rest, found := strings.Cut(rel, "/")
		_ = rest
		name := prefix + first
		if found {
			rows[name] = archiveEntry{Name: name, Directory: true}
			continue
		}
		if old, ok := rows[name]; !ok || !old.Directory {
			rows[name] = a
		}
	}
	out := make([]archiveEntry, 0, len(rows))
	for _, a := range rows {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Directory != out[j].Directory {
			return out[i].Directory
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

type nameGuard struct {
	byteLimit       uint64
	explicit, types map[string]bool
	canonical       map[string]string
	bytes           uint64
}

func newNameGuard() *nameGuard {
	return &nameGuard{explicit: map[string]bool{}, types: map[string]bool{}, canonical: map[string]string{}}
}
func (g *nameGuard) validate(name string, directory bool) error {
	g.bytes += uint64(len(name))
	limit := g.byteLimit
	if limit == 0 {
		limit = fawMaxNames
	}
	if g.bytes > limit {
		return errors.New("Превышен лимит имён FAW")
	}
	clean, e := safeName(name)
	if e != nil {
		return e
	}
	if clean != name {
		return errors.New("Неверный путь FAW")
	}
	key := strings.ToLower(name)
	if g.explicit[key] {
		return errors.New("Дублирующийся путь FAW")
	}
	if old, exists := g.types[key]; exists && old != directory {
		return errors.New("Конфликт файлов и папок FAW")
	}
	g.explicit[key] = true
	g.types[key] = directory
	for p := name; p != "."; p = path.Dir(p) {
		k := strings.ToLower(p)
		if old, exists := g.canonical[k]; exists && old != p {
			return errors.New("Неоднозначный регистр пути FAW")
		}
		if _, exists := g.canonical[k]; !exists && len(g.canonical) >= maxFiles {
			return errors.New("Превышен лимит компонентов путей")
		}
		g.canonical[k] = p
		if p != name {
			if dir, exists := g.types[k]; exists && !dir {
				return errors.New("Файл используется как папка FAW")
			}
			g.types[k] = true
		}
	}
	return nil
}
