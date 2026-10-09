package main

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
)

func TestSettingsPersistence08(t *testing.T) {
	p := filepath.Join(t.TempDir(), "profile", "settings.json")
	s, e := readSettings(p)
	if e != nil || s != defaultSettings() {
		t.Fatal(s, e)
	}
	s.Language = "EN"
	s.CPU = 2
	s.MemoryMiB = 256
	if e = writeSettings(p, s); e != nil {
		t.Fatal(e)
	}
	got, e := readSettings(p)
	if e != nil || got != s {
		t.Fatal(got, e)
	}
	s.MemoryMiB = 1024
	if e = writeSettings(p, s); e != nil {
		t.Fatal(e)
	}
	got, e = readSettings(p)
	if e != nil || got != s {
		t.Fatal(got, e)
	}
	for _, b := range []string{"{bad", `{"version":1,"language":"EN","cpu_threads":16,"memory_mib":256}`, `{"version":1,"language":"EN","cpu_threads":1,"memory_mib":16}`, `{"version":1,"language":"XX","cpu_threads":1,"memory_mib":512}`, `{"version":2,"language":"RU","cpu_threads":1,"memory_mib":512}`, `{"version":1,"language":"RU","cpu_threads":1,"memory_mib":512,"disable_av":true}`, `{"version":1,"language":"RU","cpu_threads":1,"memory_mib":512} {}`} {
		os.WriteFile(p, []byte(b), 0600)
		got, e = readSettings(p)
		if e == nil || got != defaultSettings() {
			t.Fatal(b, got, e)
		}
	}
	os.WriteFile(p, make([]byte, 4097), 0600)
	if _, e = readSettings(p); e == nil {
		t.Fatal("oversize")
	}
}
func TestResourceBudget08(t *testing.T) {
	for _, r := range []struct{ cpu, groups, budget, mem, want int }{{4, 20, 0, 512, 3}, {4, 20, 0, 256, 1}, {4, 20, 2, 512, 1}, {8, 20, 4, 2048, 3}, {1, 20, 4, 512, 1}, {4, 1, 4, 512, 1}} {
		s := defaultSettings()
		s.CPU = r.budget
		s.MemoryMiB = r.mem
		if got := resourceWorkers(r.cpu, r.groups, s); got != r.want {
			t.Fatal(r, got)
		}
	}
	old := currentSettings()
	cp := runtime.GOMAXPROCS(0)
	mem := debug.SetMemoryLimit(-1)
	defer func() { settingsValue.Store(&old); runtime.GOMAXPROCS(cp); debug.SetMemoryLimit(mem) }()
	s := defaultSettings()
	s.CPU = 1
	s.MemoryMiB = 256
	applySettings(s)
	if runtime.GOMAXPROCS(0) != 1 || debug.SetMemoryLimit(-1) != 256<<20 {
		t.Fatal("not applied")
	}
}
func TestLocalizedUI08(t *testing.T) {
	old := currentSettings()
	defer settingsValue.Store(&old)
	s := defaultSettings()
	s.Language = "EN"
	settingsValue.Store(&s)
	for k, v := range map[string]string{"Открыть…": "Open…", "Настройки…": "Settings…", "Всё равно": "Proceed anyway", "Дата изменения": "Modified", "Упаковать": "Pack"} {
		if tr(k) != v {
			t.Fatal(k, tr(k))
		}
	}
	if formatBytes(1<<20) != "1.00 MB" {
		t.Fatal(formatBytes(1 << 20))
	}
	p := `C:\Документы\Имя.txt`
	if tr(p) != p {
		t.Fatal("path translated")
	}
	r := avResult{Complete: true, ScanScope: "all_entries"}
	if strings.Contains(r.label(), "Угрозы") {
		t.Fatal(r.label())
	}
	s.Language = "RU"
	settingsValue.Store(&s)
	if tr("Открыть…") != "Открыть…" || formatBytes(1<<20) != "1,00 МБ" {
		t.Fatal("RU broken")
	}
}
func TestTranslationCoverage08(t *testing.T) {
	verb := regexp.MustCompile(`%[+#0-9.\-]*[a-zA-Z]`)
	for k, v := range englishText {
		if strings.Join(verb.FindAllString(k, -1), ",") != strings.Join(verb.FindAllString(v, -1), ",") {
			t.Fatal("format mismatch", k, v)
		}
	}
	files, _ := filepath.Glob("*.go")
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") || p == "l10n.go" {
			continue
		}
		a, e := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		ast.Inspect(a, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || len(c.Args) != 1 {
				return true
			}
			name, ok := c.Fun.(*ast.Ident)
			if !ok || name.Name != "tr" {
				return true
			}
			l, ok := c.Args[0].(*ast.BasicLit)
			if !ok {
				return true
			}
			s, _ := strconv.Unquote(l.Value)
			if _, ok := englishText[s]; !ok {
				t.Errorf("missing translation %s: %q", p, s)
			}
			return true
		})
	}
}
func TestLowBudgetRoundTrip08(t *testing.T) {
	old := currentSettings()
	defer settingsValue.Store(&old)
	s := defaultSettings()
	s.CPU = 1
	s.MemoryMiB = 256
	settingsValue.Store(&s)
	b := bytes.Repeat([]byte("ordinary\n"), 1<<18)
	p := fixture071(t, "notes.txt", b, "faw3")
	dest := filepath.Join(filepath.Dir(p), "restored")
	r, e := secureUnpack(context.Background(), p, dest, nil)
	if e != nil || !r.permitted() {
		t.Fatal(r, e)
	}
	got, e := os.ReadFile(filepath.Join(dest, "notes.txt"))
	if e != nil || !bytes.Equal(got, b) {
		t.Fatal("changed bytes", e)
	}
}
