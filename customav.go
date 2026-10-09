package main

// Native bounded port of the user-supplied CustomAV 0.5 static rules.
// Reference files remain in reference/customav; no target is executed.
import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fawusk/security/fawsecurity"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

//go:embed security/customav_signatures.json
var avBuiltinDB []byte

const avSampleLimit = 16 << 20
const avFindingLimit = 2000
const avFileLimit = 10000
const avByteLimit = 20 << 30
const avNestedLimit = 1 << 30
const avDepthLimit = 3

type avFinding struct {
	Severity string `json:"severity"`
	Rule     string `json:"rule"`
	Path     string `json:"path"`
	Detail   string `json:"detail"`
	Category string `json:"category"`
	Points   int    `json:"points"`
}
type avFile struct {
	Path            string `json:"path"`
	Size            uint64 `json:"size"`
	SHA256          string `json:"sha256"`
	Format          string `json:"format"`
	State           string `json:"state"`
	Entry           string `json:"entry"`
	ContainerFormat string `json:"container_format"`
	ScanComplete    bool   `json:"scan_complete"`
	Verdict         string `json:"verdict"`
	Complete        bool   `json:"complete"`
}
type avResult struct {
	Engine          string      `json:"engine"`
	Version         string      `json:"version"`
	Verdict         string      `json:"verdict"`
	ArchiveSHA256   string      `json:"archive_sha256"`
	ArchiveSize     int64       `json:"archive_size"`
	ContainerFormat string      `json:"container_format"`
	FormatVersion   int         `json:"format_version,omitempty"`
	ScanScope       string      `json:"scan_scope"`
	ScanComplete    bool        `json:"scan_complete"`
	Score           int         `json:"score"`
	IntegrityOK     bool        `json:"outer_integrity_ok"`
	UserOverride    bool        `json:"user_override"`
	OverrideAt      string      `json:"override_at,omitempty"`
	ReportTruncated bool        `json:"report_truncated"`
	CheckedAt       string      `json:"checked_at"`
	Complete        bool        `json:"complete"`
	MalwareSignal   int         `json:"malware_signal_score"`
	TestSignal      int         `json:"test_signal_score"`
	ReviewSignal    int         `json:"review_signal_score"`
	Findings        []avFinding `json:"findings"`
	Files           []avFile    `json:"files"`
	Limitations     []string    `json:"limitations"`
}

func (r avResult) blocked() bool   { return r.MalwareSignal > 0 || r.TestSignal > 0 }
func (r avResult) permitted() bool { return r.Complete && !r.blocked() }
func (r avResult) state() string {
	sdkStatus := fawsecurity.StatusFor(fawsecurity.ScanResult{Verdict: "NO POSITIVE MALWARE INDICATORS", MalwareSignal: r.MalwareSignal, TestSignal: r.TestSignal, ReviewSignal: r.ReviewSignal, Incomplete: !r.Complete})
	_ = sdkStatus
	if sdkStatus == "blocked" {
		return "blocked"
	}
	if r.TestSignal > 0 {
		return "test"
	}
	if sdkStatus == "incomplete" {
		return "incomplete"
	}
	if sdkStatus == "review" {
		return "review"
	}
	return "clear"
}
func (r avResult) label() string {
	if r.UserOverride {
		return "Риск разрешён пользователем · предупреждения CustomAV сохранены"
	}
	switch r.state() {
	case "blocked":
		return "Есть подозрительные файлы · распаковка заблокирована"
	case "test":
		return "Обнаружена тестовая сигнатура · EICAR / проверка правил"
	case "incomplete":
		return "Проверка неполная · открытие файлов и распаковка недоступны"
	case "review":
		return "Нужна ручная проверка · обнаружены особенности файлов"
	default:
		return "Угрозы не обнаружены · статический анализ CustomAV"
	}
}
func (r avResult) summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\nCustomAV Faw Edition · alpha 0.7.1\nSHA-256 архива: %s\nРазмер архива: %d байт\nПроверено записей файлов: %d\n\n", r.label(), r.ArchiveSHA256, r.ArchiveSize, len(r.Files))
	for i, f := range r.Findings {
		if i >= 8 {
			b.WriteString("Остальные записи — в полном JSON-отчёте.\n")
			break
		}
		fmt.Fprintf(&b, "%s\n%s: %s\n\n", avShort(f.Path, 120), f.Rule, avShort(f.Detail, 180))
	}
	if len(r.Findings) == 0 {
		b.WriteString("Положительных признаков по установленным правилам не найдено.\n\n")
	}
	b.WriteString("Это не гарантия отсутствия вирусов. Эвристики могут ошибаться. Внешние приложения не изолированы. Полный JSON-отчёт можно сохранить через меню «…».")
	return b.String()
}

type avSig struct {
	ID, Type, Classification, Description string
	Pattern                               []byte
	Regex                                 *regexp.Regexp
}
type avRun struct {
	ctx              context.Context
	result           avResult
	signatures       []avSig
	consumed, nested uint64
	count            int
	seen             map[string]bool
	progress         report
}
type avContextKey struct{}

func avFromContext(ctx context.Context) *avRun { r, _ := ctx.Value(avContextKey{}).(*avRun); return r }
func newAVRun(ctx context.Context, db []byte, progress report) *avRun {
	a := &avRun{ctx: ctx, seen: map[string]bool{}, progress: progress}
	a.result = avResult{Engine: "CustomAV", Version: "Faw Edition / native integration alpha 0.7.1", Complete: true, ScanScope: "all_entries", CheckedAt: time.Now().UTC().Format(time.RFC3339), Findings: []avFinding{}, Files: []avFile{}, Limitations: []string{"Static rules only; targets are never executed. Unknown threats can evade detection; heuristic false positives are possible.", "Native adapted port, not the Python reference runtime. PE/JAR/PDF/script/name rules and signature layer are bounded.", "16 MiB analysis sample per file; larger files are hashed fully but marked incomplete. Nested FAW/ZIP up to depth 3 and 1 GiB decoded total; nested RAR/7z/other containers not decoded.", "No cloud, sandbox, commercial reputation or signature update service. Default database contains EICAR only.", "Entropy/packer scoring and Minecraft manifest/allowlist reputation from the reference are not ported."}}
	if e := a.loadSignatures(avBuiltinDB); e != nil {
		a.incomplete("BUILTIN_SIGNATURE_ERROR", "[signature-db]", e.Error())
	}
	if e := a.loadSignatures(db); e != nil {
		a.incomplete("SIGNATURE_DB_ERROR", "[signature-db]", e.Error())
	}
	return a
}
func (a *avRun) add(severity, rule, p, detail, category string, points int) {
	key := rule + "\x00" + p + "\x00" + detail
	if a.seen[key] {
		return
	}
	// Keep blocking signal even when report storage is full.
	switch category {
	case "malware":
		a.result.MalwareSignal += points
	case "test":
		a.result.TestSignal += points
	case "review":
		a.result.ReviewSignal += points
	}
	if len(a.result.Findings) >= avFindingLimit {
		a.result.Complete = false
		a.result.ReportTruncated = true
		return
	}
	a.seen[key] = true
	a.result.Findings = append(a.result.Findings, avFinding{severity, rule, p, detail, category, points})
}
func (a *avRun) incomplete(rule, p, detail string) {
	a.result.Complete = false
	for i := range a.result.Files {
		f := &a.result.Files[i]
		if p == "[archive]" || f.Path == p || strings.HasPrefix(f.Path, p+"!/") {
			f.Complete = false
			f.ScanComplete = false
			if f.State != "blocked" && f.State != "test" {
				f.State = "incomplete"
				f.Verdict = "incomplete_scan"
			}
		}
	}
	a.add("medium", rule, p, detail, "review", 0)
}
func (a *avRun) loadSignatures(data []byte) error {
	if len(data) > 2<<20 {
		return errors.New("Слишком большая база правил")
	}
	var db struct {
		Version    int                                                                         `json:"version"`
		Signatures []struct{ ID, Type, Pattern, Classification, Description, Encoding string } `json:"signatures"`
	}
	if e := json.Unmarshal(data, &db); e != nil {
		return e
	}
	if db.Version != 1 || len(db.Signatures) == 0 || len(db.Signatures) > 256 {
		return errors.New("Неподдерживаемая или пустая база правил")
	}
	for _, r := range db.Signatures {
		if r.ID == "" || (r.Classification != "test" && r.Classification != "malware") {
			return errors.New("Неверная классификация сигнатуры")
		}
		s := avSig{ID: r.ID, Type: r.Type, Classification: r.Classification, Description: r.Description}
		var e error
		switch r.Type {
		case "exact", "contains":
			switch r.Encoding {
			case "":
				s.Pattern = []byte(r.Pattern)
			case "base64":
				s.Pattern, e = base64.StdEncoding.DecodeString(r.Pattern)
			case "hex":
				s.Pattern, e = hex.DecodeString(r.Pattern)
			default:
				e = errors.New("Неизвестная кодировка сигнатуры")
			}
			if e != nil {
				return e
			}
			if len(s.Pattern) == 0 || len(s.Pattern) > 1<<20 {
				return errors.New("Неверная длина сигнатуры")
			}
		case "regex":
			if len(r.Pattern) == 0 || len(r.Pattern) > 4096 {
				return errors.New("Слишком сложное regex-правило")
			}
			s.Regex, e = regexp.Compile("(?is)" + r.Pattern)
			if e != nil {
				return e
			}
		default:
			return errors.New("Неизвестный тип сигнатуры")
		}
		duplicate := false
		for _, old := range a.signatures {
			if old.ID == s.ID {
				duplicate = true
				if old.Type != s.Type || old.Classification != s.Classification || !bytes.Equal(old.Pattern, s.Pattern) || (old.Regex != nil && s.Regex != nil && old.Regex.String() != s.Regex.String()) {
					return errors.New("Повторяющийся идентификатор сигнатуры")
				}
			}
		}
		if !duplicate {
			a.signatures = append(a.signatures, s)
		}
	}
	return nil
}
func runtimeSignatureDB() ([]byte, error) {
	exe, e := os.Executable()
	if e != nil {
		return nil, e
	}
	p := filepath.Join(filepath.Dir(exe), "customav_signatures.json")
	st, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return avBuiltinDB, nil
	}
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || isLink(st) || platformUnsafe(p, st) || st.Size() > 2<<20 {
		return nil, errors.New("Недопустимый файл customav_signatures.json")
	}
	return os.ReadFile(p)
}
func newRuntimeAV(ctx context.Context, progress report) *avRun {
	db, e := runtimeSignatureDB()
	if e != nil {
		a := newAVRun(ctx, avBuiltinDB, progress)
		a.incomplete("SIGNATURE_DB_ERROR", "[signature-db]", e.Error())
		return a
	}
	return newAVRun(ctx, db, progress)
}
func (a *avRun) finish() avResult {
	a.result.ScanComplete = a.result.Complete && a.result.ScanScope == "all_entries"
	a.result.Score = a.result.MalwareSignal + a.result.TestSignal + a.result.ReviewSignal
	switch a.result.state() {
	case "blocked":
		a.result.Verdict = "SUSPICIOUS / DO NOT RUN"
	case "test":
		a.result.Verdict = "TEST SIGNATURE DETECTED"
	case "incomplete":
		a.result.Verdict = "INCOMPLETE SCAN / MANUAL REVIEW"
	case "review":
		a.result.Verdict = "MODIFIED OR UNTRUSTED / MANUAL REVIEW"
	default:
		a.result.Verdict = "NO POSITIVE MALWARE INDICATORS"
	}
	return a.result
}
func (a *avRun) requirePermit() error {
	r := a.finish()
	if consentPermits(a.ctx, r) {
		a.result.UserOverride = true
		c := a.ctx.Value(avConsentKey{}).(avConsent)
		a.result.OverrideAt = c.At
		return nil
	}
	if !r.permitted() {
		return fmt.Errorf("CustomAV: %s", r.label())
	}
	return nil
}

type avWriter struct {
	run             *avRun
	name            string
	depth           int
	sum             hash.Hash
	size            uint64
	sample          []byte
	closed          bool
	containerFormat string
}

func (a *avRun) file(name string, depth int) (io.WriteCloser, error) {
	a.count++
	if a.count > avFileLimit {
		a.incomplete("SCAN_FILE_LIMIT", name, "Лимит проверки — 10 000 файлов, включая вложенные")
		return nil, errors.New("Превышен лимит файлов CustomAV")
	}
	return &avWriter{run: a, name: name, depth: depth, sum: sha256.New(), containerFormat: a.result.ContainerFormat}, nil
}
func (w *avWriter) Write(p []byte) (int, error) {
	if e := check(w.run.ctx); e != nil {
		return 0, e
	}
	if uint64(len(p)) > avByteLimit-w.run.consumed {
		w.run.incomplete("SCAN_BYTE_LIMIT", w.name, "Превышен суммарный лимит проверки")
		return 0, errors.New("Превышен лимит данных CustomAV")
	}
	if w.depth > 0 && uint64(len(p)) > avNestedLimit-w.run.nested {
		w.run.incomplete("NESTED_SIZE_LIMIT", w.name, "Вложенные контейнеры ограничены 1 ГиБ")
		return 0, errors.New("Превышен лимит вложенных данных")
	}
	w.run.consumed += uint64(len(p))
	if w.depth > 0 {
		w.run.nested += uint64(len(p))
	}
	w.size += uint64(len(p))
	w.sum.Write(p)
	if left := avSampleLimit - len(w.sample); left > 0 {
		w.sample = append(w.sample, p[:min(left, len(p))]...)
	}
	return len(p), nil
}
func (w *avWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	full := w.size <= avSampleLimit
	if !full {
		w.run.incomplete("FILE_ANALYSIS_LIMIT", w.name, "SHA-256 рассчитан полностью; правила применены только к первым 16 МиБ")
	}
	kind := avMagic(w.sample)
	idx := len(w.run.result.Files)
	w.run.result.Files = append(w.run.result.Files, avFile{Path: w.name, Size: w.size, SHA256: hex.EncodeToString(w.sum.Sum(nil)), Format: kind, Complete: full})
	w.run.analyze(w.name, w.sample, full, w.depth)
	state := "clear"
	priority := map[string]int{"clear": 1, "review": 2, "incomplete": 3, "test": 4, "blocked": 5}
	for _, f := range w.run.result.Findings {
		if f.Path == w.name || strings.HasPrefix(f.Path, w.name+"!/") {
			candidate := "incomplete"
			if f.Category == "malware" {
				candidate = "blocked"
			} else if f.Category == "test" {
				candidate = "test"
			} else if f.Points > 0 {
				candidate = "review"
			}
			if priority[candidate] > priority[state] {
				state = candidate
			}
		}
	}

	if !full && state == "clear" {
		state = "incomplete"
	}
	w.run.result.Files[idx].State = state
	w.run.result.Files[idx].Entry = w.name
	container := w.containerFormat
	w.run.result.Files[idx].ContainerFormat = container
	w.run.result.Files[idx].ScanComplete = full && state != "incomplete"
	w.run.result.Files[idx].Verdict = map[string]string{"clear": "no_positive_indicators", "blocked": "suspicious", "test": "test_signature_detected", "review": "manual_review", "incomplete": "incomplete_scan"}[state]
	if state == "incomplete" {
		w.run.result.Files[idx].Complete = false
	}
	w.sample = nil
	return nil
}
func avMagic(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("MZ")):
		return "pe"
	case bytes.HasPrefix(b, []byte("PK\x03\x04")) || bytes.HasPrefix(b, []byte("PK\x05\x06")) || bytes.HasPrefix(b, []byte("PK\x07\x08")):
		return "zip"
	case bytes.HasPrefix(b, fawMagic[:]):
		return "faw"
	case bytes.HasPrefix(b, []byte("Rar!\x1a\x07")):
		return "rar"
	case bytes.HasPrefix(b, []byte("7z\xbc\xaf\x27\x1c")):
		return "7z"
	case bytes.HasPrefix(b, []byte("\x7fELF")):
		return "elf"
	case bytes.HasPrefix(b, []byte("%PDF-")):
		return "pdf"
	case bytes.HasPrefix(b, []byte("OggS")):
		return "ogg"
	case bytes.HasPrefix(b, []byte("\x1f\x8b")):
		return "gzip"
	case bytes.HasPrefix(b, []byte("BZh")):
		return "bzip2"
	case bytes.HasPrefix(b, []byte("\xfd7zXZ")):
		return "xz"
	}
	if !bytes.Contains(b[:min(512, len(b))], []byte{0}) {
		return "text"
	}
	return "data"
}

var avHighBytes = []string{"cmd.exe", "powershell", "wscript", "cscript", "mshta", "certutil", "bitsadmin", "encodedcommand", "frombase64string", "xmrig", "monero", "bitcoin", "discord.com/api/webhooks", "createremotethread", "writeprocessmemory", "urldownloadtofile", "winhttpopen", "internetopena"}
var avScripts = map[string]bool{".bat": true, ".cmd": true, ".ps1": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true, ".wsf": true, ".hta": true, ".sh": true}
var avPE = map[string]bool{".exe": true, ".dll": true, ".scr": true, ".sys": true, ".ocx": true, ".cpl": true}
var avArchiveExt = map[string]bool{".faw": true, ".zip": true, ".jar": true, ".apk": true, ".xpi": true, ".docx": true, ".xlsx": true, ".pptx": true, ".docm": true, ".xlsm": true, ".pptm": true, ".rar": true, ".7z": true, ".tar": true, ".gz": true, ".bz2": true, ".xz": true, ".tgz": true}
var avDisguise = regexp.MustCompile(`(?i)\.(txt|pdf|jpg|png|doc|mp3)\.(exe|scr|bat|cmd|js|vbs|dll)$`)
var avLongB64 = regexp.MustCompile(`[A-Za-z0-9+/]{160,}={0,2}`)
var avURL = regexp.MustCompile(`(?i)https?://([a-z0-9.-]+)`)

func avHits(b []byte, terms []string) []string {
	var hits []string
	low := bytes.ToLower(b)
	for _, s := range terms {
		if bytes.Contains(low, []byte(s)) {
			hits = append(hits, s)
		}
	}
	return hits
}
func (a *avRun) nameSignals(name string) {
	base := path.Base(name)
	ext := strings.ToLower(path.Ext(name))
	invisible, nonascii, bidi := false, false, false
	for _, c := range name {
		invisible = invisible || unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || c == 0x115f || c == 0x1160
		nonascii = nonascii || c > 127
		bidi = bidi || c == 0x202e || c == 0x2066 || c == 0x2067 || c == 0x2068
	}
	if invisible {
		a.add("medium", "UNICODE_HIDDEN_NAME", name, "Невидимые управляющие символы в имени", "review", 4)
	}
	if nonascii && (avPE[ext] || avScripts[ext]) {
		a.add("medium", "NONASCII_EXECUTABLE_NAME", name, "Не-ASCII имя приложения/скрипта", "review", 8)
	}
	if avDisguise.MatchString(base) {
		a.add("high", "DOUBLE_EXTENSION", name, "Исполняемый файл замаскирован двойным расширением", "malware", 55)
	}
	if bidi {
		a.add("high", "BIDI_FILENAME", name, "Направление текста маскирует имя", "malware", 55)
	}
}
func (a *avRun) analyze(name string, b []byte, full bool, depth int) {
	if e := check(a.ctx); e != nil {
		a.incomplete("SCAN_CANCELLED", name, e.Error())
		return
	}
	if strings.HasSuffix(strings.ToLower(name), ".class") {
		if constants, ok := avJavaStrings(b); ok {
			if hits := avHits(constants, avHighBytes); len(hits) > 0 {
				a.add("high", "JAVA_HIGH_RISK_CONSTANT", name, strings.Join(hits, ", "), "malware", 45)
			}
		} else {
			a.incomplete("JAVA_PARSE_LIMITED", name, "Некорректный constant pool")
		}
	}
	a.nameSignals(name)
	kind := avMagic(b)
	ext := strings.ToLower(path.Ext(name))
	normal := bytes.TrimSpace(bytes.ReplaceAll(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")), []byte("\r"), []byte("\n")))
	for _, s := range a.signatures {
		if e := check(a.ctx); e != nil {
			a.incomplete("SCAN_CANCELLED", name, e.Error())
			return
		}
		hit := false
		switch s.Type {
		case "exact":
			hit = full && (bytes.Equal(b, s.Pattern) || bytes.Equal(normal, s.Pattern))
		case "contains":
			hit = bytes.Contains(b, s.Pattern)
		case "regex":
			hit = s.Regex.Match(b)
		}
		if hit {
			rule := "KNOWN_SIGNATURE"
			if s.Classification == "test" {
				rule = "KNOWN_TEST_SIGNATURE"
			}
			a.add("high", rule, name, s.ID+": "+s.Description, s.Classification, 100)
		}
	}
	expected := map[string]map[string]bool{"pe": avPE, "zip": avArchiveExt, "faw": avArchiveExt, "rar": avArchiveExt, "7z": avArchiveExt, "pdf": {".pdf": true}, "ogg": {".ogg": true}, "gzip": avArchiveExt}
	if ex, ok := expected[kind]; ok && ext != "" && !ex[ext] {
		a.add("medium", "FORMAT_EXTENSION_MISMATCH", name, "Расширение "+ext+", обнаружен формат "+kind, "review", 18)
	}
	if avScripts[ext] {
		if len(b) > 2_000_000 {
			a.incomplete("SCRIPT_ANALYSIS_LIMIT", name, "Правила скрипта ограничены первыми 2 МБ")
		}
		hits := avHits(b[:min(len(b), 2_000_000)], []string{"http://", "https://", "powershell", "certutil", "bitsadmin", "schtasks", "reg add", "reg.exe", "wmic", "curl ", "wget ", "encodedcommand", "frombase64string", "runonce", "\x00"})
		if avLongB64.Match(b[:min(len(b), 2_000_000)]) {
			hits = append(hits, "long_base64")
		}
		if len(hits) > 0 {
			a.add("high", "SCRIPT_CAPABILITY", name, strings.Join(hits, ", "), "malware", 45)
		} else {
			a.add("medium", "SCRIPT_FILE", name, "Скрипт требует ручной проверки", "review", 12)
		}
	}
	switch kind {
	case "pe":
		a.scanPE(name, b)
		if h := avHits(b, avHighBytes); len(h) > 0 {
			a.add("high", "PE_HIGH_RISK_STRING", name, strings.Join(h, ", "), "malware", 40)
		}
	case "pdf":
		if h := avHits(b, []string{"/javascript", "/js", "/openaction", "/aa ", "/launch", "/embeddedfile", "/submitform"}); len(h) > 0 {
			a.add("medium", "PDF_ACTIVE_CONTENT", name, strings.Join(h, ", "), "review", 15)
		}
		if h := avHits(b, avHighBytes); len(h) > 0 {
			a.add("high", "PDF_HIGH_RISK_STRING", name, strings.Join(h, ", "), "malware", 45)
		}
		a.urlSignals(name, b, "PDF_EXTERNAL_URL")
	case "elf":
		if h := avHits(b, []string{"curl ", "wget ", "bash -c", "/dev/tcp/", "ld_preload", "ptrace", "crontab", "xmrig", "monero"}); len(h) > 0 {
			a.add("medium", "ELF_SHELL_OR_PERSISTENCE", name, strings.Join(h, ", "), "review", 20)
		}
	case "text":
		if len(b) > 10_000_000 {
			a.incomplete("TEXT_ANALYSIS_LIMIT", name, "Текстовые эвристики ограничены 10 МБ")
		}
		if len(b) <= 10_000_000 {
			if h := avHits(b, avHighBytes); len(h) > 0 {
				a.add("high", "HIGH_RISK_TEXT", name, strings.Join(h, ", "), "malware", 45)
			}
			a.urlSignals(name, b, "UNEXPECTED_URL")
		}
	case "zip":
		if full {
			a.scanNestedZIP(name, b, depth)
		} else {
			a.incomplete("NESTED_ARCHIVE_LIMIT", name, "Большой вложенный ZIP не декодирован")
		}
	case "faw":
		if full {
			a.scanNestedFAW(name, b, depth)
		} else {
			a.incomplete("NESTED_ARCHIVE_LIMIT", name, "Большой вложенный FAW не декодирован")
		}
	case "rar", "7z", "gzip", "bzip2", "xz":
		a.incomplete("NESTED_CONTAINER_NOT_SCANNED", name, "Вложенный "+kind+" не декодирован")
	}
	if kind != "pe" && kind != "zip" && kind != "text" {
		if pos := bytes.Index(b[min(1, len(b)):len(b)], []byte("MZ")); pos >= 0 {
			pos++
			if pos+64 <= len(b) {
				off := int(uint64(b[pos+60]) | uint64(b[pos+61])<<8 | uint64(b[pos+62])<<16 | uint64(b[pos+63])<<24)
				if off > 0 && off < 4<<20 && pos+off+4 <= len(b) && bytes.Equal(b[pos+off:pos+off+4], []byte("PE\x00\x00")) {
					a.add("medium", "EMBEDDED_PE_SIGNATURE", name, fmt.Sprintf("Смещение %d", pos), "review", 25)
				}
			}
		}
	}
	if ext == ".tar" || ext == ".tgz" || ext == ".tbz2" || ext == ".txz" || (len(b) > 262 && string(b[257:262]) == "ustar") {
		a.incomplete("NESTED_CONTAINER_NOT_SCANNED", name, "TAR-контейнер не декодирован")
	}
}
func (a *avRun) urlSignals(name string, b []byte, rule string) {
	allowed := []string{"minecraft.net", "mojang.com", "amazonaws.com", "lwjgl.org", "amd.com", "nvidia.com"}
	for _, m := range avURL.FindAllSubmatch(b, 64) {
		host := strings.ToLower(string(m[1]))
		ok := false
		for _, h := range allowed {
			ok = ok || host == h || strings.HasSuffix(host, "."+h)
		}
		if !ok {
			a.add("medium", rule, name, host, "review", 12)
		}
	}
}
func hashArchive(ctx context.Context, p string) (string, int64, error) {
	f, e := os.Open(p)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return "", 0, e
	}
	if !st.Mode().IsRegular() || isLink(st) || platformUnsafe(p, st) || st.Size() > int64(maxTotal)+(1<<30) {
		return "", 0, errors.New("Неподдерживаемый файл архива")
	}
	h := sha256.New()
	c := &copying{ctx: ctx, total: st.Size(), report: func(int, string) {}}
	n, e := io.CopyBuffer(io.MultiWriter(h, c), f, make([]byte, 128<<10))
	if e != nil {
		return "", 0, e
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
func scanSecurity(ctx context.Context, p string, progress report) avResult {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	a := newRuntimeAV(ctx, progress)
	hash, n, e := hashArchive(ctx, p)
	a.result.ArchiveSHA256 = hash
	a.result.ArchiveSize = n
	if e != nil {
		a.incomplete("ARCHIVE_READ_ERROR", "[archive]", e.Error())
		return a.finish()
	}
	version, _ := archiveVersion(p)
	if version > 0 || strings.EqualFold(filepath.Ext(p), ".faw") {
		a.result.ContainerFormat = "faw"
		a.result.FormatVersion = version
	} else {
		a.result.ContainerFormat = "zip"
	}
	if selectedName(ctx) != "" {
		a.result.ScanScope = "selected_entry"
		a.incomplete("PARTIAL_ARCHIVE_SCAN", "[archive]", "Проверка только одного entry не подтверждает весь архив")
	}
	if version > 0 {
		ctx = context.WithValue(ctx, avMetadataVisitorKey{}, entryVisitor(func(entry archiveEntry) { a.nameSignals(entry.Name) }))
		var reader *FawReader
		reader, e = NewFawReader(p)
		if e == nil {
			e = reader.ReadAll(ctx, func(entry archiveEntry) (io.WriteCloser, error) { return a.file(entry.Name, 0) }, progress)
		}
	} else {
		ctx = context.WithValue(ctx, avContextKey{}, a)
		e = unpack(ctx, p, "", progress)
	}
	a.result.IntegrityOK = e == nil
	if e != nil {
		a.incomplete("ARCHIVE_SCAN_ERROR", "[archive]", e.Error())
	}
	after, size, e := hashArchive(ctx, p)
	if e != nil || hash != after || size != n {
		a.result.IntegrityOK = false
		a.incomplete("ARCHIVE_CHANGED", "[archive]", "Архив изменён или недоступен во время проверки")
	}
	return a.finish()
}

// Called by all packers after closing .part but before publication.
// Called by extraction sinks after all content checks but before publication.
type avPublishGateKey struct{}
type avPublishGate func(string) error

func beforeArchivePublish(ctx context.Context, p string) error {
	if gate, ok := ctx.Value(avPublishGateKey{}).(avPublishGate); ok {
		return gate(p)
	}
	return check(ctx)
}
func securePack(ctx context.Context, inputs []string, out, format string, level int, progress report) (avResult, error) {
	var r avResult
	gate := avPublishGate(func(p string) error {
		r = scanSecurity(ctx, p, progress)
		if !r.permitted() {
			return fmt.Errorf("CustomAV: %s", r.label())
		}
		return nil
	})
	e := pack(context.WithValue(ctx, avPublishGateKey{}, gate), inputs, out, format, level, progress)
	return r, e
}
func secureUnpack(ctx context.Context, p, dest string, progress report) (avResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	a := newRuntimeAV(ctx, progress)
	v, _ := archiveVersion(p)
	if v > 0 {
		a.result.ContainerFormat = "faw"
		a.result.FormatVersion = v
	} else {
		a.result.ContainerFormat = "zip"
	}
	h, n, e := hashArchive(ctx, p)
	a.result.ArchiveSHA256 = h
	a.result.ArchiveSize = n
	if e != nil {
		a.incomplete("ARCHIVE_READ_ERROR", "[archive]", e.Error())
		return a.finish(), e
	}
	ctx = context.WithValue(ctx, avContextKey{}, a)
	gate := avPublishGate(func(_ string) error {
		after, size, e := hashArchive(ctx, p)
		if e != nil || h != after || n != size {
			a.result.IntegrityOK = false
			a.incomplete("ARCHIVE_CHANGED", "[archive]", "Источник изменился во время распаковки")
		}
		return a.requirePermit()
	})
	e = unpack(context.WithValue(ctx, avPublishGateKey{}, gate), p, dest, progress)
	if e != nil {
		a.incomplete("EXTRACTION_NOT_PUBLISHED", "[archive]", e.Error())
	}
	return a.finish(), e
}

// Hash and scan before target publication; Close does not itself run any file.
type avTeeWriter struct{ target, scan io.WriteCloser }

func (w *avTeeWriter) Write(p []byte) (int, error) {
	if _, e := w.scan.Write(p); e != nil {
		return 0, e
	}
	return w.target.Write(p)
}
func (w *avTeeWriter) Close() error {
	a := w.scan.Close()
	b := w.target.Close()
	if a != nil {
		return a
	}
	return b
}

func avShort(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func securePreview(ctx context.Context, archive, name, root string, approved avResult, progress report) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if approved.ScanScope != "all_entries" || (!approved.permitted() && !consentPermits(ctx, approved)) {
		return "", fmt.Errorf("CustomAV: %s", approved.label())
	}
	h, n, e := hashArchive(ctx, archive)
	if e != nil {
		return "", e
	}
	if h != approved.ArchiveSHA256 || n != approved.ArchiveSize {
		return "", fmt.Errorf("Архив изменился после проверки — откройте его заново")
	}
	a := newRuntimeAV(ctx, progress)
	a.result.ScanScope = "selected_entry"
	a.result.ArchiveSHA256 = h
	a.result.ArchiveSize = n
	a.result.ContainerFormat = approved.ContainerFormat
	ctx = context.WithValue(ctx, avContextKey{}, a)
	gate := avPublishGate(func(_ string) error {
		after, size, e := hashArchive(ctx, archive)
		if e != nil || h != after || n != size {
			a.result.IntegrityOK = false
			a.incomplete("ARCHIVE_CHANGED", "[archive]", "Источник изменился во время просмотра")
		}
		return a.requirePermit()
	})
	return extractSelected(context.WithValue(ctx, avPublishGateKey{}, gate), archive, name, root, progress)
}

func (a *avRun) fileInContainer(name string, depth int, container string) (io.WriteCloser, error) {
	w, e := a.file(name, depth)
	if e == nil {
		w.(*avWriter).containerFormat = container
	}
	return w, e
}
