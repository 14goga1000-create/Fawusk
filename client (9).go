package customav

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"
)

type Config struct {
    Python      string
    EnginePath  string
    SignatureDB string
    Timeout     time.Duration
    MaxFiles    int
    MaxBytes    int64
}

type Client struct { cfg Config }

func New(cfg Config) Client {
    if cfg.Python == "" { cfg.Python = "python3" }
    if cfg.Timeout == 0 { cfg.Timeout = 10 * time.Minute }
    if cfg.MaxFiles == 0 { cfg.MaxFiles = 10000 }
    if cfg.MaxBytes == 0 { cfg.MaxBytes = 1_000_000_000 }
    return Client{cfg: cfg}
}

type Finding struct {
    Severity string `json:"severity"`
    Rule     string `json:"rule"`
    Path     string `json:"path"`
    Detail   any    `json:"detail"`
    Points   int    `json:"points"`
    Category string `json:"category"`
}

type Result struct {
    Verdict           string         `json:"verdict"`
    Explanation       string         `json:"explanation,omitempty"`
    Score             int            `json:"score"`
    MalwareSignal     int            `json:"malware_signal_score"`
    TestSignal        int            `json:"test_signal_score"`
    ReviewSignal      int            `json:"review_signal_score"`
    Findings          []Finding      `json:"findings"`
    Statistics        map[string]any `json:"statistics"`
    Metadata          map[string]any `json:"metadata"`
    Limitations       []string       `json:"limitations"`
}

func (r Result) IsMalware() bool {
    return r.MalwareSignal > 0 || strings.Contains(strings.ToUpper(r.Verdict), "SUSPICIOUS")
}
func (r Result) IsTestSignature() bool { return strings.Contains(strings.ToUpper(r.Verdict), "TEST SIGNATURE") }
func (r Result) NeedsReview() bool { return strings.Contains(strings.ToUpper(r.Verdict), "REVIEW") }

func (c Client) ScanPath(parent context.Context, path string) (Result, error) {
    ctx, cancel := context.WithTimeout(parent, c.cfg.Timeout)
    defer cancel()
    reportFile, err := os.CreateTemp("", "customav-report-*.json")
    if err != nil { return Result{}, err }
    reportPath := reportFile.Name()
    reportFile.Close()
    defer os.Remove(reportPath)

    args := []string{c.cfg.EnginePath, path, "--report", reportPath, "--max-files", fmt.Sprint(c.cfg.MaxFiles), "--max-bytes", fmt.Sprint(c.cfg.MaxBytes)}
    if c.cfg.SignatureDB != "" { args = append(args, "--signature-db", c.cfg.SignatureDB) }
    cmd := exec.CommandContext(ctx, c.cfg.Python, args...)
    cmd.Env = os.Environ()
    var stderr bytes.Buffer
    cmd.Stderr = &stderr
    if err := cmd.Run(); err != nil {
        if ctx.Err() != nil { return Result{}, ctx.Err() }
        return Result{}, fmt.Errorf("customav: %w: %s", err, stderr.String())
    }
    data, err := os.ReadFile(reportPath)
    if err != nil { return Result{}, err }
    var result Result
    if err := json.Unmarshal(data, &result); err != nil { return Result{}, err }
    return result, nil
}

func (c Client) ScanReader(parent context.Context, name string, src io.Reader) (Result, error) {
    suffix := filepath.Ext(name)
    f, err := os.CreateTemp("", "customav-input-*"+suffix)
    if err != nil { return Result{}, err }
    path := f.Name()
    defer os.Remove(path)
    if _, err = io.Copy(f, src); err != nil { f.Close(); return Result{}, err }
    if err = f.Close(); err != nil { return Result{}, err }
    return c.ScanPath(parent, path)
}
