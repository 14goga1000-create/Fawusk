package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync/atomic"
)

// Resource settings are scheduling/Go-memory budgets, not an OS working-set cap.
type appSettings struct {
	Version   int    `json:"version"`
	Language  string `json:"language"`
	CPU       int    `json:"cpu_threads"`
	MemoryMiB int    `json:"memory_mib"`
}

var settingsValue atomic.Pointer[appSettings]
var startupCPU = runtime.GOMAXPROCS(0)

func defaultSettings() appSettings {
	return appSettings{Version: 1, Language: "RU", CPU: 0, MemoryMiB: 512}
}
func currentSettings() appSettings {
	if s := settingsValue.Load(); s != nil {
		return *s
	}
	return defaultSettings()
}
func validSettings(s appSettings) error {
	if s.Version != 1 || (s.Language != "RU" && s.Language != "EN") {
		return errors.New("Invalid settings version/language")
	}
	if s.CPU != 0 && s.CPU != 1 && s.CPU != 2 && s.CPU != 4 {
		return errors.New("CPU budget must be Auto, 1, 2 or 4")
	}
	if s.MemoryMiB != 256 && s.MemoryMiB != 512 && s.MemoryMiB != 1024 && s.MemoryMiB != 2048 {
		return errors.New("Memory budget must be 256, 512, 1024 or 2048 MiB")
	}
	return nil
}
func settingsPath() (string, error) {
	dir := os.Getenv("FAWUSK_CONFIG_DIR")
	if dir == "" {
		var e error
		dir, e = os.UserConfigDir()
		if e != nil {
			return "", e
		}
		dir = filepath.Join(dir, "Fawusk")
	}
	return filepath.Join(dir, "settings.json"), nil
}
func readSettings(p string) (appSettings, error) {
	d := defaultSettings()
	st, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return d, nil
	}
	if e != nil {
		return d, e
	}
	if !st.Mode().IsRegular() || st.Size() > 4096 {
		return d, errors.New("Invalid or oversized settings file")
	}
	f, e := os.Open(p)
	if e != nil {
		return d, e
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 4097))
	dec.DisallowUnknownFields()
	var s appSettings
	if e = dec.Decode(&s); e != nil {
		return d, e
	}
	var extra any
	if e = dec.Decode(&extra); e != io.EOF {
		return d, errors.New("Trailing settings data")
	}
	if e = validSettings(s); e != nil {
		return d, e
	}
	return s, nil
}
func writeSettings(p string, s appSettings) error {
	if e := validSettings(s); e != nil {
		return e
	}
	dir := filepath.Dir(p)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	if st, e := os.Lstat(p); e == nil && !st.Mode().IsRegular() {
		return errors.New("Settings target is not a regular file")
	}
	b, e := json.MarshalIndent(s, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".settings-*.tmp")
	if e != nil {
		return e
	}
	temp := f.Name()
	defer os.Remove(temp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(append(b, '\n'))
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(temp, p)
}
func effectiveCPU(s appSettings, available int) int {
	n := s.CPU
	if n == 0 {
		n = 4
	}
	return max(1, min(n, max(1, available)))
}
func applySettings(s appSettings) {
	settingsValue.Store(&s)
	runtime.GOMAXPROCS(effectiveCPU(s, startupCPU))
	debug.SetMemoryLimit(int64(s.MemoryMiB) << 20)
}
func startSettings() error {
	p, e := settingsPath()
	if e != nil {
		applySettings(defaultSettings())
		return e
	}
	s, e := readSettings(p)
	applySettings(s)
	return e
}
func commitSettings(s appSettings) error {
	p, e := settingsPath()
	if e != nil {
		return e
	}
	if e = writeSettings(p, s); e != nil {
		return e
	}
	applySettings(s)
	return nil
}
func resourceWorkers(cpu, groups int, s appSettings) int {
	cpu = effectiveCPU(s, cpu)
	n := codecWorkers(cpu, groups)
	memoryWorkers := max(1, (s.MemoryMiB-128)/128)
	return max(1, min(n, memoryWorkers))
}
func resourceSummary() string {
	s := currentSettings()
	return fmt.Sprintf(tr("Бюджет: %d МиБ · CPU до %d потоков"), s.MemoryMiB, effectiveCPU(s, startupCPU))
}
