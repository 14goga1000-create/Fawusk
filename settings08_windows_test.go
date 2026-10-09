package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindowsSettingsLanguage08(t *testing.T) {
	exe := os.Getenv("FAWUSK_GUI_EXE")
	if exe == "" {
		t.Skip("GUI opt-in")
	}
	dir := t.TempDir()
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), "FAWUSK_CONFIG_DIR="+dir)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	h := waitWindow(t, "Fawusk "+appVersion, cmd.Process.Pid)
	item := func(parent uintptr, id int) uintptr {
		r, _, _ := proc(user, "GetDlgItem").Call(parent, uintptr(id))
		return r
	}
	lang := item(h, idLanguage)
	send.Call(lang, 0x14e, 1, 0)
	post.Call(h, 0x111, idLanguage|(9<<16), lang)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && remoteText(item(h, idAdd)) != "Open…" {
		time.Sleep(30 * time.Millisecond)
	}
	if remoteText(item(h, idAdd)) != "Open…" {
		t.Fatal("language switch", remoteText(item(h, idAdd)))
	}
	post.Call(h, 0x111, 1014, 0)
	dialog := waitWindow(t, "Settings — Fawusk", cmd.Process.Pid)
	if remoteText(item(dialog, cfgSave)) != "Save" {
		t.Fatal("untranslated dialog")
	}
	send.Call(item(dialog, cfgCPU), 0x14e, 1, 0)
	send.Call(item(dialog, cfgMemory), 0x14e, 0, 0)
	post.Call(dialog, 0x111, cfgSave, 0)
	deadline = time.Now().Add(5 * time.Second)
	var s appSettings
	for time.Now().Before(deadline) {
		s, _ = readSettings(filepath.Join(dir, "settings.json"))
		if s.MemoryMiB == 256 && s.CPU == 1 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if s.Language != "EN" || s.MemoryMiB != 256 || s.CPU != 1 {
		t.Fatal("not saved", s)
	}
	if !strings.Contains(remoteText(item(h, idStatus)), "256 MiB") {
		time.Sleep(100 * time.Millisecond)
		if !strings.Contains(remoteText(item(h, idStatus)), "256 MiB") {
			t.Fatal("status", remoteText(item(h, idStatus)))
		}
	}
	post.Call(h, 0x10, 0, 0)
}
