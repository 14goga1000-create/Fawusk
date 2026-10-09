package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestWindowsRiskConsent071(t *testing.T) {
	exe := os.Getenv("FAWUSK_GUI_EXE")
	if exe == "" {
		t.Skip("GUI opt-in")
	}
	p := fixture071(t, "notes.txt", []byte("Documentation: powershell encodedcommand"), "faw3")
	cmd := exec.Command(exe, p)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	hwnd := waitWindow(t, "Fawusk "+appVersion, cmd.Process.Pid)
	item := func(id uintptr) uintptr { h, _, _ := proc(user, "GetDlgItem").Call(hwnd, id); return h }
	enabled := func(h uintptr) bool { n, _, _ := proc(user, "IsWindowEnabled").Call(h); return n != 0 }
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) && (!strings.Contains(remoteText(item(idSecurity)), "Есть подозрительные") || !enabled(item(idRisk))) {
		time.Sleep(40 * time.Millisecond)
	}
	if enabled(item(idUnpack)) || !enabled(item(idRisk)) {
		t.Fatal("risk precondition")
	}
	post.Call(hwnd, 0x111, idRisk, 0)
	dialog := waitWindow(t, "Fawusk — открыть на свой риск?", cmd.Process.Pid)
	post.Call(dialog, 0x111, 7, 0)
	time.Sleep(150 * time.Millisecond)
	if enabled(item(idUnpack)) {
		t.Fatal("No bypassed")
	}
	post.Call(hwnd, 0x111, idRisk, 0)
	dialog = waitWindow(t, "Fawusk — открыть на свой риск?", cmd.Process.Pid)
	post.Call(dialog, 0x111, 6, 0)
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !enabled(item(idUnpack)) {
		time.Sleep(30 * time.Millisecond)
	}
	if !enabled(item(idUnpack)) || remoteText(item(idRisk)) != "Снять риск" || !strings.Contains(remoteText(item(idSecurity)), "Риск разрешён") {
		t.Fatal("consent not applied", remoteText(item(idSecurity)))
	}
	post.Call(hwnd, 0x111, idRisk, 0)
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && enabled(item(idUnpack)) {
		time.Sleep(30 * time.Millisecond)
	}
	if enabled(item(idUnpack)) {
		t.Fatal("revoke failed")
	}
	post.Call(hwnd, 0x10, 0, 0)
}
