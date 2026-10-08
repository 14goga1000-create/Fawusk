package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unsafe"
)

func TestWindowsGUI(t *testing.T) {
	exe := os.Getenv("FAWUSK_GUI_EXE")
	if exe == "" {
		t.Skip("Set FAWUSK_GUI_EXE to opt in to the Windows GUI integration test")
	}
	root := t.TempDir()
	src := filepath.Join(root, "gui-smoke.txt")
	os.WriteFile(src, []byte("GUI integration — Fawusk alpha 0.1"), 0600)
	cmd := exec.Command(exe, src)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	find := proc(user, "FindWindowW")
	var hwnd uintptr
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		hwnd, _, _ = find.Call(ptr(u("FawuskMainWindow")), ptr(u("Fawusk alpha 0.1")))
		if hwnd != 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if hwnd == 0 {
		t.Fatal("GUI did not create the expected titled window")
	}
	defer post.Call(hwnd, 0x10, 0, 0)
	var title [128]uint16
	getText.Call(hwnd, uintptr(unsafe.Pointer(&title[0])), 128)
	if title[0] != 'F' {
		t.Fatal("missing window title")
	}
	// Wait for startup arguments to populate the list before invoking the primary action.
	getDlg := proc(user, "GetDlgItem")
	list, _, _ := getDlg.Call(hwnd, idFiles)
	for time.Now().Before(deadline) {
		n, _, _ := send.Call(list, 0x18b, 0, 0)
		if n == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	post.Call(hwnd, 0x111, idPack, 0)
	out := filepath.Join(root, "gui-smoke.faw")
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, e := os.Stat(out); e == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, e := os.Stat(out); e != nil {
		t.Fatal("GUI pack did not publish an archive", e)
	}
	dest := filepath.Join(root, "verified")
	if e := unpack(context.Background(), out, dest, nil); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(dest, "gui-smoke.txt"))
	if e != nil || string(b) != "GUI integration — Fawusk alpha 0.1" {
		t.Fatal("GUI round trip mismatch", e)
	}
	t.Log("Window title, initial source list, primary pack action and FAW round trip passed")
}
