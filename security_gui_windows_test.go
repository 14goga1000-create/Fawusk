package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindowsCustomAVStatuses(t *testing.T) {
	exe := os.Getenv("FAWUSK_GUI_EXE")
	if exe == "" {
		t.Skip("GUI opt-in")
	}
	for _, row := range []struct {
		name    string
		content []byte
		label   string
		allowed bool
	}{{"clear", []byte("ordinary document"), "Угрозы не обнаружены", true}, {"suspicious", []byte("powershell encodedcommand"), "Есть подозрительные файлы", false}, {"test", avEICAR(t), "Обнаружена тестовая сигнатура", false}} {
		t.Run(row.name, func(t *testing.T) {
			root := t.TempDir()
			src := filepath.Join(root, "notes.txt")
			os.WriteFile(src, row.content, 0600)
			p := filepath.Join(root, "sample.faw")
			if e := pack(context.Background(), []string{src}, p, "faw3", 1, nil); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(exe, p)
			if e := cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer cmd.Wait()
			defer cmd.Process.Kill()
			hwnd := waitWindow(t, "Fawusk "+appVersion, cmd.Process.Pid)
			label, _, _ := proc(user, "GetDlgItem").Call(hwnd, idSecurity)
			unpack, _, _ := proc(user, "GetDlgItem").Call(hwnd, idUnpack)
			deadline := time.Now().Add(12 * time.Second)
			var caption string
			for time.Now().Before(deadline) {
				label, _, _ = proc(user, "GetDlgItem").Call(hwnd, idSecurity)
				unpack, _, _ = proc(user, "GetDlgItem").Call(hwnd, idUnpack)
				caption = remoteText(label)
				enabled, _, _ := proc(user, "IsWindowEnabled").Call(unpack)
				list, _, _ := proc(user, "GetDlgItem").Call(hwnd, idFiles)
				n, _, _ := send.Call(list, 0x1004, 0, 0)
				if strings.Contains(caption, row.label) && (enabled != 0) == row.allowed && n == 1 {
					break
				}
				time.Sleep(40 * time.Millisecond)
			}
			if !strings.Contains(caption, row.label) {
				t.Fatal("wrong security label", caption)
			}
			enabled, _, _ := proc(user, "IsWindowEnabled").Call(unpack)
			if (enabled != 0) != row.allowed {
				t.Fatal("wrong extraction permission", enabled, caption)
			}
			list, _, _ := proc(user, "GetDlgItem").Call(hwnd, idFiles)
			n, _, _ := send.Call(list, 0x1004, 0, 0)
			if n != 1 {
				t.Fatal("blocked archive listing missing", n)
			}
			post.Call(hwnd, 0x10, 0, 0)
		})
	}
}
