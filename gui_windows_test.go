package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func waitWindow(t *testing.T, title string, pid int) uintptr {
	t.Helper()
	var found uintptr
	cb := syscall.NewCallback(func(h, l uintptr) uintptr {
		var owner uint32
		proc(user, "GetWindowThreadProcessId").Call(h, uintptr(unsafe.Pointer(&owner)))
		if int(owner) != pid {
			return 1
		}
		var caption [256]uint16
		proc(user, "GetWindowTextW").Call(h, uintptr(unsafe.Pointer(&caption[0])), 256)
		if syscall.UTF16ToString(caption[:]) == title {
			found = h
			return 0
		}
		return 1
	})
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		proc(user, "EnumWindows").Call(cb, 0)
		if found != 0 {
			return found
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("window not found", title, "pid", pid)
	return 0
}
func TestWindowsGUI(t *testing.T) {
	exe := os.Getenv("FAWUSK_GUI_EXE")
	if exe == "" {
		t.Skip("Set FAWUSK_GUI_EXE to run GUI integration")
	}
	root := t.TempDir()
	src := filepath.Join(root, "source")
	os.MkdirAll(filepath.Join(src, "subfolder"), 0700)
	os.WriteFile(filepath.Join(src, "hello.txt"), []byte("Fawusk alpha 0.3"), 0600)
	cmd := exec.Command(exe, src)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	hwnd := waitWindow(t, "Fawusk "+appVersion, cmd.Process.Pid)
	dlgItem := proc(user, "GetDlgItem")
	list, _, _ := dlgItem.Call(hwnd, idFiles)
	field, _, _ := dlgItem.Call(hwnd, idPath)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		list, _, _ = dlgItem.Call(hwnd, idFiles)
		field, _, _ = dlgItem.Call(hwnd, idPath)
		n, _, _ := send.Call(list, 0x1004, 0, 0)
		if n == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	n, _, _ := send.Call(list, 0x1004, 0, 0)
	if n != 2 {
		t.Fatal("directory content not shown", n)
	}
	header, _, _ := send.Call(list, 0x101f, 0, 0)
	columns, _, _ := send.Call(header, 0x1200, 0, 0)
	if columns != 3 {
		t.Fatal("table headers", columns)
	}
	send.Call(list, 0x100, 0x24, 0)
	post.Call(hwnd, 0x111, idFiles|(2<<16), list)
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && !strings.HasSuffix(remoteText(field), "subfolder") {
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.HasSuffix(remoteText(field), "subfolder") {
		t.Fatal("folder navigation failed", remoteText(field))
	}
	post.Call(hwnd, 0x111, idUp, 0)
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && remoteText(field) != src {
		time.Sleep(50 * time.Millisecond)
	}
	if remoteText(field) != src {
		t.Fatal("parent navigation failed", remoteText(field))
	}
	packButton, _, _ := dlgItem.Call(hwnd, idPack)
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ready, _, _ := proc(user, "IsWindowEnabled").Call(packButton)
		if ready != 0 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	post.Call(hwnd, 0x111, idPack, 0)
	dialog := waitWindow(t, "Создать архив", cmd.Process.Pid)
	out := filepath.Join(root, "result.faw")
	var edit uintptr
	cb := syscall.NewCallback(func(h, l uintptr) uintptr {
		var cls [64]uint16
		proc(user, "GetClassNameW").Call(h, uintptr(unsafe.Pointer(&cls[0])), 64)
		if syscall.UTF16ToString(cls[:]) == "Edit" && strings.Contains(remoteText(h), "source") {
			edit = h
		}
		return 1
	})
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && edit == 0 {
		proc(user, "EnumChildWindows").Call(dialog, cb, 0)
		time.Sleep(50 * time.Millisecond)
	}
	if edit == 0 {
		t.Fatal("save filename edit not found")
	}
	setText.Call(edit, ptr(u(out)))
	post.Call(dialog, 0x111, 1, 0)
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, e := os.Stat(out); e == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, e := os.Stat(out); e != nil {
		t.Fatal("GUI packing did not publish", e)
	}
	dest := filepath.Join(root, "verified")
	if e := unpack(context.Background(), out, dest, nil); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(dest, "source", "hello.txt"))
	if e != nil || string(b) != "Fawusk alpha 0.3" {
		t.Fatal("GUI round trip mismatch", e)
	}
	post.Call(hwnd, 0x10, 0, 0)
	t.Log("directory listing, child/parent navigation, modern save dialog and FAW 3 packing passed")
}

func remoteText(h uintptr) string {
	n, _, _ := send.Call(h, 0xe, 0, 0)
	b := make([]uint16, n+1)
	send.Call(h, 0xd, uintptr(len(b)), uintptr(unsafe.Pointer(&b[0])))
	return syscall.UTF16ToString(b)
}

func TestWindowsPlainFileView(t *testing.T) {
	exe := os.Getenv("FAWUSK_GUI_EXE")
	if exe == "" {
		t.Skip("Set FAWUSK_GUI_EXE")
	}
	root := t.TempDir()
	file := filepath.Join(root, "plain.txt")
	os.WriteFile(file, []byte("test"), 0600)
	cmd := exec.Command(exe, file)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	hwnd := waitWindow(t, "Fawusk "+appVersion, cmd.Process.Pid)
	var field, list uintptr
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		field, _, _ = proc(user, "GetDlgItem").Call(hwnd, idPath)
		list, _, _ = proc(user, "GetDlgItem").Call(hwnd, idFiles)
		if field != 0 && remoteText(field) == file {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if remoteText(field) != file {
		t.Fatal("one opened path not displayed")
	}
	visible, _, _ := proc(user, "IsWindowVisible").Call(list)
	n, _, _ := send.Call(list, 0x1004, 0, 0)
	if visible != 0 || n != 0 {
		t.Fatal("plain file must not display directory/contents")
	}
	post.Call(hwnd, 0x10, 0, 0)
}
func TestNativePathNormalization(t *testing.T) {
	for in, want := range map[string]string{`C:\folder\a.txt`: `\\?\C:\folder\a.txt`, `\\server\share\a.txt`: `\\?\UNC\server\share\a.txt`, `\\?\C:\folder\a.txt`: `\\?\C:\folder\a.txt`} {
		if got := nativePath(in); got != want {
			t.Fatalf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestWindowsLockedPreviewCleanup(t *testing.T) {
	root, e := createPreviewRoot()
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	p := filepath.Join(root, "held.txt")
	os.WriteFile(p, []byte("locked preview"), 0600)
	u, e := syscall.UTF16PtrFromString(nativePath(p))
	if e != nil {
		t.Fatal(e)
	}
	h, e := syscall.CreateFile(u, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.CloseHandle(h)
	e = cleanupPreviewRoot(root)
	if e == nil {
		t.Skip("environment does not enforce Windows delete sharing")
	}
	if _, e = previewOwnership(root); e != nil {
		t.Fatal("ownership lost while locked", e)
	}
	syscall.CloseHandle(h)
	if e = cleanupPreviewRoot(root); e != nil {
		t.Fatal("unlock cleanup failed", e)
	}
	if _, e = os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("root left behind")
	}
}

func TestWindowsEmptyTable(t *testing.T) {
	exe := os.Getenv("FAWUSK_GUI_EXE")
	if exe == "" {
		t.Skip("GUI opt-in")
	}
	root := t.TempDir()
	cmd := exec.Command(exe, root)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	hwnd := waitWindow(t, "Fawusk "+appVersion, cmd.Process.Pid)
	var list uintptr
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		list, _, _ = proc(user, "GetDlgItem").Call(hwnd, idFiles)
		ready, _, _ := proc(user, "IsWindowVisible").Call(list)
		if ready != 0 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	count, _, _ := send.Call(list, 0x1004, 0, 0)
	header, _, _ := send.Call(list, 0x101f, 0, 0)
	columns, _, _ := send.Call(header, 0x1200, 0, 0)
	if count != 0 || columns != 3 {
		t.Fatal("empty table wrong", count, columns)
	}
	post.Call(hwnd, 0x10, 0, 0)
}
