package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var moveFile = kernel.NewProc("MoveFileW")

func platformUnsafe(path string, _ os.FileInfo) bool {
	p, e := syscall.UTF16PtrFromString(nativePath(path))
	if e != nil {
		return true
	}
	a, e := syscall.GetFileAttributes(p)
	return e != nil || a&0x400 != 0
}
func publishFile(from, to string) error {
	a, e := syscall.UTF16PtrFromString(nativePath(from))
	if e != nil {
		return e
	}
	b, e := syscall.UTF16PtrFromString(nativePath(to))
	if e != nil {
		return e
	}
	r, _, err := moveFile.Call(uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(b)))
	if r == 0 {
		return err
	}
	return nil
}
func publishDirectory(from, to string) error { return publishFile(from, to) }

func nativePath(p string) string {
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	a, e := filepath.Abs(p)
	if e != nil {
		return p
	}
	a = filepath.Clean(a)
	if strings.HasPrefix(a, `\\`) {
		return `\\?\UNC\` + strings.TrimPrefix(a, `\\`)
	}
	return `\\?\` + a
}
