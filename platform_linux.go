package main

import (
	"errors"
	"os"
	"syscall"
)

func platformUnsafe(string, os.FileInfo) bool { return false }
func publishFile(from, to string) error {
	if e := os.Link(from, to); e != nil {
		return e
	}
	return os.Remove(from)
}
func publishDirectory(from, to string) error {
	if _, e := os.Lstat(to); e == nil {
		return errors.New(tr("Папка уже существует"))
	}
	return os.Rename(from, to)
}

func processAlive(pid int) bool { return syscall.Kill(pid, 0) != syscall.ESRCH }
