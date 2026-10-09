package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const previewMarker = ".fawusk-owned-preview"

type previewOwner struct {
	Version int
	PID     int
	Token   string
}

func createPreviewRoot() (string, error) {
	var token [16]byte
	if _, e := rand.Read(token[:]); e != nil {
		return "", e
	}
	id := hex.EncodeToString(token[:])
	root, e := os.MkdirTemp("", "Fawusk-preview-"+id+"-")
	if e != nil {
		return "", e
	}
	marker := ownerBytes(previewOwner{Version: 1, PID: os.Getpid(), Token: id})
	if e = os.WriteFile(filepath.Join(root, previewMarker), marker, 0600); e != nil {
		os.RemoveAll(root)
		return "", e
	}
	return root, nil
}
func previewOwnership(root string) (previewOwner, error) {
	var owner previewOwner
	root = filepath.Clean(root)
	if filepath.Dir(root) != filepath.Clean(os.TempDir()) {
		return owner, errors.New(tr("Чужая папка Temp"))
	}
	st, e := os.Lstat(root)
	if e != nil {
		return owner, e
	}
	if !st.IsDir() || isLink(st) || platformUnsafe(root, st) {
		return owner, errors.New(tr("Недопустимая папка просмотра"))
	}
	p := filepath.Join(root, previewMarker)
	st, e = os.Lstat(p)
	if e != nil {
		return owner, e
	}
	if !st.Mode().IsRegular() || st.Size() > 256 || isLink(st) || platformUnsafe(p, st) {
		return owner, errors.New(tr("Недопустимая метка владельца"))
	}
	data, e := os.ReadFile(p)
	if e != nil {
		return owner, e
	}
	parts := strings.Split(string(data), "\n")
	if len(parts) != 4 || parts[0] != "FAWUSK_PREVIEW_V1" || parts[3] != "" {
		return owner, errors.New(tr("Неверная метка владельца"))
	}
	owner.Version = 1
	owner.PID, e = strconv.Atoi(parts[1])
	if e != nil {
		return owner, e
	}
	owner.Token = parts[2]
	raw, e := hex.DecodeString(owner.Token)
	if e != nil || len(raw) != 16 || owner.Version != 1 || owner.PID <= 0 || !strings.HasPrefix(filepath.Base(root), "Fawusk-preview-"+owner.Token+"-") {
		return owner, errors.New(tr("Не принадлежит Fawusk"))
	}
	return owner, nil
}
func cleanupPreviewRoot(root string) error {
	if _, e := os.Lstat(root); os.IsNotExist(e) {
		return nil
	}
	owner, e := previewOwnership(root)
	if e != nil {
		return e
	}
	// Keep ownership marker until all other children have gone, so locked files
	// remain eligible for safe recovery by the helper or a later app launch.
	children, e := os.ReadDir(root)
	if e != nil {
		return e
	}
	var first error
	for _, a := range children {
		if a.Name() == previewMarker {
			continue
		}
		if e := os.RemoveAll(filepath.Join(root, a.Name())); e != nil && first == nil {
			first = e
		}
	}
	if first != nil {
		return first
	}
	if e = os.Remove(filepath.Join(root, previewMarker)); e != nil {
		return e
	}
	e = os.Remove(root)
	if e != nil {
		marker := ownerBytes(owner)
		os.WriteFile(filepath.Join(root, previewMarker), marker, 0600)
	}
	return e
}
func cleanupOrphanPreviews() {
	roots, _ := filepath.Glob(filepath.Join(os.TempDir(), "Fawusk-preview-*"))
	for i, root := range roots {
		if i >= 256 {
			break
		}
		owner, e := previewOwnership(root)
		if e == nil && !processAlive(owner.PID) {
			cleanupPreviewRoot(root)
		}
	}
}
func retryPreviewCleanup(roots []string, duration time.Duration) {
	deadline := time.Now().Add(duration)
	for len(roots) > 0 && time.Now().Before(deadline) {
		remaining := roots[:0]
		for _, root := range roots {
			owner, e := previewOwnership(root)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				continue
			}
			if processAlive(owner.PID) || cleanupPreviewRoot(root) != nil {
				remaining = append(remaining, root)
			}
		}
		roots = remaining
		if len(roots) > 0 {
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func ownerBytes(o previewOwner) []byte {
	return []byte("FAWUSK_PREVIEW_V1\n" + strconv.Itoa(o.PID) + "\n" + o.Token + "\n")
}
