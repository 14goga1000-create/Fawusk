package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestFourCoreBudget(t *testing.T) {
	for _, c := range []struct{ cpu, groups, want int }{{1, 100, 1}, {2, 100, 1}, {4, 100, 3}, {8, 100, 3}, {4, 1, 1}, {4, 2, 2}, {4, 0, 1}} {
		if got := codecWorkers(c.cpu, c.groups); got != c.want {
			t.Fatal(c, got)
		}
	}
}
func TestParallelGroupsCPU4(t *testing.T) {
	old := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(old)
	root := t.TempDir()
	src := filepath.Join(root, "large.bin")
	data := make([]byte, 41<<20)
	rand.Read(data)
	for _, span := range [][2]int{{8 << 20, 16 << 20}, {24 << 20, 32 << 20}, {40 << 20, 41 << 20}} {
		clear(data[span[0]:span[1]])
	}
	os.WriteFile(src, data, 0600)
	out := filepath.Join(root, "large.faw")
	if e := packFAW3(context.Background(), []string{src}, out, 1, nil); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(root, "result")
	if e := unpack(context.Background(), out, dest, nil); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(dest, "large.bin"))
	if e != nil || sha256.Sum256(b) != sha256.Sum256(data) {
		t.Fatal("parallel data mismatch", e)
	}
	cat, e := readCatalogue(context.Background(), out)
	if e != nil || len(cat.Groups) != 6 {
		t.Fatal("group count", e)
	}
	seen := map[byte]bool{}
	for _, g := range cat.Groups {
		seen[g.Codec] = true
	}
	if !seen[0] || !seen[1] {
		t.Fatal("mixed STORE/Zstandard not exercised")
	}
	t.Log("GOMAXPROCS=4 correctness test, mixed STORE/Zstandard; not a physical four-core benchmark")
}
func TestParallelGroupsCancellation(t *testing.T) {
	old := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(old)
	root := t.TempDir()
	src := filepath.Join(root, "large.bin")
	f, _ := os.Create(src)
	f.Truncate(80 << 20)
	f.Close()
	out := filepath.Join(root, "large.faw")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- packFAW3(ctx, []string{src}, out, 1, func(n int, s string) {
			if n > 0 && n < 100 {
				cancel()
			}
		})
	}()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancel ignored")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pipeline did not stop")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if e := packFAW3(context.Background(), []string{src}, out, 1, nil); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(root, "out")
	done = make(chan error, 1)
	go func() {
		done <- unpack(ctx, out, dest, func(n int, s string) {
			if n > 10 {
				cancel()
			}
		})
	}()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("reader cancel ignored")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reader leaked workers")
	}
	if _, e := os.Stat(dest); !os.IsNotExist(e) {
		t.Fatal("cancel published")
	}
}
func TestOwnedTempCleanup(t *testing.T) {
	root, e := createPreviewRoot()
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	os.Mkdir(filepath.Join(root, "content"), 0700)
	os.WriteFile(filepath.Join(root, "content", "notes.txt"), []byte("private"), 0600)
	if !processAlive(os.Getpid()) {
		t.Fatal("active process not detected")
	}
	cleanupOrphanPreviews()
	if _, e = os.Stat(root); e != nil {
		t.Fatal("active preview deleted")
	}
	if e = cleanupPreviewRoot(root); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("temp not removed")
	}
	if e = cleanupPreviewRoot(root); e != nil {
		t.Fatal("cleanup not idempotent", e)
	}
}
func TestCleanupLeavesForeignTempAlone(t *testing.T) {
	root, e := os.MkdirTemp("", "Fawusk-preview-foreign-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	file := filepath.Join(root, "keep.txt")
	os.WriteFile(file, []byte("user file"), 0600)
	if e = cleanupPreviewRoot(root); e == nil {
		t.Fatal("accepted foreign root")
	}
	cleanupOrphanPreviews()
	if _, e = os.Stat(file); e != nil {
		t.Fatal("deleted user temp", e)
	}
}
func TestCleanupOrphanRecovery(t *testing.T) {
	root, e := createPreviewRoot()
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	owner, e := previewOwnership(root)
	if e != nil {
		t.Fatal(e)
	}
	owner.PID = 0x7fffffff
	if processAlive(owner.PID) {
		t.Skip("test PID is active")
	}
	b := ownerBytes(owner)
	os.WriteFile(filepath.Join(root, previewMarker), b, 0600)
	os.WriteFile(filepath.Join(root, "remaining.txt"), []byte("orphan"), 0600)
	cleanupOrphanPreviews()
	if _, e = os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("orphan not recovered", e)
	}
}
func TestAlpha04SampleCompatibility(t *testing.T) {
	a, e := scanArchive(context.Background(), archiveFixture(t, "sample-faw4.faw"), nil)
	if e != nil || len(a) == 0 {
		t.Fatal("0.4 sample unreadable", e)
	}
}
