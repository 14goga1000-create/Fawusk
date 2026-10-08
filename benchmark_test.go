package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Synthetic microbenchmark, not a competitor comparison or peak-RAM measurement.
// Each iteration includes planning, compression, integrity hashing and fsync.
func BenchmarkFAWFast(b *testing.B) {
	for _, kind := range []string{"text", "noise"} {
		data := make([]byte, 16<<20)
		if kind == "text" {
			pattern := []byte("Fawusk repeated text for synthetic archive testing.\n")
			for i := 0; i < len(data); i += len(pattern) {
				copy(data[i:], pattern)
			}
		} else {
			if _, e := rand.Read(data); e != nil {
				b.Fatal(e)
			}
		}
		for _, version := range []int{1, 2, 3} {
			b.Run(fmt.Sprintf("%s/v%d", kind, version), func(b *testing.B) {
				root := b.TempDir()
				src := filepath.Join(root, "input.bin")
				if e := os.WriteFile(src, data, 0600); e != nil {
					b.Fatal(e)
				}
				packFn := packLegacy
				if version == 2 {
					packFn = func(ctx context.Context, inputs []string, output, format string, level int, progress report) error {
						return packFAW2(ctx, inputs, output, level, progress)
					}
				}
				if version == 3 {
					packFn = pack
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(data)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					out := filepath.Join(root, "test.faw")
					if e := packFn(context.Background(), []string{src}, out, "faw", 1, nil); e != nil {
						b.Fatal(e)
					}
					b.StopTimer()
					if i == 0 {
						dest := filepath.Join(root, "out")
						if e := unpack(context.Background(), out, dest, nil); e != nil {
							b.Fatal(e)
						}
						actual, e := os.ReadFile(filepath.Join(dest, "input.bin"))
						if e != nil || !bytes.Equal(actual, data) {
							b.Fatal("benchmark round trip mismatch", e)
						}
						st, _ := os.Stat(out)
						b.ReportMetric(float64(st.Size()), "archive-bytes")
					}
					if e := os.Remove(out); e != nil {
						b.Fatal(e)
					}
					b.StartTimer()
				}
			})
		}
	}
}
