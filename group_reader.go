package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"runtime"
	"sync"
)

// Reserve one logical processor for file I/O and hashing; three codec workers
// on a four-core CPU. Honour the Go/container CPU limit, and don't start idle
// workers for small archives. This doesn't change the FAW 3 wire format.
func codecWorkers(cpu, groups int) int {
	if groups < 1 {
		return 1
	}
	n := cpu - 1
	if n < 1 {
		n = 1
	}
	if n > 3 {
		n = 3
	}
	if n > groups {
		n = groups
	}
	return n
}
func archiveWorkers(total uint64) int {
	return resourceWorkers(runtime.GOMAXPROCS(0), int((total+faw3Window-1)/faw3Window), currentSettings())
}

type groupReadResult struct {
	data []byte
	err  error
}
type groupReadSlot struct {
	jobs    chan int
	results chan groupReadResult
}
type groupReader struct {
	slots          []groupReadSlot
	wg             sync.WaitGroup
	last, previous int
}

func newGroupReader(ctx context.Context, f *os.File, groups []groupDesc, first, last int) *groupReader {
	n := resourceWorkers(runtime.GOMAXPROCS(0), last-first, currentSettings())
	r := &groupReader{last: last, previous: -1}
	if first == last {
		return r
	}
	r.slots = make([]groupReadSlot, n)
	for i := range r.slots {
		s := groupReadSlot{jobs: make(chan int, 1), results: make(chan groupReadResult, 1)}
		r.slots[i] = s
		r.wg.Add(1)
		go func(s groupReadSlot) {
			defer r.wg.Done()
			dec, initErr := newGroupDecoder()
			if dec != nil {
				defer dec.Close()
			}
			stored := make([]byte, 0, faw3Window)
			decoded := make([]byte, 0, faw3Window)
			for gi := range s.jobs {
				result := groupReadResult{}
				if e := check(ctx); e != nil {
					result.err = e
				} else if initErr != nil {
					result.err = initErr
				} else {
					g := groups[gi]
					stored = stored[:int(g.Stored)]
					if _, e := f.ReadAt(stored, int64(g.Offset)); e != nil {
						result.err = e
					} else if sha256.Sum256(stored) != g.Hash {
						result.err = errors.New(tr("Повреждены данные группы FAW"))
					} else if g.Codec == 0 {
						result.data = stored
					} else {
						var e error
						decoded, e = dec.DecodeAll(stored, decoded[:0])
						result.data = decoded
						result.err = e
					}
					if result.err == nil && uint64(len(result.data)) != g.Raw {
						result.err = errors.New(tr("Неверный размер группы"))
					}
				}
				s.results <- result
			}
		}(s)
	}
	// Use absolute modulo consistently for queues, including a selected file
	// beginning in the middle of the archive.
	for gi := first; gi < first+n; gi++ {
		r.slots[gi%n].jobs <- gi
	}
	return r
}
func (r *groupReader) load(gi int) ([]byte, error) {
	n := len(r.slots)
	if n == 0 {
		return nil, errors.New(tr("Нет группы"))
	}
	if r.previous >= 0 {
		next := r.previous + n
		if next < r.last {
			r.slots[r.previous%n].jobs <- next
		}
	}
	result := <-r.slots[gi%n].results
	r.previous = gi
	return result.data, result.err
}
func (r *groupReader) close() {
	for _, s := range r.slots {
		close(s.jobs)
	}
	r.wg.Wait()
}
