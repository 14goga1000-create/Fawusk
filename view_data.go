package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func sizeText(a archiveEntry) string {
	if a.Directory || !a.SizeKnown {
		return "—"
	}
	return formatBytes(a.Size)
}
func formatBytes(n uint64) string {
	if n == 0 {
		return tr("0 КБ")
	}
	unit := uint64(1024)
	label := tr("КБ")
	if n >= 1<<30 {
		unit = 1 << 30
		label = tr("ГБ")
	} else if n >= 1<<20 {
		unit = 1 << 20
		label = tr("МБ")
	}
	if n < 11 {
		return tr("<0,01 КБ")
	}
	s := fmt.Sprintf("%.2f %s", float64(n)/float64(unit), label)
	if currentSettings().Language == "EN" {
		return s
	}
	return strings.ReplaceAll(s, ".", ",")
}
func dateText(a archiveEntry) string {
	if !a.DateKnown {
		return "—"
	}
	return time.Unix(a.Modified, 0).In(time.Local).Format("02.01.2006 15:04")
}

type viewTotals struct {
	Files, Directories int
	Bytes              uint64
}

func totals(a []archiveEntry) viewTotals {
	var t viewTotals
	for _, r := range a {
		if r.Directory {
			t.Directories++
			continue
		}
		t.Files++
		if r.SizeKnown {
			t.Bytes += r.Size
		}
	}
	return t
}
func orderRows(a []archiveEntry, column int, descending bool) {
	sort.SliceStable(a, func(i, j int) bool {
		x, y := a[i], a[j]
		if x.Directory != y.Directory {
			return x.Directory
		}
		cmp := 0
		switch column {
		case 1:
			if x.SizeKnown != y.SizeKnown {
				return x.SizeKnown
			}
			if x.Size < y.Size {
				cmp = -1
			} else if x.Size > y.Size {
				cmp = 1
			}
		case 2:
			if x.DateKnown != y.DateKnown {
				return x.DateKnown
			}
			if x.Modified < y.Modified {
				cmp = -1
			} else if x.Modified > y.Modified {
				cmp = 1
			}
		}
		if cmp == 0 {
			cmp = strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name))
		}
		if descending {
			return cmp > 0
		}
		return cmp < 0
	})
}
func readFolder(ctx context.Context, p string, progress report) ([]archiveEntry, error) {
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	list, e := f.ReadDir(maxFiles + 1)
	f.Close()
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(list) > maxFiles {
		return nil, fmt.Errorf(tr("Лимит отображения — %d элементов"), maxFiles)
	}
	rows := make([]archiveEntry, 0, len(list))
	for i, d := range list {
		if e = check(ctx); e != nil {
			return nil, e
		}
		a := archiveEntry{Name: filepath.Join(p, d.Name()), Directory: d.IsDir()}
		if st, e := d.Info(); e == nil {
			a.Directory = st.IsDir()
			a.Modified = st.ModTime().Unix()
			a.DateKnown = !st.ModTime().IsZero()
			if st.Mode().IsRegular() && st.Size() >= 0 {
				a.Size = uint64(st.Size())
				a.SizeKnown = true
			}
		}
		rows = append(rows, a)
		if progress != nil && i%128 == 0 {
			progress(i*99/max(1, len(list)), tr("Чтение метаданных папки…"))
		}
	}
	orderRows(rows, 0, false)
	return rows, nil
}

func countText(n int, one, few, many string) string {
	word := many
	if n%100 < 11 || n%100 > 14 {
		switch n % 10 {
		case 1:
			word = one
		case 2, 3, 4:
			word = few
		}
	}
	return fmt.Sprintf("%d %s", n, word)
}
