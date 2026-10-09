package main

import (
	"archive/zip"
	"bytes"
	"context"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (a *avRun) scanPE(name string, b []byte) {
	p, e := pe.NewFile(bytes.NewReader(b))
	if e != nil {
		a.incomplete("PE_PARSE_LIMITED", name, e.Error())
		return
	}
	defer p.Close()
	imports, e := p.ImportedSymbols()
	if e != nil {
		a.incomplete("PE_IMPORTS_LIMITED", name, e.Error())
		return
	}
	groups := map[string][]string{"process_injection": {"CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess"}, "download": {"URLDownloadToFileA", "URLDownloadToFileW", "WinHttpOpen", "InternetOpenA", "InternetOpenW", "WinInet"}, "shell": {"WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW"}, "persistence": {"RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW"}}
	for _, cat := range []string{"process_injection", "download", "shell", "persistence"} {
		var hit []string
		for _, needle := range groups[cat] {
			for _, symbol := range imports {
				base, _, _ := strings.Cut(symbol, ":")
				if strings.EqualFold(base, needle) {
					hit = append(hit, needle)
					break
				}
			}
		}
		if len(hit) > 0 {
			a.add("high", "RISKY_PE_IMPORTS", name, cat+": "+strings.Join(hit, ", "), "malware", 35)
		}
	}
}
func (a *avRun) scanNestedZIP(name string, b []byte, depth int) {
	if depth >= avDepthLimit {
		a.incomplete("NESTED_DEPTH_LIMIT", name, tr("Глубина вложенных контейнеров ограничена 3"))
		return
	}
	r := bytes.NewReader(b)
	if e := inspectDirectory(r, int64(len(b))); e != nil {
		a.incomplete("BAD_NESTED_ZIP", name, e.Error())
		return
	}
	z, e := zip.NewReader(r, int64(len(b)))
	if e != nil && !(e == zip.ErrInsecurePath && z != nil) {
		a.incomplete("BAD_NESTED_ZIP", name, e.Error())
		return
	}
	registerZipCodecs(z)
	records, _, e := zipRecords(a.ctx, z)
	if e != nil {
		a.incomplete("NESTED_ZIP_UNSUPPORTED", name, e.Error())
		return
	}
	for _, record := range records {
		if e = check(a.ctx); e != nil {
			a.incomplete("SCAN_CANCELLED", name, e.Error())
			return
		}
		m := record.entry
		if m.Directory {
			continue
		}
		rel := name + "!/" + m.Name
		ext := strings.ToLower(extensionOf(m.Name))
		if avPE[ext] || avScripts[ext] {
			a.add("high", "NESTED_EXECUTABLE", rel, tr("Приложение/скрипт во вложенном ZIP"), "malware", 40)
		}
		low := strings.ToLower(m.Name)
		if strings.Contains(low, "vbaproject.bin") || strings.Contains(low, "activex/") || strings.Contains(low, "embeddings/") {
			a.add("medium", "OFFICE_ACTIVE_CONTENT", rel, tr("Активное содержимое документа"), "review", 25)
		}
		if m.Size > avNestedLimit-a.nested {
			a.incomplete("NESTED_SIZE_LIMIT", rel, tr("Вложенный файл превышает общий лимит 1 ГиБ"))
			continue
		}
		w, e := a.fileInContainer(rel, depth+1, "zip")
		if e != nil {
			return
		}
		src, e := record.file.Open()
		if e != nil {
			a.incomplete("NESTED_READ_ERROR", rel, e.Error())
			return
		}
		n, e := io.CopyBuffer(w, io.LimitReader(src, int64(m.Size)+1), make([]byte, 128<<10))
		src.Close()
		w.Close()
		if e != nil || uint64(n) != m.Size {
			a.incomplete("NESTED_CRC_OR_SIZE_ERROR", rel, fmt.Sprint(e))
			return
		}

	}
}
func extensionOf(p string) string {
	i := strings.LastIndex(p, ".")
	j := strings.LastIndex(p, "/")
	if i > j {
		return p[i:]
	}
	return ""
}

// Java .class modified-UTF8 constants: bounds checked; no class loading.
func avJavaStrings(b []byte) ([]byte, bool) {
	if len(b) < 10 || !bytes.Equal(b[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) {
		return nil, false
	}
	count := int(binary.BigEndian.Uint16(b[8:10]))
	pos := 10
	var out []byte
	for i := 1; i < count; i++ {
		if pos >= len(b) {
			return nil, false
		}
		tag := b[pos]
		pos++
		n := 0
		switch tag {
		case 1:
			if pos+2 > len(b) {
				return nil, false
			}
			n = int(binary.BigEndian.Uint16(b[pos : pos+2]))
			pos += 2
			if pos+n > len(b) {
				return nil, false
			}
			out = append(out, b[pos:pos+n]...)
			out = append(out, ' ')
		case 3, 4:
			n = 4
		case 5, 6:
			n = 8
			i++
		case 7, 8, 16, 19, 20:
			n = 2
		case 9, 10, 11, 12, 17, 18:
			n = 4
		case 15:
			n = 3
		default:
			return nil, false
		}
		if pos+n > len(b) {
			return nil, false
		}
		pos += n
	}
	return out, true
}

func (a *avRun) scanNestedFAW(name string, b []byte, depth int) {
	if depth >= avDepthLimit {
		a.incomplete("NESTED_DEPTH_LIMIT", name, tr("Глубина вложенных контейнеров ограничена 3"))
		return
	}
	root, e := createPreviewRoot()
	if e != nil {
		a.incomplete("NESTED_TEMP_ERROR", name, e.Error())
		return
	}
	defer cleanupPreviewRoot(root)
	// Only the inert compressed container is written. Entries remain streams.
	p := filepath.Join(root, "container.faw")
	if e = os.WriteFile(p, b, 0600); e != nil {
		a.incomplete("NESTED_TEMP_ERROR", name, e.Error())
		return
	}
	reader, e := NewFawReader(p)
	if e == nil {
		e = reader.ReadAll(context.WithValue(a.ctx, avMetadataVisitorKey{}, entryVisitor(func(entry archiveEntry) { a.nameSignals(name + "!/" + entry.Name) })), func(entry archiveEntry) (io.WriteCloser, error) {
			if entry.Size > avNestedLimit-a.nested {
				return nil, fmt.Errorf("%s", tr("Превышен лимит вложенных данных"))
			}
			return a.fileInContainer(name+"!/"+entry.Name, depth+1, "faw")
		}, nil)
	}
	if e != nil {
		a.incomplete("NESTED_FAW_ERROR", name, e.Error())
	}
}
