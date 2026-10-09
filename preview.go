package main

import (
	"archive/zip"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

type selectionKey struct{}

func selectedName(ctx context.Context) string { s, _ := ctx.Value(selectionKey{}).(string); return s }

const previewLimit = 1 << 30

var mediaTypes = map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true, ".webp": true, ".tif": true, ".tiff": true, ".mp4": true, ".webm": true, ".mkv": true, ".avi": true, ".mov": true, ".m4v": true, ".mp3": true, ".wav": true, ".flac": true, ".ogg": true, ".txt": true, ".md": true, ".csv": true, ".pdf": true, ".docx": true, ".xlsx": true, ".pptx": true}
var blockedTypes = map[string]bool{"exe": true, "com": true, "dll": true, "scr": true, "msi": true, "msp": true, "bat": true, "cmd": true, "ps1": true, "psm1": true, "vbs": true, "vbe": true, "js": true, "jse": true, "wsf": true, "wsh": true, "hta": true, "lnk": true, "url": true, "reg": true, "cpl": true, "chm": true, "jar": true, "py": true, "sh": true, "docm": true, "xlsm": true, "pptm": true, "iso": true}

func previewAllowed(name string) error {
	if _, e := safeName(name); e != nil {
		return e
	}
	base := filepath.Base(strings.ReplaceAll(name, "/", string(filepath.Separator)))
	for _, r := range base {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return errors.New("Неоднозначное имя файла: просмотр запрещён")
		}
	}
	if !mediaTypes[strings.ToLower(filepath.Ext(base))] {
		return errors.New("Этот тип нельзя открыть из архива. Сначала полностью распакуйте архив и проверьте файл")
	}
	parts := strings.Split(strings.ToLower(base), ".")
	for _, p := range parts[1:] {
		if blockedTypes[p] {
			return errors.New("Исполняемые файлы, скрипты и замаскированные расширения запрещены для просмотра")
		}
	}
	return nil
}
func validatePreview(p string) error {
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		f.Close()
		return errors.New("Просмотр доступен только для обычного файла")
	}
	var head [512]byte
	n, readErr := f.Read(head[:])
	if readErr != nil && readErr != io.EOF {
		f.Close()
		return readErr
	}
	f.Close()
	b := head[:n]
	s := string(b)
	if strings.HasPrefix(s, "MZ") || strings.HasPrefix(s, "\x7fELF") || strings.HasPrefix(strings.TrimSpace(s), "#!") || strings.HasPrefix(s, "\xfe\xed\xfa") || strings.HasPrefix(s, "\xcf\xfa\xed\xfe") {
		return errors.New("Обнаружена сигнатура приложения или скрипта: открытие запрещено")
	}
	ext := strings.ToLower(filepath.Ext(p))
	match := true
	switch ext {
	case ".png":
		match = strings.HasPrefix(s, "\x89PNG\r\n\x1a\n")
	case ".jpg", ".jpeg":
		match = n >= 3 && b[0] == 255 && b[1] == 216 && b[2] == 255
	case ".gif":
		match = strings.HasPrefix(s, "GIF8")
	case ".pdf":
		match = strings.HasPrefix(s, "%PDF-")
	case ".bmp":
		match = strings.HasPrefix(s, "BM")
	case ".webp":
		match = n >= 12 && s[:4] == "RIFF" && s[8:12] == "WEBP"
	case ".txt", ".md", ".csv":
		match = !strings.Contains(s, "\x00")
	case ".docx", ".xlsx", ".pptx":
		return validateOffice(p)
	}
	if !match {
		return errors.New("Содержимое не соответствует безопасному типу файла")
	}
	return nil
}
func validateOffice(p string) error {
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return e
	}
	e = inspectDirectory(f, st.Size())
	f.Close()
	if e != nil {
		return e
	}
	z, e := zip.OpenReader(p)
	if e != nil {
		return e
	}
	defer z.Close()
	if len(z.File) > 10000 {
		return errors.New("Слишком сложный документ")
	}
	hasTypes := false
	for _, f := range z.File {
		name := strings.ReplaceAll(strings.ToLower(f.Name), "\\", "/")
		if strings.Contains(name, "vba") || strings.Contains(name, "activex") || strings.Contains(name, "embeddings/") || strings.Contains(name, "customui/") {
			return errors.New("Документ с макросами или активным содержимым: просмотр запрещён")
		}
		if name == "[content_types].xml" || strings.HasSuffix(name, ".rels") {
			if name == "[content_types].xml" {
				hasTypes = true
			}
			if f.UncompressedSize64 > 1<<20 {
				return errors.New("Неверный документ")
			}
			r, e := f.Open()
			if e != nil {
				return e
			}
			b, e := io.ReadAll(io.LimitReader(r, (1<<20)+1))
			r.Close()
			if e != nil {
				return e
			}
			xd := xml.NewDecoder(strings.NewReader(string(b)))
			for {
				token, e := xd.Token()
				if e == io.EOF {
					break
				}
				if e != nil {
					return errors.New("Повреждён XML документа")
				}
				if start, ok := token.(xml.StartElement); ok {
					for _, a := range start.Attr {
						if strings.EqualFold(a.Name.Local, "TargetMode") && strings.EqualFold(a.Value, "External") {
							return errors.New("Документ с внешними связями: просмотр запрещён")
						}
						if strings.EqualFold(a.Name.Local, "ContentType") && strings.Contains(strings.ToLower(a.Value), "macroenabled") {
							return errors.New("Макросодержащий документ запрещён")
						}
					}
				}
			}
			if strings.Contains(strings.ToLower(string(b)), "macroenabled") {
				return errors.New("Макросодержащий документ запрещён")
			}
		}
	}
	if !hasTypes {
		return errors.New("Неверный Office-документ")
	}
	return nil
}

// Only the selected file is written; legacy solid formats still have to decode
// the full stream to authenticate it. The caller owns and removes tempRoot.
func extractSelected(ctx context.Context, archive, name, tempRoot string, progress report) (string, error) {
	if e := previewAllowed(name); e != nil {
		return "", e
	}
	var e error
	if indexed(archive) {
		cat, e := readCatalogue(ctx, archive)
		if e != nil {
			return "", e
		}
		found := false
		for _, a := range cat.Entries {
			if a.Name == name && !a.Directory {
				if a.Size > previewLimit {
					return "", errors.New("Просмотр ограничен 1 ГиБ")
				}
				found = true
			}
		}
		if !found {
			return "", errors.New("Файл отсутствует")
		}
	}
	ctx = context.WithValue(ctx, selectionKey{}, name)
	dest := filepath.Join(tempRoot, "content")
	if e = unpack(ctx, archive, dest, progress); e != nil {
		return "", e
	}
	p := filepath.Join(dest, filepath.FromSlash(name))
	if e = validatePreview(p); e != nil {
		return "", e
	}
	return p, nil
}
