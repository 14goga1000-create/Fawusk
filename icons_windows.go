package main

// Small vector pictograms painted with Win32 GDI; no emoji fonts, shell icon
// handlers, thumbnails, disk lookup, or per-file executable loading.
import (
	"path"
	"path/filepath"
	"strings"
	"unsafe"
)

type drawItem struct {
	Type, ID, Item, Action, State uint32
	Window, DC                    uintptr
	Bounds                        rect
	Data                          uintptr
}
type measureItem struct {
	Type, ID, Item, Width, Height uint32
	Data                          uintptr
}

var iconBrushes map[uint32]uintptr

func iconBrush(c uint32) uintptr {
	if iconBrushes == nil {
		iconBrushes = map[uint32]uintptr{}
	}
	if b := iconBrushes[c]; b != 0 {
		return b
	}
	b, _, _ := proc(gdi, "CreateSolidBrush").Call(uintptr(c))
	iconBrushes[c] = b
	return b
}
func paintBox(dc uintptr, x, y, w, h int32, c uint32) {
	r := rect{x, y, x + w, y + h}
	proc(user, "FillRect").Call(dc, uintptr(unsafe.Pointer(&r)), iconBrush(c))
}
func iconKind(a archiveEntry) string {
	if a.Directory {
		return "folder"
	}
	ext := strings.ToLower(path.Ext(a.Name))
	switch ext {
	case ".faw", ".zip", ".rar", ".7z", ".tar", ".gz":
		return "archive"
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff":
		return "image"
	case ".mp4", ".mkv", ".webm", ".avi", ".mov", ".m4v":
		return "video"
	case ".mp3", ".wav", ".flac", ".ogg":
		return "audio"
	case ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js":
		return "application"
	}
	return "file"
}
func drawPictogram(dc uintptr, x, y int32, kind string) {
	s := func(n int) int32 { return scaled(n) }
	if kind == "folder" {
		paintBox(dc, x, y+s(4), s(20), s(14), 0x0045B7E9)
		paintBox(dc, x+s(1), y+s(1), s(8), s(5), 0x0045B7E9)
		paintBox(dc, x, y+s(7), s(20), s(11), 0x007AD2F8)
		return
	}
	if kind == "archive" {
		paintBox(dc, x+s(1), y, s(18), s(20), 0x00DE8327)
		paintBox(dc, x+s(8), y, s(4), s(20), 0x00B46719)
		for i := 1; i < 18; i += 4 {
			paintBox(dc, x+s(9), y+s(i), s(2), s(2), 0x00FFFFFF)
		}
		return
	}
	paintBox(dc, x+s(3), y, s(15), s(20), 0x00C4BEB7)
	paintBox(dc, x+s(4), y+s(1), s(13), s(18), 0x00FFFFFF)
	color := uint32(0x00BA8E5A)
	switch kind {
	case "image":
		color = 0x0071A146
	case "video":
		color = 0x00AD728F
	case "audio":
		color = 0x00C89C4F
	case "application":
		color = 0x005864E5
	}
	paintBox(dc, x+s(3), y+s(13), s(15), s(7), color)
	for i := 4; i <= 10; i += 3 {
		paintBox(dc, x+s(6), y+s(i), s(8), s(1), 0x00C4BEB7)
	}
}
func drawFileRow(lp uintptr) uintptr {
	var a drawItem
	kernel.NewProc("RtlMoveMemory").Call(uintptr(unsafe.Pointer(&a)), lp, unsafe.Sizeof(a))
	if int(a.ID) != idFiles {
		return 0
	}
	if a.Item == ^uint32(0) {
		return 1
	}
	bgColor := uint32(0x00FFFFFF)
	textColor := uint32(0x002B2C2C)
	if a.State&1 != 0 {
		bgColor = 0x00FCEBDD
	}
	paintBox(a.DC, a.Bounds.Left, a.Bounds.Top, a.Bounds.Right-a.Bounds.Left, a.Bounds.Bottom-a.Bounds.Top, bgColor)
	if int(a.Item) >= len(rows) {
		return 1
	}
	entry := rows[a.Item]
	x := a.Bounds.Left + scaled(8)
	y := a.Bounds.Top + (a.Bounds.Bottom-a.Bounds.Top-scaled(20))/2
	drawPictogram(a.DC, x, y, iconKind(entry))
	proc(gdi, "SetBkMode").Call(a.DC, 1)
	proc(gdi, "SetTextColor").Call(a.DC, uintptr(textColor))
	old, _, _ := proc(gdi, "SelectObject").Call(a.DC, font)
	defer proc(gdi, "SelectObject").Call(a.DC, old)
	r := a.Bounds
	r.Left = x + scaled(32)
	r.Right -= scaled(8)
	caption := path.Base(entry.Name)
	if currentKind == "dir" {
		caption = filepath.Base(entry.Name)
	}
	proc(user, "DrawTextW").Call(a.DC, ptr(u(caption)), ^uintptr(0), uintptr(unsafe.Pointer(&r)), 0x24|0x800|0x8000)
	if a.State&0x10 != 0 {
		proc(user, "DrawFocusRect").Call(a.DC, uintptr(unsafe.Pointer(&a.Bounds)))
	}
	return 1
}
func destroyIconBrushes() {
	for _, b := range iconBrushes {
		proc(gdi, "DeleteObject").Call(b)
	}
}
