package main

// Small vector pictograms painted with Win32 GDI; no emoji fonts, shell icon
// handlers, thumbnails, disk lookup, or per-file executable loading.
import (
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
	colors := map[string]uint32{"video": 0x00AD728F, "audio": 0x00C89C4F, "image": 0x0071A146, "pdf": 0x005864C5, "application": 0x005B6778, "code": 0x00C08863, "spreadsheet": 0x0077A046, "presentation": 0x005D8CD2, "document": 0x00DE8327, "text": 0x00BA8E5A, "font": 0x00A77989, "data": 0x009B8C71, "file": 0x00A8A09A}
	color := colors[kind]
	if color == 0 {
		color = colors["file"]
	}
	if kind == "video" {
		paintBox(dc, x, y+s(2), s(20), s(16), color)
		paintBox(dc, x+s(3), y+s(4), s(14), s(12), 0x00FFFFFF)
		paintTriangle(dc, []point{{x + s(8), y + s(6)}, {x + s(8), y + s(14)}, {x + s(14), y + s(10)}}, color)
		for _, xx := range []int{1, 18} {
			for yy := 4; yy < 16; yy += 4 {
				paintBox(dc, x+s(xx), y+s(yy), s(1), s(2), 0x00FFFFFF)
			}
		}
		return
	}
	if kind == "audio" {
		paintBox(dc, x+s(8), y+s(3), s(2), s(13), color)
		paintBox(dc, x+s(15), y+s(1), s(2), s(13), color)
		paintBox(dc, x+s(8), y+s(2), s(9), s(3), color)
		paintBox(dc, x+s(3), y+s(14), s(7), s(4), color)
		paintBox(dc, x+s(10), y+s(12), s(7), s(4), color)
		return
	}
	if kind == "image" {
		paintBox(dc, x, y+s(2), s(20), s(16), color)
		paintBox(dc, x+s(2), y+s(4), s(16), s(12), 0x00FFFFFF)
		paintBox(dc, x+s(4), y+s(5), s(3), s(3), 0x0045B7E9)
		paintTriangle(dc, []point{{x + s(3), y + s(15)}, {x + s(9), y + s(9)}, {x + s(15), y + s(15)}}, color)
		paintTriangle(dc, []point{{x + s(10), y + s(15)}, {x + s(14), y + s(11)}, {x + s(18), y + s(15)}}, 0x009BC28C)
		return
	}
	if kind == "application" {
		paintBox(dc, x, y+s(2), s(20), s(16), color)
		paintBox(dc, x+s(2), y+s(7), s(16), s(9), 0x00FFFFFF)
		for xx := 3; xx < 16; xx += 5 {
			paintBox(dc, x+s(xx), y+s(4), s(3), s(1), 0x00FFFFFF)
		}
		return
	}
	paintBox(dc, x+s(3), y, s(15), s(20), 0x00C4BEB7)
	paintBox(dc, x+s(4), y+s(1), s(13), s(18), 0x00FFFFFF)
	switch kind {
	case "spreadsheet":
		for yy := 4; yy <= 16; yy += 4 {
			paintBox(dc, x+s(5), y+s(yy), s(11), s(1), color)
		}
		for xx := 5; xx <= 15; xx += 5 {
			paintBox(dc, x+s(xx), y+s(4), s(1), s(13), color)
		}
	case "presentation":
		paintBox(dc, x+s(5), y+s(3), s(11), s(10), color)
		paintBox(dc, x+s(7), y+s(6), s(7), s(5), 0x00FFFFFF)
		paintBox(dc, x+s(10), y+s(13), s(1), s(4), color)
		paintBox(dc, x+s(7), y+s(17), s(7), s(1), color)
	case "code":
		paintTriangle(dc, []point{{x + s(5), y + s(10)}, {x + s(9), y + s(5)}, {x + s(9), y + s(15)}}, color)
		paintTriangle(dc, []point{{x + s(16), y + s(10)}, {x + s(12), y + s(5)}, {x + s(12), y + s(15)}}, color)
	case "data":
		for yy := 4; yy < 17; yy += 4 {
			paintBox(dc, x+s(6), y+s(yy), s(9), s(2), color)
		}
	case "pdf":
		paintBox(dc, x+s(3), y+s(12), s(15), s(8), color)
		paintTriangle(dc, []point{{x + s(7), y + s(10)}, {x + s(11), y + s(3)}, {x + s(14), y + s(10)}}, color)
	case "font":
		paintTriangle(dc, []point{{x + s(5), y + s(15)}, {x + s(11), y + s(4)}, {x + s(16), y + s(15)}}, color)
		paintTriangle(dc, []point{{x + s(8), y + s(15)}, {x + s(11), y + s(8)}, {x + s(13), y + s(15)}}, 0x00FFFFFF)
	default:
		paintBox(dc, x+s(3), y+s(15), s(15), s(5), color)
		for yy := 4; yy <= 12; yy += 3 {
			paintBox(dc, x+s(6), y+s(yy), s(8), s(1), color)
		}
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
	if c, ok := avEntryColor(entry.Name); ok {
		textColor = c
	}
	x := a.Bounds.Left + scaled(8)
	y := a.Bounds.Top + (a.Bounds.Bottom-a.Bounds.Top-scaled(20))/2
	drawPictogram(a.DC, x, y, iconKind(entry))
	proc(gdi, "SetBkMode").Call(a.DC, 1)
	proc(gdi, "SetTextColor").Call(a.DC, uintptr(textColor))
	old, _, _ := proc(gdi, "SelectObject").Call(a.DC, font)
	defer proc(gdi, "SelectObject").Call(a.DC, old)

	left := a.Bounds.Left
	for col := 0; col < 3; col++ {
		width, _, _ := send.Call(controls[idFiles], 0x101d, uintptr(col), 0)
		r := a.Bounds
		r.Left = left + scaled(8)
		r.Right = left + int32(width) - scaled(8)
		flags := uintptr(0x24 | 0x800 | 0x8000)
		if col == 0 {
			r.Left = x + scaled(32)
		}
		if col == 1 {
			flags |= 2
		}
		proc(user, "DrawTextW").Call(a.DC, ptr(u(tableCell(entry, col))), ^uintptr(0), uintptr(unsafe.Pointer(&r)), flags)
		left += int32(width)
	}
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
