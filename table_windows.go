package main

import (
	"path"
	"path/filepath"
	"syscall"
	"unsafe"
)

type nmHeader struct {
	Window, ID uintptr
	Code       uint32
}
type lvItem struct {
	Mask                 uint32
	Item, SubItem        int32
	State, StateMask     uint32
	Text                 uintptr
	TextMax, Image       int32
	Param                uintptr
	Indent, GroupID      int32
	Columns              uint32
	ColumnPtr, FormatPtr uintptr
	Group                int32
}
type lvColumn struct {
	Mask                                                uint32
	Format, Width                                       int32
	Text                                                uintptr
	TextMax, SubItem, Image, Order, Min, Default, Ideal int32
}
type lvDisplay struct {
	Header nmHeader
	Item   lvItem
}
type lvEvent struct {
	Header        nmHeader
	Item, SubItem int32
}

type headerItem struct {
	Mask            uint32
	Width           int32
	Text, Bitmap    uintptr
	TextMax, Format int32
	Param           uintptr
	Image, Order    int32
	Type            uint32
	Filter          uintptr
	State           uint32
}

var tableImages uintptr
var sortColumn int
var sortDescending bool

func tableName(a archiveEntry) string {
	if currentKind == "dir" {
		return filepath.Base(a.Name)
	}
	return path.Base(a.Name)
}
func tableCell(a archiveEntry, col int) string {
	switch col {
	case 1:
		return sizeText(a)
	case 2:
		return dateText(a)
	}
	return tableName(a)
}
func initTable() {
	control(idFiles, "SysListView32", "", 0x00800000|0x10000|0x1|0x4|0x8|0x400|0x1000)
	send.Call(controls[idFiles], 0x1036, 0, 0x10020)
	for i, title := range []string{"Имя", "Размер", "Дата изменения"} {
		col := lvColumn{Mask: 0xf, Width: scaled([]int{350, 110, 170}[i]), SubItem: int32(i), Text: ptr(u(title))}
		if i == 1 {
			col.Format = 1
		}
		send.Call(controls[idFiles], 0x1061, uintptr(i), uintptr(unsafe.Pointer(&col)))
	}
	tableImages, _, _ = proc(common, "ImageList_Create").Call(1, uintptr(scaled(32)), 0x21, 1, 1)
	send.Call(controls[idFiles], 0x1003, 1, tableImages)
}
func updateSortHeader() {
	h, _, _ := send.Call(controls[idFiles], 0x101f, 0, 0)
	for i := 0; i < 3; i++ {
		fmt := int32(0x4000)
		if i == 1 {
			fmt |= 1
		}
		if i == sortColumn {
			if sortDescending {
				fmt |= 0x200
			} else {
				fmt |= 0x400
			}
		}
		v := headerItem{Mask: 4, Format: fmt}
		send.Call(h, 0x120c, uintptr(i), uintptr(unsafe.Pointer(&v)))
	}
}
func resizeTable(width int) {
	send.Call(controls[idFiles], 0x101e, 0, uintptr(scaled(max(150, width-290))))
	send.Call(controls[idFiles], 0x101e, 1, uintptr(scaled(110)))
	send.Call(controls[idFiles], 0x101e, 2, uintptr(scaled(174)))
}
func refreshTable() {
	updateSortHeader()
	send.Call(controls[idFiles], 0xb, 0, 0)
	state := lvItem{StateMask: 3}
	send.Call(controls[idFiles], 0x102b, ^uintptr(0), uintptr(unsafe.Pointer(&state)))
	send.Call(controls[idFiles], 0x102f, uintptr(len(rows)), 0)
	send.Call(controls[idFiles], 0xb, 1, 0)
	proc(user, "InvalidateRect").Call(controls[idFiles], 0, 1)
}
func selectedTableRow() int {
	r, _, _ := send.Call(controls[idFiles], 0x100c, ^uintptr(0), 2)
	return int(int32(r))
}
func tableNotification(lp uintptr) uintptr {
	var h nmHeader
	kernel.NewProc("RtlMoveMemory").Call(uintptr(unsafe.Pointer(&h)), lp, unsafe.Sizeof(h))
	if h.ID != idFiles {
		return 0
	}
	switch h.Code {
	case 0xffffff4f:
		var d lvDisplay
		kernel.NewProc("RtlMoveMemory").Call(uintptr(unsafe.Pointer(&d)), lp, unsafe.Sizeof(d))
		if d.Item.Mask&1 != 0 && d.Item.Item >= 0 && int(d.Item.Item) < len(rows) && d.Item.Text != 0 && d.Item.TextMax > 0 {
			text := syscall.StringToUTF16(tableCell(rows[d.Item.Item], int(d.Item.SubItem)))
			if len(text) > int(d.Item.TextMax) {
				text = text[:d.Item.TextMax]
				text[len(text)-1] = 0
			}
			kernel.NewProc("RtlMoveMemory").Call(d.Item.Text, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)*2))
		}
		return 0
	case 0xfffffffd:
		var e lvEvent
		kernel.NewProc("RtlMoveMemory").Call(uintptr(unsafe.Pointer(&e)), lp, unsafe.Sizeof(e))
		if e.Item >= 0 && !busy {
			activateRow()
		}
		return 0
	case 0xffffff94:
		var e lvEvent
		kernel.NewProc("RtlMoveMemory").Call(uintptr(unsafe.Pointer(&e)), lp, unsafe.Sizeof(e))
		if !busy && e.SubItem >= 0 && e.SubItem < 3 {
			if sortColumn == int(e.SubItem) {
				sortDescending = !sortDescending
			} else {
				sortColumn = int(e.SubItem)
				sortDescending = false
			}
			orderRows(rows, sortColumn, sortDescending)
			refreshTable()
			status("Сортировка: " + []string{"имя", "размер", "дата изменения"}[sortColumn])
		}
		return 0
	}
	return 0
}
