package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var user = syscall.NewLazyDLL("user32.dll")
var gdi = syscall.NewLazyDLL("gdi32.dll")
var comdlg = syscall.NewLazyDLL("comdlg32.dll")
var shell = syscall.NewLazyDLL("shell32.dll")
var ole = syscall.NewLazyDLL("ole32.dll")
var common = syscall.NewLazyDLL("comctl32.dll")

func proc(d *syscall.LazyDLL, n string) *syscall.LazyProc { return d.NewProc(n) }

var createWindow = proc(user, "CreateWindowExW")
var send = proc(user, "SendMessageW")
var post = proc(user, "PostMessageW")
var defWindow = proc(user, "DefWindowProcW")
var setText = proc(user, "SetWindowTextW")
var enable = proc(user, "EnableWindow")
var getText = proc(user, "GetWindowTextW")
var getLen = proc(user, "GetWindowTextLengthW")
var mainWindow uintptr
var controls = map[int]uintptr{}
var files []string
var busy bool
var cancelWork context.CancelFunc
var font, headingFont, smallFont uintptr
var scale = 1.0
var instance uintptr
var bg, white uintptr
var resultPath string
var mu sync.Mutex
var statusUpdates []uiUpdate
var pendingProgress *uiUpdate

type uiUpdate struct {
	percent int
	text    string
	done    bool
	err     error
	path    string
}
type point struct{ X, Y int32 }
type msg struct {
	Hwnd           uintptr
	Message        uint32
	Wparam, Lparam uintptr
	Time           uint32
	Pt             point
	Private        uint32
}
type rect struct{ Left, Top, Right, Bottom int32 }
type wc struct {
	Size, Style                        uint32
	WndProc                            uintptr
	ClsExtra, WndExtra                 int32
	Instance, Icon, Cursor, Background uintptr
	Menu, Class                        *uint16
	IconSmall                          uintptr
}
type openFilename struct {
	Size                      uint32
	Owner, Instance           uintptr
	Filter, CustomFilter      *uint16
	MaxCustom, FilterIndex    uint32
	File                      *uint16
	MaxFile                   uint32
	FileTitle                 *uint16
	MaxFileTitle              uint32
	InitialDir, Title         *uint16
	Flags                     uint32
	FileOffset, FileExtension uint16
	DefExt                    *uint16
	CustData, Hook            uintptr
	Template                  *uint16
	Reserved                  uintptr
	Reserved2, FlagsEx        uint32
}
type browseInfo struct {
	Owner, Root      uintptr
	Display, Title   *uint16
	Flags            uint32
	Callback, Lparam uintptr
	Image            int32
}

const (
	idFiles       = 101
	idAdd         = 102
	idFolder      = 103
	idRemove      = 104
	idClear       = 105
	idFormat      = 106
	idLevel       = 107
	idOutput      = 108
	idBrowse      = 109
	idPack        = 110
	idUnpack      = 111
	idCancel      = 112
	idProgress    = 113
	idStatus      = 114
	idOpen        = 115
	idTitle       = 116
	idSubtitle    = 117
	idFileLabel   = 118
	idFormatLabel = 119
	idLevelLabel  = 120
	idOutputLabel = 121
	idNote        = 122
	wmUpdate      = 0x8001
)

func u(s string) *uint16    { p, _ := syscall.UTF16PtrFromString(s); return p }
func ptr(p *uint16) uintptr { return uintptr(unsafe.Pointer(p)) }
func scaled(n int) int32    { return int32(float64(n) * scale) }
func notify(n int, text string) {
	mu.Lock()
	pendingProgress = &uiUpdate{percent: n, text: text}
	mu.Unlock()
	post.Call(mainWindow, wmUpdate, 0, 0)
}
func notifyDone(e error, path string) {
	mu.Lock()
	statusUpdates = append(statusUpdates, uiUpdate{done: true, err: e, path: path})
	mu.Unlock()
	post.Call(mainWindow, wmUpdate, 0, 0)
}
func text(h uintptr) string {
	n, _, _ := getLen.Call(h)
	b := make([]uint16, n+1)
	getText.Call(h, uintptr(unsafe.Pointer(&b[0])), n+1)
	return syscall.UTF16ToString(b)
}
func status(s string) { setText.Call(controls[idStatus], ptr(u(s))) }
func message(title, body string, flags uintptr) uintptr {
	r, _, _ := proc(user, "MessageBoxW").Call(mainWindow, ptr(u(body)), ptr(u(title)), flags)
	return r
}
func control(id int, class, caption string, style uintptr) uintptr {
	h, _, _ := createWindow.Call(0, ptr(u(class)), ptr(u(caption)), 0x40000000|0x10000000|style, 0, 0, 0, 0, mainWindow, uintptr(id), instance, 0)
	controls[id] = h
	send.Call(h, 0x30, font, 1)
	return h
}
func fileDialog(save, multi bool, filter, title, initial, ext string) []string {
	buf := make([]uint16, 65536)
	copy(buf, syscall.StringToUTF16(initial))
	of := openFilename{Owner: mainWindow, Instance: instance, Filter: uMulti(filter), File: &buf[0], MaxFile: uint32(len(buf)), Title: u(title), DefExt: u(ext), Flags: 0x00080000 | 0x00000008 | 0x00001000 | 0x00000004}
	// OFN_NOCHANGEDIR | EXPLORER | PATHMUSTEXIST; no overwrite prompt, as overwrite is prohibited.
	if !save {
		of.Flags |= 0x00000800
	}
	if multi {
		of.Flags |= 0x00000200
	}
	of.Size = uint32(unsafe.Sizeof(of))
	p := proc(comdlg, "GetOpenFileNameW")
	if save {
		p = proc(comdlg, "GetSaveFileNameW")
	}
	r, _, _ := p.Call(uintptr(unsafe.Pointer(&of)))
	if r == 0 {
		e, _, _ := proc(comdlg, "CommDlgExtendedError").Call()
		if e != 0 {
			message("Ошибка выбора файла", fmt.Sprintf("Код диалога: 0x%x", e), 0x10)
		}
		return nil
	}
	var parts []string
	start := 0
	for i, v := range buf {
		if v == 0 {
			if i == start {
				break
			}
			parts = append(parts, syscall.UTF16ToString(buf[start:i]))
			start = i + 1
		}
	}
	if len(parts) > 1 {
		var result []string
		for _, n := range parts[1:] {
			result = append(result, filepath.Join(parts[0], n))
		}
		return result
	}
	return parts
}
func uMulti(s string) *uint16 {
	v := syscall.StringToUTF16(strings.ReplaceAll(s, "|", "\x01"))
	for i := range v {
		if v[i] == 1 {
			v[i] = 0
		}
	}
	return &v[0]
}
func folderDialog(title string) string {
	buf := make([]uint16, 32768)
	bi := browseInfo{Owner: mainWindow, Display: &buf[0], Title: u(title), Flags: 0x1 | 0x40}
	pid, _, _ := proc(shell, "SHBrowseForFolderW").Call(uintptr(unsafe.Pointer(&bi)))
	if pid == 0 {
		return ""
	}
	defer proc(ole, "CoTaskMemFree").Call(pid)
	r, _, _ := proc(shell, "SHGetPathFromIDListEx").Call(pid, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}
func label(id int, s string) uintptr  { return control(id, "STATIC", s, 0) }
func button(id int, s string) uintptr { return control(id, "BUTTON", s, 0x10000) }

const (
	idMore      = 123
	idEmpty     = 124
	idEmptyHint = 125
)

var compressionLevel = 1

func move(id, x, y, w, h int) {
	proc(user, "MoveWindow").Call(controls[id], uintptr(scaled(x)), uintptr(scaled(y)), uintptr(scaled(w)), uintptr(scaled(h)), 1)
}
func show(id int, b bool) {
	n := uintptr(0)
	if b {
		n = 5
	}
	proc(user, "ShowWindow").Call(controls[id], n)
}
func layout() {
	var r rect
	proc(user, "GetClientRect").Call(mainWindow, uintptr(unsafe.Pointer(&r)))
	w := int(float64(r.Right) / scale)
	h := int(float64(r.Bottom) / scale)
	if w < 620 || h < 420 {
		return
	}
	m := 28
	full := w - 2*m
	move(idTitle, m, 22, full-170, 42)
	move(idSubtitle, w-m-162, 33, 162, 28)
	move(idFileLabel, m, 88, full-230, 28)
	move(idAdd, w-m-196, 79, 138, 40)
	move(idMore, w-m-46, 79, 46, 40)
	move(idFiles, m, 134, full, h-288)
	move(idEmpty, m, 198, full, 38)
	move(idEmptyHint, m, 240, full, 28)
	y := h - 128
	move(idFormat, m, y, 200, 180)
	move(idPack, w-m-306, y-8, 148, 44)
	move(idUnpack, w-m-148, y-8, 148, 44)
	move(idCancel, w-m-148, y-8, 148, 44)
	move(idProgress, m, h-70, full, 6)
	move(idStatus, m, h-50, full, 38)
}
func boolParam(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
func chooseFormat() string {
	r, _, _ := send.Call(controls[idFormat], 0x147, 0, 0)
	if r == 1 {
		return "zip"
	}
	return "faw"
}
func defaultOutput() string {
	if len(files) == 0 {
		return ""
	}
	base := strings.TrimSuffix(filepath.Base(files[0]), filepath.Ext(files[0]))
	if st, e := os.Stat(files[0]); e == nil && st.IsDir() {
		base = filepath.Base(files[0])
	}
	if len(files) > 1 {
		base = "Fawusk-archive"
	}
	return filepath.Join(filepath.Dir(files[0]), base+"."+chooseFormat())
}
func refresh() {
	send.Call(controls[idFiles], 0x184, 0, 0)
	width := 0
	for _, p := range files {
		caption := filepath.Base(p)
		if st, e := os.Stat(p); e == nil && st.IsDir() {
			caption += "  / папка"
		}
		send.Call(controls[idFiles], 0x180, 0, ptr(u(caption)))
		n := len([]rune(caption))*9 + 24
		if n > width {
			width = n
		}
	}
	send.Call(controls[idFiles], 0x194, uintptr(scaled(width)), 0)
	caption := "Ваши файлы"
	if len(files) > 0 {
		caption = fmt.Sprintf("Ваши файлы · %d", len(files))
	}
	setText.Call(controls[idFileLabel], ptr(u(caption)))
	show(idFiles, len(files) > 0)
	show(idEmpty, len(files) == 0)
	show(idEmptyHint, len(files) == 0)
	enable.Call(controls[idPack], boolParam(!busy && len(files) > 0))
}
func add(paths []string) {
	for _, p := range paths {
		exists := false
		for _, q := range files {
			if strings.EqualFold(p, q) {
				exists = true
				break
			}
		}
		if !exists {
			files = append(files, p)
		}
	}
	refresh()
	if len(paths) > 0 {
		status("Готово к упаковке")
	}
}
func setBusy(b bool) {
	busy = b
	for _, id := range []int{idAdd, idMore, idFormat, idFiles} {
		enable.Call(controls[id], boolParam(!b))
	}
	enable.Call(controls[idPack], boolParam(!b && len(files) > 0))
	show(idUnpack, !b)
	show(idCancel, b)
	enable.Call(controls[idCancel], boolParam(b))
	show(idProgress, b)
	if !b {
		show(idProgress, false)
	}
}
func openResult() {
	if resultPath == "" {
		return
	}
	p := resultPath
	if st, e := os.Stat(p); e == nil && !st.IsDir() {
		p = filepath.Dir(p)
	}
	proc(shell, "ShellExecuteW").Call(mainWindow, ptr(u("open")), ptr(u(p)), 0, 0, 1)
}
func selected() int { r, _, _ := send.Call(controls[idFiles], 0x188, 0, 0); return int(int32(r)) }
func removeSelected() {
	i := selected()
	if i >= 0 && i < len(files) {
		files = append(files[:i], files[i+1:]...)
		refresh()
		status("Убрано из списка. Исходный файл не удалён.")
	}
}
func popup(id int, addOnly bool) {
	if busy {
		return
	}
	menu, _, _ := proc(user, "CreatePopupMenu").Call()
	defer proc(user, "DestroyMenu").Call(menu)
	appendItem := func(menu uintptr, flags uintptr, id uintptr, s string) {
		proc(user, "AppendMenuW").Call(menu, flags, id, ptr(u(s)))
	}
	if addOnly {
		appendItem(menu, 0, 1001, "Файлы…")
		appendItem(menu, 0, 1002, "Папку…")
	} else {
		flags := uintptr(0)
		if selected() < 0 {
			flags = 3
		}
		appendItem(menu, flags, 1003, "Убрать выбранное    Del")
		flags = 0
		if len(files) == 0 {
			flags = 3
		}
		appendItem(menu, flags, 1004, "Очистить список")
		proc(user, "AppendMenuW").Call(menu, 0x800, 0, 0)
		sub, _, _ := proc(user, "CreatePopupMenu").Call()
		for i, s := range []string{"Быстрое", "Сбалансированное", "Максимальное"} {
			flags := uintptr(0)
			if []int{1, 6, 9}[i] == compressionLevel {
				flags = 8
			}
			appendItem(sub, flags, uintptr(1005+i), s)
		}
		appendItem(menu, 0x10, sub, "Сжатие")
		flags = 0
		if selected() < 0 {
			flags = 3
		}
		appendItem(menu, flags, 1010, "Показать полный путь")
		flags = 0
		if resultPath == "" {
			flags = 3
		}
		appendItem(menu, flags, 1008, "Открыть папку результата")
		proc(user, "AppendMenuW").Call(menu, 0x800, 0, 0)
		appendItem(menu, 0, 1009, "О Fawusk")
	}
	var r rect
	proc(user, "GetWindowRect").Call(controls[id], uintptr(unsafe.Pointer(&r)))
	action, _, _ := proc(user, "TrackPopupMenu").Call(menu, 0x100|0x2, uintptr(r.Left), uintptr(r.Bottom), 0, mainWindow, 0)
	switch action {
	case 1001:
		add(fileDialog(false, true, "Все файлы|*.*||", "Добавить файлы", "", ""))
	case 1002:
		if p := folderDialog("Выберите папку для упаковки"); p != "" {
			add([]string{p})
		}
	case 1003:
		removeSelected()
	case 1004:
		files = nil
		refresh()
		status("Список очищен")
	case 1005, 1006, 1007:
		compressionLevel = []int{1, 6, 9}[int(action)-1005]
		status("Сжатие: " + []string{"быстрое", "сбалансированное", "максимальное"}[int(action)-1005])
	case 1008:
		openResult()
	case 1009:
		message("Fawusk "+appVersion, "Fawusk "+appVersion+"\n\nFAW 2: Zstandard и несжатые блоки.\nЧтение FAW 1 и ZIP.\n\nСжатие можно изменить в меню «…».\nRAR, 7z и шифрование пока не поддерживаются.\nЭто тестовая версия: используйте копии файлов.", 0x40)
	case 1010:
		i := selected()
		if i >= 0 && i < len(files) {
			message("Исходный путь", files[i], 0x40)
		}
	}
}
func doPack() {
	if busy || len(files) == 0 {
		return
	}
	format := chooseFormat()
	p := fileDialog(true, false, "Архив "+strings.ToUpper(format)+"|*."+format+"||", "Создать архив", defaultOutput(), format)
	if len(p) == 0 {
		return
	}
	out, e := filepath.Abs(p[0])
	if e != nil {
		message("Ошибка", e.Error(), 0x10)
		return
	}
	inputs := append([]string(nil), files...)
	level := compressionLevel
	ctx, cancel := context.WithCancel(context.Background())
	cancelWork = cancel
	resultPath = ""
	setBusy(true)
	send.Call(controls[idProgress], 0x402, 0, 0)
	status("Подготовка…")
	go func() { e := pack(ctx, inputs, out, format, level, notify); notifyDone(e, out) }()
}
func doUnpack() {
	if busy {
		return
	}
	p := fileDialog(false, false, "Архивы FAW и ZIP|*.faw;*.zip|Все файлы|*.*||", "Распаковать архив", "", "")
	if len(p) == 0 {
		return
	}
	parent := folderDialog("Где создать новую папку с результатом распаковки?")
	if parent == "" {
		return
	}
	base := strings.TrimSuffix(filepath.Base(p[0]), filepath.Ext(p[0])) + "-unpacked"
	dest := filepath.Join(parent, base)
	for n := 2; ; n++ {
		if _, e := os.Lstat(dest); os.IsNotExist(e) {
			break
		}
		if n > 9999 {
			message("Ошибка", "Не найдено свободное имя папки", 0x10)
			return
		}
		dest = filepath.Join(parent, fmt.Sprintf("%s-%d", base, n))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancelWork = cancel
	resultPath = ""
	setBusy(true)
	send.Call(controls[idProgress], 0x402, 0, 0)
	status("Проверка архива…")
	go func() { e := unpack(ctx, p[0], dest, notify); notifyDone(e, dest) }()
}
func wndProc(hwnd uintptr, messageID uint32, wparam, lparam uintptr) uintptr {
	switch messageID {
	case 0x1:
		mainWindow = hwnd
		font, _, _ = proc(gdi, "CreateFontW").Call(uintptr(-scaled(16)), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, ptr(u("Segoe UI")))
		headingFont, _, _ = proc(gdi, "CreateFontW").Call(uintptr(-scaled(30)), 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, ptr(u("Segoe UI")))
		smallFont, _, _ = proc(gdi, "CreateFontW").Call(uintptr(-scaled(14)), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, ptr(u("Segoe UI")))
		label(idTitle, "Fawusk")
		send.Call(controls[idTitle], 0x30, headingFont, 1)
		control(idSubtitle, "STATIC", appVersion, 2)
		send.Call(controls[idSubtitle], 0x30, smallFont, 1)
		label(idFileLabel, "Ваши файлы")
		button(idAdd, "Добавить…")
		button(idMore, "…")
		control(idFiles, "LISTBOX", "", 0x00800000|0x00200000|0x00100000|0x10000|0x1|0x100)
		control(idEmpty, "STATIC", "Перетащите файлы сюда", 1)
		control(idEmptyHint, "STATIC", "или нажмите «Добавить…»", 1)
		control(idFormat, "COMBOBOX", "", 0x3|0x10000|0x00200000)
		for _, s := range []string{"FAW · рекомендуется", "ZIP · совместимый"} {
			send.Call(controls[idFormat], 0x143, 0, ptr(u(s)))
		}
		send.Call(controls[idFormat], 0x14e, 0, 0)
		control(idPack, "BUTTON", "Упаковать", 0x10000|1)
		button(idUnpack, "Распаковать…")
		button(idCancel, "Отмена")
		control(idProgress, "msctls_progress32", "", 0x1)
		send.Call(controls[idProgress], 0x406, 0, 100)
		label(idStatus, "ZIP и FAW · исходные файлы не изменяются")
		send.Call(controls[idStatus], 0x30, smallFont, 1)
		proc(shell, "DragAcceptFiles").Call(hwnd, 1)
		refresh()
		setBusy(false)
		layout()
		return 0
	case 0x5:
		layout()
		return 0
	case 0x24:
		minimum := point{scaled(700), scaled(530)}
		kernel.NewProc("RtlMoveMemory").Call(lparam+24, uintptr(unsafe.Pointer(&minimum)), unsafe.Sizeof(minimum))
		return 0
	case 0x111:
		id := int(wparam & 0xffff)
		code := int((wparam >> 16) & 0xffff)
		if busy && id != idCancel {
			return 0
		}
		switch id {
		case idAdd:
			popup(idAdd, true)
		case idMore:
			popup(idMore, false)
		case idPack:
			doPack()
		case idUnpack:
			doUnpack()
		case idCancel:
			if cancelWork != nil {
				cancelWork()
				enable.Call(controls[idCancel], 0)
				status("Отмена и очистка временных данных…")
			}
		case idFiles:
			if code == 2 {
				i := selected()
				if i >= 0 && i < len(files) {
					message("Исходный путь", files[i], 0x40)
				}
			}
		}
		return 0
	case 0x100:
		if wparam == 0x2e && !busy {
			removeSelected()
			return 0
		}
	case 0x233:
		if !busy {
			n, _, _ := proc(shell, "DragQueryFileW").Call(wparam, 0xffffffff, 0, 0)
			var paths []string
			for i := uintptr(0); i < n; i++ {
				b := make([]uint16, 32768)
				proc(shell, "DragQueryFileW").Call(wparam, i, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
				paths = append(paths, syscall.UTF16ToString(b))
			}
			add(paths)
		}
		proc(shell, "DragFinish").Call(wparam)
		return 0
	case wmUpdate:
		mu.Lock()
		p := pendingProgress
		pendingProgress = nil
		updates := statusUpdates
		statusUpdates = nil
		mu.Unlock()
		if p != nil {
			send.Call(controls[idProgress], 0x402, uintptr(p.percent), 0)
			status(p.text)
		}
		for _, v := range updates {
			if cancelWork != nil {
				cancelWork()
				cancelWork = nil
			}
			setBusy(false)
			if v.err != nil {
				if errors.Is(v.err, context.Canceled) {
					status("Отменено. Исходные файлы не изменены.")
				} else {
					status("Не удалось завершить операцию")
					message("Fawusk — ошибка", v.err.Error(), 0x10)
				}
			} else {
				resultPath = v.path
				status("Готово · папка результата доступна в меню «…»")
			}
		}
		return 0
	case 0x138:
		proc(gdi, "SetBkMode").Call(wparam, 1)
		color := uintptr(0x002B2C2C)
		if lparam == controls[idSubtitle] || lparam == controls[idStatus] || lparam == controls[idEmptyHint] {
			color = 0x00645F5A
		}
		proc(gdi, "SetTextColor").Call(wparam, color)
		return bg
	case 0x10:
		if busy {
			message("Операция выполняется", "Сначала отмените операцию и дождитесь очистки.", 0x40)
			return 0
		}
		proc(user, "DestroyWindow").Call(hwnd)
		return 0
	case 0x2:
		for _, f := range []uintptr{font, headingFont, smallFont} {
			proc(gdi, "DeleteObject").Call(f)
		}
		proc(user, "PostQuitMessage").Call(0)
		return 0
	}
	r, _, _ := defWindow.Call(hwnd, uintptr(messageID), wparam, lparam)
	return r
}

func main() {
	runtime.LockOSThread()
	ole.NewProc("CoInitializeEx").Call(0, 2)
	defer ole.NewProc("CoUninitialize").Call()
	if p := proc(user, "SetProcessDpiAwarenessContext"); p.Find() == nil {
		p.Call(^uintptr(1))
	} else {
		proc(user, "SetProcessDPIAware").Call()
	}
	if p := proc(user, "GetDpiForSystem"); p.Find() == nil {
		d, _, _ := p.Call()
		if d > 0 {
			scale = float64(d) / 96
		}
	}
	instance, _, _ = kernel.NewProc("GetModuleHandleW").Call(0)
	init := struct{ Size, Classes uint32 }{8, 0x20}
	proc(common, "InitCommonControlsEx").Call(uintptr(unsafe.Pointer(&init)))
	bg, _, _ = proc(gdi, "CreateSolidBrush").Call(0x00F7F8F9)
	cursor, _, _ := proc(user, "LoadCursorW").Call(0, 32512)
	icon, _, _ := proc(user, "LoadIconW").Call(instance, 1)
	if icon == 0 {
		icon, _, _ = proc(user, "LoadIconW").Call(0, 32512)
	}
	cl := wc{Size: uint32(unsafe.Sizeof(wc{})), Style: 3, WndProc: syscall.NewCallback(wndProc), Instance: instance, Icon: icon, IconSmall: icon, Cursor: cursor, Background: bg, Class: u("FawuskMainWindow")}
	r, _, e := proc(user, "RegisterClassExW").Call(uintptr(unsafe.Pointer(&cl)))
	if r == 0 {
		message("Fawusk", fmt.Sprint(e), 0x10)
		return
	}
	mainWindow, _, e = createWindow.Call(0, ptr(cl.Class), ptr(u("Fawusk "+appVersion)), 0x00CF0000, 0x80000000, 0x80000000, uintptr(scaled(760)), uintptr(scaled(590)), 0, 0, instance, 0)
	if mainWindow == 0 {
		message("Fawusk", fmt.Sprint(e), 0x10)
		return
	}
	proc(user, "ShowWindow").Call(mainWindow, 1)
	proc(user, "UpdateWindow").Call(mainWindow)
	if len(os.Args) > 1 {
		add(os.Args[1:])
	}
	var m msg
	for {
		r, _, _ := proc(user, "GetMessageW").Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if m.Message == 0x100 && m.Wparam == 0x2e && m.Hwnd == controls[idFiles] && !busy {
			removeSelected()
			continue
		}
		handled, _, _ := proc(user, "IsDialogMessageW").Call(mainWindow, uintptr(unsafe.Pointer(&m)))
		if handled == 0 {
			proc(user, "TranslateMessage").Call(uintptr(unsafe.Pointer(&m)))
			proc(user, "DispatchMessageW").Call(uintptr(unsafe.Pointer(&m)))
		}
	}
	proc(gdi, "DeleteObject").Call(bg)
}
