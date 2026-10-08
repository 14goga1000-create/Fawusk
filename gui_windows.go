package main

import (
	"context"
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
func label(id int, s string) uintptr  { return control(id, "STATIC", s, 0) }
func button(id int, s string) uintptr { return control(id, "BUTTON", s, 0x10000) }
func move(id, x, y, w, h int) {
	proc(user, "MoveWindow").Call(controls[id], uintptr(scaled(x)), uintptr(scaled(y)), uintptr(scaled(w)), uintptr(scaled(h)), 1)
}
func layout() {
	var r rect
	proc(user, "GetClientRect").Call(mainWindow, uintptr(unsafe.Pointer(&r)))
	w := int(float64(r.Right) / scale)
	h := int(float64(r.Bottom) / scale)
	if w < 700 || h < 600 {
		return
	}
	margin := 28
	full := w - 2*margin
	listH := h - 520
	move(idTitle, margin, 24, full, 38)
	move(idSubtitle, margin, 67, full, 24)
	move(idFileLabel, margin, 110, full, 24)
	move(idFiles, margin, 142, full, listH)
	y := 142 + listH + 12
	move(idAdd, margin, y, 150, 38)
	move(idFolder, margin+160, y, 150, 38)
	move(idRemove, margin+320, y, 110, 38)
	move(idClear, w-margin-110, y, 110, 38)
	y += 58
	move(idFormatLabel, margin, y, 220, 22)
	move(idLevelLabel, margin+260, y, full-260, 22)
	y += 26
	move(idFormat, margin, y, 240, 180)
	move(idLevel, margin+260, y, full-260, 180)
	y += 44
	move(idOutputLabel, margin, y, full, 22)
	y += 26
	move(idOutput, margin, y, full-104, 32)
	move(idBrowse, w-margin-92, y-2, 92, 36)
	y += 48
	move(idPack, margin, y, 178, 44)
	move(idUnpack, margin+190, y, 178, 44)
	move(idCancel, margin+380, y, 110, 44)
	move(idOpen, w-margin-118, y, 118, 44)
	y += 59
	move(idProgress, margin, y, full, 8)
	y += 16
	move(idStatus, margin, y, full, 42)
	y += 44
	move(idNote, margin, y, full, 20)
}
func selection() int { r, _, _ := send.Call(controls[idFormat], 0x147, 0, 0); return int(r) }
func refresh() {
	send.Call(controls[idFiles], 0x184, 0, 0)
	for _, p := range files {
		send.Call(controls[idFiles], 0x180, 0, ptr(u(p)))
	}
	setText.Call(controls[idFileLabel], ptr(u(fmt.Sprintf("Исходные файлы и папки  ·  %d", len(files)))))
	enable.Call(controls[idPack], boolParam(!busy && len(files) > 0))
}
func boolParam(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
func chooseFormat() string {
	if selection() == 1 {
		return "zip"
	}
	if selection() == 2 {
		return "rar"
	}
	return "faw"
}
func defaultOutput() {
	if len(files) == 0 {
		return
	}
	base := strings.TrimSuffix(filepath.Base(files[0]), filepath.Ext(files[0]))
	if st, e := os.Stat(files[0]); e == nil && st.IsDir() {
		base = filepath.Base(files[0])
	}
	if len(files) > 1 {
		base = "Fawusk-archive"
	}
	setText.Call(controls[idOutput], ptr(u(filepath.Join(filepath.Dir(files[0]), base+"."+chooseFormat()))))
}
func add(paths []string) {
	for _, p := range paths {
		found := false
		for _, q := range files {
			if strings.EqualFold(p, q) {
				found = true
			}
		}
		if !found {
			files = append(files, p)
		}
	}
	refresh()
	if text(controls[idOutput]) == "" {
		defaultOutput()
	}
	status("Готов к упаковке. Исходные файлы останутся без изменений.")
}
func setBusy(b bool) {
	busy = b
	for _, id := range []int{idAdd, idFolder, idRemove, idClear, idFormat, idLevel, idOutput, idBrowse, idUnpack, idFiles} {
		enable.Call(controls[id], boolParam(!b))
	}
	enable.Call(controls[idPack], boolParam(!b && len(files) > 0))
	enable.Call(controls[idCancel], boolParam(b))
	enable.Call(controls[idOpen], boolParam(!b && resultPath != ""))
}
func fileDialog(save, multi bool, filter, title, initial, ext string) []string {
	buf := make([]uint16, 65536)
	copy(buf, syscall.StringToUTF16(initial))
	of := openFilename{Owner: mainWindow, Instance: instance, Filter: uMulti(filter), File: &buf[0], MaxFile: uint32(len(buf)), Title: u(title), DefExt: u(ext), Flags: 0x00080000 | 0x00000008 | 0x00001000}
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
func doPack() {
	if busy {
		return
	}
	if chooseFormat() == "rar" {
		message("RAR недоступен в alpha 0.1", "Для создания RAR нужен лицензированный фирменный инструмент.\n\nВыберите FAW или ZIP. Fawusk не подменяет RAR другим форматом.", 0x40)
		return
	}
	out := strings.TrimSpace(text(controls[idOutput]))
	if out == "" {
		message("Куда сохранить архив?", "Укажите путь и имя нового архива.", 0x40)
		return
	}
	out, e := filepath.Abs(out)
	if e != nil {
		message("Ошибка", e.Error(), 0x10)
		return
	}
	inputs := append([]string(nil), files...)
	format := chooseFormat()
	r, _, _ := send.Call(controls[idLevel], 0x147, 0, 0)
	level := 1
	if r == 1 {
		level = 6
	}
	if r == 2 {
		level = 9
	}
	resultPath = ""
	ctx, cancel := context.WithCancel(context.Background())
	cancelWork = cancel
	setBusy(true)
	send.Call(controls[idProgress], 0x402, 0, 0)
	status("Подготовка…")
	go func() { err := pack(ctx, inputs, out, format, level, notify); notifyDone(err, out) }()
}
func doUnpack() {
	if busy {
		return
	}
	paths := fileDialog(false, false, "Архивы FAW и ZIP|*.faw;*.zip|Все файлы|*.*||", "Выберите архив для распаковки", "", "")
	if len(paths) == 0 {
		return
	}
	parent := folderDialog("Выберите папку. Внутри будет создана НОВАЯ папка с содержимым архива.")
	if parent == "" {
		return
	}
	base := strings.TrimSuffix(filepath.Base(paths[0]), filepath.Ext(paths[0])) + "-unpacked"
	dest := filepath.Join(parent, base)
	for n := 2; ; n++ {
		if _, e := os.Lstat(dest); os.IsNotExist(e) {
			break
		}
		if n > 9999 {
			message("Ошибка", "Не удалось выбрать свободное имя папки.", 0x10)
			return
		}
		dest = filepath.Join(parent, fmt.Sprintf("%s-%d", base, n))
	}
	resultPath = ""
	ctx, cancel := context.WithCancel(context.Background())
	cancelWork = cancel
	setBusy(true)
	send.Call(controls[idProgress], 0x402, 0, 0)
	status("Проверка архива…")
	go func() { err := unpack(ctx, paths[0], dest, notify); notifyDone(err, dest) }()
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
func wndProc(hwnd uintptr, messageID uint32, wparam, lparam uintptr) uintptr {
	switch messageID {
	case 0x0001:
		mainWindow = hwnd
		font, _, _ = proc(gdi, "CreateFontW").Call(uintptr(-scaled(16)), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, ptr(u("Segoe UI")))
		headingFont, _, _ = proc(gdi, "CreateFontW").Call(uintptr(-scaled(30)), 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, ptr(u("Segoe UI")))
		smallFont, _, _ = proc(gdi, "CreateFontW").Call(uintptr(-scaled(13)), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, ptr(u("Segoe UI")))
		label(idTitle, "Fawusk")
		send.Call(controls[idTitle], 0x30, headingFont, 1)
		label(idSubtitle, "alpha 0.1  /  Локальный архиватор для Windows")
		label(idFileLabel, "Исходные файлы и папки  ·  0")
		control(idFiles, "LISTBOX", "", 0x00800000|0x00200000|0x10000|0x0001|0x0100)
		button(idAdd, "Добавить файлы")
		button(idFolder, "Добавить папку")
		button(idRemove, "Удалить")
		button(idClear, "Очистить")
		label(idFormatLabel, "Формат архива")
		label(idLevelLabel, "Сжатие")
		control(idFormat, "COMBOBOX", "", 0x3|0x10000|0x00200000)
		control(idLevel, "COMBOBOX", "", 0x3|0x10000|0x00200000)
		for _, s := range []string{"FAW — формат Fawusk", "ZIP — совместимый", "RAR — пока недоступен"} {
			send.Call(controls[idFormat], 0x143, 0, ptr(u(s)))
		}
		send.Call(controls[idFormat], 0x14e, 0, 0)
		for _, s := range []string{"Быстрое — меньше нагрузки", "Сбалансированное", "Максимальное — медленнее"} {
			send.Call(controls[idLevel], 0x143, 0, ptr(u(s)))
		}
		send.Call(controls[idLevel], 0x14e, 0, 0)
		label(idOutputLabel, "Сохранить новый архив")
		control(idOutput, "EDIT", "", 0x00800000|0x10000|0x80)
		button(idBrowse, "Обзор…")
		control(idPack, "BUTTON", "Упаковать", 0x10000|1)
		button(idUnpack, "Распаковать…")
		button(idCancel, "Отмена")
		button(idOpen, "Открыть папку")
		control(idProgress, "msctls_progress32", "", 0x1)
		send.Call(controls[idProgress], 0x406, 0, 100)
		label(idStatus, "Добавьте файлы или папку. Для распаковки нажмите «Распаковать…».")
		label(idNote, "Без перезаписи  ·  Без сети  ·  FAW: SHA-256, без шифрования")
		send.Call(controls[idNote], 0x30, smallFont, 1)
		proc(shell, "DragAcceptFiles").Call(hwnd, 1)
		setBusy(false)
		layout()
		return 0
	case 0x0005:
		layout()
		return 0
	case 0x0024: // MINMAXINFO: reserve space at every supported DPI.
		minimum := point{scaled(840), scaled(710)}
		kernel.NewProc("RtlMoveMemory").Call(lparam+24, uintptr(unsafe.Pointer(&minimum)), unsafe.Sizeof(minimum))
		return 0
	case 0x0111:
		id := int(wparam & 0xffff)
		code := int((wparam >> 16) & 0xffff)
		if busy && id != idCancel {
			return 0
		}
		switch id {
		case idAdd:
			add(fileDialog(false, true, "Все файлы|*.*||", "Добавить файлы", "", ""))
		case idFolder:
			if p := folderDialog("Выберите папку для упаковки целиком"); p != "" {
				add([]string{p})
			}
		case idRemove:
			r, _, _ := send.Call(controls[idFiles], 0x188, 0, 0)
			i := int(int32(r))
			if i >= 0 && i < len(files) {
				files = append(files[:i], files[i+1:]...)
				refresh()
			}
		case idClear:
			files = nil
			refresh()
			setText.Call(controls[idOutput], ptr(u("")))
			status("Список очищен. Исходные файлы не удалены.")
		case idFormat:
			if code == 1 {
				out := text(controls[idOutput])
				if out != "" {
					out = strings.TrimSuffix(out, filepath.Ext(out)) + "." + chooseFormat()
					setText.Call(controls[idOutput], ptr(u(out)))
				}
				if selection() == 2 {
					status("RAR пока недоступен. Выберите FAW или ZIP.")
				} else {
					status("Выбран формат " + strings.ToUpper(chooseFormat()) + ".")
				}
			}
		case idBrowse:
			format := chooseFormat()
			if format == "rar" {
				format = "faw"
				send.Call(controls[idFormat], 0x14e, 0, 0)
			}
			p := fileDialog(true, false, "Архив "+strings.ToUpper(format)+"|*."+format+"||", "Сохранить новый архив", text(controls[idOutput]), format)
			if len(p) > 0 {
				setText.Call(controls[idOutput], ptr(u(p[0])))
			}
		case idPack:
			doPack()
		case idUnpack:
			doUnpack()
		case idCancel:
			if cancelWork != nil {
				cancelWork()
				enable.Call(controls[idCancel], 0)
				status("Отмена и удаление временных данных…")
			}
		case idOpen:
			openResult()
		}
		return 0
	case 0x0233:
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
				send.Call(controls[idProgress], 0x402, 0, 0)
				if v.err == context.Canceled {
					status("Операция отменена. Исходные файлы не изменены.")
				} else {
					status("Ошибка: " + v.err.Error())
					message("Fawusk — операция не завершена", v.err.Error(), 0x10)
				}
			} else {
				resultPath = v.path
				enable.Call(controls[idOpen], 1)
				send.Call(controls[idProgress], 0x402, 100, 0)
				status("Готово. " + v.path)
			}
		}
		return 0
	case 0x0138: // static colors
		proc(gdi, "SetBkMode").Call(wparam, 1)
		color := uintptr(0x002B2C2C)
		if lparam == controls[idSubtitle] || lparam == controls[idNote] {
			color = 0x00645F5A
		}
		proc(gdi, "SetTextColor").Call(wparam, color)
		return bg
	case 0x0010:
		if busy {
			message("Операция выполняется", "Сначала нажмите «Отмена» и дождитесь завершения очистки.", 0x40)
			return 0
		}
		proc(user, "DestroyWindow").Call(hwnd)
		return 0
	case 0x0002:
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
	mainWindow, _, e = createWindow.Call(0, ptr(cl.Class), ptr(u("Fawusk "+appVersion)), 0x00CF0000, 0x80000000, 0x80000000, uintptr(scaled(940)), uintptr(scaled(780)), 0, 0, instance, 0)
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
		handled, _, _ := proc(user, "IsDialogMessageW").Call(mainWindow, uintptr(unsafe.Pointer(&m)))
		if handled == 0 {
			proc(user, "TranslateMessage").Call(uintptr(unsafe.Pointer(&m)))
			proc(user, "DispatchMessageW").Call(uintptr(unsafe.Pointer(&m)))
		}
	}
	proc(gdi, "DeleteObject").Call(bg)
}
