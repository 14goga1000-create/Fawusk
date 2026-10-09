package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
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
var busy bool
var cancelWork context.CancelFunc
var font, headingFont, smallFont uintptr
var scale = 1.0
var instance uintptr
var bg, white uintptr
var resultPath string
var previewRoots []string
var mu sync.Mutex
var statusUpdates []uiUpdate
var pendingProgress *uiUpdate

type uiUpdate struct {
	percent int
	text    string
	done    bool
	err     error
	path    string
	scan    bool
	preview bool
	entries []archiveEntry
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

const (
	idMore      = 123
	idEmpty     = 124
	idEmptyHint = 125
	idPath      = 126
	idUp        = 127
	idExternal  = 128
)

var currentPath, currentKind, archivePrefix string
var entries []archiveEntry
var rows []archiveEntry
var taskKind string
var archiveReady bool
var pathOldProc uintptr

func programPath() string { p, _ := os.Executable(); return p }
func newWindow(p string) {
	args := []string{}
	if p != "" {
		args = append(args, p)
	}
	cmd := exec.Command(programPath(), args...)
	if e := cmd.Start(); e != nil {
		message("Новое окно", e.Error(), 0x10)
	} else {
		go cmd.Wait()
	}
}
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
func boolParam(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
func layout() {
	var r rect
	proc(user, "GetClientRect").Call(mainWindow, uintptr(unsafe.Pointer(&r)))
	w := int(float64(r.Right) / scale)
	h := int(float64(r.Bottom) / scale)
	if w < 620 || h < 450 {
		return
	}
	m := 28
	full := w - 2*m
	move(idTitle, m, 20, full-170, 42)
	move(idSubtitle, w-m-162, 30, 162, 28)
	move(idFileLabel, m, 87, full-222, 26)
	move(idAdd, w-m-196, 78, 138, 40)
	move(idMore, w-m-46, 78, 46, 40)
	move(idPath, m, 133, full-92, 34)
	move(idUp, w-m-80, 131, 80, 38)
	move(idFiles, m, 185, full, h-355)
	move(idEmpty, m, 235, full, 38)
	move(idEmptyHint, m, 278, full, 44)
	y := h - 128
	move(idFormatLabel, m, y-30, 250, 22)
	move(idLevelLabel, m+262, y-30, 155, 22)
	move(idFormat, m, y, 250, 180)
	move(idLevel, m+262, y, 155, 180)
	move(idPack, w-m-148, y-8, 148, 44)
	move(idUnpack, w-m-148, y-8, 148, 44)
	move(idCancel, w-m-148, y-8, 148, 44)
	move(idProgress, m, h-70, full, 6)
	move(idStatus, m, h-50, full, 38)
}
func chooseFormat() string {
	r, _, _ := send.Call(controls[idFormat], 0x147, 0, 0)
	if r > 3 {
		return "faw3"
	}
	return []string{"faw3", "faw2", "faw1", "zip"}[r]
}
func outputExt() string {
	if chooseFormat() == "zip" {
		return "zip"
	}
	return "faw"
}
func selected() int { r, _, _ := send.Call(controls[idFiles], 0x188, 0, 0); return int(int32(r)) }
func refresh() {
	send.Call(controls[idFiles], 0x184, 0, 0)
	width := 0
	for _, a := range rows {
		caption := path.Base(a.Name)
		if currentKind == "dir" {
			caption = filepath.Base(a.Name)
		}

		send.Call(controls[idFiles], 0x180, 0, ptr(u(caption)))
		if n := len([]rune(caption))*9 + 52; n > width {
			width = n
		}
	}
	send.Call(controls[idFiles], 0x194, uintptr(scaled(width)), 0)
	display := currentPath
	if archivePrefix != "" {
		display += "  ›  " + strings.TrimSuffix(archivePrefix, "/")
	}
	setText.Call(controls[idPath], ptr(u(display)))
	caption := "Один файл или папка на окно"
	switch currentKind {
	case "dir":
		caption = fmt.Sprintf("Папка · %d элементов", len(rows))
	case "file":
		caption = "Обычный файл"
	case "archive":
		caption = fmt.Sprintf("Архив · %d элементов", len(rows))
	}
	setText.Call(controls[idFileLabel], ptr(u(caption)))
	hasList := currentKind == "dir" || currentKind == "archive"
	show(idFiles, hasList && len(rows) > 0)
	show(idEmpty, (currentKind == "" || hasList && len(rows) == 0))
	show(idEmptyHint, currentKind == "" || hasList && len(rows) == 0)
	if currentKind == "" {
		setText.Call(controls[idEmpty], ptr(u("Откройте файл или папку")))
		setText.Call(controls[idEmptyHint], ptr(u("или перетащите один путь в окно")))
	} else if hasList {
		title, hint := "Папка пуста", "Можно упаковать пустую папку"
		if currentKind == "archive" {
			title, hint = "Архив не прочитан", "Откройте архив для проверки"
			if busy {
				title, hint = "Чтение архива…", "Содержимое появится после проверки"
			} else if archiveReady {
				title, hint = "Нет элементов", "В этой папке архива нет файлов"
			}
		}
		setText.Call(controls[idEmpty], ptr(u(title)))
		setText.Call(controls[idEmptyHint], ptr(u(hint)))
	}
	show(idPack, !busy && currentKind != "archive")
	show(idFormat, currentKind != "archive")
	show(idLevel, currentKind != "archive")
	show(idFormatLabel, currentKind != "archive")
	show(idLevelLabel, currentKind != "archive")
	show(idUnpack, !busy && currentKind == "archive")
	enable.Call(controls[idFormat], boolParam(!busy && (currentKind == "dir" || currentKind == "file")))
	enable.Call(controls[idLevel], boolParam(!busy && (currentKind == "dir" || currentKind == "file")))
	enable.Call(controls[idPack], boolParam(!busy && (currentKind == "dir" || currentKind == "file")))
	enable.Call(controls[idUnpack], boolParam(!busy && currentKind == "archive"))
	enable.Call(controls[idUp], boolParam(!busy && (currentKind == "dir" || currentKind == "archive")))
}
func setBusy(b bool) {
	busy = b
	for _, id := range []int{idAdd, idMore, idFormat, idLevel, idFiles, idUp, idPath} {
		enable.Call(controls[id], boolParam(!b))
	}
	show(idUnpack, !b)
	show(idCancel, b)
	enable.Call(controls[idCancel], boolParam(b))
	show(idProgress, b)
	refresh()
}
func notifyScan(e error, a []archiveEntry) {
	mu.Lock()
	statusUpdates = append(statusUpdates, uiUpdate{done: true, err: e, scan: true, entries: a})
	mu.Unlock()
	post.Call(mainWindow, wmUpdate, 0, 0)
}
func openPath(p string) {
	if busy || p == "" {
		return
	}
	absolute, e := filepath.Abs(p)
	if e != nil {
		message("Путь", e.Error(), 0x10)
		return
	}
	info, e := os.Lstat(absolute)
	if e != nil {
		message("Открытие", e.Error(), 0x10)
		return
	}
	if isLink(info) || platformUnsafe(absolute, info) {
		message("Открытие", "Ссылки, junction и специальные файлы пока не поддерживаются", 0x40)
		return
	}
	currentPath = absolute
	archivePrefix = ""
	entries = nil
	archiveReady = false
	rows = nil
	resultPath = ""
	if info.IsDir() {
		currentKind = "dir"
		folder, e := os.Open(absolute)
		if e != nil {
			refresh()
			message("Чтение папки", e.Error(), 0x10)
			return
		}
		dir, e := folder.ReadDir(maxFiles + 1)
		folder.Close()
		if e != nil && e != io.EOF {
			refresh()
			message("Чтение папки", e.Error(), 0x10)
			return
		}
		if len(dir) > maxFiles {
			refresh()
			message("Чтение папки", "Лимит отображения — 100 000 элементов", 0x40)
			return
		}
		for _, d := range dir {
			rows = append(rows, archiveEntry{Name: filepath.Join(absolute, d.Name()), Directory: d.IsDir()})
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Directory != rows[j].Directory {
				return rows[i].Directory
			}
			return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name)
		})
		refresh()
		status("Двойной клик: папка — переход, файл — внешнее приложение")
		return
	}
	version, e := archiveVersion(absolute)
	if e != nil {
		currentKind = "archive"
		refresh()
		message("Чтение архива", e.Error(), 0x10)
		return
	}
	if version != 0 {
		currentKind = "archive"
		refresh()
		taskKind = "scan"
		ctx, cancel := context.WithCancel(context.Background())
		cancelWork = cancel
		setBusy(true)
		status("Чтение и проверка архива…")
		go func() { a, e := scanArchive(ctx, absolute, notify); notifyScan(e, a) }()
		return
	}
	currentKind = "file"
	refresh()
	status("Двойной клик по пути — открыть файл внешним приложением")
}
func activateRow() {
	if busy {
		return
	}
	i := selected()
	if i < 0 || i >= len(rows) {
		return
	}
	a := rows[i]
	if currentKind == "archive" {
		if a.Directory {
			archivePrefix = a.Name + "/"
			rows = archiveChildren(entries, archivePrefix)
			refresh()
			status("Двойной клик — просмотр медиа и документов")
		} else {
			doPreview(a.Name)
		}
		return
	}
	if a.Directory {
		openPath(a.Name)
		return
	}
	info, e := os.Lstat(a.Name)
	if e != nil {
		message("Открытие", e.Error(), 0x10)
		return
	}
	if isLink(info) || platformUnsafe(a.Name, info) {
		message("Открытие", "Ссылки и специальные файлы пока не поддерживаются", 0x40)
		return
	}
	version, e := archiveVersion(a.Name)
	if e != nil || version != 0 {
		openPath(a.Name)
	} else {
		openExternal(a.Name)
	}
}
func goUp() {
	if busy {
		return
	}
	if currentKind == "dir" {
		openPath(filepath.Dir(currentPath))
	}
	if currentKind == "archive" {
		if archivePrefix == "" {
			openPath(filepath.Dir(currentPath))
			return
		}
		p := path.Dir(strings.TrimSuffix(archivePrefix, "/"))
		archivePrefix = ""
		if p != "." {
			archivePrefix = p + "/"
		}
		rows = archiveChildren(entries, archivePrefix)
		refresh()
	}
}
func openExternal(p string) {
	if p == "" {
		return
	}
	r, _, _ := proc(shell, "ShellExecuteW").Call(mainWindow, ptr(u("open")), ptr(u(p)), 0, 0, 1)
	if r <= 32 {
		message("Открытие файла", "Windows не смогла открыть файл. Проверьте назначенное приложение и путь.", 0x10)
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
	openExternal(p)
}
func defaultOutput() string {
	base := filepath.Base(currentPath)
	if currentKind != "dir" {
		base = strings.TrimSuffix(base, filepath.Ext(base))
	}
	if base == "." || base == string(filepath.Separator) || strings.Contains(base, ":") {
		base = "Fawusk-archive"
	}
	return filepath.Join(filepath.Dir(currentPath), base+"."+outputExt())
}
func doPack() {
	if busy || (currentKind != "dir" && currentKind != "file") {
		return
	}
	format := chooseFormat()
	ext := outputExt()
	p := fileDialog(true, false, "Архив "+strings.ToUpper(ext)+"|*."+ext+"||", "Создать архив", defaultOutput(), ext)
	if len(p) == 0 {
		return
	}
	out, e := filepath.Abs(p[0])
	if e != nil {
		message("Путь", e.Error(), 0x10)
		return
	}
	inputs := []string{currentPath}
	r, _, _ := send.Call(controls[idLevel], 0x147, 0, 0)
	level := []int{1, 6, 9}[min(r, 2)]
	ctx, cancel := context.WithCancel(context.Background())
	cancelWork = cancel
	taskKind = "pack"
	setBusy(true)
	send.Call(controls[idProgress], 0x402, 0, 0)
	status("Подготовка…")
	go func() { e := pack(ctx, inputs, out, format, level, notify); notifyDone(e, out) }()
}
func doUnpack() {
	if busy || currentKind != "archive" {
		return
	}
	parent := folderDialog("Где создать новую папку с результатом распаковки?")
	if parent == "" {
		return
	}
	base := strings.TrimSuffix(filepath.Base(currentPath), filepath.Ext(currentPath)) + "-unpacked"
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
	input := currentPath
	ctx, cancel := context.WithCancel(context.Background())
	cancelWork = cancel
	taskKind = "unpack"
	setBusy(true)
	status("Распаковка…")
	go func() { e := unpack(ctx, input, dest, notify); notifyDone(e, dest) }()
}
func popup(id int, opening bool) {
	if busy {
		return
	}
	menu, _, _ := proc(user, "CreatePopupMenu").Call()
	defer proc(user, "DestroyMenu").Call(menu)
	addItem := func(m, flags, number uintptr, s string) { proc(user, "AppendMenuW").Call(m, flags, number, ptr(u(s))) }
	if opening {
		addItem(menu, 0, 1001, "Файл или архив…")
		addItem(menu, 0, 1002, "Папку…")
	} else {
		addItem(menu, 0, 1003, "Новое окно")
		f := uintptr(0)
		if resultPath == "" {
			f = 3
		}
		addItem(menu, f, 1008, "Папка результата")
		addItem(menu, 0, 1011, "Добавить .faw в «Открыть с помощью»")
		addItem(menu, 0, 1009, "О Fawusk")
	}
	var r rect
	proc(user, "GetWindowRect").Call(controls[id], uintptr(unsafe.Pointer(&r)))
	action, _, _ := proc(user, "TrackPopupMenu").Call(menu, 0x102, uintptr(r.Left), uintptr(r.Bottom), 0, mainWindow, 0)
	switch action {
	case 1001:
		p := fileDialog(false, false, "Все файлы|*.*|Архивы FAW и ZIP|*.faw;*.zip||", "Открыть файл или архив", "", "")
		if len(p) > 0 {
			openPath(p[0])
		}
	case 1002:
		if p := folderDialog("Открыть папку"); p != "" {
			openPath(p)
		}
	case 1003:
		newWindow("")
	case 1008:
		openResult()
	case 1011:
		if e := registerFAWOpenWith(); e != nil {
			message("Регистрация FAW", e.Error(), 0x10)
		} else {
			message("Регистрация FAW", "Fawusk добавлен в список «Открыть с помощью» для .faw.\n\nПриложение по умолчанию не менялось. Выберите Fawusk средствами Windows. Не перемещайте EXE после регистрации.", 0x40)
		}
	case 1009:
		message("Fawusk "+appVersion, "Fawusk "+appVersion+"\n\nОдин путь на окно.\nFAW 3: индексированные solid-группы, SHA-256.\nFAW 2: отдельное сжатие файлов.\nЧтение FAW 1/2/3 и ZIP.\n\nПроект развивается как конкурент WinRAR и 7-Zip.\nЭто альфа, превосходство пока не доказано.\nRAR, 7z и шифрование не реализованы.", 0x40)
	}
}
func pathProc(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	if msg == 0x203 && currentKind == "file" && !busy {
		post.Call(mainWindow, 0x111, idExternal, 0)
		return 0
	}
	r, _, _ := proc(user, "CallWindowProcW").Call(pathOldProc, hwnd, uintptr(msg), wparam, lparam)
	return r
}
func wndProc(hwnd uintptr, messageID uint32, wparam, lparam uintptr) uintptr {
	switch messageID {
	case 0x2b:
		return drawFileRow(lparam)
	case 0x2c:
		var a measureItem
		kernel.NewProc("RtlMoveMemory").Call(uintptr(unsafe.Pointer(&a)), lparam, unsafe.Sizeof(a))
		if int(a.ID) == idFiles {
			a.Height = uint32(scaled(32))
			kernel.NewProc("RtlMoveMemory").Call(lparam, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a))
			return 1
		}
	case 1:
		mainWindow = hwnd
		font, _, _ = proc(gdi, "CreateFontW").Call(uintptr(-scaled(16)), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, ptr(u("Segoe UI")))
		headingFont, _, _ = proc(gdi, "CreateFontW").Call(uintptr(-scaled(30)), 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, ptr(u("Segoe UI")))
		smallFont, _, _ = proc(gdi, "CreateFontW").Call(uintptr(-scaled(14)), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, ptr(u("Segoe UI")))
		label(idTitle, "Fawusk")
		send.Call(controls[idTitle], 0x30, headingFont, 1)
		control(idSubtitle, "STATIC", appVersion, 2)
		send.Call(controls[idSubtitle], 0x30, smallFont, 1)
		label(idFileLabel, "Один путь на окно")
		button(idAdd, "Открыть…")
		button(idMore, "…")
		control(idPath, "EDIT", "", 0x00800000|0x10000|0x80|0x800)
		pathOldProc, _, _ = proc(user, "SetWindowLongPtrW").Call(controls[idPath], ^uintptr(3), syscall.NewCallback(pathProc))
		button(idUp, "Вверх")
		control(idFiles, "LISTBOX", "", 0x00800000|0x00200000|0x00100000|0x10000|0x151)
		send.Call(controls[idFiles], 0x1a0, 0, uintptr(scaled(32)))
		control(idEmpty, "STATIC", "Откройте файл или папку", 1)
		control(idEmptyHint, "STATIC", "или перетащите один путь в окно", 1)
		label(idFormatLabel, "Формат архива")
		label(idLevelLabel, "Сжатие")
		send.Call(controls[idFormatLabel], 0x30, smallFont, 1)
		send.Call(controls[idLevelLabel], 0x30, smallFont, 1)
		control(idFormat, "COMBOBOX", "", 0x3|0x10000|0x00200000)
		for _, s := range []string{"FAW 3 · рекомендуемый", "FAW 2 · классический", "FAW 1 · совместимость", "ZIP · совместимый"} {
			send.Call(controls[idFormat], 0x143, 0, ptr(u(s)))
		}
		send.Call(controls[idFormat], 0x14e, 0, 0)
		control(idLevel, "COMBOBOX", "", 0x3|0x10000|0x00200000)
		for _, s := range []string{"Быстрый", "Хороший", "Максимальный"} {
			send.Call(controls[idLevel], 0x143, 0, ptr(u(s)))
		}
		send.Call(controls[idLevel], 0x14e, 0, 0)
		control(idPack, "BUTTON", "Упаковать", 0x10000|1)
		button(idUnpack, "Распаковать…")
		button(idCancel, "Отмена")
		control(idProgress, "msctls_progress32", "", 1)
		send.Call(controls[idProgress], 0x406, 0, 100)
		label(idStatus, "Откройте один путь · дополнительные окна доступны в меню «…»")
		send.Call(controls[idStatus], 0x30, smallFont, 1)
		proc(shell, "DragAcceptFiles").Call(hwnd, 1)
		setBusy(false)
		layout()
		return 0
	case 5:
		layout()
		return 0
	case 0x24:
		minimum := point{scaled(700), scaled(570)}
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
		case idUp:
			goUp()
		case idPack:
			doPack()
		case idUnpack:
			doUnpack()
		case idExternal:
			if currentKind == "file" {
				openExternal(currentPath)
			}
		case idFiles:
			if code == 2 {
				activateRow()
			}
		case idCancel:
			if cancelWork != nil {
				cancelWork()
				enable.Call(controls[idCancel], 0)
				status("Отмена и очистка…")
			}
		}
		return 0
	case 0x233:
		if !busy {
			n, _, _ := proc(shell, "DragQueryFileW").Call(wparam, 0xffffffff, 0, 0)
			for i := uintptr(0); i < n; i++ {
				b := make([]uint16, 32768)
				proc(shell, "DragQueryFileW").Call(wparam, i, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
				p := syscall.UTF16ToString(b)
				if i == 0 {
					openPath(p)
				} else {
					newWindow(p)
				}
			}
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
			s := p.text
			if taskKind == "scan" {
				s = strings.Replace(s, "Распаковка:", "Чтение:", 1)
			}
			status(s)
		}
		for _, v := range updates {
			if cancelWork != nil {
				cancelWork()
				cancelWork = nil
			}
			setBusy(false)
			if v.err != nil {
				if errors.Is(v.err, context.Canceled) {
					status("Отменено")
				} else {
					status("Операция не завершена")
					message("Fawusk — ошибка", v.err.Error(), 0x10)
				}
			} else if v.scan {
				archiveReady = true
				entries = v.entries
				rows = archiveChildren(entries, archivePrefix)
				refresh()
				status("Каталог прочитан · двойной клик — безопасный просмотр")
			} else if v.preview {
				openExternal(v.path)
				status("Открыт только выбранный файл · приложение Windows")
			} else {
				resultPath = v.path
				status("Готово · папка результата доступна в меню «…»")
			}
		}
		return 0
	case 0x138:
		proc(gdi, "SetBkMode").Call(wparam, 1)
		color := uintptr(0x002b2c2c)
		if lparam == controls[idSubtitle] || lparam == controls[idStatus] || lparam == controls[idEmptyHint] {
			color = 0x00645f5a
		}
		proc(gdi, "SetTextColor").Call(wparam, color)
		return bg
	case 0x10:
		if busy {
			message("Операция выполняется", "Сначала отмените операцию и дождитесь завершения очистки", 0x40)
			return 0
		}
		proc(user, "DestroyWindow").Call(hwnd)
		return 0
	case 2:
		shutdownPreviews()
		destroyIconBrushes()
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
	if len(os.Args) > 1 && os.Args[1] == "--cleanup-preview" {
		retryPreviewCleanup(os.Args[2:], 2*time.Minute)
		return
	}
	runtime.LockOSThread()
	go cleanupOrphanPreviews()
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
	mainWindow, _, e = createWindow.Call(0, ptr(cl.Class), ptr(u("Fawusk "+appVersion)), 0x00CF0000, 0x80000000, 0x80000000, uintptr(scaled(800)), uintptr(scaled(650)), 0, 0, instance, 0)
	if mainWindow == 0 {
		message("Fawusk", fmt.Sprint(e), 0x10)
		return
	}
	proc(user, "ShowWindow").Call(mainWindow, 1)
	proc(user, "UpdateWindow").Call(mainWindow)
	if len(os.Args) > 1 {
		openPath(os.Args[1])
		for _, p := range os.Args[2:] {
			newWindow(p)
		}
	}
	var m msg
	for {
		r, _, _ := proc(user, "GetMessageW").Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if m.Message == 0x100 && m.Wparam == 0x0d && m.Hwnd == controls[idFiles] && !busy {
			activateRow()
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

func doPreview(name string) {
	if busy {
		return
	}
	if e := previewAllowed(name); e != nil {
		message("Безопасный просмотр", e.Error(), 0x40)
		return
	}
	remaining := previewRoots[:0]
	for _, r := range previewRoots {
		if e := cleanupPreviewRoot(r); e != nil {
			remaining = append(remaining, r)
		}
	}
	previewRoots = remaining
	root, e := createPreviewRoot()
	if e != nil {
		message("Temp", e.Error(), 0x10)
		return
	}
	previewRoots = append(previewRoots, root)
	archive := currentPath
	ctx, cancel := context.WithCancel(context.Background())
	cancelWork = cancel
	taskKind = "preview"
	setBusy(true)
	status("Извлечение выбранного файла…")
	go func() {
		p, e := extractSelected(ctx, archive, name, root, notify)
		if e != nil {
			cleanupPreviewRoot(root)
		}
		mu.Lock()
		statusUpdates = append(statusUpdates, uiUpdate{done: true, err: e, path: p, preview: true})
		mu.Unlock()
		post.Call(mainWindow, wmUpdate, 0, 0)
	}()
}

func shutdownPreviews() {
	locked := []string{}
	for _, root := range previewRoots {
		if e := cleanupPreviewRoot(root); e != nil {
			locked = append(locked, root)
		}
	}
	if len(locked) > 0 {
		args := append([]string{"--cleanup-preview"}, locked...)
		cmd := exec.Command(programPath(), args...)
		if e := cmd.Start(); e == nil {
			cmd.Process.Release()
		}
	}
}
