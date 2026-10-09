package main

import (
	"syscall"
	"unsafe"
)

const idLanguage = 132
const (
	cfgCPU    = 2001
	cfgMemory = 2002
	cfgSave   = 2003
	cfgCancel = 2004
	cfgReset  = 2005
)

var cfgWindow uintptr
var cfgControls map[int]uintptr
var cfgRegistered bool

func cfgControl(id int, class, caption string, style uintptr, x, y, w, h int) uintptr {
	r, _, _ := createWindow.Call(0, ptr(u(class)), ptr(u(caption)), 0x40000000|0x10000000|style, uintptr(scaled(x)), uintptr(scaled(y)), uintptr(scaled(w)), uintptr(scaled(h)), cfgWindow, uintptr(id), instance, 0)
	if id > 0 {
		cfgControls[id] = r
	}
	send.Call(r, 0x30, font, 1)
	return r
}
func cfgFill(s appSettings) {
	cpu := map[int]int{0: 0, 1: 1, 2: 2, 4: 3}[s.CPU]
	mem := map[int]int{256: 0, 512: 1, 1024: 2, 2048: 3}[s.MemoryMiB]
	send.Call(cfgControls[cfgCPU], 0x14e, uintptr(cpu), 0)
	send.Call(cfgControls[cfgMemory], 0x14e, uintptr(mem), 0)
}
func cfgProc(h uintptr, m uint32, w, l uintptr) uintptr {
	switch m {
	case 1:
		cfgWindow = h
		cfgControls = map[int]uintptr{}
		cfgControl(0, "STATIC", tr("Настройки ресурсов"), 0, 24, 18, 490, 26)
		cfgControl(0, "STATIC", tr("Лимит потоков CPU"), 0, 24, 65, 230, 24)
		cfgControl(cfgCPU, "COMBOBOX", "", 0x10000|3|0x200000, 300, 60, 210, 160)
		for _, s := range []string{tr("Авто (до 4)"), "1", "2", "4"} {
			send.Call(cfgControls[cfgCPU], 0x143, 0, ptr(u(s)))
		}
		cfgControl(0, "STATIC", tr("Бюджет памяти"), 0, 24, 123, 230, 24)
		cfgControl(cfgMemory, "COMBOBOX", "", 0x10000|3|0x200000, 300, 118, 210, 160)
		for _, s := range []string{"256 MiB", "512 MiB", "1024 MiB", "2048 MiB"} {
			send.Call(cfgControls[cfgMemory], 0x143, 0, ptr(u(s)))
		}
		cfgControl(0, "STATIC", tr("Мягкий бюджет памяти Go и число codec-потоков. Это не жёсткий лимит всей памяти процесса и не привязка к физическим ядрам. Память Windows и декодеров может превышать бюджет."), 0, 24, 179, 486, 110)
		cfgControl(0, "STATIC", tr("Безопасность CustomAV и очистка Temp не отключаются."), 0, 24, 293, 490, 42)
		cfgControl(cfgReset, "BUTTON", tr("По умолчанию"), 0x10000, 24, 346, 152, 36)
		cfgControl(cfgSave, "BUTTON", tr("Сохранить"), 0x10000|1, 282, 346, 110, 36)
		cfgControl(cfgCancel, "BUTTON", tr("Отмена"), 0x10000, 400, 346, 110, 36)
		cfgFill(currentSettings())
		return 0
	case 0x111:
		switch int(w & 0xffff) {
		case cfgCancel:
			proc(user, "DestroyWindow").Call(h)
		case cfgReset:
			s := defaultSettings()
			s.Language = currentSettings().Language
			cfgFill(s)
		case cfgSave:
			c, _, _ := send.Call(cfgControls[cfgCPU], 0x147, 0, 0)
			m, _, _ := send.Call(cfgControls[cfgMemory], 0x147, 0, 0)
			if c > 3 || m > 3 {
				return 0
			}
			s := currentSettings()
			s.CPU = []int{0, 1, 2, 4}[c]
			s.MemoryMiB = []int{256, 512, 1024, 2048}[m]
			if e := commitSettings(s); e != nil {
				proc(user, "MessageBoxW").Call(h, ptr(u(tr("Не удалось сохранить настройки. Изменения не применены.")+"\n\n"+e.Error())), ptr(u(tr("Настройки"))), 0x10)
				return 0
			}
			proc(user, "DestroyWindow").Call(h)
			status(resourceSummary())
		}
		return 0
	case 0x10:
		proc(user, "DestroyWindow").Call(h)
		return 0
	}
	r, _, _ := defWindow.Call(h, uintptr(m), w, l)
	return r
}
func showSettings() {
	if busy {
		return
	}
	if !cfgRegistered {
		cl := wc{Size: uint32(unsafe.Sizeof(wc{})), WndProc: syscall.NewCallback(cfgProc), Instance: instance, Background: bg, Class: u("FawuskSettingsWindow")}
		r, _, _ := proc(user, "RegisterClassExW").Call(uintptr(unsafe.Pointer(&cl)))
		if r == 0 {
			return
		}
		cfgRegistered = true
	}
	var parent rect
	proc(user, "GetWindowRect").Call(mainWindow, uintptr(unsafe.Pointer(&parent)))
	w := scaled(556)
	h := scaled(435)
	x := parent.Left + (parent.Right-parent.Left-w)/2
	y := parent.Top + (parent.Bottom-parent.Top-h)/2
	hwnd, _, _ := createWindow.Call(0x1, ptr(u("FawuskSettingsWindow")), ptr(u(tr("Настройки — Fawusk"))), 0x00C80000, uintptr(x), uintptr(y), uintptr(w), uintptr(h), mainWindow, 0, instance, 0)
	if hwnd == 0 {
		return
	}
	enable.Call(mainWindow, 0)
	defer func() { enable.Call(mainWindow, 1); proc(user, "SetForegroundWindow").Call(mainWindow) }()
	proc(user, "ShowWindow").Call(hwnd, 5)
	for {
		valid, _, _ := proc(user, "IsWindow").Call(hwnd)
		if valid == 0 {
			break
		}
		var m msg
		r, _, _ := proc(user, "GetMessageW").Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			if r == 0 {
				proc(user, "PostQuitMessage").Call(m.Wparam)
			}
			break
		}
		if m.Message == 0x100 && m.Wparam == 27 {
			proc(user, "DestroyWindow").Call(hwnd)
			continue
		}
		handled, _, _ := proc(user, "IsDialogMessageW").Call(hwnd, uintptr(unsafe.Pointer(&m)))
		if handled == 0 {
			proc(user, "TranslateMessage").Call(uintptr(unsafe.Pointer(&m)))
			proc(user, "DispatchMessageW").Call(uintptr(unsafe.Pointer(&m)))
		}
	}
}
func localizeUI() {
	for id, s := range map[int]string{idAdd: tr("Открыть…"), idUp: tr("Вверх"), idFormatLabel: tr("Формат архива"), idLevelLabel: tr("Сжатие"), idPack: tr("Упаковать"), idUnpack: tr("Распаковать…"), idCancel: tr("Отмена"), idSecurityReport: tr("Отчёт…")} {
		setText.Call(controls[id], ptr(u(s)))
	}
	for id, values := range map[int][]string{idFormat: {tr("FAW 3 · рекомендуемый"), tr("FAW 2 · классический"), tr("FAW 1 · совместимость"), tr("ZIP · совместимый")}, idLevel: {tr("Быстрый"), tr("Хороший"), tr("Максимальный")}} {
		selected, _, _ := send.Call(controls[id], 0x147, 0, 0)
		if selected > 3 {
			selected = 0
		}
		send.Call(controls[id], 0x14b, 0, 0)
		for _, s := range values {
			send.Call(controls[id], 0x143, 0, ptr(u(s)))
		}
		send.Call(controls[id], 0x14e, selected, 0)
	}
	for i, s := range []string{tr("Имя"), tr("Размер"), tr("Дата изменения")} {
		col := lvColumn{Mask: 4, Text: ptr(u(s))}
		send.Call(controls[idFiles], 0x1060, uintptr(i), uintptr(unsafe.Pointer(&col)))
	}
	lang := 0
	if currentSettings().Language == "EN" {
		lang = 1
	}
	send.Call(controls[idLanguage], 0x14e, uintptr(lang), 0)
	refresh()
	status(resourceSummary())
}
func changeLanguage() {
	n, _, _ := send.Call(controls[idLanguage], 0x147, 0, 0)
	if n > 1 {
		return
	}
	s := currentSettings()
	s.Language = []string{"RU", "EN"}[n]
	if e := commitSettings(s); e != nil {
		message(tr("Настройки"), tr("Не удалось сохранить настройки. Изменения не применены.")+"\n\n"+e.Error(), 0x10)
	}
	localizeUI()
}
