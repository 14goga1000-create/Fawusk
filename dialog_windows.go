package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

type guid struct {
	A    uint32
	B, C uint16
	D    [8]byte
}
type comObject struct{ V *[32]uintptr }

func (o *comObject) call(i int, args ...uintptr) uint32 {
	a := append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)
	r, _, _ := syscall.SyscallN(o.V[i], a...)
	return uint32(r)
}
func (o *comObject) release() {
	if o != nil {
		o.call(2)
	}
}

var shellItemID = guid{0x43826d1e, 0xe718, 0x42ee, [8]byte{0xbc, 0x55, 0xa1, 0xe2, 0x61, 0xc3, 0x7b, 0xfe}}

func wideString(p *uint16) string {
	if p == nil {
		return ""
	}
	var s []uint16
	for i := 0; i < 32768; i++ {
		v := *(*uint16)(unsafe.Add(unsafe.Pointer(p), i*2))
		if v == 0 {
			break
		}
		s = append(s, v)
	}
	return syscall.UTF16ToString(s)
}
func modernDialog(save, folder bool, filter, title, initial, ext string) (string, error) {
	class := guid{0xdc1c5a9c, 0xe88a, 0x4dde, [8]byte{0xa5, 0xa1, 0x60, 0xf8, 0x2a, 0x20, 0xae, 0xf7}}
	iid := guid{0xd57c7288, 0xd4ad, 0x4768, [8]byte{0xbe, 0x02, 0x9d, 0x96, 0x95, 0x32, 0xd9, 0x60}}
	if save {
		class = guid{0xc0b4e2f3, 0xba21, 0x4773, [8]byte{0x8d, 0xba, 0x33, 0x5e, 0xc9, 0x46, 0xeb, 0x8b}}
		iid = guid{0x84bccd23, 0x5fde, 0x4cdb, [8]byte{0xae, 0xa4, 0xaf, 0x64, 0xb8, 0x3d, 0x78, 0xab}}
	}
	var dlg *comObject
	r, _, _ := proc(ole, "CoCreateInstance").Call(uintptr(unsafe.Pointer(&class)), 0, 1, uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&dlg)))
	if uint32(r) != 0 || dlg == nil {
		return "", fmt.Errorf("Не удалось открыть современный диалог: 0x%x", uint32(r))
	}
	defer dlg.release()
	options := uintptr(0x40 | 0x800 | 0x8)
	if !save {
		options |= 0x1000
	}
	if folder {
		options |= 0x20
	}
	if hr := dlg.call(9, options); hr != 0 {
		return "", fmt.Errorf("Настройки диалога: 0x%x", hr)
	}
	dlg.call(17, ptr(u(title)))
	type spec struct{ Name, Pattern *uint16 }
	var filters []spec
	if !folder {
		parts := strings.Split(filter, "|")
		for i := 0; i+1 < len(parts); i += 2 {
			if parts[i] == "" {
				break
			}
			filters = append(filters, spec{u(parts[i]), u(parts[i+1])})
		}
		if len(filters) > 0 {
			dlg.call(4, uintptr(len(filters)), uintptr(unsafe.Pointer(&filters[0])))
		}
		if ext != "" {
			dlg.call(22, ptr(u(ext)))
		}
	}
	if initial != "" {
		dir := initial
		if !folder {
			dir = filepath.Dir(initial)
			dlg.call(15, ptr(u(filepath.Base(initial))))
		}
		var item *comObject
		hr, _, _ := proc(shell, "SHCreateItemFromParsingName").Call(ptr(u(dir)), 0, uintptr(unsafe.Pointer(&shellItemID)), uintptr(unsafe.Pointer(&item)))
		if uint32(hr) == 0 && item != nil {
			dlg.call(12, uintptr(unsafe.Pointer(item)))
			item.release()
		}
	}
	hr := dlg.call(3, mainWindow)
	runtime.KeepAlive(filters)
	if hr == 0x800704c7 {
		return "", nil
	}
	if hr != 0 {
		return "", fmt.Errorf("Диалог: 0x%x", hr)
	}
	var item *comObject
	if hr = dlg.call(20, uintptr(unsafe.Pointer(&item))); hr != 0 || item == nil {
		return "", fmt.Errorf("Результат диалога: 0x%x", hr)
	}
	defer item.release()
	var p *uint16
	if hr = item.call(5, 0x80058000, uintptr(unsafe.Pointer(&p))); hr != 0 {
		return "", fmt.Errorf("Путь диалога: 0x%x", hr)
	}
	result := wideString(p)
	proc(ole, "CoTaskMemFree").Call(uintptr(unsafe.Pointer(p)))
	return result, nil
}
func fileDialog(save, multi bool, filter, title, initial, ext string) []string {
	p, e := modernDialog(save, false, filter, title, initial, ext)
	if e != nil {
		message("Выбор файла", e.Error(), 0x10)
		return nil
	}
	if p == "" {
		return nil
	}
	return []string{p}
}
func folderDialog(title string) string {
	p, e := modernDialog(false, true, "", title, "", "")
	if e != nil {
		message("Выбор папки", e.Error(), 0x10)
	}
	return p
}
func registerFAWOpenWith() error {
	exe, e := filepath.Abs(programPath())
	if e != nil {
		return e
	}
	adv := syscall.NewLazyDLL("advapi32.dll")
	write := func(sub, name, value string) error {
		var key uintptr
		r, _, _ := adv.NewProc("RegCreateKeyExW").Call(uintptr(syscall.HKEY_CURRENT_USER), ptr(u(sub)), 0, 0, 0, 2, 0, uintptr(unsafe.Pointer(&key)), 0)
		if r != 0 {
			return fmt.Errorf("Реестр: код %d", r)
		}
		defer adv.NewProc("RegCloseKey").Call(key)
		v := syscall.StringToUTF16(value)
		var n uintptr
		if name != "" {
			n = ptr(u(name))
		}
		r, _, _ = adv.NewProc("RegSetValueExW").Call(key, n, 0, 1, uintptr(unsafe.Pointer(&v[0])), uintptr(len(v)*2))
		if r != 0 {
			return fmt.Errorf("Реестр: код %d", r)
		}
		return nil
	}
	for _, v := range [][3]string{{`Software\Classes\Fawusk.FAW`, "", "Fawusk archive"}, {`Software\Classes\Fawusk.FAW\DefaultIcon`, "", `"` + exe + `",0`}, {`Software\Classes\Fawusk.FAW\shell\open\command`, "", `"` + exe + `" "%1"`}, {`Software\Classes\.faw\OpenWithProgids`, "Fawusk.FAW", ""}} {
		if e = write(v[0], v[1], v[2]); e != nil {
			return e
		}
	}
	proc(shell, "SHChangeNotify").Call(0x08000000, 0, 0, 0)
	return nil
}
