package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

const (
	idSecurity       = 129
	idSecurityReport = 130
)

var currentAV *avResult
var avPhase string

func avCaption() string {
	if currentKind != "archive" {
		return "  CustomAV · проверка при открытии и создании архива\n  Статический анализ, без запуска файлов"
	}
	if avPhase != "" {
		return "  " + avPhase + "\n  Файлы не запускаются · можно отменить проверку"
	}
	if currentAV == nil {
		return "  Архив не проверен\n  Просмотр файлов и распаковка недоступны"
	}
	detail := fmt.Sprintf("Проверено записей: %d · подробности в отчёте", len(currentAV.Files))
	if currentAV.blocked() {
		names := []string{}
		seen := map[string]bool{}
		for _, f := range currentAV.Findings {
			if (f.Category == "malware" || f.Category == "test") && !seen[f.Path] {
				seen[f.Path] = true
				names = append(names, avShort(f.Path, 42))
				if len(names) == 2 {
					break
				}
			}
		}
		if len(names) > 0 {
			detail = "Файлы: " + avShort(strings.Join(names, "; "), 78)
		}
	}
	return "  " + currentAV.label() + "\n  " + detail
}
func securityColors() (uint32, uint32) {
	state := "incomplete"
	if currentKind == "archive" && currentAV != nil && avPhase == "" {
		state = currentAV.state()
	}
	switch state {
	case "clear":
		return 0x00446824, 0x00ECF1E8
	case "blocked":
		return 0x0025259C, 0x00E7E9FC
	case "test", "review":
		return 0x001F5278, 0x00DEEBFB
	default:
		return 0x00544E48, 0x00EDEFF0
	}
}
func refreshSecurity() {
	setText.Call(controls[idSecurity], ptr(u(avCaption())))
	enable.Call(controls[idSecurityReport], boolParam(!busy && currentKind == "archive" && currentAV != nil))
	proc(user, "InvalidateRect").Call(controls[idSecurity], 0, 1)
}
func securityActionAllowed(action string) bool {
	if currentAV == nil || !currentAV.permitted() {
		message("CustomAV", "Операция недоступна до полной проверки без блокирующих находок.\n\n"+avCaption(), 0x30)
		return false
	}
	if currentAV.ReviewSignal > 0 {
		return message("CustomAV — ручная проверка", "Есть предупреждения CustomAV. Они не доказывают заражение, но требуют проверки.\n\nОперация: "+action+". Продолжить?", 0x34) == 6
	}
	return true
}
func showAVReport() {
	if currentAV != nil {
		message("Отчёт CustomAV", currentAV.summary(), 0x40)
	}
}
func saveAVReport() {
	if currentAV == nil {
		return
	}
	p := fileDialog(true, false, "Отчёт JSON|*.json||", "Сохранить полный отчёт CustomAV", filepath.Join(filepath.Dir(currentPath), "Fawusk-CustomAV-report.json"), "json")
	if len(p) == 0 {
		return
	}
	b, e := json.MarshalIndent(currentAV, "", "  ")
	if e != nil {
		message("Отчёт", e.Error(), 0x10)
		return
	}
	f, e := os.OpenFile(p[0], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e == nil {
		_, e = f.Write(b)
		ce := f.Close()
		if e == nil {
			e = ce
		}
	}
	if e != nil {
		message("Отчёт", e.Error(), 0x10)
	} else {
		status("Полный JSON-отчёт сохранён")
	}
}
func avEntryColor(name string) (uint32, bool) {
	if currentKind != "archive" || currentAV == nil {
		return 0, false
	}
	state := ""
	priority := map[string]int{"clear": 1, "review": 2, "incomplete": 3, "test": 4, "blocked": 5}
	for _, f := range currentAV.Files {
		if f.Path == name || strings.HasPrefix(f.Path, name+"/") || strings.HasPrefix(f.Path, name+"!/") {
			if priority[f.State] > priority[state] {
				state = f.State
			}
		}
	}
	colors := map[string]uint32{"clear": 0x00446824, "review": 0x001F5278, "test": 0x001F5278, "incomplete": 0x00665E55, "blocked": 0x0025259C}
	if !currentAV.Complete && (state == "clear" || state == "review") {
		state = "incomplete"
	}
	c, ok := colors[state]
	return c, ok
}
func securityStatic(dc uintptr) uintptr {
	fg, bg := securityColors()
	proc(gdi, "SetBkMode").Call(dc, 2)
	proc(gdi, "SetTextColor").Call(dc, uintptr(fg))
	proc(gdi, "SetBkColor").Call(dc, uintptr(bg))
	return iconBrush(bg)
}
func paintTriangle(dc uintptr, pts []point, c uint32) {
	brush := iconBrush(c)
	old, _, _ := proc(gdi, "SelectObject").Call(dc, brush)
	pen, _, _ := proc(gdi, "GetStockObject").Call(8)
	oldpen, _, _ := proc(gdi, "SelectObject").Call(dc, pen)
	proc(gdi, "Polygon").Call(dc, uintptr(unsafe.Pointer(&pts[0])), uintptr(len(pts)))
	proc(gdi, "SelectObject").Call(dc, oldpen)
	proc(gdi, "SelectObject").Call(dc, old)
}
