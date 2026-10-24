// ©AngelaMos | 2026
// render.go

package render

import (
	"strings"

	"charm.land/lipgloss/v2"
)

const (
	Indent    = "  "
	FixIndent = "       "
	FixPrefix = "fix: "

	Gutter   = 2
	ellipsis = "..."
	space    = " "
)

func Width(s string) int {
	return lipgloss.Width(s)
}

func Pad(s string, width int) string {
	used := Width(s)
	if used >= width {
		return s
	}
	return s + strings.Repeat(space, width-used)
}

func Truncate(s string, width int) string {
	if width <= 0 {
		return ""
	}

	if Width(s) <= width {
		return s
	}

	marker := []rune(ellipsis)
	if width <= len(marker) {
		return string(marker[:width])
	}

	runes := []rune(s)
	for len(runes) > 0 {
		runes = runes[:len(runes)-1]
		if candidate := string(runes) + ellipsis; Width(candidate) <= width {
			return candidate
		}
	}

	return ellipsis
}

func Cell(s string, width int) string {
	return Pad(Truncate(s, width-Gutter), width)
}
