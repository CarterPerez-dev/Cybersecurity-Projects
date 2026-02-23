// ©AngelaMos | 2026
// symbol.go

package ui

import "strings"

const (
	Arrow       = "\u2192"
	ArrowRight  = "\u25b8"
	ArrowUp     = "\u2191"
	Diamond     = "\u25c6"
	Gem         = "\u25c8"
	Star        = "\u2726"
	TriangleUp  = "\u25b2"
	Check       = "\u2713"
	Cross       = "\u2717"
	Timer       = "\u23f1"
	Warning     = "\u26a0"
	Shield      = "\u25c9"
	DividerChar = "\u2501"
)

func HRule(width int) string {
	return strings.Repeat(DividerChar, width)
}
