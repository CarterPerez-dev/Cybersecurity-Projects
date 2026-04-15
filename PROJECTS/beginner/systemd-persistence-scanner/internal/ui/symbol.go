/*
©AngelaMos | 2026
symbol.go

Named Unicode symbol constants and horizontal rule helper for terminal output

Centralizes every UI glyph used across the CLI so report formatters
stay readable without hard-coded Unicode literals.
*/

package ui

import "strings"

const (
	Arrow       = "→"
	ArrowRight  = "▸"
	Check       = "✓"
	Cross       = "✗"
	Diamond     = "◆"
	DividerChar = "━"
	Dot         = "●"
	Timer       = "⏱"
	Shield      = "🛡"
)

func HRule(width int) string {
	return strings.Repeat(DividerChar, width)
}
