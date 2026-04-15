/*
©AngelaMos | 2026
color.go

ANSI color sprint functions for terminal output

Exposes pre-built color functions from fatih/color for all severity
levels and UI elements used by the report formatter and banner.
*/

package ui

import "github.com/fatih/color"

var (
	Red     = color.New(color.FgRed).SprintFunc()
	Green   = color.New(color.FgGreen).SprintFunc()
	Yellow  = color.New(color.FgYellow).SprintFunc()
	Blue    = color.New(color.FgBlue).SprintFunc()
	Magenta = color.New(color.FgMagenta).SprintFunc()
	Cyan    = color.New(color.FgCyan).SprintFunc()
	White   = color.New(color.FgWhite).SprintFunc()

	HiRed   = color.New(color.FgHiRed).SprintFunc()
	HiGreen = color.New(color.FgHiGreen).SprintFunc()
	HiCyan  = color.New(color.FgHiCyan).SprintFunc()
	HiWhite = color.New(color.FgHiWhite).SprintFunc()

	RedBold = color.New(
		color.FgRed, color.Bold,
	).SprintFunc()
	YellowBold = color.New(
		color.FgYellow, color.Bold,
	).SprintFunc()
	CyanBold = color.New(
		color.FgCyan, color.Bold,
	).SprintFunc()
	GreenBold = color.New(
		color.FgGreen, color.Bold,
	).SprintFunc()
	MagentaBold = color.New(
		color.FgMagenta, color.Bold,
	).SprintFunc()
	WhiteBold = color.New(
		color.FgWhite, color.Bold,
	).SprintFunc()
	HiRedBold = color.New(
		color.FgHiRed, color.Bold,
	).SprintFunc()

	Dim       = color.New(color.Faint).SprintFunc()
	DimItalic = color.New(
		color.Faint, color.Italic,
	).SprintFunc()
	HiBlackItalic = color.New(
		color.FgHiBlack, color.Italic,
	).SprintFunc()
)
