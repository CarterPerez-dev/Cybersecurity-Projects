/*
©AngelaMos | 2026
color.go

Terminal color helpers backed by fatih/color
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
	Dim     = color.New(color.Faint).SprintFunc()
	Bold    = color.New(color.Bold).SprintFunc()
)
