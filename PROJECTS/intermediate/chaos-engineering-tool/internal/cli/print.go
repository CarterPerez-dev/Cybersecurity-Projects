// ©AngelaMos | 2026
// print.go

package cli

import (
	"fmt"
	"io"

	"github.com/CarterPerez-dev/khaos/internal/render"
	"github.com/CarterPerez-dev/khaos/internal/theme"
)

const (
	lineLayout  = "%s%s\n"
	eventLayout = "%s%s  %s\n"

	subjectFormat = "%s on %s"
	faultFormat   = "%s on %s: %v"
	leaseFormat   = "%s on %s (run %s, lease %s)"
)

func say(out io.Writer, text string) {
	fmt.Fprintf(
		out,
		lineLayout,
		render.Indent,
		theme.Fg(theme.TextNormal, text),
	)
}

func note(out io.Writer, text string) {
	fmt.Fprintf(out, lineLayout, render.Indent, theme.Fg(theme.TextDim, text))
}

func event(out io.Writer, mark string, markColor theme.Color, text string) {
	fmt.Fprintf(out, eventLayout, render.Indent,
		theme.Fg(markColor, mark), theme.Fg(theme.TextNormal, text))
}

func fixLine(out io.Writer, fix string) {
	if fix == "" {
		return
	}
	fmt.Fprintf(
		out,
		lineLayout,
		render.FixIndent,
		theme.Fg(theme.TextBright, render.FixPrefix+fix),
	)
}

func subject(kind, target string) string {
	return fmt.Sprintf(subjectFormat, kind, target)
}
