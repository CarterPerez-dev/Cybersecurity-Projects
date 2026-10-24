// ©AngelaMos | 2026
// gradient.go

package theme

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
)

const newline = '\n'

func Ramp(steps int) []color.Color {
	return lipgloss.Blend1D(
		steps,
		lipgloss.Color(string(BrandDeep)),
		lipgloss.Color(string(BrandLight)),
	)
}

func Block(lines []string) string {
	if len(lines) == 0 {
		return ""
	}

	ramp := Ramp(len(lines))

	var b strings.Builder
	for i, line := range lines {
		b.WriteString(lipgloss.NewStyle().Foreground(ramp[i]).Render(line))
		if i < len(lines)-1 {
			b.WriteRune(newline)
		}
	}

	return b.String()
}

func Fg(c Color, s string) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color(string(c))).Render(s)
}
