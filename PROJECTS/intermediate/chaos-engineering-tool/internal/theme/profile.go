// ©AngelaMos | 2026
// profile.go

package theme

import (
	"io"
	"strings"

	"github.com/charmbracelet/colorprofile"
)

const (
	envNoColor = "NO_COLOR"
	envSep     = "="
)

func NewWriter(
	w io.Writer,
	environ []string,
	forceNoColor bool,
) *colorprofile.Writer {
	out := colorprofile.NewWriter(w, environ)
	if forceNoColor || noColorRequested(environ) {
		out.Profile = colorprofile.NoTTY
	}
	return out
}

func noColorRequested(environ []string) bool {
	for _, entry := range environ {
		name, value, ok := strings.Cut(entry, envSep)
		if ok && name == envNoColor {
			return value != ""
		}
	}
	return false
}
