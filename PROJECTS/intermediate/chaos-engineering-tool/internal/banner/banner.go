// ©AngelaMos | 2026
// banner.go

package banner

import (
	_ "embed"
	"io"
	"strings"

	"github.com/CarterPerez-dev/khaos/internal/theme"
	"github.com/CarterPerez-dev/khaos/internal/version"
)

//go:embed khaos.ascii
var art string

const (
	indent  = "  "
	metaGap = "   "
	nl      = "\n"
)

func Lines() []string {
	return strings.Split(strings.TrimRight(art, nl), nl)
}

func Render() string {
	var b strings.Builder

	b.WriteString(theme.Block(Lines()))
	b.WriteString(nl)
	b.WriteString(nl)

	b.WriteString(indent)
	b.WriteString(theme.Fg(theme.TextDim, version.Tagline))
	b.WriteString(metaGap)
	b.WriteString(theme.Fg(theme.TextBright, version.Version()))
	b.WriteString(nl)

	b.WriteString(indent)
	b.WriteString(theme.Fg(theme.TextDim, version.Author))
	b.WriteString(nl)

	return b.String()
}

func Write(w io.Writer) error {
	_, err := io.WriteString(w, Render())
	return err
}
