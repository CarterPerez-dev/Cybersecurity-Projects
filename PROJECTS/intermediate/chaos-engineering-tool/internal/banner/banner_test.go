// ©AngelaMos | 2026
// banner_test.go

package banner

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/theme"
	"github.com/CarterPerez-dev/khaos/internal/version"
)

const (
	wantRows    = 9
	wantColumns = 43
)

func TestArtDimensionsAreLocked(t *testing.T) {
	lines := Lines()

	if len(lines) != wantRows {
		t.Fatalf("wordmark has %d rows, want %d", len(lines), wantRows)
	}

	widest := 0
	for _, line := range lines {
		if w := len([]rune(line)); w > widest {
			widest = w
		}
	}

	if widest != wantColumns {
		t.Fatalf("wordmark is %d columns wide, want %d", widest, wantColumns)
	}
}

func TestArtCarriesNoFileHeader(t *testing.T) {
	for i, line := range Lines() {
		if strings.Contains(line, "AngelaMos") || strings.HasPrefix(line, "#") {
			t.Fatalf(
				"line %d looks like a file header and would print inside the banner: %q",
				i,
				line,
			)
		}
	}
}

func TestRenderIncludesVersionAndAuthor(t *testing.T) {
	out := Render()

	for _, want := range []string{version.Tagline, version.Author, version.Version()} {
		if !strings.Contains(out, want) {
			t.Fatalf("banner is missing %q", want)
		}
	}
}

func TestRenderThroughNoColorWriterIsPlainText(t *testing.T) {
	var buf bytes.Buffer
	w := theme.NewWriter(
		&buf,
		[]string{"CLICOLOR_FORCE=1", "COLORTERM=truecolor"},
		true,
	)

	if err := Write(w); err != nil {
		t.Fatalf("write: %v", err)
	}

	if strings.Contains(buf.String(), "\x1b") {
		t.Fatal("banner emitted escape sequences through a no-color writer")
	}

	if !strings.Contains(buf.String(), "█") {
		t.Fatal("the block glyphs did not survive stripping")
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	if Render() != Render() {
		t.Fatal("banner output changed between two calls")
	}
}

func TestWritePropagatesWriterErrors(t *testing.T) {
	if err := Write(failingWriter{}); err == nil {
		t.Fatal("Write swallowed a writer error")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
