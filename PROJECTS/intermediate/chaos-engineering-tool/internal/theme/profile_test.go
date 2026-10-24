// ©AngelaMos | 2026
// profile_test.go

package theme

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

const sample = "khaos"

func TestNoColorRequested(t *testing.T) {
	cases := []struct {
		name    string
		environ []string
		want    bool
	}{
		{"absent", []string{"TERM=xterm-256color"}, false},
		{"set to one", []string{"NO_COLOR=1"}, true},
		{"set to zero is still set", []string{"NO_COLOR=0"}, true},
		{"set to arbitrary value", []string{"NO_COLOR=please"}, true},
		{"present but empty means color allowed", []string{"NO_COLOR="}, false},
		{"prefix match must not count", []string{"NO_COLORS=1"}, false},
		{"suffix match must not count", []string{"XNO_COLOR=1"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := noColorRequested(tc.environ); got != tc.want {
				t.Fatalf(
					"noColorRequested(%q) = %v, want %v",
					tc.environ,
					got,
					tc.want,
				)
			}
		})
	}
}

func TestNewWriterStripsEverythingWhenNoColorRequested(t *testing.T) {
	forcing := []string{
		"CLICOLOR_FORCE=1",
		"COLORTERM=truecolor",
		"TERM=xterm-256color",
	}

	cases := []struct {
		name    string
		environ []string
		force   bool
	}{
		{
			"NO_COLOR beats CLICOLOR_FORCE",
			append([]string{"NO_COLOR=1"}, forcing...),
			false,
		},
		{"explicit force beats CLICOLOR_FORCE", forcing, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf, tc.environ, tc.force)

			if _, err := io.WriteString(w, Fg(BrandDeep, sample)); err != nil {
				t.Fatalf("write: %v", err)
			}

			if got := buf.String(); got != sample {
				t.Fatalf(
					"got %q, want %q with no escape sequences at all",
					got,
					sample,
				)
			}
		})
	}
}

func TestNewWriterKeepsColorWhenForced(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(
		&buf,
		[]string{
			"CLICOLOR_FORCE=1",
			"COLORTERM=truecolor",
			"TERM=xterm-256color",
		},
		false,
	)

	if _, err := io.WriteString(w, Fg(BrandDeep, sample)); err != nil {
		t.Fatalf("write: %v", err)
	}

	if !strings.Contains(buf.String(), "\x1b[") {
		t.Fatal(
			"no escape sequence survived, so the stripping tests above prove nothing",
		)
	}
}
