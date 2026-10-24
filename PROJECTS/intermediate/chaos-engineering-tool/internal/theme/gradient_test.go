// ©AngelaMos | 2026
// gradient_test.go

package theme

import (
	"image/color"
	"strings"
	"testing"
)

func rgb(c color.Color) (uint32, uint32, uint32) {
	r, g, b, _ := c.RGBA()
	return r >> 8, g >> 8, b >> 8
}

func TestRampEndpointsAreExact(t *testing.T) {
	const steps = 9

	ramp := Ramp(steps)
	if len(ramp) != steps {
		t.Fatalf("Ramp(%d) returned %d colors", steps, len(ramp))
	}

	wantFirstR, wantFirstG, wantFirstB := uint32(
		0x48,
	), uint32(
		0x05,
	), uint32(
		0xFF,
	)
	wantLastR, wantLastG, wantLastB := uint32(0x94), uint32(0x6E), uint32(0xFF)

	if r, g, b := rgb(
		ramp[0],
	); r != wantFirstR || g != wantFirstG ||
		b != wantFirstB {
		t.Fatalf("first stop = %02X%02X%02X, want %s", r, g, b, BrandDeep)
	}

	if r, g, b := rgb(
		ramp[steps-1],
	); r != wantLastR || g != wantLastG ||
		b != wantLastB {
		t.Fatalf("last stop = %02X%02X%02X, want %s", r, g, b, BrandLight)
	}
}

func TestRampIsMonotonicTowardTheLightStop(t *testing.T) {
	ramp := Ramp(16)

	var previous uint32
	for i, c := range ramp {
		r, _, _ := rgb(c)
		if i > 0 && r < previous {
			t.Fatalf(
				"red channel went backwards at step %d: %d after %d",
				i,
				r,
				previous,
			)
		}
		previous = r
	}
}

func TestBlockPreservesEveryVisibleRune(t *testing.T) {
	lines := []string{"abc", "d e", ""}

	out := Block(lines)

	for _, want := range []string{"abc", "d e"} {
		if !strings.Contains(out, want) {
			t.Fatalf("Block dropped or split %q: %q", want, out)
		}
	}

	if got := strings.Count(out, "\n"); got != len(lines)-1 {
		t.Fatalf("Block emitted %d newlines, want %d", got, len(lines)-1)
	}
}

func TestBlockHandlesEmptyInput(t *testing.T) {
	if got := Block(nil); got != "" {
		t.Fatalf("Block(nil) = %q, want empty", got)
	}
}

func TestBlockEmitsOneStyleSpanPerRow(t *testing.T) {
	const rows = 3

	out := Block([]string{"aaa", "bbb", "ccc"})

	if got := strings.Count(out, "\x1b[38"); got != rows {
		t.Fatalf(
			"Block emitted %d color sequences for %d rows; a vertical gradient needs exactly one per row",
			got,
			rows,
		)
	}
}
