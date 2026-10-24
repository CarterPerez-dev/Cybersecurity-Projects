// ©AngelaMos | 2026
// render_test.go

package render

import "testing"

const column = 26

func TestCellIsExactlyOneWidthForEveryScript(t *testing.T) {
	names := []string{
		"shop-api-1",
		"cafe-api-1",
		"café-api-1",
		"日本語-api",
		"日本語サービス-api-1",
		"a-very-long-container-name-that-overflows-the-column",
		"",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			got := Width(Cell(name, column))
			if got != column {
				t.Fatalf(
					"Cell(%q, %d) occupies %d display columns, want %d",
					name,
					column,
					got,
					column,
				)
			}
		})
	}
}

func TestPadMeasuresDisplayWidthNotBytes(t *testing.T) {
	const accented = "café-api-1"

	padded := Pad(accented, column)
	if got := Width(padded); got != column {
		t.Fatalf(
			"a multi-byte name padded to %d display columns, want %d",
			got,
			column,
		)
	}

	if len(padded) == column {
		t.Fatal(
			"padding matched the byte count, which means it is counting bytes rather than display width",
		)
	}
}

func TestTruncateNeverPanicsOnNarrowWidths(t *testing.T) {
	for width := -3; width <= 6; width++ {
		got := Truncate("abcdefghij", width)
		if width <= 0 {
			if got != "" {
				t.Fatalf(
					"Truncate at width %d returned %q, want empty",
					width,
					got,
				)
			}
			continue
		}
		if Width(got) > width {
			t.Fatalf(
				"Truncate(_, %d) returned %q which is %d wide",
				width,
				got,
				Width(got),
			)
		}
	}
}

func TestTruncateLeavesShortStringsAlone(t *testing.T) {
	const short = "api"
	if got := Truncate(short, column); got != short {
		t.Fatalf("Truncate(%q) = %q, want it unchanged", short, got)
	}
}

func TestTruncateMarksWhatItCut(t *testing.T) {
	got := Truncate("a-very-long-container-name", 12)
	if Width(got) > 12 {
		t.Fatalf("%q is wider than requested", got)
	}
	if len(got) < len(ellipsis) || got[len(got)-len(ellipsis):] != ellipsis {
		t.Fatalf(
			"%q does not end in %q, so the operator cannot tell it was cut",
			got,
			ellipsis,
		)
	}
}
