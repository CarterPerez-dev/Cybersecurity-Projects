// ©AngelaMos | 2026
// client_test.go

package pypi

import (
	"testing"
)

func TestNormalizeName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"requests", "requests"},
		{"Requests", "requests"},
		{"REQUESTS", "requests"},
		{"some-package", "some-package"},
		{"some_package", "some-package"},
		{"some.package", "some-package"},
		{"Some_Package", "some-package"},
		{"my---package", "my-package"},
		{"my__.package", "my-package"},
		{"Flask", "flask"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()

			got := NormalizeName(tt.input)
			if got != tt.want {
				t.Errorf(
					"NormalizeName(%q) = %q, want %q",
					tt.input, got, tt.want,
				)
			}
		})
	}
}
