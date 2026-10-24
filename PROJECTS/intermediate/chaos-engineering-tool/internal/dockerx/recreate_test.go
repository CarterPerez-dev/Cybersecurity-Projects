// ©AngelaMos | 2026
// recreate_test.go

package dockerx

import (
	"slices"
	"testing"
)

// TestEnvValueTakesTheLastOccurrence is the control for the one thing the
// environment faults mis-report if read naively. Docker deduplicates on the
// whole `KEY=VALUE` string rather than on the key, so a shadowed variable
// appears TWICE in an inspect and the process sees the last one. Measured on
// khaos's own range: the replacement's environment carried the original value
// and an empty shadow, in that order.
func TestEnvValueTakesTheLastOccurrence(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin",
		"KHAOS_SECRET=original",
		"OTHER=keep",
		"KHAOS_SECRET=",
	}

	value, found := EnvValue(environ, "KHAOS_SECRET")
	if !found {
		t.Fatal("the variable was not found at all")
	}

	if value != "" {
		t.Fatalf(
			"EnvValue = %q, want the LAST occurrence, which is empty",
			value,
		)
	}

	if _, found := EnvValue(environ, "ABSENT"); found {
		t.Error("a variable that is not there was reported as present")
	}
}

// TestWithoutVariableRemovesEVERYOccurrence matters for the same reason: one
// left behind would shadow the removal and khaos would report a fault it had
// not injected.
func TestWithoutVariableRemovesEveryOccurrence(t *testing.T) {
	environ := []string{
		"KHAOS_SECRET=original",
		"PATH=/usr/bin",
		"KHAOS_SECRET=",
		"KHAOS_SECRET=again",
	}

	out := WithoutVariable(environ, "KHAOS_SECRET")

	if _, found := EnvValue(out, "KHAOS_SECRET"); found {
		t.Fatalf("the variable survived removal: %v", out)
	}

	if !slices.Contains(out, "PATH=/usr/bin") {
		t.Error("removal took another variable with it")
	}
}

// TestShadowedEmptyAppendsRatherThanReplacing is what makes the empty fault
// reversible without khaos holding the value: the original is still underneath,
// so the revert only has to drop what was appended.
func TestShadowedEmptyAppendsRatherThanReplacing(t *testing.T) {
	environ := []string{"KHAOS_SECRET=original", "PATH=/usr/bin"}

	out := ShadowedEmpty(environ, "KHAOS_SECRET")

	if len(out) != len(environ)+1 {
		t.Fatalf("len = %d, want %d", len(out), len(environ)+1)
	}

	if out[len(out)-1] != "KHAOS_SECRET=" {
		t.Fatalf("the shadow is %q, want an empty assignment", out[len(out)-1])
	}

	if !slices.Contains(out, "KHAOS_SECRET=original") {
		t.Error(
			"the original was replaced rather than shadowed, so the revert would have nothing to restore from",
		)
	}

	// And the process reads the shadow.
	if value, _ := EnvValue(out, "KHAOS_SECRET"); value != "" {
		t.Errorf("the shadow does not win: EnvValue = %q", value)
	}

	// The input is not mutated, or a second fault would compound the first.
	if len(environ) != 2 {
		t.Errorf("ShadowedEmpty mutated its input: %v", environ)
	}
}

// TestImageDefinesIsTheOnePreconditionAnUnsetCannotWorkAround pins the measured
// reason `env_unset` refuses: the daemon merges the image's environment into
// any key a create request omits, so a variable defined in both places cannot
// be taken away by omission and khaos would report a fault the daemon had
// undone for it.
func TestImageDefinesIsTheOnePrecondition(t *testing.T) {
	imageEnv := []string{"PATH=/usr/bin", "APP_SECRET=baked-in"}

	if !ImageDefines(imageEnv, "APP_SECRET") {
		t.Error("a variable the image defines was not recognised")
	}

	if ImageDefines(imageEnv, "CONTAINER_ONLY") {
		t.Error("a variable only the container carries was blamed on the image")
	}
}

func TestHeldNamesAreDerivedRatherThanInvented(t *testing.T) {
	if got := HeldName("shop-api"); got != "shop-api"+HeldSuffix {
		t.Errorf("HeldName = %q", got)
	}

	if got := HeldFor("APP_SECRET"); got != HeldVarPrefix+"APP_SECRET" {
		t.Errorf("HeldFor = %q", got)
	}
}

func TestVariablesNamesWhatIsThere(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin",
		"B=2",
		"A=1",
		"B=3",
		"malformed-without-equals",
	}

	got := Variables(environ)
	want := []string{"A", "B", "PATH"}

	if !slices.Equal(got, want) {
		t.Fatalf("Variables = %v, want %v", got, want)
	}
}
