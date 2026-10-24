// ©AngelaMos | 2026
// bundle_test.go

package rangelab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocateExtractsRangeOutsideACheckout(t *testing.T) {
	working := t.TempDir()
	cache := t.TempDir()
	t.Chdir(working)
	t.Setenv(EnvComposeDir, "")
	t.Setenv("XDG_CACHE_HOME", cache)
	lab, err := Locate(Ports{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(lab.Dir, cache+string(os.PathSeparator)) {
		t.Fatalf("range did not use the private cache: %s", lab.Dir)
	}
	if err := VerifyOwned(filepath.Join(lab.Dir, composeFile)); err != nil {
		t.Fatal(err)
	}
}

func TestExplicitForeignRangeNeverFallsBackToBundle(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(EnvComposeDir, filepath.Dir(writeCompose(t, "name: foreign\n")))
	if _, err := Locate(Ports{}); err == nil {
		t.Fatal("a foreign explicit range was silently replaced")
	}
}
