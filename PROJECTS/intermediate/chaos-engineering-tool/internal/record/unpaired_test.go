// ©AngelaMos | 2026
// unpaired_test.go

package record

import (
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/experiment"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

func TestUnpairedAndUncountableObservationsRemainInTheRecord(t *testing.T) {
	observation := experiment.Observation{}
	observation.Fault.Record(probe.Outcome{
		Credential:  probe.Revoked,
		Disposition: probe.Accepted,
	})
	observation.Recovery.Record(probe.Outcome{
		Credential:  probe.Valid,
		Disposition: probe.ProbeFailed,
	})
	got := windows(observation)
	if got["fault"].Streams["revoked"].Distribution["accepted"] != 1 {
		t.Fatal("unpaired revoked acceptance omitted")
	}
	if _, ok := got["recovery"]; !ok {
		t.Fatal("uncountable observations omitted")
	}
}
