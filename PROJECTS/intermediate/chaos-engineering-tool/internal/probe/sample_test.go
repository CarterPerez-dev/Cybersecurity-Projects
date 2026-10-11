// ©AngelaMos | 2026
// sample_test.go

package probe

import (
	"testing"
	"time"
)

func streamOf(dispositions ...Disposition) Stream {
	s := Stream{Credential: Invalid}
	base := time.Now().UTC()

	for i, d := range dispositions {
		s.Outcomes = append(s.Outcomes, Outcome{
			At:          base.Add(time.Duration(i) * time.Second),
			Credential:  Invalid,
			Disposition: d,
		})
	}

	return s
}

func TestAcceptedAfterRejectedCountsOrderNotTotals(t *testing.T) {
	cases := []struct {
		name         string
		dispositions []Disposition
		want         int
	}{
		{
			name:         "never accepted",
			dispositions: []Disposition{Rejected, Rejected, Rejected},
			want:         0,
		},
		{
			name:         "rejected then accepted is the control giving way",
			dispositions: []Disposition{Rejected, Rejected, Accepted, Accepted},
			want:         2,
		},
		{
			// This is the case that separates ordering from counting. A single
			// early acceptance followed by consistent enforcement is a target
			// that warmed up, not a control that stopped enforcing. A naive
			// "was anything accepted" check calls this a failure to enforce.
			name:         "accepted first, then enforced consistently",
			dispositions: []Disposition{Accepted, Rejected, Rejected, Rejected},
			want:         0,
		},
		{
			name:         "accepted, enforced, then gave way again",
			dispositions: []Disposition{Accepted, Rejected, Accepted},
			want:         1,
		},
		{
			name:         "unreachable samples do not establish enforcement",
			dispositions: []Disposition{Unavailable, Accepted, Unavailable},
			want:         0,
		},
		{
			name:         "no samples at all",
			dispositions: nil,
			want:         0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := streamOf(tc.dispositions...).AcceptedAfterRejected()
			if got != tc.want {
				t.Fatalf(
					"got %d, want %d; this is the test that distinguishes "+
						"'a credential it had already refused was later honoured' from "+
						"'something succeeded at some point'",
					got,
					tc.want,
				)
			}
		})
	}
}

func TestCountAndAnyAgree(t *testing.T) {
	s := streamOf(Accepted, Rejected, Rejected, Unavailable)

	if s.Count(Rejected) != 2 {
		t.Fatalf("Count(Rejected) = %d, want 2", s.Count(Rejected))
	}

	if !s.Any(Unavailable) {
		t.Fatal("Any(Unavailable) was false with an unreachable sample present")
	}

	if s.Any(Redirected) {
		t.Fatal("Any reported a disposition that never occurred")
	}

	if s.Len() != 4 {
		t.Fatalf("Len() = %d, want 4", s.Len())
	}
}

func TestWindowLengthIsThePairedCount(t *testing.T) {
	w := Window{}

	w.Record(Outcome{Credential: Valid, Disposition: Accepted})
	w.Record(Outcome{Credential: Valid, Disposition: Accepted})
	w.Record(Outcome{Credential: Invalid, Disposition: Rejected})

	if w.Len() != 1 {
		t.Fatalf(
			"Len() = %d, want 1; a window is only as long as its shorter stream, because "+
				"a verdict needs both halves of the pair",
			w.Len(),
		)
	}
}

func TestRecordRoutesByCredential(t *testing.T) {
	w := Window{}

	w.Record(Outcome{Credential: Valid, Disposition: Accepted})
	w.Record(Outcome{Credential: Invalid, Disposition: Rejected})

	if w.Valid.Len() != 1 || w.Invalid.Len() != 1 {
		t.Fatalf(
			"valid=%d invalid=%d, want 1 and 1",
			w.Valid.Len(),
			w.Invalid.Len(),
		)
	}

	if w.Valid.Outcomes[0].Disposition != Accepted {
		t.Fatal("the valid outcome was routed into the wrong stream")
	}

	if w.Invalid.Outcomes[0].Disposition != Rejected {
		t.Fatal("the invalid outcome was routed into the wrong stream")
	}
}

func TestRejectedAfterCountsTheTargetGivingUp(t *testing.T) {
	cases := []struct {
		name         string
		seed         bool
		dispositions []Disposition
		want         int
	}{
		{
			// The case the range exposed: a gateway serves from its decision
			// cache for the first seconds of an outage and then starts
			// refusing. Asking only whether it ever served calls that a clean
			// survival.
			name: "served from cache, then refused",
			seed: true,
			dispositions: []Disposition{
				Accepted,
				Accepted,
				Rejected,
				Rejected,
				Rejected,
			},
			want: 3,
		},
		{
			name:         "served throughout",
			seed:         true,
			dispositions: []Disposition{Accepted, Accepted, Accepted},
			want:         0,
		},
		{
			name:         "refused throughout, with no prior acceptance to lose",
			seed:         false,
			dispositions: []Disposition{Rejected, Rejected},
			want:         0,
		},
		{
			name:         "refused throughout, having served in the baseline",
			seed:         true,
			dispositions: []Disposition{Rejected, Rejected},
			want:         2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Stream{Credential: Valid}
			for _, d := range tc.dispositions {
				s.Outcomes = append(
					s.Outcomes,
					Outcome{Credential: Valid, Disposition: d},
				)
			}

			if got := s.RejectedAfter(tc.seed); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestProbeFailuresAreNotChargedToTheTarget(t *testing.T) {
	s := Stream{Credential: Invalid, Outcomes: []Outcome{
		{Disposition: Rejected},
		{Disposition: ProbeFailed},
		{Disposition: Rejected},
	}}

	if s.Countable() != 2 {
		t.Fatalf(
			"Countable() = %d, want 2; khaos's own failure is not a target outcome and "+
				"must not enter any rate",
			s.Countable(),
		)
	}

	if ProbeFailed.Answered() {
		t.Fatal("a khaos-side failure was counted as the target answering")
	}
}

// The bounded-stale pattern is a PASS, and a plain count of acceptances reports
// it as a bypass. These are the three shapes that have to separate.
func TestAcceptedSinceLastRefusalSeparatesABoundedCacheFromABrokenOne(
	t *testing.T,
) {
	cases := []struct {
		name     string
		sequence []Disposition
		want     int
	}{
		{
			name: "a bounded cache lapses and stays lapsed",
			sequence: []Disposition{
				Accepted,
				Accepted,
				Rejected,
				Rejected,
				Rejected,
			},
			want: 0,
		},
		{
			name:     "a cache with no expiry never lapses",
			sequence: []Disposition{Accepted, Accepted, Accepted, Accepted},
			want:     4,
		},
		{
			name: "a cache that re-populates after refusing is its own bug",
			sequence: []Disposition{
				Accepted,
				Rejected,
				Rejected,
				Accepted,
				Accepted,
			},
			want: 2,
		},
		{
			name:     "a target that refused throughout",
			sequence: []Disposition{Rejected, Rejected, Rejected},
			want:     0,
		},
		{
			name:     "khaos's own failures do not reset the latch or count",
			sequence: []Disposition{Accepted, ProbeFailed, Accepted},
			want:     2,
		},
		{
			name:     "an empty window",
			sequence: nil,
			want:     0,
		},
	}

	for _, each := range cases {
		t.Run(each.name, func(t *testing.T) {
			stream := Stream{Credential: Revoked}
			for _, disposition := range each.sequence {
				stream.Outcomes = append(
					stream.Outcomes,
					Outcome{Disposition: disposition},
				)
			}

			if got := stream.AcceptedSinceLastRefusal(); got != each.want {
				t.Fatalf(
					"AcceptedSinceLastRefusal() = %d, want %d",
					got,
					each.want,
				)
			}
		})
	}
}

// The distinction has to be live: if it agreed with a plain count on every
// sequence, the order-sensitivity would be decoration.
func TestAcceptedSinceLastRefusalDisagreesWithAPlainCount(t *testing.T) {
	bounded := Stream{Credential: Revoked, Outcomes: []Outcome{
		{Disposition: Accepted},
		{Disposition: Accepted},
		{Disposition: Rejected},
		{Disposition: Rejected},
	}}

	if bounded.Count(Accepted) == bounded.AcceptedSinceLastRefusal() {
		t.Fatal(
			"the order-sensitive count agrees with the plain count on a bounded cache, " +
				"so nothing distinguishes the defensible pattern from the broken one",
		)
	}
}

// The case AcceptedSinceLastRefusal destroys. Enforcement resumed, the
// invalidated credential got through anyway, and a later refusal erased it.
func TestAcceptedDespiteLapseKeepsAReacceptanceALaterRefusalWouldErase(
	t *testing.T,
) {
	cases := []struct {
		name         string
		sequence     []Disposition
		despiteLapse int
		sinceRefusal int
	}{
		{
			"never lapsed",
			[]Disposition{Accepted, Accepted, Accepted, Accepted},
			4,
			4,
		},
		{
			"lapsed and stayed lapsed",
			[]Disposition{Accepted, Accepted, Rejected, Rejected},
			0,
			0,
		},
		{
			"came back after a lapse",
			[]Disposition{Rejected, Accepted, Rejected},
			1,
			0,
		},
		{
			"came back and stayed",
			[]Disposition{Accepted, Rejected, Rejected, Accepted, Accepted},
			2,
			2,
		},
		{"refused throughout", []Disposition{Rejected, Rejected}, 0, 0},
		{"empty", nil, 0, 0},
	}

	disagreed := false

	for _, each := range cases {
		t.Run(each.name, func(t *testing.T) {
			stream := Stream{Credential: Revoked}
			for _, d := range each.sequence {
				stream.Outcomes = append(
					stream.Outcomes,
					Outcome{Disposition: d},
				)
			}

			if got := stream.AcceptedDespiteLapse(); got != each.despiteLapse {
				t.Fatalf(
					"AcceptedDespiteLapse() = %d, want %d",
					got,
					each.despiteLapse,
				)
			}

			if stream.AcceptedSinceLastRefusal() != each.sinceRefusal {
				t.Fatalf(
					"the older count changed behaviour; this test pins the difference",
				)
			}

			if each.despiteLapse != each.sinceRefusal {
				disagreed = true
			}
		})
	}

	// The two must disagree somewhere, or replacing one with the other fixed
	// nothing and this whole test is decoration.
	if !disagreed {
		t.Fatal(
			"AcceptedDespiteLapse never differs from AcceptedSinceLastRefusal across these cases",
		)
	}
}
