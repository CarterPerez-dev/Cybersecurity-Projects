// ©AngelaMos | 2026
// version_test.go

package pypi

import (
	"errors"
	"testing"
)

//nolint:gocognit,funlen
func TestParseVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    Version
		wantErr bool
	}{
		{
			name:  "simple three-segment",
			input: "1.2.3",
			want: Version{
				Raw: "1.2.3", Release: []int{1, 2, 3},
				Post: -1, Dev: -1,
			},
		},
		{
			name:  "two segments",
			input: "2.0",
			want: Version{
				Raw: "2.0", Release: []int{2, 0},
				Post: -1, Dev: -1,
			},
		},
		{
			name:  "single segment",
			input: "42",
			want: Version{
				Raw: "42", Release: []int{42},
				Post: -1, Dev: -1,
			},
		},
		{
			name:  "leading v prefix",
			input: "v1.0.0",
			want: Version{
				Raw: "v1.0.0", Release: []int{1, 0, 0},
				Post: -1, Dev: -1,
			},
		},
		{
			name:  "epoch",
			input: "2!1.0",
			want: Version{
				Raw: "2!1.0", Epoch: 2, Release: []int{1, 0},
				Post: -1, Dev: -1,
			},
		},
		{
			name:  "alpha pre-release",
			input: "1.0a1",
			want: Version{
				Raw: "1.0a1", Release: []int{1, 0},
				PreKind: "a", PreNum: 1, Post: -1, Dev: -1,
			},
		},
		{
			name:  "beta pre-release",
			input: "1.0b2",
			want: Version{
				Raw: "1.0b2", Release: []int{1, 0},
				PreKind: "b", PreNum: 2, Post: -1, Dev: -1,
			},
		},
		{
			name:  "release candidate",
			input: "1.0rc1",
			want: Version{
				Raw: "1.0rc1", Release: []int{1, 0},
				PreKind: "rc", PreNum: 1, Post: -1, Dev: -1,
			},
		},
		{
			name:  "alpha spelled out",
			input: "1.0alpha1",
			want: Version{
				Raw: "1.0alpha1", Release: []int{1, 0},
				PreKind: "a", PreNum: 1, Post: -1, Dev: -1,
			},
		},
		{
			name:  "beta spelled out",
			input: "1.0beta3",
			want: Version{
				Raw: "1.0beta3", Release: []int{1, 0},
				PreKind: "b", PreNum: 3, Post: -1, Dev: -1,
			},
		},
		{
			name:  "preview normalizes to rc",
			input: "1.0preview2",
			want: Version{
				Raw: "1.0preview2", Release: []int{1, 0},
				PreKind: "rc", PreNum: 2, Post: -1, Dev: -1,
			},
		},
		{
			name:  "c normalizes to rc",
			input: "1.0c1",
			want: Version{
				Raw: "1.0c1", Release: []int{1, 0},
				PreKind: "rc", PreNum: 1, Post: -1, Dev: -1,
			},
		},
		{
			name:  "pre normalizes to rc",
			input: "1.0pre4",
			want: Version{
				Raw: "1.0pre4", Release: []int{1, 0},
				PreKind: "rc", PreNum: 4, Post: -1, Dev: -1,
			},
		},
		{
			name:  "pre-release with dot separator",
			input: "1.0.a1",
			want: Version{
				Raw: "1.0.a1", Release: []int{1, 0},
				PreKind: "a", PreNum: 1, Post: -1, Dev: -1,
			},
		},
		{
			name:  "pre-release with dash separator",
			input: "1.0-alpha1",
			want: Version{
				Raw: "1.0-alpha1", Release: []int{1, 0},
				PreKind: "a", PreNum: 1, Post: -1, Dev: -1,
			},
		},
		{
			name:  "pre-release with underscore separator",
			input: "1.0_b2",
			want: Version{
				Raw: "1.0_b2", Release: []int{1, 0},
				PreKind: "b", PreNum: 2, Post: -1, Dev: -1,
			},
		},
		{
			name:  "implicit pre-release zero",
			input: "1.0a",
			want: Version{
				Raw: "1.0a", Release: []int{1, 0},
				PreKind: "a", PreNum: 0, Post: -1, Dev: -1,
			},
		},
		{
			name:  "post-release",
			input: "1.0.post1",
			want: Version{
				Raw: "1.0.post1", Release: []int{1, 0},
				Post: 1, Dev: -1,
			},
		},
		{
			name:  "post-release implicit zero",
			input: "1.0.post",
			want: Version{
				Raw: "1.0.post", Release: []int{1, 0},
				Post: 0, Dev: -1,
			},
		},
		{
			name:  "implicit post via dash-number",
			input: "1.0-1",
			want: Version{
				Raw: "1.0-1", Release: []int{1, 0},
				Post: 1, Dev: -1,
			},
		},
		{
			name:  "rev normalizes to post",
			input: "1.0.rev2",
			want: Version{
				Raw: "1.0.rev2", Release: []int{1, 0},
				Post: 2, Dev: -1,
			},
		},
		{
			name:  "r normalizes to post",
			input: "1.0.r3",
			want: Version{
				Raw: "1.0.r3", Release: []int{1, 0},
				Post: 3, Dev: -1,
			},
		},
		{
			name:  "dev release",
			input: "1.0.dev1",
			want: Version{
				Raw: "1.0.dev1", Release: []int{1, 0},
				Post: -1, Dev: 1,
			},
		},
		{
			name:  "dev release implicit zero",
			input: "1.0.dev",
			want: Version{
				Raw: "1.0.dev", Release: []int{1, 0},
				Post: -1, Dev: 0,
			},
		},
		{
			name:  "dev release with dash separator",
			input: "1.0-dev3",
			want: Version{
				Raw: "1.0-dev3", Release: []int{1, 0},
				Post: -1, Dev: 3,
			},
		},
		{
			name:  "local version",
			input: "1.0+ubuntu1",
			want: Version{
				Raw: "1.0+ubuntu1", Release: []int{1, 0},
				Post: -1, Dev: -1, Local: "ubuntu1",
			},
		},
		{
			name:  "full complex version",
			input: "2!1.2.3a4.post5.dev6+local7",
			want: Version{
				Raw:   "2!1.2.3a4.post5.dev6+local7",
				Epoch: 2, Release: []int{1, 2, 3},
				PreKind: "a", PreNum: 4,
				Post: 5, Dev: 6, Local: "local7",
			},
		},
		{
			name:  "post and dev combined",
			input: "1.0.post1.dev2",
			want: Version{
				Raw: "1.0.post1.dev2", Release: []int{1, 0},
				Post: 1, Dev: 2,
			},
		},
		{
			name:  "pre and dev combined",
			input: "1.0a1.dev1",
			want: Version{
				Raw: "1.0a1.dev1", Release: []int{1, 0},
				PreKind: "a", PreNum: 1, Post: -1, Dev: 1,
			},
		},
		{
			name:  "leading zeros normalized",
			input: "1.01.010",
			want: Version{
				Raw: "1.01.010", Release: []int{1, 1, 10},
				Post: -1, Dev: -1,
			},
		},
		{
			name:  "many release segments",
			input: "1.2.3.4.5",
			want: Version{
				Raw: "1.2.3.4.5", Release: []int{1, 2, 3, 4, 5},
				Post: -1, Dev: -1,
			},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "garbage",
			input:   "not-a-version",
			wantErr: true,
		},
		{
			name:    "just text",
			input:   "latest",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf(
						"ParseVersion(%q) succeeded, want error",
						tt.input,
					)
				}
				if !errors.Is(err, ErrInvalidVersion) {
					t.Fatalf(
						"ParseVersion(%q) err = %v, want ErrInvalidVersion",
						tt.input, err,
					)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseVersion(%q) error: %v", tt.input, err)
			}

			if got.Epoch != tt.want.Epoch {
				t.Errorf("Epoch = %d, want %d", got.Epoch, tt.want.Epoch)
			}
			if !intSliceEqual(got.Release, tt.want.Release) {
				t.Errorf(
					"Release = %v, want %v",
					got.Release, tt.want.Release,
				)
			}
			if got.PreKind != tt.want.PreKind {
				t.Errorf(
					"PreKind = %q, want %q",
					got.PreKind, tt.want.PreKind,
				)
			}
			if got.PreNum != tt.want.PreNum {
				t.Errorf("PreNum = %d, want %d", got.PreNum, tt.want.PreNum)
			}
			if got.Post != tt.want.Post {
				t.Errorf("Post = %d, want %d", got.Post, tt.want.Post)
			}
			if got.Dev != tt.want.Dev {
				t.Errorf("Dev = %d, want %d", got.Dev, tt.want.Dev)
			}
			if got.Local != tt.want.Local {
				t.Errorf(
					"Local = %q, want %q",
					got.Local, tt.want.Local,
				)
			}
		})
	}
}

func TestVersionString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"1.0", "1.0"},
		{"1.2.3", "1.2.3"},
		{"2!1.0", "2!1.0"},
		{"1.0a1", "1.0a1"},
		{"1.0b2", "1.0b2"},
		{"1.0rc1", "1.0rc1"},
		{"1.0.post1", "1.0.post1"},
		{"1.0.dev1", "1.0.dev1"},
		{"1.0+local", "1.0+local"},
		{"1.0alpha1", "1.0a1"},
		{"1.0beta2", "1.0b2"},
		{"1.0preview1", "1.0rc1"},
		{"1.0c3", "1.0rc3"},
		{"1.0pre1", "1.0rc1"},
		{"v1.0.0", "1.0.0"},
		{"1.0a", "1.0a0"},
		{"1.0.post", "1.0.post0"},
		{"1.0.dev", "1.0.dev0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()

			v, err := ParseVersion(tt.input)
			if err != nil {
				t.Fatalf("ParseVersion(%q) error: %v", tt.input, err)
			}
			got := v.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVersionIsStable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		{"1.0", true},
		{"1.2.3", true},
		{"1.0.post1", true},
		{"2!1.0", true},
		{"1.0+local", true},
		{"1.0a1", false},
		{"1.0b1", false},
		{"1.0rc1", false},
		{"1.0.dev1", false},
		{"1.0a1.dev1", false},
		{"1.0.post1.dev1", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()

			v, err := ParseVersion(tt.input)
			if err != nil {
				t.Fatalf("ParseVersion(%q) error: %v", tt.input, err)
			}
			if got := v.IsStable(); got != tt.want {
				t.Errorf("IsStable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVersionCompare(t *testing.T) {
	t.Parallel()

	ordered := []string{
		"1.0.dev0",
		"1.0.dev1",
		"1.0a1.dev1",
		"1.0a1",
		"1.0a2",
		"1.0b1",
		"1.0b2",
		"1.0rc1",
		"1.0rc2",
		"1.0",
		"1.0.post0",
		"1.0.post1",
		"1.0.post2",
		"1.1",
		"2.0",
	}

	versions := make([]Version, len(ordered))
	for i, s := range ordered {
		v, err := ParseVersion(s)
		if err != nil {
			t.Fatalf("ParseVersion(%q) error: %v", s, err)
		}
		versions[i] = v
	}

	for i := range len(versions) {
		for j := range len(versions) {
			got := versions[i].Compare(versions[j])
			var want int
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			default:
				want = 0
			}

			if (want < 0 && got >= 0) ||
				(want > 0 && got <= 0) ||
				(want == 0 && got != 0) {
				t.Errorf(
					"Compare(%s, %s) = %d, want sign %d",
					ordered[i], ordered[j], got, want,
				)
			}
		}
	}
}

func TestVersionCompareEpoch(t *testing.T) {
	t.Parallel()

	low, err := ParseVersion("99.0")
	if err != nil {
		t.Fatal(err)
	}
	high, err := ParseVersion("2!1.0")
	if err != nil {
		t.Fatal(err)
	}

	if got := low.Compare(high); got >= 0 {
		t.Errorf("99.0 should be less than 2!1.0, got %d", got)
	}
	if got := high.Compare(low); got <= 0 {
		t.Errorf("2!1.0 should be greater than 99.0, got %d", got)
	}
}

func TestVersionCompareImplicitZeros(t *testing.T) {
	t.Parallel()

	a, err := ParseVersion("1.0")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseVersion("1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseVersion("1.0.0.0")
	if err != nil {
		t.Fatal(err)
	}

	if got := a.Compare(b); got != 0 {
		t.Errorf("1.0 vs 1.0.0 = %d, want 0", got)
	}
	if got := b.Compare(c); got != 0 {
		t.Errorf("1.0.0 vs 1.0.0.0 = %d, want 0", got)
	}
	if got := a.Compare(c); got != 0 {
		t.Errorf("1.0 vs 1.0.0.0 = %d, want 0", got)
	}
}

func TestClassifyChange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		from string
		to   string
		want ChangeKind
	}{
		{"1.0.0", "1.0.1", Patch},
		{"1.0.0", "1.1.0", Minor},
		{"1.0.0", "2.0.0", Major},
		{"1.0", "1.1", Minor},
		{"1.0", "2.0", Major},
		{"3.2.0", "4.2.8", Major},
		{"2.28.1", "2.31.0", Minor},
		{"7.4.0", "7.4.3", Patch},
	}

	for _, tt := range tests {
		t.Run(tt.from+"->"+tt.to, func(t *testing.T) {
			t.Parallel()

			from, err := ParseVersion(tt.from)
			if err != nil {
				t.Fatal(err)
			}
			to, err := ParseVersion(tt.to)
			if err != nil {
				t.Fatal(err)
			}
			if got := ClassifyChange(from, to); got != tt.want {
				t.Errorf(
					"ClassifyChange(%s, %s) = %s, want %s",
					tt.from, tt.to, got, tt.want,
				)
			}
		})
	}
}

func TestLatestStable(t *testing.T) {
	t.Parallel()

	versions := []string{
		"1.0",
		"1.1",
		"1.2a1",
		"1.2b1",
		"1.2rc1",
		"1.2.dev1",
		"1.1.1",
		"1.1.2",
		"0.9",
	}

	got, err := LatestStable(versions)
	if err != nil {
		t.Fatalf("LatestStable() error: %v", err)
	}
	if got.String() != "1.1.2" {
		t.Errorf("LatestStable() = %s, want 1.1.2", got.String())
	}
}

func TestLatestStableNoStable(t *testing.T) {
	t.Parallel()

	versions := []string{"1.0a1", "1.0b1", "1.0.dev1"}
	_, err := LatestStable(versions)
	if err == nil {
		t.Fatal("LatestStable() should fail when no stable versions exist")
	}
}

func TestLatestStableSkipsInvalid(t *testing.T) {
	t.Parallel()

	versions := []string{"not-a-version", "also-bad", "1.0", "???"}
	got, err := LatestStable(versions)
	if err != nil {
		t.Fatalf("LatestStable() error: %v", err)
	}
	if got.String() != "1.0" {
		t.Errorf("LatestStable() = %s, want 1.0", got.String())
	}
}

func intSliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
