// ©AngelaMos | 2026
// resp_test.go

package main

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

// An error reply must never be read as a count. A limiter that read -ERR as a
// number would compare garbage against its budget and decide from it, which
// is worse than failing: it would decide WRONGLY and report confidently.
//
// The empty row is the one whose guard is load-bearing rather than redundant:
// without it `line[0]` on an empty reply is an index panic that takes the
// gateway down mid-run.
func TestOnlyAnIntegerReplyIsReadAsACount(t *testing.T) {
	for _, row := range []struct {
		name    string
		reply   string
		want    int64
		counted bool
	}{
		{"an integer", ":5\r\n", 5, true},
		{"zero", ":0\r\n", 0, true},
		{"an unknown command", "-ERR unknown command\r\n", 0, false},
		{
			"the wrong type",
			"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n",
			0,
			false,
		},
		{
			"a non-integer value",
			"-ERR value is not an integer or out of range\r\n",
			0,
			false,
		},
		{"an empty reply", "\r\n", 0, false},
		{"a simple string", "+PONG\r\n", 0, false},
		{"an int64 overflow", ":9223372036854775808\r\n", 0, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			count, err := respInteger64(
				bufio.NewReader(strings.NewReader(row.reply)),
			)

			if row.counted {
				if err != nil {
					t.Fatalf("an integer reply errored: %v", err)
				}

				if count != row.want {
					t.Fatalf("count = %d, want %d", count, row.want)
				}

				return
			}

			if err == nil {
				t.Fatalf(
					"%q was read as the count %d rather than refused",
					row.reply,
					count,
				)
			}

			if count != 0 {
				t.Fatalf(
					"%q errored AND returned %d; a caller reading the count "+
						"before the error gets garbage",
					row.reply,
					count,
				)
			}
		})
	}
}

// The error line is classified, so a refusal is distinguishable from a
// transport failure by something other than its text.
func TestARefusalIsDistinguishableFromATransportFailure(t *testing.T) {
	_, err := respInteger64(
		bufio.NewReader(strings.NewReader("-ERR unknown command\r\n")),
	)

	if !errors.Is(err, errRESPRefused) {
		t.Fatalf("an -ERR reply did not classify as a refusal: %v", err)
	}
}

// The exact bytes, because the stub datastore's own parser discards the bulk
// length lines: a wrong length is invisible to it and a protocol error to
// real Redis.
func TestTheEncodingIsAnArrayOfBulkStrings(t *testing.T) {
	got := respEncode([]string{respINCR, "a-key"})
	want := "*2\r\n$4\r\nINCR\r\n$5\r\na-key\r\n"

	if got != want {
		t.Fatalf("respEncode = %q, want %q", got, want)
	}
}
