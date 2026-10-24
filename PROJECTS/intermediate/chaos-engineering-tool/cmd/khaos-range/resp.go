// ©AngelaMos | 2026
// resp.go

package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// INCR and EXPIRE are integer-reply in RESP2 and RESP3 alike, so this
	// sends no HELLO. redis:7.4-alpine patches protected-mode off at build
	// time and sets no password, so the first command on a socket runs.
	respINCR   = "INCR"
	respEXPIRE = "EXPIRE"

	respInteger = ':'
	respError   = '-'
	respCRLF    = "\r\n"

	// A severed datastore has to reach the fault-tolerance branch inside one
	// request, or the observable is a timeout rather than a decision.
	respDialTimeout = 400 * time.Millisecond
	respIOTimeout   = 400 * time.Millisecond

	errRESPReply = "the datastore answered %q, which is not an integer reply"
)

var errRESPRefused = errors.New("the datastore refused the command")

// respCount is one fixed-window increment, dialled per call: a pooled client
// would hide the severance behind a connection established before it.
func respCount(address, key string, window time.Duration) (int64, error) {
	conn, err := net.DialTimeout("tcp", address, respDialTimeout)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()

	if err = conn.SetDeadline(time.Now().Add(respIOTimeout)); err != nil {
		return 0, err
	}

	reader := bufio.NewReader(conn)

	count, err := respCommand(conn, reader, respINCR, key)
	if err != nil {
		return 0, err
	}

	// INCR leaves an existing timeout untouched, so the window is set on the
	// increment that created the key. A key per window means an EXPIRE that
	// never lands leaks one key rather than disabling the limit.
	if count == 1 {
		seconds := strconv.FormatInt(int64(window.Seconds()), 10)
		if _, err = respCommand(
			conn,
			reader,
			respEXPIRE,
			key,
			seconds,
		); err != nil {
			return 0, err
		}
	}

	return count, nil
}

func respCommand(
	conn net.Conn,
	reader *bufio.Reader,
	parts ...string,
) (int64, error) {
	if _, err := conn.Write([]byte(respEncode(parts))); err != nil {
		return 0, err
	}

	return respInteger64(reader)
}

func respEncode(parts []string) string {
	var out strings.Builder

	out.WriteString("*" + strconv.Itoa(len(parts)) + respCRLF)

	for _, part := range parts {
		out.WriteString("$" + strconv.Itoa(len(part)) + respCRLF)
		out.WriteString(part + respCRLF)
	}

	return out.String()
}

// respInteger64 reads the only two replies these commands produce. WRONGTYPE,
// a non-integer value and an int64 overflow all arrive on the error line and
// must never be read as a count.
func respInteger64(reader *bufio.Reader) (int64, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}

	line = strings.TrimRight(line, respCRLF)

	// Load-bearing rather than defensive: without it line[0] on an empty
	// reply is an index panic that takes this process down mid-run.
	if line == "" {
		return 0, fmt.Errorf(errRESPReply, line)
	}

	if line[0] == respError {
		return 0, fmt.Errorf("%w: %s", errRESPRefused, line[1:])
	}

	if line[0] != respInteger {
		return 0, fmt.Errorf(errRESPReply, line)
	}

	// Zero on failure, explicitly. ParseInt returns MaxInt64 alongside its
	// error on overflow, and a count returned beside an error is one a caller
	// can read before noticing it is garbage.
	count, err := strconv.ParseInt(line[1:], 10, 64)
	if err != nil {
		return 0, err
	}

	return count, nil
}
