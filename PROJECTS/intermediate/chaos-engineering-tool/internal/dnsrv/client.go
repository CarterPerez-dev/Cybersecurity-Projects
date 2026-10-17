// ©AngelaMos | 2026
// client.go

package dnsrv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

const (
	// probeTimeout must clear the largest delay khaos can arm plus a client's
	// re-ask over TCP, or confirmation times out and reports the resolver dead.
	probeTimeout = 10 * time.Second

	controlTimeout = 5 * time.Second

	errControlStatus = "%w: %s answered %s"
	errControlCall   = "reach the resolver's control surface at %s: %w"
	errExchange      = "ask %s for %s over %s: %w"
	errDecode        = "decode the resolver's reply from %s: %w"
)

var ErrControlRefused = errors.New(
	"the resolver's control surface refused this request",
)

// Client talks to a resolver running in a container. Both addresses are the
// CONTAINER's own, reached directly over the bridge network, so neither the DNS
// port nor the control port is ever published to the host.
type Client struct {
	DNS string

	Control string

	// Nonce authorises every control call. The target shares the network, so
	// without it the target could arm or disarm khaos's own fault.
	Nonce string

	ControlName string

	// Zone is read back from the resolver rather than remembered, so a
	// redirect's observable can name the address the fault replaced.
	Zone map[string]string

	http *http.Client
}

func NewClient(dnsAddr, controlURL, nonce, controlName string) *Client {
	return &Client{
		DNS:         dnsAddr,
		Control:     controlURL,
		Nonce:       nonce,
		ControlName: controlName,
		http:        &http.Client{Timeout: controlTimeout},
	}
}

func (c *Client) Arm(ctx context.Context, trap Trap) (Stats, error) {
	body, err := json.Marshal(trap)
	if err != nil {
		return Stats{}, err
	}

	return c.call(ctx, http.MethodPost, PathArm, body)
}

// Rotate moves a name's address in the zone. A non-2xx is an error rather than
// a silent no-op, which is what lets a failed rotation VOID the run instead of
// leaving khaos measuring a name nobody moved.
func (c *Client) Rotate(
	ctx context.Context,
	name, address string,
) (Stats, error) {
	body, err := json.Marshal(Rotation{Name: name, Address: address})
	if err != nil {
		return Stats{}, err
	}

	return c.call(ctx, http.MethodPost, PathRotate, body)
}

func (c *Client) Disarm(ctx context.Context) (Stats, error) {
	return c.call(ctx, http.MethodPost, PathDisarm, nil)
}

func (c *Client) State(ctx context.Context) (Stats, error) {
	return c.call(ctx, http.MethodGet, PathState, nil)
}

// Healthy reports whether the resolver is up without sending the nonce, so
// khaos can wait on a container before it has read the nonce back out of it.
func (c *Client) Healthy(ctx context.Context) bool {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.Control+PathHealthz,
		nil,
	)
	if err != nil {
		return false
	}

	response, err := c.client().Do(request)
	if err != nil {
		return false
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)

	return response.StatusCode == http.StatusOK
}

func (c *Client) call(
	ctx context.Context,
	method string,
	path string,
	body []byte,
) (Stats, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		method,
		c.Control+path,
		reader,
	)
	if err != nil {
		return Stats{}, err
	}
	request.Header.Set(NonceHeader, c.Nonce)

	response, err := c.client().Do(request)
	if err != nil {
		return Stats{}, fmt.Errorf(errControlCall, c.Control+path, err)
	}
	defer func() { _ = response.Body.Close() }()

	payload, err := io.ReadAll(
		io.LimitReader(response.Body, controlBodyLimit),
	)
	if err != nil {
		return Stats{}, err
	}

	if response.StatusCode != http.StatusOK {
		return Stats{}, fmt.Errorf(
			errControlStatus,
			ErrControlRefused,
			path,
			firstLine(payload, response.Status),
		)
	}

	var stats Stats
	if err := json.Unmarshal(payload, &stats); err != nil {
		return Stats{}, fmt.Errorf(errDecode, path, err)
	}

	return stats, nil
}

func (c *Client) client() *http.Client {
	if c.http == nil {
		c.http = &http.Client{Timeout: controlTimeout}
	}
	return c.http
}

type answer struct {
	rcode     int
	truncated bool
	records   []dns.RR
	elapsed   time.Duration
	err       error

	// authoritative is the AA bit. Several paths in serveFault answer SERVFAIL,
	// so the rcode alone cannot tell an armed fault from khaos's own failure.
	authoritative bool
}

func (a answer) addresses() []string {
	out := make([]string, 0, len(a.records))
	for _, rr := range a.records {
		switch record := rr.(type) {
		case *dns.A:
			out = append(out, record.A.String())
		case *dns.AAAA:
			out = append(out, record.AAAA.String())
		}
	}
	return out
}

func (a answer) cnames() []string {
	out := make([]string, 0, len(a.records))
	for _, rr := range a.records {
		if record, ok := rr.(*dns.CNAME); ok {
			out = append(out, dns.CanonicalName(record.Target))
		}
	}
	return out
}

func (a answer) ttls() []uint32 {
	out := make([]uint32, 0, len(a.records))
	for _, rr := range a.records {
		if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		out = append(out, rr.Header().Ttl)
	}
	return out
}

func (a answer) resolved() bool {
	return a.err == nil &&
		a.rcode == dns.RcodeSuccess &&
		len(a.addresses()) > 0
}

// ask performs one exchange and records what came back, including the failure.
// A timeout is data rather than an error to propagate, because
// TruncationNoTCP's whole observable is that neither transport ever completes.
func (c *Client) ask(name, proto string) answer {
	client := &dns.Client{Net: proto, Timeout: probeTimeout}

	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), dns.TypeA)

	start := time.Now()
	response, _, err := client.Exchange(message, c.dnsAddr())
	elapsed := time.Since(start)

	if err != nil {
		return answer{
			elapsed: elapsed,
			err:     fmt.Errorf(errExchange, c.DNS, name, proto, err),
		}
	}

	return answer{
		rcode:         response.Rcode,
		truncated:     response.Truncated,
		records:       response.Answer,
		elapsed:       elapsed,
		authoritative: response.Authoritative,
	}
}

func (c *Client) dnsAddr() string {
	if _, _, err := net.SplitHostPort(c.DNS); err != nil {
		return net.JoinHostPort(c.DNS, fmt.Sprint(DefaultPort))
	}
	return c.DNS
}

func firstLine(payload []byte, fallback string) string {
	text := string(bytes.TrimSpace(payload))
	if text == "" {
		return fallback
	}

	if index := bytes.IndexByte([]byte(text), '\n'); index > 0 {
		return text[:index]
	}

	return text
}

// Queries reads how many times one source asked about one name the resolver is
// authoritative for. A read failure returns an error rather than zero, because
// zero is the sentinel meaning the target never asked.
func (c *Client) Queries(
	ctx context.Context,
	source, zoneName string,
) (int64, error) {
	stats, err := c.State(ctx)
	if err != nil {
		return 0, err
	}

	return stats.Queries[QueryKey(source, zoneName)], nil
}

// Health reads the resolver's liveness endpoint, which also reports the control
// name no fault touches. That name is read back rather than remembered, since
// the resolver is the only authority on which name it will refuse to fault.
func (c *Client) Health(ctx context.Context) (Health, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.Control+PathHealthz,
		nil,
	)
	if err != nil {
		return Health{}, err
	}

	response, err := c.client().Do(request)
	if err != nil {
		return Health{}, fmt.Errorf(errControlCall, c.Control+PathHealthz, err)
	}
	defer func() { _ = response.Body.Close() }()

	payload, err := io.ReadAll(io.LimitReader(response.Body, controlBodyLimit))
	if err != nil {
		return Health{}, err
	}

	if response.StatusCode != http.StatusOK {
		return Health{}, fmt.Errorf(
			errControlStatus,
			ErrControlRefused,
			PathHealthz,
			firstLine(payload, response.Status),
		)
	}

	var health Health
	if err := json.Unmarshal(payload, &health); err != nil {
		return Health{}, fmt.Errorf(errDecode, PathHealthz, err)
	}

	return health, nil
}
