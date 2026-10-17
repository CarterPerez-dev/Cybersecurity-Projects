// ©AngelaMos | 2026
// http.go

package probe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	DefaultTimeout = 5 * time.Second

	headerAuthorization = "Authorization"
	bearerPrefix        = "Bearer "
	headerUserAgent     = "User-Agent"
	userAgentValue      = "khaos"

	describeHTTP     = "%s %s with a %s credential"
	describeHTTPMint = "%s %s with a %s credential minted per request"
	detailError      = "%v"
	detailStatus     = "HTTP %d"
	detailMint       = "khaos could not mint the credential for this probe: %v"
	nonceSep         = "."
)

type HTTPOptions struct {
	Name string

	// Describe overrides the generic sentence for a stream whose POINT is not
	// the credential it carries: a readiness endpoint that has to dial, or a
	// credential signed with a zero-length key.
	Describe string

	Method     string
	URL        string
	Token      string
	Credential Credential
	Timeout    time.Duration

	// Unique appends a per-request nonce, because one fixed credential keeps
	// the target's decision cache warm.
	Unique bool

	// Mint supplies the credential per request instead of Token, for a stream
	// whose provider is armed between the baseline and the fault.
	Mint func(context.Context) (string, error)
}

type HTTPProbe struct {
	options HTTPOptions
	client  *http.Client
}

func NewHTTP(options HTTPOptions) *HTTPProbe {
	if options.Method == "" {
		options.Method = http.MethodGet
	}
	if options.Timeout <= 0 {
		options.Timeout = DefaultTimeout
	}

	return &HTTPProbe{
		options: options,
		client: &http.Client{
			Timeout: options.Timeout,
			Transport: &http.Transport{
				// Resumption does not repeat chain verification, and a nil cache
				// is what disables it.
				TLSClientConfig: &tls.Config{
					ClientSessionCache: nil,
					MinVersion:         tls.VersionTLS12,
				},
				DisableKeepAlives: true,
				// Setting TLSClientConfig disables automatic HTTP/2.
				ForceAttemptHTTP2: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (p *HTTPProbe) Name() string {
	return p.options.Name
}

func (p *HTTPProbe) Credential() Credential {
	return p.options.Credential
}

func (p *HTTPProbe) Describe() string {
	if p.options.Describe != "" {
		return p.options.Describe
	}

	if p.options.Mint != nil {
		return fmt.Sprintf(
			describeHTTPMint,
			p.options.Method,
			p.options.URL,
			p.options.Credential,
		)
	}
	return fmt.Sprintf(
		describeHTTP,
		p.options.Method,
		p.options.URL,
		p.options.Credential,
	)
}

func (p *HTTPProbe) Run(ctx context.Context) Outcome {
	started := time.Now().UTC()

	outcome := Outcome{
		At:          started,
		Credential:  p.options.Credential,
		Disposition: Unknown,
	}

	request, err := http.NewRequestWithContext(
		ctx,
		p.options.Method,
		p.options.URL,
		nil,
	)
	if err != nil {
		outcome.Disposition = ProbeFailed
		outcome.Detail = fmt.Sprintf(detailError, err)
		return outcome
	}

	request.Header.Set(headerUserAgent, userAgentValue)

	token, err := p.credential(ctx)
	if err != nil {
		outcome.Disposition = ProbeFailed
		outcome.Detail = fmt.Sprintf(detailMint, err)
		return outcome
	}

	if token != "" {
		request.Header.Set(headerAuthorization, bearerPrefix+token)
	}

	response, err := p.client.Do(request)
	outcome.SetLatency(time.Since(started))

	if err != nil {
		outcome.Disposition = transportDisposition(err)
		outcome.Detail = fmt.Sprintf(detailError, err)
		return outcome
	}
	defer func() { _ = response.Body.Close() }()

	// Under TLS 1.3 a handshake rejection surfaces on the first read, not at
	// dial, so the body must be read.
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		outcome.Disposition = transportDisposition(err)
		outcome.Detail = fmt.Sprintf(detailError, err)
		return outcome
	}

	outcome.SetLatency(time.Since(started))
	outcome.Status = response.StatusCode
	outcome.Disposition = statusDisposition(response.StatusCode)
	outcome.Detail = fmt.Sprintf(detailStatus, response.StatusCode)

	return outcome
}

// credential never nonces a minted token, because appending to a signed token
// would corrupt it into a different fault than the one armed.
func (p *HTTPProbe) credential(ctx context.Context) (string, error) {
	if p.options.Mint != nil {
		return p.options.Mint(ctx)
	}

	if p.options.Token == "" || !p.options.Unique {
		return p.options.Token, nil
	}

	return p.options.Token + nonceSep + rand.Text(), nil
}

func transportDisposition(err error) Disposition {
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrDeadlineExceeded) {
		return TimedOut
	}
	if errors.Is(err, context.Canceled) {
		return ProbeFailed
	}

	// Unreachable and not Unavailable: nothing answered. The target refusing
	// the connection, resetting it or closing it without a response are all
	// the target failing to ANSWER, which is a different observation from a
	// 503 with a status line, and four experiments declare the second as their
	// fail-closed outcome.
	return Unreachable
}

// statusDisposition maps a status to what it says about the CREDENTIAL, not to
// whether the request succeeded.
func statusDisposition(status int) Disposition {
	switch {
	case status == http.StatusTooManyRequests:
		return Throttled
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return Rejected
	case status >= http.StatusInternalServerError:
		return Unavailable
	case status >= http.StatusMultipleChoices && status < http.StatusBadRequest:
		// Gateways refuse and route the same way, so this decides nothing.
		return Redirected
	case status >= http.StatusOK && status < http.StatusMultipleChoices:
		return Accepted
	default:
		return Rejected
	}
}
