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
	Name       string
	Method     string
	URL        string
	Token      string
	Credential Credential
	Timeout    time.Duration

	// Unique appends a per-request nonce to the token. A negative control that
	// reuses one fixed credential keeps the target's decision cache warm, so
	// the cached refusal answers every probe and a control that stops
	// enforcing during the fault is never exercised.
	Unique bool

	// Mint supplies the credential per request instead of Token. A forged stream
	// needs it: the provider's arming changes between the baseline and the fault,
	// so a credential captured once would carry the baseline's honest token into
	// the fault window and the trap would never be presented at all.
	//
	// A mint failure is khaos's own fault and is reported as ProbeFailed, which
	// every rate already excludes. Folding it into a target outcome would
	// manufacture a finding out of khaos's own bug.
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
				// TLS session resumption does not repeat chain verification, so
				// a probe that resumes passes against a certificate that has
				// since expired. A nil cache is what actually disables it:
				// crypto/tls only stores and loads sessions when one is set.
				TLSClientConfig:   &tls.Config{ClientSessionCache: nil, MinVersion: tls.VersionTLS12},
				DisableKeepAlives: true,
				// Setting TLSClientConfig disables automatic HTTP/2 unless this
				// is set, and h2 connection reuse is itself a fail-open khaos
				// needs to be able to observe.
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
	if p.options.Mint != nil {
		return fmt.Sprintf(describeHTTPMint, p.options.Method, p.options.URL, p.options.Credential)
	}
	return fmt.Sprintf(describeHTTP, p.options.Method, p.options.URL, p.options.Credential)
}

func (p *HTTPProbe) Run(ctx context.Context) Outcome {
	started := time.Now().UTC()

	outcome := Outcome{
		At:          started,
		Credential:  p.options.Credential,
		Disposition: Unknown,
	}

	request, err := http.NewRequestWithContext(ctx, p.options.Method, p.options.URL, nil)
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

	// The body must be read. Under TLS 1.3 a handshake rejection surfaces on
	// the first read rather than at dial, so a probe that never reads reports
	// success against a server that refused its identity.
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

// credential resolves what this request carries. A minted credential is never
// given a nonce: the mint already produced a fresh one, and appending to a
// signed token would corrupt it into a different fault than the one armed.
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
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return TimedOut
	}
	if errors.Is(err, context.Canceled) {
		return ProbeFailed
	}
	return Unavailable
}

// statusDisposition maps a status to what it says about the CREDENTIAL, which
// is not the same question as whether the request succeeded.
func statusDisposition(status int) Disposition {
	switch {
	case status == http.StatusTooManyRequests:
		return Throttled
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return Rejected
	case status >= http.StatusInternalServerError:
		return Unavailable
	case status >= http.StatusMultipleChoices && status < http.StatusBadRequest:
		// A redirect is how most browser-facing gateways refuse an
		// unauthenticated request, and it is also how they route an
		// authenticated one. It decides nothing about the credential.
		return Redirected
	case status >= http.StatusOK && status < http.StatusMultipleChoices:
		return Accepted
	default:
		return Rejected
	}
}
