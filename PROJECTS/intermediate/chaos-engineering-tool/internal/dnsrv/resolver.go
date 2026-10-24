// ©AngelaMos | 2026
// resolver.go

package dnsrv

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// Has to be 53, because `--dns` carries an address and no port. It is also
	// why the resolver is a container: an unprivileged process cannot bind 53.
	DefaultPort = 53

	// The resolver container's OWN embedded resolver, so it inherits exactly
	// the resolution the host has with no configuration and no third party.
	DefaultUpstream = "127.0.0.11:53"

	// Under the embedded resolver's own 4s ceiling, so a slow upstream surfaces
	// here rather than dying a layer up where nothing records it.
	forwardTimeout = 3 * time.Second

	udpNet = "udp"
	tcpNet = "tcp"

	// Only matters for an ephemeral port: the kernel can hand out a UDP port
	// something else already holds in the TCP space.
	bindAttempts = 8
)

const (
	errBindFailed   = "bind the chaos resolver on %s: %w"
	errUpstreamSet  = "%w: the resolver's upstream is %s, which is itself"
	errAlreadyUp    = "%w: this resolver is already serving"
	errNotUp        = "%w: this resolver is not serving"
	errEmptyZone    = "%w: a resolver with an empty zone has nothing it could fault"
	errZoneAddress  = "%w: the zone maps %s to %q"
	errControlName  = "%w: %q is not in the zone, so a confirmation could never use it as a control"
	errFaultedHost  = "%w: %s is the confirmation control and cannot also be the faulted name"
	errOutsideZone  = "%w: %s is not a name this resolver is authoritative for (zone: %s)"
	errSameAddress  = "%w: %s already answers with %s, so rotating it there changes nothing and khaos would measure a rotation that never happened"
	errNoZoneTarget = "%w: this resolver was given no confirmation control name"
)

var ErrUpstreamLoop = errors.New(
	"a resolver whose upstream is itself would answer every query with itself",
)

var ErrAlreadyServing = errors.New("that resolver is already serving")

var ErrNotServing = errors.New("that resolver is not serving")

var ErrEmptyZone = errors.New("a chaos resolver needs a zone to be wrong about")

var ErrZoneAddress = errors.New("a zone entry must map a name to an IP address")

var ErrNoControl = errors.New(
	"a chaos resolver needs a control name its faults never touch",
)

var ErrControlIsHost = errors.New(
	"the confirmation control cannot be the name under fault",
)

var ErrSameAddress = errors.New(
	"a rotation to the address a name already answers with is not a rotation",
)

var ErrOutsideZone = errors.New(
	"this resolver is not authoritative for that name",
)

// Config is everything the resolver needs to exist. The FAULT is not here
// because Docker refuses `--ip` on a network whose subnet it chose, so
// recreating the container to arm it would move the address the target dials.
type Config struct {
	Listen string

	// Answers everything OUTSIDE the zone, so unrelated names keep working.
	Upstream string

	Nonce string

	// The names khaos is AUTHORITATIVE for, mapped to their honest addresses. A
	// container name or alias can never be faulted, because the target's own
	// embedded resolver answers those locally and never forwards them here.
	Zone map[string]string

	// The name in Zone no fault touches, served from the same table, so a
	// control that stops resolving means khaos is broken rather than lying.
	Control string
}

// Resolver is khaos's authoritative chaos resolver, one instance per network.
type Resolver struct {
	cfg  Config
	zone map[string]string

	mu      sync.Mutex
	trap    Trap
	rotated rotation
	servers []*dns.Server
	arrival map[string]int64
	queries map[string]int64
	faulted int64
	honest  int64
	forward int64
	errs    int64
	denied  int64

	control     *http.Server
	controlAddr string
	controls    int64
}

// New builds a resolver without binding anything; nothing listens until Serve.
func New(cfg Config) (*Resolver, error) {
	if cfg.Listen == "" {
		cfg.Listen = fmt.Sprintf(":%d", DefaultPort)
	}
	if cfg.Upstream == "" {
		cfg.Upstream = DefaultUpstream
	}

	if sameAddr(cfg.Listen, cfg.Upstream) {
		return nil, fmt.Errorf(errUpstreamSet, ErrUpstreamLoop, cfg.Upstream)
	}

	if len(cfg.Zone) == 0 {
		return nil, fmt.Errorf(errEmptyZone, ErrEmptyZone)
	}

	zone := make(map[string]string, len(cfg.Zone))
	for name, address := range cfg.Zone {
		if net.ParseIP(address) == nil {
			return nil, fmt.Errorf(
				errZoneAddress,
				ErrZoneAddress,
				name,
				address,
			)
		}
		zone[dns.CanonicalName(name)] = address
	}

	if cfg.Control == "" {
		return nil, fmt.Errorf(errNoZoneTarget, ErrNoControl)
	}

	if _, ok := zone[dns.CanonicalName(cfg.Control)]; !ok {
		return nil, fmt.Errorf(errControlName, ErrNoControl, cfg.Control)
	}

	return &Resolver{
		cfg:     cfg,
		zone:    zone,
		arrival: map[string]int64{},
		queries: map[string]int64{},
	}, nil
}

// Zone reports the names this resolver is authoritative for.
func (r *Resolver) Zone() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return maps.Clone(r.zone)
}

// Serve binds UDP and TCP and returns once both accept. Both are mandatory: a
// client that sees the truncation bit re-asks over TCP.
func (r *Resolver) Serve() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", r.handle)

	r.mu.Lock()
	if len(r.servers) > 0 {
		r.mu.Unlock()
		return fmt.Errorf(errAlreadyUp, ErrAlreadyServing)
	}
	r.mu.Unlock()

	conn, listener, err := bindBoth(r.cfg.Listen)
	if err != nil {
		return err
	}

	servers := []*dns.Server{
		{PacketConn: conn, Net: udpNet, Handler: mux},
		{Listener: listener, Net: tcpNet, Handler: mux},
	}

	r.mu.Lock()
	r.servers = servers
	r.mu.Unlock()

	// Each goroutine serves the LOCAL it was handed, never a field that a
	// mutex-held shutdown nils underneath it.
	ready := make(chan error, len(servers))
	for _, server := range servers {
		srv := server
		srv.NotifyStartedFunc = func() { ready <- nil }
		go func() {
			if err := srv.ActivateAndServe(); err != nil {
				ready <- fmt.Errorf(errBindFailed, srv.Net, err)
			}
		}()
	}

	var failures []error
	for range servers {
		if err := <-ready; err != nil {
			failures = append(failures, err)
		}
	}

	if len(failures) > 0 {
		_ = r.Shutdown()
		return errors.Join(failures...)
	}

	return nil
}

// bindBoth puts UDP and TCP on the SAME port. They are separate port spaces, so
// letting each bind port 0 itself yields different ports and a resolver that is
// unreachable for every RFC 5966 retry.
func bindBoth(listen string) (net.PacketConn, net.Listener, error) {
	udpAddr, err := net.ResolveUDPAddr(udpNet, listen)
	if err != nil {
		return nil, nil, fmt.Errorf(errBindFailed, udpNet, err)
	}

	var last error

	for attempt := 0; attempt < bindAttempts; attempt++ {
		conn, err := net.ListenUDP(udpNet, udpAddr)
		if err != nil {
			return nil, nil, fmt.Errorf(errBindFailed, udpNet, err)
		}

		listener, err := net.Listen(tcpNet, conn.LocalAddr().String())
		if err == nil {
			return conn, listener, nil
		}

		_ = conn.Close()
		last = fmt.Errorf(errBindFailed, tcpNet, err)

		// An explicit port cannot be retried into success.
		if udpAddr.Port != 0 {
			break
		}
	}

	return nil, nil, last
}

// Addr reports where the resolver actually bound, which matters for port 0.
func (r *Resolver) Addr() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, srv := range r.servers {
		if srv.Net == udpNet && srv.PacketConn != nil {
			return srv.PacketConn.LocalAddr().String()
		}
	}

	return r.cfg.Listen
}

// Shutdown closes both transports and, unconditionally, the control surface: a
// resolver whose /arm answers while its DNS is gone could be armed and then
// confirmed against nothing.
func (r *Resolver) Shutdown() error {
	r.mu.Lock()
	servers := r.servers
	r.servers = nil
	r.mu.Unlock()

	failures := []error{r.shutdownControl()}

	if len(servers) == 0 {
		failures = append(failures, fmt.Errorf(errNotUp, ErrNotServing))
	}

	for _, srv := range servers {
		if err := srv.Shutdown(); err != nil {
			failures = append(failures, err)
		}
	}

	return errors.Join(failures...)
}

// Arm installs a fault. An inert trap is still installed, so it travels the
// same path as a live one.
func (r *Resolver) Arm(trap Trap) error {
	if err := trap.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if trap.Kind != PassThrough {
		if err := r.inZone(trap.Host); err != nil {
			return err
		}

		if dns.CanonicalName(trap.Host) == dns.CanonicalName(r.cfg.Control) {
			return fmt.Errorf(errFaultedHost, ErrControlIsHost, trap.Host)
		}
	}

	// The one trap whose arming moves the ZONE rather than installing a wrong
	// answer, so the honest path serves the new address afterwards and a target
	// that asks again follows it. The previous address is recorded here, which
	// is what makes Disarm a restore rather than a guess.
	// INERT skips the rotation and keeps everything else, which is the whole
	// point of the control: an inert arm that still moved the zone would be
	// confirmed by an oracle reading the served answer, and the one negative
	// control this package relies on would pass against a mutation it was
	// built to catch. Measured -- it did.
	if trap.Kind == AddressRotated && !trap.Inert {
		if r.rotated.name != "" &&
			dns.CanonicalName(r.rotated.name) != dns.CanonicalName(trap.Host) {
			return fmt.Errorf(
				"restore the active rotation of %s before rotating %s",
				r.rotated.name, trap.Host,
			)
		}
		previous, err := r.rotate(trap.Host, trap.Address)
		if err != nil {
			return err
		}

		if r.rotated.name == "" {
			r.rotated = rotation{name: trap.Host, from: previous}
		}
	}

	r.trap = trap

	return nil
}

// inZone refuses a fault on a name this resolver does not answer, which would
// arm cleanly, forward untouched, and report a survival against nothing.
func (r *Resolver) inZone(host string) error {
	if _, ok := r.zone[dns.CanonicalName(host)]; ok {
		return nil
	}

	names := make([]string, 0, len(r.zone))
	for name := range r.zone {
		names = append(names, name)
	}

	return fmt.Errorf(
		errOutsideZone,
		ErrOutsideZone,
		host,
		joinWith(sorted(names), ", "),
	)
}

// Rotate changes the ADDRESS a name answers with, which is a different act from
// arming a fault: a fault is a wrong answer the resolver gives while the zone
// stays put, and this moves the zone itself. The honest answer is served from
// the same table afterwards, so a target that asks again gets the new address
// and nothing else about the resolver changes.
//
// It is the operational act an operator performs for DNS-based failover or
// endpoint revocation, and the finding khaos measures is whether it reached the
// target at all.
func (r *Resolver) Rotate(name, address string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rotate(name, address)
}

func (r *Resolver) rotate(name, address string) (string, error) {
	if err := validAddress(address); err != nil {
		return "", err
	}

	canonical := dns.CanonicalName(name)

	previous, ok := r.zone[canonical]
	if !ok {
		names := make([]string, 0, len(r.zone))
		for zoneName := range r.zone {
			names = append(names, zoneName)
		}

		return "", fmt.Errorf(
			errOutsideZone,
			ErrOutsideZone,
			name,
			joinWith(sorted(names), ", "),
		)
	}

	if previous == address {
		return "", fmt.Errorf(errSameAddress, ErrSameAddress, name, address)
	}

	r.zone[canonical] = address

	return previous, nil
}

// Disarm removes the fault and RESTORES a rotation, because khaos has to leave
// the zone as it found it: a rotation that outlived the run would be khaos
// changing an operator's resolution permanently.
func (r *Resolver) Disarm() {
	r.mu.Lock()
	defer r.mu.Unlock()
	moved := r.rotated
	r.rotated = rotation{}
	r.trap = Trap{}

	if moved.name == "" {
		return
	}

	r.zone[dns.CanonicalName(moved.name)] = moved.from
}

// rotation is what a restore needs: the name and the address it answered with
// before khaos moved it.
type rotation struct {
	name string
	from string
}

// Arrivals is attributed by SOURCE rather than totalled: khaos's own probes
// arrive from the bridge gateway and the target's from its container address,
// so a total would be non-zero even when the target never used this resolver.
func (r *Resolver) Arrivals(from string) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.arrival[from]
}

// Stats is what the control surface reports and what khaos reads to decide
// whether a run is interpretable at all.
type Stats struct {
	Armed    Kind             `json:"armed"`
	Host     string           `json:"host"`
	Inert    bool             `json:"inert"`
	Faulted  int64            `json:"faulted"`
	Honest   int64            `json:"honest"`
	Forward  int64            `json:"forwarded"`
	Errors   int64            `json:"forward_errors"`
	Control  int64            `json:"control_requests"`
	Denied   int64            `json:"control_denied"`
	Arrivals map[string]int64 `json:"arrivals"`

	// Read back rather than remembered, so a redirect's observable can name the
	// address the fault replaced.
	Zone map[string]string `json:"zone"`

	// Rotated is the address a rotation REPLACED, echoed by that one route so
	// khaos's observable can name what the zone used to say.
	Rotated string `json:"rotated,omitempty"`

	// Only the queries khaos was AUTHORITATIVE for, keyed by source and name.
	// An arrival count alone goes non-zero for a target resolving anything else.
	Queries map[string]int64 `json:"queries"`
}

func (r *Resolver) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()

	return Stats{
		Armed:    r.trap.Kind,
		Host:     r.trap.Host,
		Inert:    r.trap.Inert,
		Faulted:  r.faulted,
		Honest:   r.honest,
		Forward:  r.forward,
		Errors:   r.errs,
		Control:  r.controls,
		Denied:   r.denied,
		Arrivals: maps.Clone(r.arrival),
		Queries:  maps.Clone(r.queries),
		Zone:     maps.Clone(r.zone),
	}
}

func (r *Resolver) handle(w dns.ResponseWriter, req *dns.Msg) {
	if req == nil || len(req.Question) == 0 {
		return
	}

	question := req.Question[0]

	r.record(sourceAddr(w.RemoteAddr()))

	honest, trap, authoritative := r.answerState(question.Name)
	if !authoritative {
		r.reply(w, req, r.forwardQuery(req, w))
		return
	}

	r.recordQuery(sourceAddr(w.RemoteAddr()), honest.Host)

	if !r.applies(trap, honest.Host) {
		r.countHonest()
		r.reply(w, req, r.synthesize(req, question, honest, addressAnswer))
		return
	}

	r.countFaulted()
	r.reply(w, req, r.serveFault(trap, req, question, honest, w))
}

func (r *Resolver) answerState(name string) (Trap, Trap, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	zoneName, found := r.lookup(name)
	return Trap{Host: zoneName, Address: r.zone[zoneName]}, r.trap, found
}

// lookup matches the whole name or the name plus a suffix, because a container's
// resolv.conf carries a forced `search` domain and a client whose absolute
// attempt fails RETRIES with that suffix.
func (r *Resolver) lookup(name string) (string, bool) {
	asked := dns.CanonicalName(name)

	if _, ok := r.zone[asked]; ok {
		return asked, true
	}

	for entry := range r.zone {
		if strings.HasPrefix(asked, strings.TrimSuffix(entry, ".")+".") {
			return entry, true
		}
	}

	return "", false
}

func (r *Resolver) applies(trap Trap, zoneName string) bool {
	if trap.Kind == PassThrough || trap.Inert || trap.Host == "" {
		return false
	}

	return dns.CanonicalName(trap.Host) == zoneName
}

// serveFault acts on khaos's OWN honest answer for the name, so each trap
// corrupts exactly ONE property rather than being two faults reported as one.
func (r *Resolver) serveFault(
	trap Trap,
	req *dns.Msg,
	question dns.Question,
	honest Trap,
	w dns.ResponseWriter,
) *dns.Msg {
	switch trap.Kind {
	case NXDomain:
		return authoritativeRcode(req, dns.RcodeNameError)

	case ServFail:
		return authoritativeRcode(req, dns.RcodeServerFailure)

	case WrongAddress:
		return r.synthesize(req, question, Trap{
			Host:    honest.Host,
			Address: trap.address(),
		}, addressAnswer)

	case CNAMEChain:
		// Ends at the trap's address, not the honest one, or the indirection
		// changes nothing about where the traffic went.
		return r.synthesize(req, question, Trap{
			Host:    honest.Host,
			Address: trap.address(),
		}, chainAnswer)

	case AddressRotated:
		// The HONEST answer, deliberately: this trap moved the zone, so the
		// honest path already serves the new address. Synthesizing from the
		// trap instead would make it a wrong-answer fault and khaos would be
		// serving a redirect while reporting a rotation.
		return r.synthesize(req, question, honest, addressAnswer)

	case CNAMELoop:
		return r.synthesize(req, question, honest, loopAnswer)

	case SlowResponse:
		time.Sleep(trap.delay())
		return r.synthesize(req, question, honest, addressAnswer)

	case Truncation:
		// Emptying the UDP answer makes the fault about the RETRY rather than
		// the bit, since a client that ignores `tc` keeps what it was given.
		reply := r.synthesize(req, question, honest, addressAnswer)
		if protoOf(w) == udpNet {
			reply.Truncated = true
			reply.Answer = nil
		}
		return reply

	case TruncationNoTCP:
		reply := r.synthesize(req, question, honest, addressAnswer)
		reply.Truncated = true
		reply.Answer = nil
		return reply

	case TTLZero, TTLLong:
		return rettl(
			r.synthesize(req, question, honest, addressAnswer),
			trap.ttl(),
		)

	case Refused, Timeout, PassThrough:
		// Unreachable, and SERVFAIL rather than a silent empty reply so a future
		// kind that forgets its branch is observably broken.
		return new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)

	default:
		return new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
	}
}

// authoritativeRcode is an rcode khaos answers ON PURPOSE; every other SERVFAIL
// here is khaos failing and stays NON-authoritative, which is what tells the
// two apart from outside.
func authoritativeRcode(req *dns.Msg, rcode int) *dns.Msg {
	reply := new(dns.Msg).SetRcode(req, rcode)
	reply.Authoritative = true

	return reply
}

func (r *Resolver) synthesize(
	req *dns.Msg,
	question dns.Question,
	trap Trap,
	build func(dns.Question, Trap) ([]dns.RR, error),
) *dns.Msg {
	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.Authoritative = true

	records, err := build(question, trap)
	if err != nil {
		r.countError()
		return new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
	}

	reply.Answer = records

	return reply
}

func (r *Resolver) reply(w dns.ResponseWriter, req, msg *dns.Msg) {
	if msg == nil {
		msg = new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
	}

	if err := w.WriteMsg(msg); err != nil {
		r.countError()
	}
}

func (r *Resolver) forwardQuery(req *dns.Msg, w dns.ResponseWriter) *dns.Msg {
	client := &dns.Client{Net: protoOf(w), Timeout: forwardTimeout}

	resp, _, err := client.Exchange(req.Copy(), r.cfg.Upstream)
	if err != nil || resp == nil {
		r.countError()
		return new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
	}

	r.countForward()
	resp.Id = req.Id

	return resp
}

func (r *Resolver) record(source string) {
	r.mu.Lock()
	r.arrival[source]++
	r.mu.Unlock()
}

func (r *Resolver) recordQuery(source, zoneName string) {
	r.mu.Lock()
	r.queries[QueryKey(source, zoneName)]++
	r.mu.Unlock()
}

// QueryKey is the one place the composite key is spelled.
func QueryKey(source, zoneName string) string {
	return source + " " + dns.CanonicalName(zoneName)
}

// Queries reports how many times one source asked about one name khaos owns.
func (r *Resolver) Queries(source, zoneName string) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.queries[QueryKey(source, zoneName)]
}

func (r *Resolver) countFaulted() {
	r.mu.Lock()
	r.faulted++
	r.mu.Unlock()
}

func (r *Resolver) countHonest() {
	r.mu.Lock()
	r.honest++
	r.mu.Unlock()
}

func (r *Resolver) countForward() {
	r.mu.Lock()
	r.forward++
	r.mu.Unlock()
}

func (r *Resolver) countError() {
	r.mu.Lock()
	r.errs++
	r.mu.Unlock()
}

func protoOf(w dns.ResponseWriter) string {
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		return tcpNet
	}
	return udpNet
}

func sourceAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}

	return host
}

func sameAddr(listen, upstream string) bool {
	lh, lp, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}

	uh, up, err := net.SplitHostPort(upstream)
	if err != nil {
		return false
	}

	if lp != up {
		return false
	}

	return lh != "" && lh == uh
}

func joinWith(parts []string, sep string) string {
	return strings.Join(parts, sep)
}
