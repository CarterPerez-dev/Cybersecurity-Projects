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
	// DefaultPort is the port the resolver listens on INSIDE its container. It
	// is 53 and it has to be, because `--dns` carries an address and no port:
	// the CLI calls a port malformed and the daemon rejects it at container
	// start with `ParseAddr(...): unexpected character`, after create has
	// already succeeded. resolv.conf has no port field either.
	//
	// This is also why the resolver is a container and not a goroutine in khaos.
	// An unprivileged process gets `bind: permission denied` on port 53 at every
	// address, loopback included, while high ports on the same addresses bind
	// fine. Inside a container the process is root in its own namespace and
	// NET_BIND_SERVICE is in Docker's default set, so no host port is published
	// and khaos still holds no capability.
	DefaultPort = 53

	// DefaultUpstream is the resolver container's OWN embedded resolver.
	//
	// Forwarding there rather than to a public address is what keeps khaos
	// keyless and offline-capable: the resolver inherits exactly the resolution
	// the host has, with no configuration and no third party. There is no loop,
	// because khaos's resolver container is never created with `--dns` pointing
	// at itself, and khaos refuses to start one that is.
	DefaultUpstream = "127.0.0.11:53"

	// forwardTimeout is under the embedded resolver's own 4s `extIOTimeout`, so
	// a slow upstream surfaces here as a forward error khaos can read rather
	// than as the target's query dying one layer up where nothing records it.
	forwardTimeout = 3 * time.Second

	udpNet = "udp"
	tcpNet = "tcp"

	// bindAttempts only ever matters for an ephemeral port: the kernel can hand
	// out a UDP port that something else already holds in the TCP space.
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

var ErrOutsideZone = errors.New(
	"this resolver is not authoritative for that name",
)

// Config is everything the resolver needs to exist. It is deliberately small:
// the FAULT is not here, because a resolver is armed in band after it is
// running, for a reason that is measured rather than stylistic. Docker refuses
// `--ip` on a network whose subnet it chose, so khaos cannot pin the resolver's
// address, so re-creating the container to arm it would move the address the
// target was created to dial and the target would be talking to nothing.
type Config struct {
	// Listen is the address:port to bind. Empty binds every address on
	// DefaultPort, which is correct inside a container and is why khaos never
	// binds a wildcard on the host.
	Listen string

	// Upstream answers everything OUTSIDE the zone. A resolver that NXDOMAINed
	// unrelated names would break the target for reasons the experiment never
	// claimed, and the measured property that makes this safe is that the
	// target's own embedded resolver answers container names locally and never
	// forwards them here at all.
	Upstream string

	// Nonce authorises the control surface. khaos generates it, passes it at
	// container creation, and reads it back out of the container rather than
	// remembering what it chose, the same way the range reads its ports back
	// from the containers that will dial them.
	Nonce string

	// Zone is the set of names khaos is AUTHORITATIVE for, mapped to the honest
	// address each one really has.
	//
	// This exists because of a measured constraint rather than for convenience.
	// A container name or network alias can never be faulted: the target's own
	// embedded resolver answers those out of its own table and never forwards
	// them to an upstream, so khaos would never see the query. The faulted name
	// therefore has to be one the embedded resolver cannot answer — and then
	// NOBODY would answer it, and the baseline would measure a target whose
	// dependency never resolved. So khaos serves it honestly itself, and the
	// fault is a deviation from khaos's own correct answer.
	Zone map[string]string

	// Control is the name in Zone that no fault ever touches. It is the
	// confirmation oracle's positive control: khaos serves it from the same
	// table, over the same transports, through the same handler, so a control
	// that stops resolving means khaos's resolver is broken rather than lying.
	Control string
}

// Resolver is khaos's authoritative chaos resolver. One instance serves one
// network, is armed and disarmed in band, and attributes every query it answers
// to the address it came from.
type Resolver struct {
	cfg  Config
	zone map[string]string

	mu      sync.Mutex
	trap    Trap
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

// New builds a resolver without binding anything. Nothing listens until Serve,
// which is what makes the whole package unit-testable in process on a high port
// with no container and no privilege.
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

// Zone reports the names this resolver is authoritative for, so khaos can state
// them in a plan and a gate can census them.
func (r *Resolver) Zone() map[string]string {
	return maps.Clone(r.zone)
}

// Serve binds UDP and TCP and returns once both are accepting. Both transports
// are mandatory and not a nicety: a client that sees the truncation bit re-asks
// over TCP, the embedded resolver forwards on the transport the client used, and
// a UDP-only resolver would turn every truncation experiment into a timeout.
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

	// Each goroutine serves the LOCAL it was handed, never a field it reads back
	// off the struct. `internal/pki` shipped three data races doing the
	// opposite: its serve goroutines dereferenced a field that mutex-held
	// shutdown nils, and the plain test suite was green for both new packages.
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

// bindBoth puts UDP and TCP on the SAME port, and that is a correctness
// requirement rather than tidiness.
//
// Handing `dns.Server` an `Addr` with port 0 and letting each transport bind
// itself gives them DIFFERENT ports, because UDP and TCP are separate port
// spaces and the kernel picks independently. A resolver like that answers over
// UDP and is unreachable over TCP, so every client that sees the truncation bit
// and re-asks per RFC 5966 gets `connection refused` — the truncation fault
// becomes an outage, and the no-TCP variant confirms itself for free against a
// port that was never listening. A test caught it; at the real :53 both happen
// to land on the same number and nothing would have.
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

		// An explicit port cannot be retried into success, so the only case
		// worth another attempt is an ephemeral one the kernel chose for UDP
		// that something else already holds in the TCP space.
		if udpAddr.Port != 0 {
			break
		}
	}

	return nil, nil, last
}

// Addr reports where the resolver actually bound, which matters because a test
// asks for port 0 and has to find out what it got.
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

// Shutdown closes both DNS transports and the control surface. The control
// surface goes down too, and unconditionally, because a resolver whose DNS is
// gone but whose /arm still answers is one khaos could arm and then confirm
// against nothing.
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

// Arm installs a fault. An inert trap is still installed, because the negative
// control has to travel the same path as a live one: a control that skipped
// arming would prove only that the resolver was never asked.
func (r *Resolver) Arm(trap Trap) error {
	if err := trap.Validate(); err != nil {
		return err
	}

	if trap.Kind != PassThrough {
		if err := r.inZone(trap.Host); err != nil {
			return err
		}

		if dns.CanonicalName(trap.Host) == dns.CanonicalName(r.cfg.Control) {
			return fmt.Errorf(errFaultedHost, ErrControlIsHost, trap.Host)
		}
	}

	r.mu.Lock()
	r.trap = trap
	r.mu.Unlock()

	return nil
}

// inZone refuses a fault aimed at a name this resolver does not answer.
//
// Without it the most likely operator mistake is also the most silent one: a
// trap on a name khaos is not authoritative for arms cleanly, every query for
// it is forwarded untouched, the target resolves it perfectly, and the run
// reports a clean survival against a fault that was never applied to anything.
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

func (r *Resolver) Disarm() {
	r.mu.Lock()
	r.trap = Trap{}
	r.mu.Unlock()
}

func (r *Resolver) armed() Trap {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.trap
}

// Arrivals reports how many queries came from one address. It is attributed by
// SOURCE rather than counted in total, and that is the difference between a
// proof of arrival and a number that is always non-zero.
//
// khaos queries its own resolver to confirm the fault, from the host, so its
// source is the bridge gateway. The target's queries are forwarded by the
// embedded resolver from the TARGET's own network namespace, so their source is
// the target's container address. Counting both together would make "the target
// used khaos's resolver" true on every run, including the runs where the target
// never used it at all.
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

	// Zone is the honest answer khaos serves for each name it owns, read back
	// rather than remembered. A redirect's observable needs it to name the
	// address the fault replaced rather than restating the one it served.
	Zone map[string]string `json:"zone"`

	// Queries counts only the queries khaos was AUTHORITATIVE for, keyed by
	// source address and zone name.
	//
	// Arrivals alone cannot carry the proof-of-arrival control, and that is the
	// whole reason this exists. A target resolving anything else through khaos's
	// resolver -- a public name, another service -- makes its arrival count
	// non-zero without ever asking about the dependency under fault, so the
	// guard would pass for a target that never experienced the experiment. It
	// would also break the TTL faults outright, whose whole measurement is HOW
	// MANY times the faulted name was asked for.
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

	name, authoritative := r.lookup(question.Name)
	if !authoritative {
		r.reply(w, req, r.forwardQuery(req, w))
		return
	}

	r.recordQuery(sourceAddr(w.RemoteAddr()), name)

	trap := r.armed()
	if !r.applies(trap, name) {
		r.countHonest()
		r.reply(w, req, r.honestAnswer(req, question, name))
		return
	}

	r.countFaulted()
	r.reply(w, req, r.serveFault(trap, req, question, name, w))
}

// lookup resolves a query name to the zone entry it belongs to, and reports
// whether khaos is authoritative for it at all.
//
// Matching is on the WHOLE name or on the name plus a suffix, because a
// container's resolv.conf carries a forced `search` domain. A target asking for
// `dependency.khaos.test` was measured arriving as both
// `dependency.khaos.test.` and `dependency.khaos.test.mynetworksettings.com.`,
// and that is not cosmetic: under a negative fault the absolute attempt fails
// and the client RETRIES with the search suffix, so a resolver that faulted only
// the exact name would answer the retry honestly and defeat its own fault.
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

// honestAnswer is what khaos serves for a zone name with nothing armed against
// it, and what it serves for the control name always. Every baseline is
// measured through this, so it has to be indistinguishable from a correct
// resolver's answer.
func (r *Resolver) honestAnswer(
	req *dns.Msg,
	question dns.Question,
	zoneName string,
) *dns.Msg {
	return r.synthesize(req, question, Trap{
		Host:    zoneName,
		Address: r.zone[zoneName],
	}, addressAnswer)
}

// serveFault produces the faulted answer. Every kind acts on khaos's OWN honest
// answer for the name, which is the design rule from the PKI tier restated:
// every trap corrupts exactly ONE property. A fault that synthesized its own
// address as a side effect of being slow would be two faults reported as one.
func (r *Resolver) serveFault(
	trap Trap,
	req *dns.Msg,
	question dns.Question,
	zoneName string,
	w dns.ResponseWriter,
) *dns.Msg {
	honest := Trap{Host: zoneName, Address: r.zone[zoneName]}

	switch trap.Kind {
	case NXDomain:
		return authoritativeRcode(req, dns.RcodeNameError)

	case ServFail:
		return authoritativeRcode(req, dns.RcodeServerFailure)

	case WrongAddress:
		return r.synthesize(req, question, Trap{
			Host:    zoneName,
			Address: trap.address(),
		}, addressAnswer)

	case CNAMEChain:
		// The chain ends at the trap's address, not the honest one, and that is
		// what makes it a finding rather than decoration. Research 05 section 10
		// states the fault precisely: if name matching happens on the name that
		// was ASKED rather than on the target the connection goes to, a CNAME
		// out of the allowlisted zone passes the check while the traffic goes
		// somewhere else. Ending the chain at the honest address would test the
		// indirection and change nothing about where the traffic went, so there
		// would be nothing for a control to have failed to notice.
		return r.synthesize(req, question, Trap{
			Host:    zoneName,
			Address: trap.address(),
		}, chainAnswer)

	case CNAMELoop:
		return r.synthesize(req, question, honest, loopAnswer)

	case SlowResponse:
		time.Sleep(trap.delay())
		return r.synthesize(req, question, honest, addressAnswer)

	case Truncation:
		// Truncated with nothing in it over UDP, complete over TCP: the shape a
		// correct truncating server has. Emptying the UDP answer is what makes
		// the fault about the RETRY rather than about the bit, because a client
		// that ignores `tc` and keeps the records it was given has not been
		// tested by a truncated message that was complete anyway.
		reply := r.synthesize(req, question, honest, addressAnswer)
		if protoOf(w) == udpNet {
			reply.Truncated = true
			reply.Answer = nil
		}
		return reply

	case TruncationNoTCP:
		// Truncated and empty on BOTH transports, so the client exhausts UDP and
		// TCP and still has nothing. This is research 05 row 9's actual security
		// question — whether DNS over TCP is permitted at all — rather than the
		// fallback question above.
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
		// Unreachable: Validate refuses both masked kinds before a trap can be
		// armed, and applies() excludes PassThrough. SERVFAIL rather than a
		// silent empty reply means a future kind that forgets its branch is
		// observably broken instead of looking like a target that resolved
		// nothing.
		return new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)

	default:
		return new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
	}
}

// authoritativeRcode is an rcode khaos is answering ON PURPOSE, for a name it
// owns. Every other SERVFAIL in this file is khaos failing at something and is
// left NON-authoritative, which is what makes the two distinguishable from
// outside: deleting the ServFail arm used to fall through to `default`, serve
// the same rcode, and leave every test and the whole gate green.
//
// It is also the protocol-correct answer. khaos IS the authority for its zone,
// so an NXDOMAIN or a SERVFAIL it decides on carries AA, and one it stumbles
// into does not.
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

// recordQuery counts a query for a name khaos answers authoritatively, keyed by
// source AND name, because both predicates built on it need the pair.
func (r *Resolver) recordQuery(source, zoneName string) {
	r.mu.Lock()
	r.queries[QueryKey(source, zoneName)]++
	r.mu.Unlock()
}

// QueryKey is the one place the composite key is spelled, so the resolver
// counting and khaos reading cannot disagree about its shape.
func QueryKey(source, zoneName string) string {
	return source + " " + dns.CanonicalName(zoneName)
}

// Queries reports how many times one source asked about one name khaos is
// authoritative for.
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
