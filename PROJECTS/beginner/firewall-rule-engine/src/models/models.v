/*
©AngelaMos | 2026
models.v

Domain types for firewall rule representation and matching

Every rule parsed from iptables or nftables input lands in the same
unified Rule struct so the analyzer and generator never need to know
which format the original file used. Enums use explicit u8 backing for
compact storage when rulesets grow large. NetworkAddr and PortSpec carry
a negated flag so "! -s 10.0.0.0/8" round-trips cleanly through parse,
analyze, and export. ip_to_u32 and cidr_contains power the superset and
overlap checks in the conflict analyzer by converting dotted-quad
addresses to a single u32 for prefix comparison.

Key exports:
  Protocol      - Network protocol enum (tcp, udp, icmp, icmpv6, all, sctp, gre)
  Action        - Firewall target action (accept, drop, reject, log, NAT variants)
  Table         - Netfilter table (filter, nat, mangle, raw, security)
  ChainType     - Built-in chain identifiers plus custom
  RuleSource    - Discriminates iptables from nftables origin
  Severity      - Finding severity for analyzer output (info, warning, critical)
  ConnState     - Bitflag set for conntrack states (new, established, related, invalid)
  NetworkAddr   - IP address with CIDR prefix length and negation
  PortSpec      - Single port or port range with negation
  MatchCriteria - Full match tuple: protocol, addresses, ports, interfaces, conntrack
  Rule          - One firewall rule: table, chain, action, criteria, line number, raw text
  Finding       - Analyzer result: severity, title, description, affected rules, suggestion
  Ruleset       - Collection of rules with chain default policies
  ip_to_u32     - Converts dotted-quad IPv4 string to a 32-bit integer
  cidr_contains - Tests whether one CIDR prefix fully contains another
  port_range_contains - Tests whether one port range fully contains another

Connects to:
  parser/common.v   - imports all enums and structs for parsing
  parser/iptables.v - imports Rule, Ruleset, MatchCriteria, NetworkAddr, Action, Table
  parser/nftables.v - imports Rule, Ruleset, MatchCriteria, NetworkAddr, Action, Table
  analyzer/conflict.v  - imports Rule, Ruleset, MatchCriteria, Finding, Action, NetworkAddr, PortSpec
  analyzer/optimizer.v - imports Rule, Ruleset, Finding
  generator/generator.v - imports Rule, Ruleset, RuleSource
  display/display.v     - imports Rule, Ruleset, Finding, Action, Severity
*/

module models

pub enum Protocol as u8 {
	tcp
	udp
	icmp
	icmpv6
	all
	sctp
	gre
}

pub fn (p Protocol) str() string {
	return match p {
		.tcp { 'tcp' }
		.udp { 'udp' }
		.icmp { 'icmp' }
		.icmpv6 { 'icmpv6' }
		.all { 'all' }
		.sctp { 'sctp' }
		.gre { 'gre' }
	}
}

pub enum Action as u8 {
	accept
	drop
	reject
	log
	masquerade
	snat
	dnat
	return_action
	jump
	queue
}

pub fn (a Action) str() string {
	return match a {
		.accept { 'ACCEPT' }
		.drop { 'DROP' }
		.reject { 'REJECT' }
		.log { 'LOG' }
		.masquerade { 'MASQUERADE' }
		.snat { 'SNAT' }
		.dnat { 'DNAT' }
		.return_action { 'RETURN' }
		.jump { 'JUMP' }
		.queue { 'QUEUE' }
	}
}

pub enum Table as u8 {
	filter
	nat
	mangle
	raw
	security
}

pub fn (t Table) str() string {
	return match t {
		.filter { 'filter' }
		.nat { 'nat' }
		.mangle { 'mangle' }
		.raw { 'raw' }
		.security { 'security' }
	}
}

pub enum ChainType as u8 {
	input
	output
	forward
	prerouting
	postrouting
	custom
}

pub fn (c ChainType) str() string {
	return match c {
		.input { 'INPUT' }
		.output { 'OUTPUT' }
		.forward { 'FORWARD' }
		.prerouting { 'PREROUTING' }
		.postrouting { 'POSTROUTING' }
		.custom { 'CUSTOM' }
	}
}

pub enum RuleSource as u8 {
	iptables
	nftables
}

pub fn (r RuleSource) str() string {
	return match r {
		.iptables { 'iptables' }
		.nftables { 'nftables' }
	}
}

pub enum Severity as u8 {
	info
	warning
	critical
}

pub fn (s Severity) str() string {
	return match s {
		.info { 'INFO' }
		.warning { 'WARNING' }
		.critical { 'CRITICAL' }
	}
}

@[flag]
pub enum ConnState {
	new_conn
	established
	related
	invalid
	untracked
}

pub struct NetworkAddr {
pub:
	address string
	cidr    int = 32
	negated bool
}

pub fn (n NetworkAddr) str() string {
	mut s := ''
	if n.negated {
		s += '!'
	}
	s += n.address
	if n.cidr != 32 {
		s += '/${n.cidr}'
	}
	return s
}

pub fn ip_to_u32(ip string) !u32 {
	parts := ip.split('.')
	if parts.len != 4 {
		return error('invalid IPv4 address: ${ip}')
	}
	mut result := u32(0)
	for part in parts {
		trimmed := part.trim_space()
		if trimmed.len == 0 {
			return error('invalid octet in address: ${ip}')
		}
		for ch in trimmed.bytes() {
			if ch < `0` || ch > `9` {
				return error('invalid octet in address: ${ip}')
			}
		}
		val := trimmed.int()
		if val < 0 || val > 255 {
			return error('invalid octet in address: ${ip}')
		}
		result = (result << 8) | u32(val)
	}
	return result
}

pub fn cidr_contains(outer NetworkAddr, inner NetworkAddr) bool {
	outer_ip := ip_to_u32(outer.address) or { return false }
	inner_ip := ip_to_u32(inner.address) or { return false }
	if outer.cidr > inner.cidr {
		return false
	}
	if outer.cidr == 0 {
		return true
	}
	shift := u32(32 - outer.cidr)
	return (outer_ip >> shift) == (inner_ip >> shift)
}

pub struct PortSpec {
pub:
	start   int
	end     int = -1
	negated bool
}

pub fn (p PortSpec) str() string {
	mut s := ''
	if p.negated {
		s += '!'
	}
	s += '${p.start}'
	if p.end > 0 && p.end != p.start {
		s += ':${p.end}'
	}
	return s
}

pub fn (p PortSpec) effective_end() int {
	if p.end < 0 {
		return p.start
	}
	return p.end
}

pub fn port_range_contains(outer PortSpec, inner PortSpec) bool {
	return outer.start <= inner.start && outer.effective_end() >= inner.effective_end()
}

pub struct MatchCriteria {
pub:
	protocol    Protocol = .all
	source      ?NetworkAddr
	destination ?NetworkAddr
	src_ports   []PortSpec
	dst_ports   []PortSpec
	in_iface    ?string
	out_iface   ?string
	states      ConnState
	icmp_type   ?string
	limit_rate  ?string
	limit_burst ?int
	comment     ?string
}

pub struct Rule {
pub:
	table       Table = .filter
	chain       string
	chain_type  ChainType
	action      Action
	criteria    MatchCriteria
	target_args string
	line_number int
	raw_text    string
	source      RuleSource
}

pub fn (r Rule) str() string {
	mut parts := []string{}
	parts << r.chain
	parts << r.criteria.protocol.str()
	if src := r.criteria.source {
		parts << src.str()
	} else {
		parts << '*'
	}
	if dst := r.criteria.destination {
		parts << dst.str()
	} else {
		parts << '*'
	}
	if r.criteria.dst_ports.len > 0 {
		port_strs := r.criteria.dst_ports.map(it.str())
		parts << port_strs.join(',')
	} else {
		parts << '*'
	}
	parts << r.action.str()
	return parts.join('\t')
}

pub struct Finding {
pub:
	severity     Severity
	title        string
	description  string
	rule_indices []int
	suggestion   string
}

pub struct Ruleset {
pub mut:
	rules    []Rule
	policies map[string]Action
	source   RuleSource
}

pub fn (rs Ruleset) rules_by_chain() map[string][]int {
	mut result := map[string][]int{}
	for i, rule in rs.rules {
		result[rule.chain] << i
	}
	return result
}
