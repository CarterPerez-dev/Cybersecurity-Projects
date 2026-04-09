/*
©AngelaMos | 2026
common.v

Shared parsing primitives and format auto-detection

Provides the low-level converters that both iptables.v and nftables.v
call: network addresses with optional CIDR and negation, single ports
and port lists, protocol names and numbers, actions, tables, chain
types, and conntrack state flags. detect_format examines the first
non-blank, non-comment line of a ruleset file to choose between the
iptables and nftables parsers. Protocol parsing accepts both names
("tcp") and IANA numbers ("6") so either style works in rule files.

Key exports:
  parse_network_addr - Parses "!10.0.0.0/8" into a NetworkAddr with negation and CIDR
  parse_port_spec    - Parses "!1024:65535" into a PortSpec with range and negation
  parse_port_list    - Splits "80,443,8080" into a []PortSpec
  parse_protocol     - Converts name or IANA number to Protocol enum
  parse_action       - Converts target string to Action enum
  parse_table        - Converts table name to Table enum
  parse_chain_type   - Maps chain name to ChainType, defaults to .custom
  parse_conn_states  - Splits "ESTABLISHED,RELATED" into a ConnState bitflag set
  detect_format      - Auto-detects whether input is iptables or nftables

Connects to:
  models/models.v     - imports all enum and struct types
  parser/iptables.v   - calls every function here during rule parsing
  parser/nftables.v   - calls parse_network_addr, parse_port_spec, parse_protocol, parse_action, parse_table, parse_chain_type, parse_conn_states
  main.v              - calls detect_format for auto-detection
*/

module parser

import src.models { Action, ChainType, ConnState, NetworkAddr, PortSpec, Protocol, RuleSource, Table }

pub fn parse_network_addr(s string) !NetworkAddr {
	mut input := s.trim_space()
	mut negated := false
	if input.starts_with('!') {
		negated = true
		input = input[1..].trim_space()
	}
	if input.contains('/') {
		parts := input.split('/')
		if parts.len != 2 {
			return error('invalid CIDR notation: ${s}')
		}
		cidr := parts[1].int()
		if cidr < 0 || cidr > 128 {
			return error('invalid CIDR prefix length: ${parts[1]}')
		}
		return NetworkAddr{
			address: parts[0]
			cidr:    cidr
			negated: negated
		}
	}
	return NetworkAddr{
		address: input
		cidr:    32
		negated: negated
	}
}

pub fn parse_port_spec(s string) !PortSpec {
	mut input := s.trim_space()
	mut negated := false
	if input.starts_with('!') {
		negated = true
		input = input[1..].trim_space()
	}
	if input.contains(':') {
		parts := input.split(':')
		if parts.len != 2 {
			return error('invalid port range: ${s}')
		}
		start := parts[0].int()
		end := parts[1].int()
		if start < 0 || start > 65535 || end < 0 || end > 65535 {
			return error('port out of range: ${s}')
		}
		return PortSpec{
			start:   start
			end:     end
			negated: negated
		}
	}
	port := input.int()
	if port < 0 || port > 65535 {
		return error('port out of range: ${s}')
	}
	return PortSpec{
		start:   port
		end:     -1
		negated: negated
	}
}

pub fn parse_port_list(s string) ![]PortSpec {
	mut result := []PortSpec{}
	parts := s.split(',')
	for part in parts {
		trimmed := part.trim_space()
		if trimmed.len == 0 {
			continue
		}
		result << parse_port_spec(trimmed)!
	}
	return result
}

pub fn parse_protocol(s string) !Protocol {
	return match s.to_lower().trim_space() {
		'tcp', '6' { .tcp }
		'udp', '17' { .udp }
		'icmp', '1' { .icmp }
		'icmpv6', 'ipv6-icmp', '58' { .icmpv6 }
		'all', '0' { .all }
		'sctp', '132' { .sctp }
		'gre', '47' { .gre }
		else { error('unknown protocol: ${s}') }
	}
}

pub fn parse_action(s string) !Action {
	return match s.to_upper().trim_space() {
		'ACCEPT' { .accept }
		'DROP' { .drop }
		'REJECT' { .reject }
		'LOG' { .log }
		'MASQUERADE' { .masquerade }
		'SNAT' { .snat }
		'DNAT' { .dnat }
		'RETURN' { .return_action }
		'JUMP' { .jump }
		'QUEUE' { .queue }
		else { error('unknown action: ${s}') }
	}
}

pub fn parse_table(s string) !Table {
	return match s.to_lower().trim_space() {
		'filter' { .filter }
		'nat' { .nat }
		'mangle' { .mangle }
		'raw' { .raw }
		'security' { .security }
		else { error('unknown table: ${s}') }
	}
}

pub fn parse_chain_type(s string) ChainType {
	return match s.to_upper().trim_space() {
		'INPUT' { .input }
		'OUTPUT' { .output }
		'FORWARD' { .forward }
		'PREROUTING' { .prerouting }
		'POSTROUTING' { .postrouting }
		else { .custom }
	}
}

pub fn parse_conn_states(s string) ConnState {
	mut result := ConnState.zero()
	parts := s.to_upper().split(',')
	for part in parts {
		match part.trim_space() {
			'NEW' { result.set(.new_conn) }
			'ESTABLISHED' { result.set(.established) }
			'RELATED' { result.set(.related) }
			'INVALID' { result.set(.invalid) }
			'UNTRACKED' { result.set(.untracked) }
			else {}
		}
	}
	return result
}

pub fn detect_format(content string) !RuleSource {
	lines := content.split('\n')
	for line in lines {
		trimmed := line.trim_space()
		if trimmed.len == 0 || trimmed.starts_with('#') {
			continue
		}
		if trimmed.starts_with('*') {
			return .iptables
		}
		if trimmed.starts_with('table') {
			return .nftables
		}
		if trimmed.starts_with(':') {
			return .iptables
		}
		if trimmed.starts_with('-A') || trimmed.starts_with('-I') {
			return .iptables
		}
		break
	}
	return error('unable to detect ruleset format')
}
