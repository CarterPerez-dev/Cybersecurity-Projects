/*
©AngelaMos | 2026
iptables.v

Parser for iptables-save output format

Reads the *table / :CHAIN POLICY / -A rule / COMMIT structure that
iptables-save produces. tokenize_iptables splits each rule line into
tokens while respecting single and double quotes so log prefixes like
"DROPPED: " stay intact. parse_iptables_rule walks the token stream
flag by flag (-p, -s, -d, --dport, --state, -j, etc.) building a Rule
struct. The ! negation token is tracked across flag boundaries so
"! -s 10.0.0.0/8" correctly sets NetworkAddr.negated. Chain default
policies (":INPUT DROP [0:0]") are stored in Ruleset.policies.

Key exports:
  parse_iptables      - Parses a full iptables-save string into a Ruleset
  parse_iptables_file - Convenience wrapper that reads a file first

Connects to:
  parser/common.v - calls parse_network_addr, parse_port_spec, parse_port_list,
                     parse_protocol, parse_action, parse_table, parse_chain_type,
                     parse_conn_states for every token type
  models/models.v - imports Rule, Ruleset, MatchCriteria, NetworkAddr, Action, Table
  main.v          - called from load_ruleset when format is .iptables
*/

module parser

import os
import src.models { Action, MatchCriteria, NetworkAddr, Rule, Ruleset, Table }

pub fn parse_iptables_file(path string) !Ruleset {
	content := os.read_file(path) or { return error('cannot read file: ${path}') }
	return parse_iptables(content)
}

pub fn parse_iptables(content string) !Ruleset {
	mut ruleset := Ruleset{
		source: .iptables
	}
	mut current_table := Table.filter
	lines := content.split('\n')
	for i, line in lines {
		trimmed := line.trim_space()
		if trimmed.len == 0 || trimmed.starts_with('#') {
			continue
		}
		if trimmed == 'COMMIT' {
			continue
		}
		if trimmed.starts_with('*') {
			current_table = parse_table(trimmed[1..])!
			continue
		}
		if trimmed.starts_with(':') {
			chain_name, policy := parse_chain_policy(trimmed)!
			ruleset.policies[chain_name] = policy
			continue
		}
		if trimmed.starts_with('-A') || trimmed.starts_with('-I') {
			rule := parse_iptables_rule(trimmed, current_table, i + 1)!
			ruleset.rules << rule
		}
	}
	return ruleset
}

fn parse_table_header(line string) !Table {
	if !line.starts_with('*') {
		return error('expected table header starting with *')
	}
	return parse_table(line[1..])
}

fn parse_chain_policy(line string) !(string, Action) {
	if !line.starts_with(':') {
		return error('expected chain policy starting with :')
	}
	content := line[1..]
	parts := content.split(' ')
	if parts.len < 2 {
		return error('invalid chain policy: ${line}')
	}
	chain_name := parts[0]
	action := parse_action(parts[1])!
	return chain_name, action
}

fn parse_iptables_rule(line string, current_table Table, line_num int) !Rule {
	tokens := tokenize_iptables(line)
	mut i := 0
	mut chain := ''
	mut protocol := models.Protocol.all
	mut source := ?NetworkAddr(none)
	mut destination := ?NetworkAddr(none)
	mut src_ports := []models.PortSpec{}
	mut dst_ports := []models.PortSpec{}
	mut in_iface := ?string(none)
	mut out_iface := ?string(none)
	mut states := models.ConnState.zero()
	mut icmp_type := ?string(none)
	mut limit_rate := ?string(none)
	mut limit_burst := ?int(none)
	mut comment := ?string(none)
	mut action := Action.accept
	mut target_args := ''
	mut next_negated := false

	for i < tokens.len {
		tok := tokens[i]
		match tok {
			'!' {
				next_negated = true
				i++
				continue
			}
			'-A', '-I' {
				i++
				if i < tokens.len {
					chain = tokens[i]
				}
			}
			'-p', '--protocol' {
				i++
				if i < tokens.len {
					protocol = parse_protocol(tokens[i])!
				}
			}
			'-s', '--source' {
				i++
				if i < tokens.len {
					mut addr := parse_network_addr(tokens[i])!
					if next_negated {
						addr = NetworkAddr{
							address: addr.address
							cidr:    addr.cidr
							negated: true
						}
						next_negated = false
					}
					source = addr
				}
			}
			'-d', '--destination' {
				i++
				if i < tokens.len {
					mut addr := parse_network_addr(tokens[i])!
					if next_negated {
						addr = NetworkAddr{
							address: addr.address
							cidr:    addr.cidr
							negated: true
						}
						next_negated = false
					}
					destination = addr
				}
			}
			'--sport', '--source-port' {
				i++
				if i < tokens.len {
					mut ps := parse_port_spec(tokens[i])!
					if next_negated {
						ps = models.PortSpec{
							start:   ps.start
							end:     ps.end
							negated: true
						}
						next_negated = false
					}
					src_ports << ps
				}
			}
			'--dport', '--destination-port' {
				i++
				if i < tokens.len {
					mut ps := parse_port_spec(tokens[i])!
					if next_negated {
						ps = models.PortSpec{
							start:   ps.start
							end:     ps.end
							negated: true
						}
						next_negated = false
					}
					dst_ports << ps
				}
			}
			'--dports' {
				i++
				if i < tokens.len {
					dst_ports = parse_port_list(tokens[i])!
				}
			}
			'--sports' {
				i++
				if i < tokens.len {
					src_ports = parse_port_list(tokens[i])!
				}
			}
			'-i', '--in-interface' {
				i++
				if i < tokens.len {
					in_iface = tokens[i]
				}
			}
			'-o', '--out-interface' {
				i++
				if i < tokens.len {
					out_iface = tokens[i]
				}
			}
			'--state', '--ctstate' {
				i++
				if i < tokens.len {
					states = parse_conn_states(tokens[i])
				}
			}
			'--icmp-type' {
				i++
				if i < tokens.len {
					icmp_type = tokens[i]
				}
			}
			'--limit' {
				i++
				if i < tokens.len {
					limit_rate = tokens[i]
				}
			}
			'--limit-burst' {
				i++
				if i < tokens.len {
					limit_burst = tokens[i].int()
				}
			}
			'--comment' {
				i++
				if i < tokens.len {
					comment = tokens[i]
				}
			}
			'-j', '--jump', '-g', '--goto' {
				i++
				if i < tokens.len {
					action = parse_action(tokens[i]) or { Action.jump }
					if i + 1 < tokens.len && tokens[i + 1].starts_with('--') {
						mut args := []string{}
						for i + 1 < tokens.len {
							i++
							args << tokens[i]
						}
						target_args = args.join(' ')
					}
				}
			}
			'-m', '--match' {
				i++
			}
			else {
				next_negated = false
			}
		}
		i++
	}

	return Rule{
		table:       current_table
		chain:       chain
		chain_type:  parse_chain_type(chain)
		action:      action
		criteria:    MatchCriteria{
			protocol:    protocol
			source:      source
			destination: destination
			src_ports:   src_ports
			dst_ports:   dst_ports
			in_iface:    in_iface
			out_iface:   out_iface
			states:      states
			icmp_type:   icmp_type
			limit_rate:  limit_rate
			limit_burst: limit_burst
			comment:     comment
		}
		target_args: target_args
		line_number: line_num
		raw_text:    line
		source:      .iptables
	}
}

fn tokenize_iptables(line string) []string {
	mut tokens := []string{}
	mut current := []u8{}
	mut in_quote := false
	mut quote_char := u8(0)

	for ch in line.bytes() {
		if in_quote {
			if ch == quote_char {
				in_quote = false
				if current.len > 0 {
					tokens << current.bytestr()
					current.clear()
				}
			} else {
				current << ch
			}
		} else if ch == `"` || ch == `'` {
			in_quote = true
			quote_char = ch
		} else if ch == ` ` || ch == `\t` {
			if current.len > 0 {
				tokens << current.bytestr()
				current.clear()
			}
		} else {
			current << ch
		}
	}
	if current.len > 0 {
		tokens << current.bytestr()
	}
	return tokens
}
