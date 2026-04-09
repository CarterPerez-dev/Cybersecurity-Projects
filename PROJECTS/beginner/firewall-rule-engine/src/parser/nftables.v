/*
©AngelaMos | 2026
nftables.v

Parser for nftables ruleset format

Uses recursive descent to walk the nested brace structure: table blocks
contain chain blocks which contain rule lines. parse_nft_table extracts
the table name (skipping address family keywords like inet/ip/ip6),
parse_nft_chain reads the "type filter hook ... policy ..." preamble to
capture chain policies, and parse_nft_rule tokenizes individual rule
lines. Port matching handles both single ports ("dport 22") and set
syntax ("dport { 80, 443 }"). Supports IPv4/IPv6 address matching via
"ip saddr"/"ip6 saddr", conntrack via "ct state", rate limiting, NAT
actions (dnat/snat/masquerade), and log with prefix.

Key exports:
  parse_nftables      - Parses a full nftables ruleset string into a Ruleset
  parse_nftables_file - Convenience wrapper that reads a file first

Connects to:
  parser/common.v - calls parse_network_addr, parse_port_spec, parse_protocol,
                     parse_action, parse_table, parse_chain_type, parse_conn_states
  models/models.v - imports Rule, Ruleset, MatchCriteria, NetworkAddr, Action, Table
  main.v          - called from load_ruleset when format is .nftables
*/

module parser

import os
import src.models { Action, MatchCriteria, NetworkAddr, Rule, Ruleset, Table }

pub fn parse_nftables_file(path string) !Ruleset {
	content := os.read_file(path) or { return error('cannot read file: ${path}') }
	return parse_nftables(content)
}

pub fn parse_nftables(content string) !Ruleset {
	mut ruleset := Ruleset{
		source: .nftables
	}
	lines := content.split('\n')
	mut i := 0

	for i < lines.len {
		trimmed := lines[i].trim_space()
		if trimmed.len == 0 || trimmed.starts_with('#') {
			i++
			continue
		}
		if trimmed.starts_with('table') {
			tbl, new_i := parse_nft_table(mut ruleset, lines, i)!
			_ = tbl
			i = new_i
			continue
		}
		i++
	}
	return ruleset
}

fn parse_nft_table(mut ruleset Ruleset, lines []string, start int) !(Table, int) {
	header := lines[start].trim_space()
	parts := header.replace('{', '').trim_space().split(' ')
	mut table_name := ''
	for part in parts {
		trimmed := part.trim_space()
		if trimmed.len == 0 || trimmed == 'table' || trimmed == 'inet' || trimmed == 'ip'
			|| trimmed == 'ip6' || trimmed == 'arp' || trimmed == 'bridge' || trimmed == 'netdev' {
			continue
		}
		table_name = trimmed
		break
	}
	tbl := parse_table(table_name) or { Table.filter }
	mut i := start + 1
	for i < lines.len {
		trimmed := lines[i].trim_space()
		if trimmed == '}' {
			return tbl, i + 1
		}
		if trimmed.starts_with('chain') {
			chain_name, new_i := parse_nft_chain(mut ruleset, lines, i, tbl)!
			_ = chain_name
			i = new_i
			continue
		}
		i++
	}
	return tbl, i
}

fn parse_nft_chain(mut ruleset Ruleset, lines []string, start int, tbl Table) !(string, int) {
	header := lines[start].trim_space()
	chain_name := header.replace('chain', '').replace('{', '').trim_space()
	chain_type := parse_chain_type(chain_name)
	mut i := start + 1
	mut line_in_chain := 0

	for i < lines.len {
		trimmed := lines[i].trim_space()
		if trimmed == '}' {
			return chain_name, i + 1
		}
		if trimmed.starts_with('type') {
			policy := extract_nft_policy(trimmed)
			if p := policy {
				ruleset.policies[chain_name.to_upper()] = p
			}
			i++
			continue
		}
		if trimmed.len > 0 && !trimmed.starts_with('#') {
			rule := parse_nft_rule(trimmed, tbl, chain_name.to_upper(), chain_type, i + 1) or {
				i++
				continue
			}
			ruleset.rules << rule
			line_in_chain++
		}
		i++
	}
	return chain_name, i
}

fn extract_nft_policy(line string) ?Action {
	if !line.contains('policy') {
		return none
	}
	parts := line.split(';')
	for part in parts {
		trimmed := part.trim_space()
		if trimmed.starts_with('policy') {
			policy_str := trimmed.replace('policy', '').trim_space().trim_right(';')
			return parse_action(policy_str) or { return none }
		}
	}
	return none
}

fn parse_nft_rule(line string, tbl Table, chain string, chain_type models.ChainType, line_num int) !Rule {
	tokens := line.split(' ').map(it.trim_space()).filter(it.len > 0)
	mut protocol := models.Protocol.all
	mut source := ?NetworkAddr(none)
	mut destination := ?NetworkAddr(none)
	mut dst_ports := []models.PortSpec{}
	mut src_ports := []models.PortSpec{}
	mut in_iface := ?string(none)
	mut out_iface := ?string(none)
	mut states := models.ConnState.zero()
	mut limit_rate := ?string(none)
	mut comment := ?string(none)
	mut action := ?Action(none)
	mut target_args := ''
	mut i := 0

	for i < tokens.len {
		tok := tokens[i]
		match tok {
			'tcp' {
				protocol = .tcp
				i++
				if i < tokens.len {
					i = parse_nft_port_match(tokens, i, mut dst_ports, mut src_ports)
					continue
				}
			}
			'udp' {
				protocol = .udp
				i++
				if i < tokens.len {
					i = parse_nft_port_match(tokens, i, mut dst_ports, mut src_ports)
					continue
				}
			}
			'ip', 'ip6' {
				i++
				if i < tokens.len {
					match tokens[i] {
						'saddr' {
							i++
							if i < tokens.len {
								source = parse_network_addr(tokens[i]) or { continue }
							}
						}
						'daddr' {
							i++
							if i < tokens.len {
								destination = parse_network_addr(tokens[i]) or { continue }
							}
						}
						'protocol' {
							i++
							if i < tokens.len {
								protocol = parse_protocol(tokens[i]) or { models.Protocol.all }
							}
						}
						else {}
					}
				}
			}
			'ct' {
				i++
				if i < tokens.len && tokens[i] == 'state' {
					i++
					if i < tokens.len {
						states = parse_conn_states(tokens[i])
					}
				}
			}
			'iifname', 'iif' {
				i++
				if i < tokens.len {
					in_iface = tokens[i].replace('"', '')
				}
			}
			'oifname', 'oif' {
				i++
				if i < tokens.len {
					out_iface = tokens[i].replace('"', '')
				}
			}
			'limit' {
				i++
				if i < tokens.len && tokens[i] == 'rate' {
					i++
					mut rate_parts := []string{}
					for i < tokens.len {
						t := tokens[i]
						if t == 'accept' || t == 'drop' || t == 'reject' || t == 'log'
							|| t == 'counter' {
							break
						}
						rate_parts << t
						i++
					}
					limit_rate = rate_parts.join(' ')
					continue
				}
			}
			'log' {
				if action == none {
					action = .log
				}
				i++
				if i < tokens.len && tokens[i] == 'prefix' {
					i++
					if i < tokens.len {
						target_args = 'prefix ${tokens[i]}'
					}
				}
				continue
			}
			'counter' {
				i++
				continue
			}
			'comment' {
				i++
				if i < tokens.len {
					comment = tokens[i].replace('"', '')
				}
			}
			'accept' {
				action = .accept
			}
			'drop' {
				action = .drop
			}
			'reject' {
				action = .reject
			}
			'masquerade' {
				action = .masquerade
			}
			'queue' {
				action = .queue
			}
			'return' {
				action = .return_action
			}
			'dnat' {
				action = .dnat
				i++
				if i < tokens.len && tokens[i] == 'to' {
					i++
					if i < tokens.len {
						target_args = 'to ${tokens[i]}'
					}
				}
				continue
			}
			'snat' {
				action = .snat
				i++
				if i < tokens.len && tokens[i] == 'to' {
					i++
					if i < tokens.len {
						target_args = 'to ${tokens[i]}'
					}
				}
				continue
			}
			else {}
		}
		i++
	}

	final_action := action or { return error('no action found in rule: ${line}') }

	return Rule{
		table:       tbl
		chain:       chain
		chain_type:  chain_type
		action:      final_action
		criteria:    MatchCriteria{
			protocol:    protocol
			source:      source
			destination: destination
			src_ports:   src_ports
			dst_ports:   dst_ports
			in_iface:    in_iface
			out_iface:   out_iface
			states:      states
			limit_rate:  limit_rate
			comment:     comment
		}
		target_args: target_args
		line_number: line_num
		raw_text:    line
		source:      .nftables
	}
}

fn parse_nft_port_match(tokens []string, start int, mut dst_ports []models.PortSpec, mut src_ports []models.PortSpec) int {
	mut i := start
	if i >= tokens.len {
		return i
	}
	is_dport := tokens[i] == 'dport'
	is_sport := tokens[i] == 'sport'
	if !is_dport && !is_sport {
		return i
	}
	i++
	if i >= tokens.len {
		return i
	}
	if tokens[i] == '{' {
		i++
		mut port_str := []string{}
		for i < tokens.len && tokens[i] != '}' {
			cleaned := tokens[i].replace(',', '').trim_space()
			if cleaned.len > 0 {
				port_str << cleaned
			}
			i++
		}
		if i < tokens.len && tokens[i] == '}' {
			i++
		}
		for ps in port_str {
			if p := parse_port_spec(ps) {
				if is_dport {
					dst_ports << p
				} else {
					src_ports << p
				}
			}
		}
	} else {
		if p := parse_port_spec(tokens[i]) {
			if is_dport {
				dst_ports << p
			} else {
				src_ports << p
			}
		}
		i++
	}
	return i
}
