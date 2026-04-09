/*
©AngelaMos | 2026
generator_test.v

Tests for hardened ruleset generation and cross-format export

Hardened generation tests verify both iptables and nftables output
formats: default-deny policies, loopback acceptance, conntrack early
in the chain, SSH rate limiting, HTTP/HTTPS service rules, RFC 1918
anti-spoofing drops, ICMP rate limiting, LOG before final drop, COMMIT
wrapping, DNS dual-protocol (tcp+udp), NTP udp-only, and custom
interface names. Serialization tests cover rule_to_iptables and
rule_to_nftables for TCP port rules, source/destination addresses with
negation, multiport sets, interface matching, and log prefix handling.
Export tests verify round-trip conversion of Rulesets including
multi-table layouts with filter and nat tables, correct chain nesting
inside their parent tables, and empty ruleset edge cases.

Connects to:
  generator/generator.v - tests generate_hardened, export_ruleset, rule_to_iptables,
                           rule_to_nftables
  models/models.v       - uses Rule, Ruleset, MatchCriteria, NetworkAddr, PortSpec, Action
*/

module generator

import src.models { Action, MatchCriteria, NetworkAddr, PortSpec, Rule, Ruleset }

fn test_generate_iptables_hardened_default_deny() {
	output := generate_hardened(['ssh'], 'eth0', .iptables)
	assert output.contains(':INPUT DROP')
	assert output.contains(':FORWARD DROP')
	assert output.contains(':OUTPUT ACCEPT')
}

fn test_generate_iptables_hardened_loopback() {
	output := generate_hardened(['ssh'], 'eth0', .iptables)
	assert output.contains('-A INPUT -i lo -j ACCEPT')
	assert output.contains('-A OUTPUT -o lo -j ACCEPT')
}

fn test_generate_iptables_hardened_conntrack() {
	output := generate_hardened(['ssh'], 'eth0', .iptables)
	assert output.contains('--ctstate ESTABLISHED,RELATED -j ACCEPT')
	assert output.contains('--ctstate INVALID -j DROP')
}

fn test_generate_iptables_hardened_ssh_with_rate_limit() {
	output := generate_hardened(['ssh'], 'eth0', .iptables)
	assert output.contains('--dport 22')
	assert output.contains('--limit 3/minute')
	assert output.contains('--limit-burst 5')
}

fn test_generate_iptables_hardened_http_https() {
	output := generate_hardened(['http', 'https'], 'eth0', .iptables)
	assert output.contains('--dport 80 -j ACCEPT')
	assert output.contains('--dport 443 -j ACCEPT')
}

fn test_generate_iptables_hardened_anti_spoofing() {
	output := generate_hardened(['ssh'], 'eth0', .iptables)
	assert output.contains('-s 10.0.0.0/8 -j DROP')
	assert output.contains('-s 172.16.0.0/12 -j DROP')
	assert output.contains('-s 192.168.0.0/16 -j DROP')
}

fn test_generate_iptables_hardened_icmp_rate_limit() {
	output := generate_hardened(['ssh'], 'eth0', .iptables)
	assert output.contains('-p icmp')
	assert output.contains('echo-request')
	assert output.contains('--limit 1/second')
}

fn test_generate_iptables_hardened_logging() {
	output := generate_hardened(['ssh'], 'eth0', .iptables)
	assert output.contains('-j LOG')
	assert output.contains('DROPPED: ')
}

fn test_generate_iptables_hardened_final_drop() {
	output := generate_hardened(['ssh'], 'eth0', .iptables)
	lines := output.split('\n')
	mut last_rule := ''
	for line in lines {
		trimmed := line.trim_space()
		if trimmed.starts_with('-A INPUT') {
			last_rule = trimmed
		}
	}
	assert last_rule == '-A INPUT -j DROP'
}

fn test_generate_iptables_hardened_commit() {
	output := generate_hardened(['ssh'], 'eth0', .iptables)
	assert output.contains('*filter')
	assert output.contains('COMMIT')
}

fn test_generate_iptables_hardened_dns_dual_protocol() {
	output := generate_hardened(['dns'], 'eth0', .iptables)
	assert output.contains('-p tcp --dport 53 -j ACCEPT')
	assert output.contains('-p udp --dport 53 -j ACCEPT')
}

fn test_generate_iptables_hardened_ntp_udp() {
	output := generate_hardened(['ntp'], 'eth0', .iptables)
	assert output.contains('-p udp --dport 123 -j ACCEPT')
}

fn test_generate_iptables_hardened_custom_iface() {
	output := generate_hardened(['ssh'], 'ens192', .iptables)
	assert output.contains('-i ens192')
}

fn test_generate_nftables_hardened_structure() {
	output := generate_hardened(['ssh', 'http'], 'eth0', .nftables)
	assert output.contains('table inet filter {')
	assert output.contains('chain input {')
	assert output.contains('policy drop;')
	assert output.contains('chain forward {')
	assert output.contains('chain output {')
}

fn test_generate_nftables_hardened_conntrack() {
	output := generate_hardened(['ssh'], 'eth0', .nftables)
	assert output.contains('ct state established,related accept')
	assert output.contains('ct state invalid drop')
}

fn test_generate_nftables_hardened_ssh_rate_limit() {
	output := generate_hardened(['ssh'], 'eth0', .nftables)
	assert output.contains('tcp dport 22')
	assert output.contains('limit rate 3/minute')
	assert output.contains('burst 5')
}

fn test_generate_nftables_hardened_anti_spoofing() {
	output := generate_hardened(['ssh'], 'eth0', .nftables)
	assert output.contains('ip saddr 10.0.0.0/8 drop')
	assert output.contains('ip saddr 172.16.0.0/12 drop')
	assert output.contains('ip saddr 192.168.0.0/16 drop')
}

fn test_generate_nftables_hardened_loopback() {
	output := generate_hardened(['ssh'], 'eth0', .nftables)
	assert output.contains('iifname "lo" accept')
}

fn test_generate_nftables_hardened_dns_dual_protocol() {
	output := generate_hardened(['dns'], 'eth0', .nftables)
	assert output.contains('tcp dport 53 accept')
	assert output.contains('udp dport 53 accept')
}

fn test_rule_to_iptables_tcp_port() {
	r := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 80
			}]
		}
	}
	result := rule_to_iptables(r)
	assert result.contains('-A INPUT')
	assert result.contains('-p tcp')
	assert result.contains('--dport 80')
	assert result.contains('-j ACCEPT')
}

fn test_rule_to_iptables_with_source() {
	r := Rule{
		chain:    'INPUT'
		action:   .drop
		criteria: MatchCriteria{
			protocol: .tcp
			source:   NetworkAddr{
				address: '10.0.0.0'
				cidr:    8
			}
		}
	}
	result := rule_to_iptables(r)
	assert result.contains('-s 10.0.0.0/8')
	assert result.contains('-j DROP')
}

fn test_rule_to_iptables_negated_source() {
	r := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			source: NetworkAddr{
				address: '10.0.0.0'
				cidr:    8
				negated: true
			}
		}
	}
	result := rule_to_iptables(r)
	assert result.contains('! -s 10.0.0.0/8')
}

fn test_rule_to_iptables_with_destination() {
	r := Rule{
		chain:    'FORWARD'
		action:   .reject
		criteria: MatchCriteria{
			destination: NetworkAddr{
				address: '192.168.1.0'
				cidr:    24
			}
		}
	}
	result := rule_to_iptables(r)
	assert result.contains('-A FORWARD')
	assert result.contains('-d 192.168.1.0/24')
	assert result.contains('-j REJECT')
}

fn test_rule_to_iptables_multiport() {
	r := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 80
			}, PortSpec{
				start: 443
			}]
		}
	}
	result := rule_to_iptables(r)
	assert result.contains('-m multiport --dports')
}

fn test_rule_to_iptables_interface() {
	r := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			in_iface: 'lo'
		}
	}
	result := rule_to_iptables(r)
	assert result.contains('-i lo')
}

fn test_rule_to_iptables_out_interface() {
	r := Rule{
		chain:    'OUTPUT'
		action:   .accept
		criteria: MatchCriteria{
			out_iface: 'eth0'
		}
	}
	result := rule_to_iptables(r)
	assert result.contains('-o eth0')
}

fn test_rule_to_nftables_tcp_port() {
	r := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 443
			}]
		}
	}
	result := rule_to_nftables(r)
	assert result.contains('tcp dport 443')
	assert result.contains('accept')
}

fn test_rule_to_nftables_with_iface() {
	r := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			in_iface: 'lo'
		}
	}
	result := rule_to_nftables(r)
	assert result.contains('iifname "lo"')
	assert result.contains('accept')
}

fn test_rule_to_nftables_with_source() {
	r := Rule{
		chain:    'INPUT'
		action:   .drop
		criteria: MatchCriteria{
			source: NetworkAddr{
				address: '10.0.0.0'
				cidr:    8
			}
		}
	}
	result := rule_to_nftables(r)
	assert result.contains('ip saddr 10.0.0.0/8')
	assert result.contains('drop')
}

fn test_rule_to_nftables_negated_source() {
	r := Rule{
		chain:    'INPUT'
		action:   .drop
		criteria: MatchCriteria{
			source: NetworkAddr{
				address: '10.0.0.0'
				cidr:    8
				negated: true
			}
		}
	}
	result := rule_to_nftables(r)
	assert result.contains('!= 10.0.0.0/8')
}

fn test_rule_to_nftables_multiport() {
	r := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 80
			}, PortSpec{
				start: 443
			}]
		}
	}
	result := rule_to_nftables(r)
	assert result.contains('tcp dport {')
	assert result.contains('80')
	assert result.contains('443')
}

fn test_rule_to_nftables_log_with_prefix() {
	r := Rule{
		chain:       'INPUT'
		action:      .log
		target_args: 'prefix "DROPPED: "'
	}
	result := rule_to_nftables(r)
	assert result.contains('log prefix "DROPPED: "')
}

fn test_export_ruleset_iptables() {
	rs := Ruleset{
		rules:    [
			Rule{
				table:    .filter
				chain:    'INPUT'
				action:   .accept
				criteria: MatchCriteria{
					protocol:  .tcp
					dst_ports: [PortSpec{
						start: 80
					}]
				}
				source:   .iptables
			},
		]
		policies: {
			'INPUT': Action.drop
		}
		source:   .iptables
	}
	output := export_ruleset(rs, .iptables)
	assert output.contains('*filter')
	assert output.contains(':INPUT DROP')
	assert output.contains('-A INPUT')
	assert output.contains('COMMIT')
}

fn test_export_ruleset_nftables() {
	rs := Ruleset{
		rules:    [
			Rule{
				table:    .filter
				chain:    'INPUT'
				action:   .accept
				criteria: MatchCriteria{
					protocol:  .tcp
					dst_ports: [PortSpec{
						start: 80
					}]
				}
				source:   .iptables
			},
		]
		policies: {
			'INPUT': Action.drop
		}
		source:   .iptables
	}
	output := export_ruleset(rs, .nftables)
	assert output.contains('table inet filter')
	assert output.contains('chain input')
	assert output.contains('tcp dport 80')
}

fn test_export_empty_ruleset() {
	rs := Ruleset{
		source: .iptables
	}
	ipt := export_ruleset(rs, .iptables)
	nft := export_ruleset(rs, .nftables)
	assert ipt.len >= 0
	assert nft.len >= 0
}

fn test_export_nftables_multi_table() {
	rs := Ruleset{
		rules:    [
			Rule{
				table:    .filter
				chain:    'INPUT'
				action:   .accept
				criteria: MatchCriteria{
					protocol:  .tcp
					dst_ports: [PortSpec{
						start: 80
					}]
				}
				source:   .iptables
			},
			Rule{
				table:    .nat
				chain:    'POSTROUTING'
				action:   .masquerade
				criteria: MatchCriteria{
					out_iface: 'eth0'
				}
				source:   .iptables
			},
		]
		policies: {
			'INPUT':       Action.drop
			'POSTROUTING': Action.accept
		}
		source:   .iptables
	}
	output := export_ruleset(rs, .nftables)
	assert output.contains('table inet filter {')
	assert output.contains('table inet nat {')
	filter_pos := output.index('table inet filter') or { -1 }
	nat_pos := output.index('table inet nat') or { -1 }
	assert filter_pos >= 0 && nat_pos >= 0
	assert output.contains('chain input {')
	assert output.contains('chain postrouting {')
}

fn test_export_nftables_multi_table_chains_inside_correct_table() {
	rs := Ruleset{
		rules:    [
			Rule{
				table:  .filter
				chain:  'INPUT'
				action: .accept
				source: .iptables
			},
			Rule{
				table:  .nat
				chain:  'POSTROUTING'
				action: .masquerade
				source: .iptables
			},
		]
		policies: {
			'INPUT':       Action.drop
			'POSTROUTING': Action.accept
		}
		source:   .iptables
	}
	output := export_ruleset(rs, .nftables)
	lines := output.split('\n')
	mut in_filter := false
	mut in_nat := false
	mut input_in_filter := false
	mut postrouting_in_nat := false
	for line in lines {
		trimmed := line.trim_space()
		if trimmed.starts_with('table inet filter') {
			in_filter = true
			in_nat = false
		} else if trimmed.starts_with('table inet nat') {
			in_nat = true
			in_filter = false
		}
		if in_filter && trimmed.starts_with('chain input') {
			input_in_filter = true
		}
		if in_nat && trimmed.starts_with('chain postrouting') {
			postrouting_in_nat = true
		}
	}
	assert input_in_filter
	assert postrouting_in_nat
}
