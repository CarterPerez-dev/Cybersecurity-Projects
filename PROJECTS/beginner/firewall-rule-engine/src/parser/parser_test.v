/*
©AngelaMos | 2026
parser_test.v

Tests for parsing primitives, format detection, and full ruleset parsing

Covers every public function in common.v, iptables.v, and nftables.v.
Primitive tests verify network address CIDR and negation parsing, single
and ranged port specs, protocol name and number resolution, action and
table mapping, chain type classification, and conntrack state flag
combinations. Format detection tests confirm heuristic identification of
iptables table headers, chain policies, rule lines, and nftables table
blocks. Integration tests load fixture files from testdata/ to verify
rule counts, policy extraction, SSH port rules, conntrack rules,
multiport parsing, rate limits, NAT/masquerade actions, and IPv6
address handling. Also tests tokenize_iptables for quoted strings,
ip_to_u32 for valid/invalid addresses, and goto (-g/--goto) handling.

Connects to:
  parser/common.v   - tests parse_network_addr, parse_port_spec, parse_port_list,
                       parse_protocol, parse_action, parse_table, parse_chain_type,
                       parse_conn_states, detect_format
  parser/iptables.v - tests parse_iptables, tokenize_iptables
  parser/nftables.v - tests parse_nftables
  models/models.v   - tests ip_to_u32 directly
  testdata/         - loads iptables_basic, iptables_complex, iptables_conflicts,
                       nftables_basic, nftables_complex, nftables_conflicts fixtures
*/

module parser

import os
import src.models

fn test_parse_network_addr_plain() {
	addr := parse_network_addr('192.168.1.1')!
	assert addr.address == '192.168.1.1'
	assert addr.cidr == 32
	assert addr.negated == false
}

fn test_parse_network_addr_cidr() {
	addr := parse_network_addr('10.0.0.0/8')!
	assert addr.address == '10.0.0.0'
	assert addr.cidr == 8
	assert addr.negated == false
}

fn test_parse_network_addr_cidr_24() {
	addr := parse_network_addr('192.168.1.0/24')!
	assert addr.address == '192.168.1.0'
	assert addr.cidr == 24
}

fn test_parse_network_addr_negated() {
	addr := parse_network_addr('!172.16.0.0/12')!
	assert addr.address == '172.16.0.0'
	assert addr.cidr == 12
	assert addr.negated == true
}

fn test_parse_port_spec_single() {
	ps := parse_port_spec('80')!
	assert ps.start == 80
	assert ps.end == -1
	assert ps.negated == false
}

fn test_parse_port_spec_range() {
	ps := parse_port_spec('1024:65535')!
	assert ps.start == 1024
	assert ps.end == 65535
	assert ps.negated == false
}

fn test_parse_port_spec_negated() {
	ps := parse_port_spec('!22')!
	assert ps.start == 22
	assert ps.negated == true
}

fn test_parse_port_list() {
	ports := parse_port_list('80,443,8080')!
	assert ports.len == 3
	assert ports[0].start == 80
	assert ports[1].start == 443
	assert ports[2].start == 8080
}

fn test_parse_port_list_with_spaces() {
	ports := parse_port_list('22, 80, 443')!
	assert ports.len == 3
	assert ports[0].start == 22
	assert ports[1].start == 80
	assert ports[2].start == 443
}

fn test_parse_protocol_tcp() {
	p := parse_protocol('tcp')!
	assert p == .tcp
}

fn test_parse_protocol_udp() {
	p := parse_protocol('udp')!
	assert p == .udp
}

fn test_parse_protocol_icmp() {
	p := parse_protocol('icmp')!
	assert p == .icmp
}

fn test_parse_protocol_number_tcp() {
	p := parse_protocol('6')!
	assert p == .tcp
}

fn test_parse_protocol_number_udp() {
	p := parse_protocol('17')!
	assert p == .udp
}

fn test_parse_protocol_case_insensitive() {
	p := parse_protocol('TCP')!
	assert p == .tcp
}

fn test_parse_action_accept() {
	a := parse_action('ACCEPT')!
	assert a == .accept
}

fn test_parse_action_drop() {
	a := parse_action('DROP')!
	assert a == .drop
}

fn test_parse_action_reject() {
	a := parse_action('REJECT')!
	assert a == .reject
}

fn test_parse_action_log() {
	a := parse_action('LOG')!
	assert a == .log
}

fn test_parse_action_masquerade() {
	a := parse_action('MASQUERADE')!
	assert a == .masquerade
}

fn test_parse_table_filter() {
	t := parse_table('filter')!
	assert t == .filter
}

fn test_parse_table_nat() {
	t := parse_table('nat')!
	assert t == .nat
}

fn test_parse_table_mangle() {
	t := parse_table('mangle')!
	assert t == .mangle
}

fn test_parse_chain_type_input() {
	ct := parse_chain_type('INPUT')
	assert ct == .input
}

fn test_parse_chain_type_output() {
	ct := parse_chain_type('OUTPUT')
	assert ct == .output
}

fn test_parse_chain_type_forward() {
	ct := parse_chain_type('FORWARD')
	assert ct == .forward
}

fn test_parse_chain_type_custom() {
	ct := parse_chain_type('MYCHAIN')
	assert ct == .custom
}

fn test_parse_conn_states_single() {
	states := parse_conn_states('ESTABLISHED')
	assert states.has(.established)
	assert !states.has(.related)
	assert !states.has(.new_conn)
}

fn test_parse_conn_states_multiple() {
	states := parse_conn_states('ESTABLISHED,RELATED')
	assert states.has(.established)
	assert states.has(.related)
	assert !states.has(.new_conn)
}

fn test_parse_conn_states_all_four() {
	states := parse_conn_states('NEW,ESTABLISHED,RELATED,INVALID')
	assert states.has(.new_conn)
	assert states.has(.established)
	assert states.has(.related)
	assert states.has(.invalid)
}

fn test_parse_conn_states_case_insensitive() {
	states := parse_conn_states('established,related')
	assert states.has(.established)
	assert states.has(.related)
}

fn test_detect_format_iptables_table_header() {
	fmt := detect_format('*filter\n:INPUT DROP [0:0]')!
	assert fmt == .iptables
}

fn test_detect_format_iptables_chain_policy() {
	fmt := detect_format(':INPUT DROP [0:0]\n-A INPUT -j ACCEPT')!
	assert fmt == .iptables
}

fn test_detect_format_iptables_rule_line() {
	fmt := detect_format('-A INPUT -j ACCEPT')!
	assert fmt == .iptables
}

fn test_detect_format_nftables() {
	fmt := detect_format('table inet filter {\n    chain input {\n')!
	assert fmt == .nftables
}

fn test_detect_format_skips_comments() {
	fmt := detect_format('# this is a comment\n*filter\n')!
	assert fmt == .iptables
}

fn test_parse_iptables_basic_rule_count() {
	content := os.read_file(@VMODROOT + '/testdata/iptables_basic.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_iptables(content)!
	assert rs.rules.len == 9
	assert rs.source == .iptables
}

fn test_parse_iptables_basic_policies() {
	content := os.read_file(@VMODROOT + '/testdata/iptables_basic.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_iptables(content)!
	assert rs.policies['INPUT'] == models.Action.drop
	assert rs.policies['FORWARD'] == models.Action.drop
	assert rs.policies['OUTPUT'] == models.Action.accept
}

fn test_parse_iptables_basic_first_rule() {
	content := os.read_file(@VMODROOT + '/testdata/iptables_basic.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_iptables(content)!
	assert rs.rules[0].chain == 'INPUT'
	assert rs.rules[0].action == .accept
	assert rs.rules[0].table == .filter
}

fn test_parse_iptables_basic_ssh_rule() {
	content := os.read_file(@VMODROOT + '/testdata/iptables_basic.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_iptables(content)!
	assert rs.rules[3].criteria.protocol == .tcp
	assert rs.rules[3].criteria.dst_ports.len == 1
	assert rs.rules[3].criteria.dst_ports[0].start == 22
	assert rs.rules[3].action == .accept
}

fn test_parse_iptables_basic_conntrack() {
	content := os.read_file(@VMODROOT + '/testdata/iptables_basic.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_iptables(content)!
	assert rs.rules[1].criteria.states.has(.established)
	assert rs.rules[1].criteria.states.has(.related)
	assert rs.rules[2].criteria.states.has(.invalid)
}

fn test_parse_iptables_conflicts_rule_count() {
	content := os.read_file(@VMODROOT + '/testdata/iptables_conflicts.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_iptables(content)!
	assert rs.rules.len == 11
}

fn test_parse_iptables_conflicts_source_addr() {
	content := os.read_file(@VMODROOT + '/testdata/iptables_conflicts.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_iptables(content)!
	src := rs.rules[3].criteria.source or { panic('expected source address') }

	assert src.address == '10.0.0.0'
	assert src.cidr == 8
}

fn test_parse_nftables_basic_rule_count() {
	content := os.read_file(@VMODROOT + '/testdata/nftables_basic.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_nftables(content)!
	assert rs.rules.len == 8
	assert rs.source == .nftables
}

fn test_parse_nftables_basic_policies() {
	content := os.read_file(@VMODROOT + '/testdata/nftables_basic.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_nftables(content)!
	assert rs.policies['INPUT'] == models.Action.drop
	assert rs.policies['FORWARD'] == models.Action.drop
	assert rs.policies['OUTPUT'] == models.Action.accept
}

fn test_parse_nftables_basic_first_rule() {
	content := os.read_file(@VMODROOT + '/testdata/nftables_basic.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_nftables(content)!
	assert rs.rules[0].chain == 'INPUT'
	assert rs.rules[0].action == .accept
}

fn test_parse_nftables_basic_conntrack() {
	content := os.read_file(@VMODROOT + '/testdata/nftables_basic.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_nftables(content)!
	assert rs.rules[1].criteria.states.has(.established)
	assert rs.rules[1].criteria.states.has(.related)
	assert rs.rules[2].criteria.states.has(.invalid)
}

fn test_parse_nftables_basic_tcp_port() {
	content := os.read_file(@VMODROOT + '/testdata/nftables_basic.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_nftables(content)!
	assert rs.rules[3].criteria.protocol == .tcp
	assert rs.rules[3].criteria.dst_ports.len == 1
	assert rs.rules[3].criteria.dst_ports[0].start == 22
}

fn test_tokenize_iptables_basic() {
	tokens := tokenize_iptables('-A INPUT -p tcp --dport 22 -j ACCEPT')
	assert tokens.len == 8
	assert tokens[0] == '-A'
	assert tokens[1] == 'INPUT'
	assert tokens[2] == '-p'
	assert tokens[3] == 'tcp'
	assert tokens[4] == '--dport'
	assert tokens[5] == '22'
	assert tokens[6] == '-j'
	assert tokens[7] == 'ACCEPT'
}

fn test_tokenize_iptables_quoted_string() {
	tokens := tokenize_iptables('-j LOG --log-prefix "DROPPED: "')
	assert tokens.len == 4
	assert tokens[0] == '-j'
	assert tokens[1] == 'LOG'
	assert tokens[2] == '--log-prefix'
	assert tokens[3] == 'DROPPED: '
}

fn test_tokenize_iptables_single_quotes() {
	tokens := tokenize_iptables("--comment 'my rule'")
	assert tokens.len == 2
	assert tokens[0] == '--comment'
	assert tokens[1] == 'my rule'
}

fn test_parse_iptables_complex_multiport() {
	content := os.read_file(@VMODROOT + '/testdata/iptables_complex.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_iptables(content)!
	mut found_multiport := false
	for rule in rs.rules {
		if rule.criteria.dst_ports.len == 2 {
			if rule.criteria.dst_ports[0].start == 80 && rule.criteria.dst_ports[1].start == 443 {
				found_multiport = true
				break
			}
		}
	}
	assert found_multiport
}

fn test_parse_iptables_complex_rate_limit() {
	content := os.read_file(@VMODROOT + '/testdata/iptables_complex.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_iptables(content)!
	mut found_rate_limited := false
	for rule in rs.rules {
		if rate := rule.criteria.limit_rate {
			if rate.contains('3/minute') {
				found_rate_limited = true
				break
			}
		}
	}
	assert found_rate_limited
}

fn test_parse_iptables_complex_nat_table() {
	content := os.read_file(@VMODROOT + '/testdata/iptables_complex.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_iptables(content)!
	mut has_masquerade := false
	for rule in rs.rules {
		if rule.table == .nat && rule.action == .masquerade {
			has_masquerade = true
			break
		}
	}
	assert has_masquerade
}

fn test_ip_to_u32_valid() {
	result := models.ip_to_u32('192.168.1.1')!
	assert result == (u32(192) << 24) | (u32(168) << 16) | (u32(1) << 8) | u32(1)
}

fn test_ip_to_u32_zeros() {
	result := models.ip_to_u32('0.0.0.0')!
	assert result == u32(0)
}

fn test_ip_to_u32_max() {
	result := models.ip_to_u32('255.255.255.255')!
	assert result == u32(0xFFFFFFFF)
}

fn test_ip_to_u32_invalid_octet() {
	if _ := models.ip_to_u32('999.0.0.1') {
		assert false
	}
}

fn test_ip_to_u32_non_numeric() {
	if _ := models.ip_to_u32('hello.world.foo.bar') {
		assert false
	}
}

fn test_ip_to_u32_too_few_octets() {
	if _ := models.ip_to_u32('10.0.1') {
		assert false
	}
}

fn test_parse_nftables_complex_dnat() {
	content := os.read_file(@VMODROOT + '/testdata/nftables_complex.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_nftables(content)!
	mut found_dnat := false
	for rule in rs.rules {
		if rule.action == models.Action.dnat {
			found_dnat = true
			assert rule.target_args.contains('10.0.1.5')
			break
		}
	}
	assert found_dnat
}

fn test_parse_nftables_complex_masquerade() {
	content := os.read_file(@VMODROOT + '/testdata/nftables_complex.rules') or {
		panic('cannot read testdata: ${err}')
	}
	rs := parse_nftables(content)!
	mut found_masq := false
	for rule in rs.rules {
		if rule.action == models.Action.masquerade {
			found_masq = true
			break
		}
	}
	assert found_masq
}

fn test_parse_nftables_ipv6_saddr() {
	content := 'table inet filter {\n    chain input {\n        ip6 saddr 2001:db8::/32 drop\n    }\n}'
	rs := parse_nftables(content)!
	assert rs.rules.len == 1
	src := rs.rules[0].criteria.source or { panic('expected source') }
	assert src.address == '2001:db8::'
	assert src.cidr == 32
}

fn test_parse_nftables_ipv6_daddr() {
	content := 'table inet filter {\n    chain input {\n        ip6 daddr ::1/128 drop\n    }\n}'
	rs := parse_nftables(content)!
	assert rs.rules.len == 1
	dst := rs.rules[0].criteria.destination or { panic('expected destination') }
	assert dst.address == '::1'
	assert dst.cidr == 128
}

fn test_parse_iptables_goto() {
	rs := parse_iptables('-A INPUT -p tcp --dport 80 -g MYCHAIN')!
	assert rs.rules.len == 1
	assert rs.rules[0].action == models.Action.jump
	assert rs.rules[0].chain == 'INPUT'
	assert rs.rules[0].criteria.protocol == .tcp
}

fn test_parse_iptables_goto_long_form() {
	rs := parse_iptables('-A FORWARD -p udp --goto CUSTOM')!
	assert rs.rules.len == 1
	assert rs.rules[0].action == models.Action.jump
}
