/*
©AngelaMos | 2026
analyzer_test.v

Tests for conflict detection and optimization analysis

Tests both conflict.v and optimizer.v functions. Conflict tests cover
shadowed rules (broad ACCEPT before narrow DROP), contradictions
(overlapping criteria with opposing actions), duplicates (identical
criteria and action), and redundant rules (strict subset with same
action). Also verifies that disjoint rules (different protocols, non-
overlapping ports) produce no false positives. Comparison helper tests
exercise matches_overlap, match_is_superset, criteria_equal,
actions_conflict, ports_overlap, ports_is_superset, addr_is_superset,
addrs_overlap, and opt_str_equal with various none/some combinations.
Optimizer tests cover mergeable ports, missing SSH rate limits, missing
conntrack, unreachable rules after catch-all drops, overly permissive
source-less rules on sensitive ports, redundant terminal drops against
chain policy, and CIDR /0 containment.

Connects to:
  analyzer/conflict.v  - tests analyze_conflicts, find_shadowed_rules,
                          find_contradictions, find_duplicates, find_redundant_rules,
                          matches_overlap, match_is_superset, criteria_equal,
                          actions_conflict, ports_overlap, ports_is_superset,
                          addr_is_superset, addrs_overlap, opt_str_equal
  analyzer/optimizer.v - tests find_mergeable_ports, find_missing_rate_limits,
                          find_missing_conntrack, find_unreachable_after_drop,
                          find_overly_permissive, find_redundant_terminal_drop
  models/models.v      - uses MatchCriteria, NetworkAddr, PortSpec, Rule, Ruleset,
                          tests cidr_contains directly
*/

module analyzer

import src.models { MatchCriteria, NetworkAddr, PortSpec, Rule, Ruleset }

fn test_find_shadowed_rule() {
	broad := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol: .tcp
		}
	}
	narrow := Rule{
		chain:    'INPUT'
		action:   .drop
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 80
			}]
		}
	}
	findings := find_shadowed_rules([broad, narrow], [0, 1])
	assert findings.len == 1
	assert findings[0].severity == .critical
	assert findings[0].title.contains('Shadowed')
}

fn test_find_contradiction() {
	r1 := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			source:    NetworkAddr{
				address: '192.168.1.0'
				cidr:    24
			}
			dst_ports: [PortSpec{
				start: 80
			}]
		}
	}
	r2 := Rule{
		chain:    'INPUT'
		action:   .drop
		criteria: MatchCriteria{
			protocol:    .tcp
			destination: NetworkAddr{
				address: '10.0.0.0'
				cidr:    8
			}
			dst_ports:   [PortSpec{
				start: 80
			}]
		}
	}
	findings := find_contradictions([r1, r2], [0, 1])
	assert findings.len == 1
	assert findings[0].severity == .warning
	assert findings[0].title.contains('Contradictory')
}

fn test_find_duplicate() {
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
	findings := find_duplicates([r, r], [0, 1])
	assert findings.len == 1
	assert findings[0].severity == .warning
	assert findings[0].title.contains('Duplicate')
}

fn test_find_redundant() {
	broad := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol: .tcp
		}
	}
	narrow := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 80
			}]
		}
	}
	findings := find_redundant_rules([broad, narrow], [0, 1])
	assert findings.len == 1
	assert findings[0].severity == .info
	assert findings[0].title.contains('Redundant')
}

fn test_no_false_positives_disjoint_rules() {
	r1 := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 22
			}]
		}
	}
	r2 := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .udp
			dst_ports: [PortSpec{
				start: 53
			}]
		}
	}
	rs := Ruleset{
		rules:  [r1, r2]
		source: .iptables
	}
	findings := analyze_conflicts(rs)
	for f in findings {
		assert f.severity != .critical
	}
}

fn test_matches_overlap_same_protocol() {
	a := MatchCriteria{
		protocol:  .tcp
		dst_ports: [PortSpec{
			start: 80
		}]
	}
	b := MatchCriteria{
		protocol:  .tcp
		dst_ports: [PortSpec{
			start: 80
		}]
	}
	assert matches_overlap(a, b)
}

fn test_matches_overlap_different_protocol() {
	a := MatchCriteria{
		protocol: .tcp
	}
	b := MatchCriteria{
		protocol: .udp
	}
	assert !matches_overlap(a, b)
}

fn test_matches_overlap_all_protocol() {
	a := MatchCriteria{
		protocol: .all
	}
	b := MatchCriteria{
		protocol: .tcp
	}
	assert matches_overlap(a, b)
}

fn test_matches_overlap_no_port_overlap() {
	a := MatchCriteria{
		protocol:  .tcp
		dst_ports: [PortSpec{
			start: 80
		}]
	}
	b := MatchCriteria{
		protocol:  .tcp
		dst_ports: [PortSpec{
			start: 443
		}]
	}
	assert !matches_overlap(a, b)
}

fn test_matches_overlap_empty_ports() {
	a := MatchCriteria{
		protocol: .tcp
	}
	b := MatchCriteria{
		protocol:  .tcp
		dst_ports: [PortSpec{
			start: 80
		}]
	}
	assert matches_overlap(a, b)
}

fn test_match_is_superset_broader() {
	outer := MatchCriteria{
		protocol: .tcp
	}
	inner := MatchCriteria{
		protocol:  .tcp
		dst_ports: [PortSpec{
			start: 80
		}]
	}
	assert match_is_superset(outer, inner)
}

fn test_match_is_superset_narrower_not_superset() {
	outer := MatchCriteria{
		protocol:  .tcp
		dst_ports: [PortSpec{
			start: 80
		}]
	}
	inner := MatchCriteria{
		protocol: .tcp
	}
	assert !match_is_superset(outer, inner)
}

fn test_match_is_superset_all_protocol() {
	outer := MatchCriteria{
		protocol: .all
	}
	inner := MatchCriteria{
		protocol:  .tcp
		dst_ports: [PortSpec{
			start: 80
		}]
	}
	assert match_is_superset(outer, inner)
}

fn test_match_is_superset_cidr_containment() {
	outer := MatchCriteria{
		source: NetworkAddr{
			address: '10.0.0.0'
			cidr:    8
		}
	}
	inner := MatchCriteria{
		source: NetworkAddr{
			address: '10.1.2.0'
			cidr:    24
		}
	}
	assert match_is_superset(outer, inner)
}

fn test_match_is_superset_cidr_not_contained() {
	outer := MatchCriteria{
		source: NetworkAddr{
			address: '10.0.0.0'
			cidr:    24
		}
	}
	inner := MatchCriteria{
		source: NetworkAddr{
			address: '172.16.0.0'
			cidr:    24
		}
	}
	assert !match_is_superset(outer, inner)
}

fn test_criteria_equal_identical() {
	a := MatchCriteria{
		protocol:  .tcp
		dst_ports: [PortSpec{
			start: 80
		}]
	}
	b := MatchCriteria{
		protocol:  .tcp
		dst_ports: [PortSpec{
			start: 80
		}]
	}
	assert criteria_equal(a, b)
}

fn test_criteria_equal_different_ports() {
	a := MatchCriteria{
		protocol:  .tcp
		dst_ports: [PortSpec{
			start: 80
		}]
	}
	b := MatchCriteria{
		protocol:  .tcp
		dst_ports: [PortSpec{
			start: 443
		}]
	}
	assert !criteria_equal(a, b)
}

fn test_criteria_equal_different_protocol() {
	a := MatchCriteria{
		protocol: .tcp
	}
	b := MatchCriteria{
		protocol: .udp
	}
	assert !criteria_equal(a, b)
}

fn test_criteria_equal_with_addresses() {
	a := MatchCriteria{
		source: NetworkAddr{
			address: '10.0.0.0'
			cidr:    8
		}
	}
	b := MatchCriteria{
		source: NetworkAddr{
			address: '10.0.0.0'
			cidr:    8
		}
	}
	assert criteria_equal(a, b)
}

fn test_criteria_equal_none_vs_some() {
	a := MatchCriteria{}
	b := MatchCriteria{
		source: NetworkAddr{
			address: '10.0.0.0'
			cidr:    8
		}
	}
	assert !criteria_equal(a, b)
}

fn test_actions_conflict_accept_drop() {
	assert actions_conflict(.accept, .drop)
}

fn test_actions_conflict_accept_reject() {
	assert actions_conflict(.accept, .reject)
}

fn test_actions_conflict_drop_accept() {
	assert actions_conflict(.drop, .accept)
}

fn test_actions_no_conflict_same() {
	assert !actions_conflict(.accept, .accept)
	assert !actions_conflict(.drop, .drop)
}

fn test_actions_no_conflict_drop_reject() {
	assert !actions_conflict(.drop, .reject)
}

fn test_ports_overlap_same_port() {
	a := [PortSpec{
		start: 80
	}]
	b := [PortSpec{
		start: 80
	}]
	assert ports_overlap(a, b)
}

fn test_ports_overlap_different_ports() {
	a := [PortSpec{
		start: 80
	}]
	b := [PortSpec{
		start: 443
	}]
	assert !ports_overlap(a, b)
}

fn test_ports_overlap_range_contains_single() {
	a := [PortSpec{
		start: 1
		end:   1024
	}]
	b := [PortSpec{
		start: 80
	}]
	assert ports_overlap(a, b)
}

fn test_ports_overlap_empty_matches_all() {
	a := []PortSpec{}
	b := [PortSpec{
		start: 80
	}]
	assert ports_overlap(a, b)
}

fn test_ports_overlap_both_empty() {
	a := []PortSpec{}
	b := []PortSpec{}
	assert ports_overlap(a, b)
}

fn test_ports_is_superset_empty_outer() {
	assert ports_is_superset([]PortSpec{}, [PortSpec{ start: 80 }])
}

fn test_ports_is_superset_empty_inner() {
	assert !ports_is_superset([PortSpec{ start: 80 }], []PortSpec{})
}

fn test_ports_is_superset_range() {
	outer := [PortSpec{
		start: 1
		end:   1024
	}]
	inner := [PortSpec{
		start: 80
	}]
	assert ports_is_superset(outer, inner)
}

fn test_ports_is_superset_not_contained() {
	outer := [PortSpec{
		start: 80
	}]
	inner := [PortSpec{
		start: 443
	}]
	assert !ports_is_superset(outer, inner)
}

fn test_addr_is_superset_broader_cidr() {
	outer := NetworkAddr{
		address: '10.0.0.0'
		cidr:    8
	}
	inner := NetworkAddr{
		address: '10.1.2.3'
		cidr:    32
	}
	assert addr_is_superset(outer, inner)
}

fn test_addr_is_superset_none_outer() {
	inner := NetworkAddr{
		address: '10.0.0.0'
		cidr:    8
	}
	assert addr_is_superset(none, inner)
}

fn test_addr_is_superset_none_inner() {
	outer := NetworkAddr{
		address: '10.0.0.0'
		cidr:    8
	}
	assert !addr_is_superset(outer, none)
}

fn test_addr_is_superset_both_none() {
	assert addr_is_superset(?NetworkAddr(none), ?NetworkAddr(none))
}

fn test_addrs_overlap_both_none() {
	assert addrs_overlap(?NetworkAddr(none), ?NetworkAddr(none))
}

fn test_addrs_overlap_one_none() {
	addr := NetworkAddr{
		address: '10.0.0.0'
		cidr:    8
	}
	assert addrs_overlap(addr, ?NetworkAddr(none))
	assert addrs_overlap(?NetworkAddr(none), addr)
}

fn test_addrs_overlap_contained() {
	a := NetworkAddr{
		address: '10.0.0.0'
		cidr:    8
	}
	b := NetworkAddr{
		address: '10.1.0.0'
		cidr:    16
	}
	assert addrs_overlap(a, b)
}

fn test_addrs_overlap_disjoint() {
	a := NetworkAddr{
		address: '10.0.0.0'
		cidr:    8
	}
	b := NetworkAddr{
		address: '172.16.0.0'
		cidr:    12
	}
	assert !addrs_overlap(a, b)
}

fn test_find_mergeable_ports() {
	r1 := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 80
			}]
		}
	}
	r2 := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 443
			}]
		}
	}
	r3 := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 8080
			}]
		}
	}
	findings := find_mergeable_ports([r1, r2, r3], [0, 1, 2])
	assert findings.len == 1
	assert findings[0].title == 'Mergeable port rules'
}

fn test_find_missing_rate_limits_ssh() {
	r := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 22
			}]
		}
	}
	findings := find_missing_rate_limits([r], [0])
	assert findings.len == 1
	assert findings[0].severity == .warning
	assert findings[0].title.contains('rate limit')
}

fn test_find_missing_conntrack_empty() {
	findings := find_missing_conntrack([]Rule{}, []int{})
	assert findings.len == 0
}

fn test_opt_str_equal_both_none() {
	assert opt_str_equal(?string(none), ?string(none))
}

fn test_opt_str_equal_same() {
	assert opt_str_equal('eth0', 'eth0')
}

fn test_opt_str_equal_different() {
	assert !opt_str_equal('eth0', 'lo')
}

fn test_opt_str_equal_one_none() {
	assert !opt_str_equal('eth0', ?string(none))
	assert !opt_str_equal(?string(none), 'eth0')
}

fn test_find_shadowed_same_action_not_reported() {
	broad := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol: .tcp
		}
	}
	narrow := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 80
			}]
		}
	}
	findings := find_shadowed_rules([broad, narrow], [0, 1])
	assert findings.len == 0
}

fn test_find_shadowed_different_action_reported() {
	broad := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol: .tcp
		}
	}
	narrow := Rule{
		chain:    'INPUT'
		action:   .drop
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 80
			}]
		}
	}
	findings := find_shadowed_rules([broad, narrow], [0, 1])
	assert findings.len == 1
	assert findings[0].severity == .critical
	assert findings[0].description.contains('DROP')
	assert findings[0].description.contains('ACCEPT')
}

fn test_cidr_contains_slash_zero() {
	outer := NetworkAddr{
		address: '0.0.0.0'
		cidr:    0
	}
	inner := NetworkAddr{
		address: '192.168.1.1'
		cidr:    32
	}
	assert models.cidr_contains(outer, inner)
}

fn test_cidr_contains_slash_zero_any_addr() {
	outer := NetworkAddr{
		address: '0.0.0.0'
		cidr:    0
	}
	inner := NetworkAddr{
		address: '10.255.0.1'
		cidr:    24
	}
	assert models.cidr_contains(outer, inner)
}

fn test_find_unreachable_after_drop() {
	catch_all := Rule{
		chain:    'INPUT'
		action:   .drop
		criteria: MatchCriteria{}
	}
	unreachable := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 80
			}]
		}
	}
	findings := find_unreachable_after_drop([catch_all, unreachable], [0, 1])
	assert findings.len == 1
	assert findings[0].severity == .warning
	assert findings[0].title.contains('Unreachable')
}

fn test_find_unreachable_no_catchall() {
	r1 := Rule{
		chain:    'INPUT'
		action:   .drop
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 22
			}]
		}
	}
	r2 := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 80
			}]
		}
	}
	findings := find_unreachable_after_drop([r1, r2], [0, 1])
	assert findings.len == 0
}

fn test_find_overly_permissive_ssh() {
	r := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			dst_ports: [PortSpec{
				start: 22
			}]
		}
	}
	findings := find_overly_permissive([r], [0])
	assert findings.len == 1
	assert findings[0].severity == .warning
	assert findings[0].title.contains('permissive')
}

fn test_find_overly_permissive_with_source() {
	r := Rule{
		chain:    'INPUT'
		action:   .accept
		criteria: MatchCriteria{
			protocol:  .tcp
			source:    NetworkAddr{
				address: '10.0.0.0'
				cidr:    8
			}
			dst_ports: [PortSpec{
				start: 22
			}]
		}
	}
	findings := find_overly_permissive([r], [0])
	assert findings.len == 0
}

fn test_find_overly_permissive_non_sensitive_port() {
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
	findings := find_overly_permissive([r], [0])
	assert findings.len == 0
}

fn test_find_redundant_terminal_drop() {
	catch_all := Rule{
		chain:    'INPUT'
		action:   .drop
		criteria: MatchCriteria{}
	}
	policies := {
		'INPUT': models.Action.drop
	}
	findings := find_redundant_terminal_drop([catch_all], [0], policies, 'INPUT')
	assert findings.len == 1
	assert findings[0].severity == .info
	assert findings[0].title.contains('Redundant')
}

fn test_find_redundant_terminal_drop_accept_policy() {
	catch_all := Rule{
		chain:    'INPUT'
		action:   .drop
		criteria: MatchCriteria{}
	}
	policies := {
		'INPUT': models.Action.accept
	}
	findings := find_redundant_terminal_drop([catch_all], [0], policies, 'INPUT')
	assert findings.len == 0
}
