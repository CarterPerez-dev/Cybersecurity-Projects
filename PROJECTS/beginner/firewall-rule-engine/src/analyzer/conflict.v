/*
©AngelaMos | 2026
conflict.v

Conflict detection engine for firewall rulesets

Walks every chain pairwise comparing rules to find four classes of
problems: shadowed rules (a broader rule with a different action appears
earlier, making the narrower rule unreachable), contradictions (two
rules overlap in traffic but have opposing accept/deny actions),
duplicates (identical criteria and action), and redundant rules (a
strict subset of another rule with the same action). The comparison
logic uses match_is_superset for subset testing and matches_overlap for
partial intersection, both of which recurse through protocol, source
address, destination address, ports, interfaces, and conntrack states.
CIDR containment delegates to models.cidr_contains for the actual
prefix arithmetic.

Key exports:
  analyze_conflicts - Scans a Ruleset and returns all conflict Findings

Connects to:
  models/models.v        - imports Rule, Ruleset, MatchCriteria, Finding, Action,
                            NetworkAddr, PortSpec, cidr_contains, port_range_contains
  analyzer/optimizer.v   - sibling module, both called from main.v cmd_analyze
  main.v                 - called from cmd_analyze
  display/display.v      - Findings are rendered by print_findings
*/

module analyzer

import src.models {
	Action,
	Finding,
	MatchCriteria,
	NetworkAddr,
	PortSpec,
	Rule,
	Ruleset,
}

pub fn analyze_conflicts(rs Ruleset) []Finding {
	mut findings := []Finding{}
	chains := rs.rules_by_chain()
	for _, indices in chains {
		rules := indices.map(rs.rules[it])
		findings << find_duplicates(rules, indices)
		findings << find_shadowed_rules(rules, indices)
		findings << find_contradictions(rules, indices)
		findings << find_redundant_rules(rules, indices)
	}
	return findings
}

fn find_shadowed_rules(rules []Rule, indices []int) []Finding {
	mut findings := []Finding{}
	for i := 0; i < rules.len; i++ {
		for j := i + 1; j < rules.len; j++ {
			if match_is_superset(rules[i].criteria, rules[j].criteria)
				&& rules[i].action != rules[j].action {
				findings << Finding{
					severity:     .critical
					title:        'Shadowed rule detected'
					description:  'Rule ${indices[j] + 1} (${rules[j].action.str()}) can never match because rule ${
						indices[i] + 1} (${rules[i].action.str()}) catches all its traffic first'
					rule_indices: [indices[i], indices[j]]
					suggestion:   'Remove rule ${indices[j] + 1} or reorder it before rule ${
						indices[i] + 1}'
				}
			}
		}
	}
	return findings
}

fn find_contradictions(rules []Rule, indices []int) []Finding {
	mut findings := []Finding{}
	for i := 0; i < rules.len; i++ {
		for j := i + 1; j < rules.len; j++ {
			if matches_overlap(rules[i].criteria, rules[j].criteria)
				&& actions_conflict(rules[i].action, rules[j].action) {
				if match_is_superset(rules[i].criteria, rules[j].criteria) {
					continue
				}
				findings << Finding{
					severity:     .warning
					title:        'Contradictory rules'
					description:  'Rules ${indices[i] + 1} (${rules[i].action.str()}) and ${
						indices[j] + 1} (${rules[j].action.str()}) overlap but have opposing actions'
					rule_indices: [indices[i], indices[j]]
					suggestion:   'Review whether both rules are needed and clarify the intended behavior'
				}
			}
		}
	}
	return findings
}

fn find_duplicates(rules []Rule, indices []int) []Finding {
	mut findings := []Finding{}
	for i := 0; i < rules.len; i++ {
		for j := i + 1; j < rules.len; j++ {
			if criteria_equal(rules[i].criteria, rules[j].criteria)
				&& rules[i].action == rules[j].action {
				findings << Finding{
					severity:     .warning
					title:        'Duplicate rule'
					description:  'Rules ${indices[i] + 1} and ${indices[j] + 1} have identical match criteria and action'
					rule_indices: [indices[i], indices[j]]
					suggestion:   'Remove rule ${indices[j] + 1}'
				}
			}
		}
	}
	return findings
}

fn find_redundant_rules(rules []Rule, indices []int) []Finding {
	mut findings := []Finding{}
	for i := 0; i < rules.len; i++ {
		for j := 0; j < rules.len; j++ {
			if i == j {
				continue
			}
			if rules[i].action == rules[j].action
				&& match_is_superset(rules[i].criteria, rules[j].criteria)
				&& !criteria_equal(rules[i].criteria, rules[j].criteria) {
				if i < j {
					findings << Finding{
						severity:     .info
						title:        'Redundant rule'
						description:  'Rule ${indices[j] + 1} is a subset of rule ${indices[i] + 1} with the same action'
						rule_indices: [indices[i], indices[j]]
						suggestion:   'Rule ${indices[j] + 1} can be safely removed'
					}
				}
			}
		}
	}
	return findings
}

fn matches_overlap(a MatchCriteria, b MatchCriteria) bool {
	if a.protocol != .all && b.protocol != .all && a.protocol != b.protocol {
		return false
	}
	if !addrs_overlap(a.source, b.source) {
		return false
	}
	if !addrs_overlap(a.destination, b.destination) {
		return false
	}
	if !ports_overlap(a.dst_ports, b.dst_ports) {
		return false
	}
	if !iface_overlaps(a.in_iface, b.in_iface) {
		return false
	}
	if !iface_overlaps(a.out_iface, b.out_iface) {
		return false
	}
	return true
}

fn match_is_superset(outer MatchCriteria, inner MatchCriteria) bool {
	if outer.protocol != .all && outer.protocol != inner.protocol {
		return false
	}
	if !addr_is_superset(outer.source, inner.source) {
		return false
	}
	if !addr_is_superset(outer.destination, inner.destination) {
		return false
	}
	if !ports_is_superset(outer.dst_ports, inner.dst_ports) {
		return false
	}
	if !ports_is_superset(outer.src_ports, inner.src_ports) {
		return false
	}
	if !iface_is_superset(outer.in_iface, inner.in_iface) {
		return false
	}
	if !iface_is_superset(outer.out_iface, inner.out_iface) {
		return false
	}
	if !outer.states.is_empty() {
		if inner.states.is_empty() || !outer.states.all(inner.states) {
			return false
		}
	}
	return true
}

fn criteria_equal(a MatchCriteria, b MatchCriteria) bool {
	if a.protocol != b.protocol {
		return false
	}
	if !addrs_equal(a.source, b.source) {
		return false
	}
	if !addrs_equal(a.destination, b.destination) {
		return false
	}
	if !ports_equal(a.dst_ports, b.dst_ports) {
		return false
	}
	if !ports_equal(a.src_ports, b.src_ports) {
		return false
	}
	if !opt_str_equal(a.in_iface, b.in_iface) {
		return false
	}
	if !opt_str_equal(a.out_iface, b.out_iface) {
		return false
	}
	if a.states != b.states {
		return false
	}
	return true
}

fn actions_conflict(a Action, b Action) bool {
	accept_like := [Action.accept]
	deny_like := [Action.drop, Action.reject]
	a_allows := a in accept_like
	b_allows := b in accept_like
	a_denies := a in deny_like
	b_denies := b in deny_like
	return (a_allows && b_denies) || (a_denies && b_allows)
}

fn addrs_overlap(a ?NetworkAddr, b ?NetworkAddr) bool {
	a_val := a or { return true }
	b_val := b or { return true }
	if a_val.negated != b_val.negated {
		return true
	}
	return models.cidr_contains(a_val, b_val) || models.cidr_contains(b_val, a_val)
}

fn addr_is_superset(outer ?NetworkAddr, inner ?NetworkAddr) bool {
	if ov := outer {
		if iv := inner {
			return models.cidr_contains(ov, iv)
		}
		return false
	}
	return true
}

fn addrs_equal(a ?NetworkAddr, b ?NetworkAddr) bool {
	if av := a {
		if bv := b {
			return av.address == bv.address && av.cidr == bv.cidr && av.negated == bv.negated
		}
		return false
	}
	if _ := b {
		return false
	}
	return true
}

fn ports_overlap(a []PortSpec, b []PortSpec) bool {
	if a.len == 0 || b.len == 0 {
		return true
	}
	for pa in a {
		for pb in b {
			if pa.start <= pb.effective_end() && pb.start <= pa.effective_end() {
				return true
			}
		}
	}
	return false
}

fn ports_is_superset(outer []PortSpec, inner []PortSpec) bool {
	if outer.len == 0 {
		return true
	}
	if inner.len == 0 {
		return false
	}
	for ip in inner {
		mut covered := false
		for op in outer {
			if models.port_range_contains(op, ip) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

fn ports_equal(a []PortSpec, b []PortSpec) bool {
	if a.len != b.len {
		return false
	}
	for i, pa in a {
		if pa.start != b[i].start || pa.effective_end() != b[i].effective_end()
			|| pa.negated != b[i].negated {
			return false
		}
	}
	return true
}

fn iface_overlaps(a ?string, b ?string) bool {
	a_val := a or { return true }
	b_val := b or { return true }
	return a_val == b_val
}

fn iface_is_superset(outer ?string, inner ?string) bool {
	if ov := outer {
		if iv := inner {
			return ov == iv
		}
		return false
	}
	return true
}

fn opt_str_equal(a ?string, b ?string) bool {
	if av := a {
		if bv := b {
			return av == bv
		}
		return false
	}
	if _ := b {
		return false
	}
	return true
}
