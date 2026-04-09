/*
©AngelaMos | 2026
optimizer.v

Optimization and hardening suggestions for firewall rulesets

Produces advisory Findings that do not indicate bugs but highlight ways
to tighten or simplify a ruleset. find_mergeable_ports groups rules that
differ only in destination port and suggests combining them into a
single multiport rule. suggest_reordering flags high-traffic port rules
(HTTP, HTTPS, DNS) buried deep in a chain where they slow traversal.
find_missing_rate_limits warns when sensitive ports like SSH accept
traffic without rate limiting. find_missing_conntrack checks for an
ESTABLISHED/RELATED rule near the top of each chain. find_overly_permissive
flags sensitive ports (SSH, MySQL, PostgreSQL, Redis) open to any source.
find_redundant_terminal_drop catches explicit drop-all rules that duplicate
the chain default policy.

Key exports:
  suggest_optimizations - Scans a Ruleset and returns optimization Findings

Connects to:
  config/config.v        - reads port constants, rate-limit defaults, multiport_max
  models/models.v        - imports Rule, Ruleset, Finding
  analyzer/conflict.v    - sibling module, both called from main.v cmd_analyze
  main.v                 - called from cmd_analyze and cmd_optimize
  display/display.v      - Findings are rendered by print_findings
*/

module analyzer

import src.config
import src.models { Finding, Rule, Ruleset }

pub fn suggest_optimizations(rs Ruleset) []Finding {
	mut findings := []Finding{}
	chains := rs.rules_by_chain()
	for chain_name, indices in chains {
		rules := indices.map(rs.rules[it])
		findings << find_mergeable_ports(rules, indices)
		findings << suggest_reordering(rules, indices)
		findings << find_missing_rate_limits(rules, indices)
		findings << find_missing_conntrack(rules, indices)
		findings << find_unreachable_after_drop(rules, indices)
		findings << find_overly_permissive(rules, indices)
		findings << find_redundant_terminal_drop(rules, indices, rs.policies, chain_name)
	}
	findings << find_missing_logging(rs)
	return findings
}

fn find_mergeable_ports(rules []Rule, indices []int) []Finding {
	mut findings := []Finding{}
	mut groups := map[string][][]int{}
	for i, rule in rules {
		if rule.criteria.dst_ports.len != 1 {
			continue
		}
		key := '${rule.criteria.protocol}|${format_opt_addr(rule.criteria.source)}|${format_opt_addr(rule.criteria.destination)}|${rule.action}'
		groups[key] << [indices[i], rule.criteria.dst_ports[0].start]
	}
	for _, entries in groups {
		if entries.len < 2 {
			continue
		}
		if entries.len > config.multiport_max {
			continue
		}
		rule_indices := entries.map(it[0])
		ports := entries.map('${it[1]}')
		findings << Finding{
			severity:     .info
			title:        'Mergeable port rules'
			description:  '${entries.len} rules could be combined into a single multiport rule'
			rule_indices: rule_indices
			suggestion:   'Merge into one rule with --dports ${ports.join(',')}'
		}
	}
	return findings
}

fn suggest_reordering(rules []Rule, indices []int) []Finding {
	mut findings := []Finding{}
	high_traffic_ports := [config.port_http, config.port_https, config.port_dns]
	for i, rule in rules {
		if i < 3 {
			continue
		}
		for dp in rule.criteria.dst_ports {
			if dp.start in high_traffic_ports && rule.action == .accept {
				findings << Finding{
					severity:     .info
					title:        'Rule ordering optimization'
					description:  'Rule ${indices[i] + 1} matches high-traffic port ${dp.start} but is at position ${
						i + 1} in the chain'
					rule_indices: [indices[i]]
					suggestion:   'Move this rule earlier in the chain for better performance'
				}
				break
			}
		}
	}
	return findings
}

fn find_missing_rate_limits(rules []Rule, indices []int) []Finding {
	mut findings := []Finding{}
	mut rate_limited_ports := map[int]bool{}
	for rule in rules {
		if limit := rule.criteria.limit_rate {
			_ = limit
			for dp in rule.criteria.dst_ports {
				rate_limited_ports[dp.start] = true
			}
		}
	}
	exposed_ports := [config.port_ssh]
	for i, rule in rules {
		if rule.action != .accept {
			continue
		}
		for dp in rule.criteria.dst_ports {
			if dp.start in exposed_ports && dp.start !in rate_limited_ports {
				findings << Finding{
					severity:     .warning
					title:        'Missing rate limit'
					description:  'Port ${dp.start} is allowed without rate limiting'
					rule_indices: [indices[i]]
					suggestion:   'Add rate limiting (e.g., ${config.ssh_rate_limit} burst ${config.ssh_rate_burst}) for port ${dp.start}'
				}
			}
		}
	}
	return findings
}

fn find_missing_logging(rs Ruleset) []Finding {
	mut findings := []Finding{}
	for chain_name, policy in rs.policies {
		if policy == .drop || policy == .reject {
			mut has_log := false
			for rule in rs.rules {
				if rule.chain == chain_name && rule.action == .log {
					has_log = true
					break
				}
			}
			if !has_log {
				findings << Finding{
					severity:     .info
					title:        'Missing drop logging'
					description:  '${chain_name} chain has ${policy.str()} policy but no LOG rule'
					rule_indices: []
					suggestion:   'Add a LOG rule before the final drop to track rejected traffic'
				}
			}
		}
	}
	return findings
}

fn find_missing_conntrack(rules []Rule, indices []int) []Finding {
	mut findings := []Finding{}
	if rules.len == 0 {
		return findings
	}
	mut has_conntrack := false
	mut conntrack_position := -1
	for i, rule in rules {
		if !rule.criteria.states.is_empty() {
			if rule.criteria.states.has(.established) {
				has_conntrack = true
				conntrack_position = i
				break
			}
		}
	}
	if !has_conntrack && rules.len > 2 {
		findings << Finding{
			severity:     .warning
			title:        'Missing connection tracking'
			description:  'No ESTABLISHED/RELATED rule found in this chain'
			rule_indices: []
			suggestion:   'Add a conntrack rule early in the chain to allow established connections'
		}
	} else if has_conntrack && conntrack_position > 2 {
		findings << Finding{
			severity:     .info
			title:        'Late connection tracking rule'
			description:  'ESTABLISHED/RELATED rule is at position ${conntrack_position + 1}, should be near the top'
			rule_indices: [indices[conntrack_position]]
			suggestion:   'Move the conntrack rule to position 1 or 2 in the chain for optimal performance'
		}
	}
	return findings
}

fn find_unreachable_after_drop(rules []Rule, indices []int) []Finding {
	mut findings := []Finding{}
	for i := 0; i < rules.len; i++ {
		is_catchall := (rules[i].action == .drop || rules[i].action == .reject)
			&& rules[i].criteria.protocol == .all && rules[i].criteria.source == none
			&& rules[i].criteria.destination == none && rules[i].criteria.dst_ports.len == 0
			&& rules[i].criteria.src_ports.len == 0
		if is_catchall && i + 1 < rules.len {
			for j := i + 1; j < rules.len; j++ {
				findings << Finding{
					severity:     .warning
					title:        'Unreachable rule after catch-all drop'
					description:  'Rule ${indices[j] + 1} appears after a catch-all ${rules[i].action.str()} at position ${
						indices[i] + 1} and can never be reached'
					rule_indices: [indices[i], indices[j]]
					suggestion:   'Remove rule ${indices[j] + 1} or move it before the catch-all drop'
				}
			}
			break
		}
	}
	return findings
}

fn find_overly_permissive(rules []Rule, indices []int) []Finding {
	mut findings := []Finding{}
	sensitive_ports := [config.port_ssh, 3306, 5432, 6379]
	for i, rule in rules {
		if rule.action != .accept {
			continue
		}
		if rule.criteria.source != none {
			continue
		}
		for dp in rule.criteria.dst_ports {
			if dp.start in sensitive_ports {
				findings << Finding{
					severity:     .warning
					title:        'Overly permissive source'
					description:  'Rule ${indices[i] + 1} allows access to port ${dp.start} from any source address'
					rule_indices: [indices[i]]
					suggestion:   'Restrict the source address to trusted networks for port ${dp.start}'
				}
				break
			}
		}
	}
	return findings
}

fn find_redundant_terminal_drop(rules []Rule, indices []int, policies map[string]models.Action, chain_name string) []Finding {
	mut findings := []Finding{}
	if rules.len == 0 {
		return findings
	}
	policy := policies[chain_name] or { return findings }
	if policy != .drop && policy != .reject {
		return findings
	}
	last := rules[rules.len - 1]
	is_catchall_drop := (last.action == .drop || last.action == .reject)
		&& last.criteria.protocol == .all && last.criteria.source == none
		&& last.criteria.destination == none && last.criteria.dst_ports.len == 0
		&& last.criteria.src_ports.len == 0
	if is_catchall_drop {
		findings << Finding{
			severity:     .info
			title:        'Redundant terminal drop'
			description:  'Rule ${indices[rules.len - 1] + 1} explicitly drops all traffic but the chain policy is already ${policy.str()}'
			rule_indices: [indices[rules.len - 1]]
			suggestion:   'Remove the explicit drop since the chain policy handles it'
		}
	}
	return findings
}

fn format_opt_addr(addr ?models.NetworkAddr) string {
	if a := addr {
		return a.str()
	}
	return '*'
}
