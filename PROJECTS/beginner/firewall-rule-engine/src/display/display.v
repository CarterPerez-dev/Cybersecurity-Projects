/*
©AngelaMos | 2026
display.v

Terminal output formatting for rulesets, findings, and diffs

Handles all user-facing output so the rest of the codebase never calls
println directly for structured data. print_rule_table renders a
fixed-width ASCII table with columns for rule number, chain, protocol,
source, destination, ports, and action. Actions are color-coded green
for ACCEPT, red for DROP/REJECT, yellow for LOG. print_findings groups
analyzer results by severity with colored brackets and includes the
suggestion arrow for each finding. print_diff compares two Rulesets by
building a set of normalized rule strings and showing only-left /
only-right entries, similar to a unified diff.

Key exports:
  print_banner    - Renders the boxed FWRULE header with version
  print_rule_table - Renders a tabular view of all rules in a Ruleset
  print_summary    - Shows format, rule count, chains, and policies
  print_findings   - Renders a list of analyzer Findings with severity counts
  print_finding    - Renders a single Finding with colored severity tag
  print_diff       - Side-by-side comparison of two Rulesets

Connects to:
  config/config.v - reads column widths, Unicode symbols, version
  models/models.v - imports Rule, Ruleset, Finding, Action, Severity
  main.v          - called from every cmd_* handler for display
*/

module display

import term
import src.config
import src.models { Action, Finding, Rule, Ruleset, Severity }

pub fn print_banner() {
	banner := '
${term.bold(term.cyan('┌─────────────────────────────────────────┐'))}
${term.bold(term.cyan('│'))}  ${term.bold('FWRULE')} ${term.dim(
		'v' + config.version)}                         ${term.bold(term.cyan('│'))}
${term.bold(term.cyan('│'))}  ${term.dim('Firewall Rule Engine for iptables/nft')}   ${term.bold(term.cyan('│'))}
${term.bold(term.cyan('└─────────────────────────────────────────┘'))}
'
	println(banner)
}

pub fn print_rule_table(rs Ruleset) {
	header := pad_right('#', config.col_num) + pad_right('Chain', config.col_chain) +
		pad_right('Proto', config.col_proto) + pad_right('Source', config.col_source) +
		pad_right('Dest', config.col_dest) + pad_right('Ports', config.col_ports) +
		pad_right('Action', config.col_action)
	println(term.bold(header))
	println('${'─'.repeat(config.col_num + config.col_chain + config.col_proto +
		config.col_source + config.col_dest + config.col_ports + config.col_action)}')

	for i, rule in rs.rules {
		num := pad_right('${i + 1}', config.col_num)
		chain := pad_right(rule.chain, config.col_chain)
		proto := pad_right(rule.criteria.protocol.str(), config.col_proto)
		src := pad_right(format_addr(rule.criteria.source), config.col_source)
		dst := pad_right(format_addr(rule.criteria.destination), config.col_dest)
		ports := pad_right(format_ports(rule.criteria.dst_ports), config.col_ports)
		action_str := colorize_action(rule.action)
		println('${num}${chain}${proto}${src}${dst}${ports}${action_str}')
	}
	println('')
}

pub fn print_finding(f Finding) {
	severity_str := colorize_severity(f.severity, f.severity.str())
	println('  ${severity_str} ${term.bold(f.title)}')
	println('    ${f.description}')
	if f.rule_indices.len > 0 {
		rule_nums := f.rule_indices.map('${it + 1}')
		println('    ${term.dim('Rules:')} ${rule_nums.join(', ')}')
	}
	if f.suggestion.len > 0 {
		println('    ${term.dim(config.sym_arrow)} ${term.green(f.suggestion)}')
	}
	println('')
}

pub fn print_findings(findings []Finding) {
	if findings.len == 0 {
		println('  ${term.green(config.sym_check)} No issues found')
		return
	}
	mut criticals := 0
	mut warnings := 0
	mut infos := 0
	for f in findings {
		match f.severity {
			.critical { criticals++ }
			.warning { warnings++ }
			.info { infos++ }
		}
	}
	println(term.bold('  Findings: ${findings.len} total'))
	if criticals > 0 {
		println('    ${term.red('${criticals} critical')}')
	}
	if warnings > 0 {
		println('    ${term.yellow('${warnings} warnings')}')
	}
	if infos > 0 {
		println('    ${term.cyan('${infos} info')}')
	}
	println('')
	for f in findings {
		print_finding(f)
	}
}

pub fn print_summary(rs Ruleset) {
	println(term.bold('  Ruleset Summary'))
	println('    ${term.dim('Format:')}  ${rs.source.str()}')
	println('    ${term.dim('Rules:')}   ${rs.rules.len}')
	chains := rs.rules_by_chain()
	println('    ${term.dim('Chains:')}  ${chains.len}')
	for chain_name, indices in chains {
		policy_str := if p := rs.policies[chain_name] {
			colorize_action(p)
		} else {
			term.dim('-')
		}
		println('      ${chain_name}: ${indices.len} rules (policy: ${policy_str})')
	}
	println('')
}

pub fn print_diff(left Ruleset, right Ruleset) {
	println(term.bold('  Ruleset Comparison'))
	println('    ${term.dim('Left:')}  ${left.source.str()} (${left.rules.len} rules)')
	println('    ${term.dim('Right:')} ${right.source.str()} (${right.rules.len} rules)')
	println('')
	left_set := build_rule_set(left.rules)
	right_set := build_rule_set(right.rules)
	mut only_left := []string{}
	mut only_right := []string{}
	for key, _ in left_set {
		if key !in right_set {
			only_left << key
		}
	}
	for key, _ in right_set {
		if key !in left_set {
			only_right << key
		}
	}
	if only_left.len == 0 && only_right.len == 0 {
		println('  ${term.green(config.sym_check)} Rulesets are equivalent')
		return
	}
	if only_left.len > 0 {
		println(term.bold('  Only in left:'))
		for entry in only_left {
			println('    ${term.red('- ' + entry)}')
		}
	}
	if only_right.len > 0 {
		println(term.bold('  Only in right:'))
		for entry in only_right {
			println('    ${term.green('+ ' + entry)}')
		}
	}
	println('')
}

fn build_rule_set(rules []Rule) map[string]bool {
	mut result := map[string]bool{}
	for rule in rules {
		result[rule.str()] = true
	}
	return result
}

fn format_addr(addr ?models.NetworkAddr) string {
	if a := addr {
		return truncate(a.str(), config.col_source - 2)
	}
	return '*'
}

fn format_ports(ports []models.PortSpec) string {
	if ports.len == 0 {
		return '*'
	}
	strs := ports.map(it.str())
	return truncate(strs.join(','), config.col_ports - 2)
}

fn colorize_action(a Action) string {
	return match a {
		.accept { term.green(a.str()) }
		.drop { term.red(a.str()) }
		.reject { term.red(a.str()) }
		.log { term.yellow(a.str()) }
		else { a.str() }
	}
}

fn colorize_severity(s Severity, text string) string {
	return match s {
		.critical { term.bold(term.red('[${text}]')) }
		.warning { term.yellow('[${text}]') }
		.info { term.cyan('[${text}]') }
	}
}

fn pad_right(s string, width int) string {
	if s.len >= width {
		return s
	}
	return s + ' '.repeat(width - s.len)
}

fn truncate(s string, max_len int) string {
	if s.len <= max_len {
		return s
	}
	if max_len <= 3 {
		return s[..max_len]
	}
	return s[..max_len - 3] + '...'
}
