/*
©AngelaMos | 2026
main.v

CLI entry point with command dispatch and ruleset loading

Parses the first positional argument as a subcommand and fans out to
the appropriate handler. load/analyze/optimize/diff read a ruleset file
through load_ruleset, which auto-detects iptables vs nftables format
via parser.detect_format before delegating to the correct parser.
harden and export use V's flag module for option parsing (--services,
--iface, --format). Every command prints through the display module so
output formatting is consistent.

Key exports:
  main          - Entry point, dispatches to cmd_* handlers
  load_ruleset  - Reads a file, auto-detects format, returns a Ruleset

Connects to:
  config/config.v       - exit codes, app_name, version, default_services, default_iface
  models/models.v       - RuleSource for format selection in harden/export
  parser/common.v       - detect_format for auto-detection
  parser/iptables.v     - parse_iptables for iptables input
  parser/nftables.v     - parse_nftables for nftables input
  analyzer/conflict.v   - analyze_conflicts for the analyze command
  analyzer/optimizer.v  - suggest_optimizations for analyze/optimize commands
  generator/generator.v - generate_hardened, export_ruleset
  display/display.v     - print_banner, print_summary, print_rule_table, print_findings, print_diff
*/

module main

import os
import flag
import src.config
import src.models
import src.parser
import src.analyzer
import src.generator
import term
import src.display

fn main() {
	if os.args.len < 2 {
		cmd_help()
		exit(config.exit_usage_error)
	}
	command := os.args[1]
	remaining := if os.args.len > 2 { os.args[2..] } else { []string{} }

	match command {
		'load', 'display' {
			cmd_load(remaining)
		}
		'analyze' {
			cmd_analyze(remaining)
		}
		'optimize' {
			cmd_optimize(remaining)
		}
		'harden' {
			cmd_harden(remaining)
		}
		'export' {
			cmd_export(remaining)
		}
		'diff' {
			cmd_diff(remaining)
		}
		'version', '--version', '-v' {
			cmd_version()
		}
		'help', '--help', '-h' {
			cmd_help()
		}
		else {
			eprintln('unknown command: ${command}')
			eprintln('Run "${config.app_name} help" for usage')
			exit(config.exit_usage_error)
		}
	}
}

fn cmd_load(args []string) {
	if args.len == 0 {
		eprintln('usage: ${config.app_name} load <file>')
		exit(config.exit_usage_error)
	}
	rs := load_ruleset(args[0]) or {
		eprintln('${err}')
		exit(config.exit_parse_error)
	}
	display.print_banner()
	display.print_summary(rs)
	display.print_rule_table(rs)
}

fn cmd_analyze(args []string) {
	if args.len == 0 {
		eprintln('usage: ${config.app_name} analyze <file>')
		exit(config.exit_usage_error)
	}
	rs := load_ruleset(args[0]) or {
		eprintln('${err}')
		exit(config.exit_parse_error)
	}
	display.print_banner()
	display.print_summary(rs)

	println(term.bold('  Conflict Analysis'))
	conflicts := analyzer.analyze_conflicts(rs)
	display.print_findings(conflicts)

	println(term.bold('  Optimization Suggestions'))
	optimizations := analyzer.suggest_optimizations(rs)
	display.print_findings(optimizations)
}

fn cmd_optimize(args []string) {
	if args.len == 0 {
		eprintln('usage: ${config.app_name} optimize <file>')
		exit(config.exit_usage_error)
	}
	rs := load_ruleset(args[0]) or {
		eprintln('${err}')
		exit(config.exit_parse_error)
	}
	display.print_banner()

	println(term.bold('  Optimization Suggestions'))
	findings := analyzer.suggest_optimizations(rs)
	display.print_findings(findings)
}

fn cmd_harden(args []string) {
	mut fp := flag.new_flag_parser(args)
	fp.application(config.app_name)
	fp.description('Generate a hardened firewall ruleset')
	services_str := fp.string('services', `s`, config.default_services.join(','), 'comma-separated list of services to allow')
	iface := fp.string('iface', `i`, config.default_iface, 'public-facing network interface')
	format_str := fp.string('format', `f`, 'iptables', 'output format (iptables or nftables)')
	fp.finalize() or {
		eprintln('${err}')
		exit(config.exit_usage_error)
	}

	services := services_str.split(',').map(it.trim_space()).filter(it.len > 0)
	out_format := match format_str.to_lower() {
		'iptables' {
			models.RuleSource.iptables
		}
		'nftables' {
			models.RuleSource.nftables
		}
		else {
			eprintln('invalid format: ${format_str} (use iptables or nftables)')
			exit(config.exit_usage_error)
			models.RuleSource.iptables
		}
	}

	display.print_banner()
	output := generator.generate_hardened(services, iface, out_format)
	println(output)
}

fn cmd_export(args []string) {
	mut fp := flag.new_flag_parser(args)
	fp.application(config.app_name)
	fp.description('Export ruleset in a different format')
	format_str := fp.string('format', `f`, 'nftables', 'output format (iptables or nftables)')
	remaining := fp.finalize() or {
		eprintln('${err}')
		exit(config.exit_usage_error)
		[]string{}
	}

	if remaining.len == 0 {
		eprintln('usage: ${config.app_name} export <file> --format <iptables|nftables>')
		exit(config.exit_usage_error)
	}

	rs := load_ruleset(remaining[0]) or {
		eprintln('${err}')
		exit(config.exit_parse_error)
	}

	out_format := match format_str.to_lower() {
		'nftables' {
			models.RuleSource.nftables
		}
		'iptables' {
			models.RuleSource.iptables
		}
		else {
			eprintln('invalid format: ${format_str}')
			exit(config.exit_usage_error)
			models.RuleSource.iptables
		}
	}

	output := generator.export_ruleset(rs, out_format)
	println(output)
}

fn cmd_diff(args []string) {
	if args.len < 2 {
		eprintln('usage: ${config.app_name} diff <file1> <file2>')
		exit(config.exit_usage_error)
	}
	left := load_ruleset(args[0]) or {
		eprintln('${err}')
		exit(config.exit_parse_error)
	}
	right := load_ruleset(args[1]) or {
		eprintln('${err}')
		exit(config.exit_parse_error)
	}
	display.print_banner()
	display.print_diff(left, right)
}

fn cmd_version() {
	println('${config.app_name} v${config.version}')
}

fn cmd_help() {
	println('${config.app_name} v${config.version} - Firewall Rule Engine')
	println('')
	println('USAGE:')
	println('  ${config.app_name} <command> [options]')
	println('')
	println('COMMANDS:')
	println('  load <file>        Load and display a ruleset')
	println('  analyze <file>     Run conflict detection and optimization analysis')
	println('  optimize <file>    Show optimization suggestions')
	println('  harden             Generate a hardened ruleset')
	println('  export <file>      Convert ruleset between iptables/nftables formats')
	println('  diff <f1> <f2>     Compare two rulesets')
	println('  version            Show version')
	println('  help               Show this help')
	println('')
	println('HARDEN OPTIONS:')
	println('  -s, --services     Services to allow (default: ssh,http,https)')
	println('  -i, --iface        Public interface (default: eth0)')
	println('  -f, --format       Output format: iptables or nftables (default: iptables)')
	println('')
	println('EXPORT OPTIONS:')
	println('  -f, --format       Target format: iptables or nftables (default: nftables)')
	println('')
	println('EXAMPLES:')
	println('  ${config.app_name} load rules.txt')
	println('  ${config.app_name} analyze /etc/iptables.rules')
	println('  ${config.app_name} harden -s ssh,http,https -f nftables')
	println('  ${config.app_name} export rules.txt -f nftables')
	println('  ${config.app_name} diff old.rules new.rules')
}

fn load_ruleset(path string) !models.Ruleset {
	if !os.exists(path) {
		return error('file not found: ${path}')
	}
	content := os.read_file(path) or { return error('cannot read file: ${path}') }
	fmt := parser.detect_format(content)!
	return match fmt {
		.iptables { parser.parse_iptables(content)! }
		.nftables { parser.parse_nftables(content)! }
	}
}
