/*
©AngelaMos | 2026
config.v

Application-wide constants for ports, limits, display, and exit codes

Centralizes every magic number and string the tool uses. Well-known
ports and service_ports drive the hardened ruleset generator so adding a
new service is a one-line map entry. Rate-limit defaults (ssh_rate_limit,
icmp_rate_limit) match common CIS and NIST hardening baselines.
private_ranges lists RFC 1918 CIDR blocks used for anti-spoofing rules.
Column widths and Unicode symbols control the terminal table layout in
the display module.

Key exports:
  version, app_name         - Binary identity
  exit_success .. exit_usage_error - Process exit codes
  port_ssh .. port_ntp      - Well-known port constants
  private_ranges            - RFC 1918 CIDR blocks for spoofing checks
  ssh_rate_limit, icmp_rate_limit - Default rate-limit strings
  service_ports             - Service name to port number map
  col_num .. col_action     - Terminal table column widths
  sym_check .. sym_bullet   - Unicode glyphs for display

Connects to:
  analyzer/optimizer.v   - reads port constants, rate-limit defaults, multiport_max
  generator/generator.v  - reads service_ports, private_ranges, rate-limit strings
  display/display.v      - reads column widths, Unicode symbols, version
  main.v                 - reads app_name, version, exit codes
*/

module config

pub const version = '1.0.0'

pub const app_name = 'fwrule'

pub const exit_success = 0

pub const exit_parse_error = 1

pub const exit_file_error = 2

pub const exit_analysis_error = 3

pub const exit_usage_error = 64

pub const port_ssh = 22

pub const port_dns = 53

pub const port_http = 80

pub const port_https = 443

pub const port_smtp = 25

pub const port_ntp = 123

pub const cidr_max_v4 = 32

pub const cidr_max_v6 = 128

pub const private_ranges = [
	'10.0.0.0/8',
	'172.16.0.0/12',
	'192.168.0.0/16',
]

pub const loopback_v4 = '127.0.0.0/8'

pub const loopback_v6 = '::1/128'

pub const multiport_max = 15

pub const default_iface = 'eth0'

pub const default_services = ['ssh', 'http', 'https']

pub const ssh_rate_limit = '3/minute'

pub const ssh_rate_burst = 5

pub const icmp_rate_limit = '1/second'

pub const icmp_rate_burst = 5

pub const log_prefix_dropped = 'DROPPED: '

pub const log_prefix_rejected = 'REJECTED: '

pub const col_num = 5

pub const col_chain = 12

pub const col_proto = 8

pub const col_source = 22

pub const col_dest = 22

pub const col_ports = 16

pub const col_action = 12

pub const sym_check = '\u2713'

pub const sym_cross = '\u2717'

pub const sym_warn = '\u26A0'

pub const sym_arrow = '\u2192'

pub const sym_bullet = '\u2022'

pub const service_ports = {
	'ssh':   22
	'dns':   53
	'http':  80
	'https': 443
	'smtp':  25
	'ntp':   123
	'ftp':   21
	'mysql': 3306
	'pg':    5432
	'redis': 6379
}
