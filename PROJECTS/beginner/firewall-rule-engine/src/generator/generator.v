/*
©AngelaMos | 2026
generator.v

Hardened ruleset generation and cross-format export

generate_hardened builds a complete firewall ruleset from scratch using
CIS-aligned defaults: default-deny INPUT/FORWARD, loopback acceptance,
conntrack early in the chain, RFC 1918 anti-spoofing, rate-limited ICMP
and SSH, and a LOG rule before the final drop. Services are resolved
through config.service_ports so DNS gets dual tcp/udp rules and NTP gets
udp-only. export_ruleset converts an existing parsed Ruleset into the
opposite format by serializing each Rule through rule_to_iptables or
rule_to_nftables, preserving table and chain structure including
multi-table layouts (filter + nat).

Key exports:
  generate_hardened - Builds a hardened ruleset string for given services and format
  export_ruleset    - Converts a Ruleset to iptables or nftables string output

Connects to:
  config/config.v   - reads service_ports, private_ranges, rate-limit strings, log prefixes
  models/models.v   - imports Rule, Ruleset, RuleSource
  main.v            - called from cmd_harden and cmd_export
*/

module generator

import src.config
import src.models { Rule, RuleSource, Ruleset }

pub fn generate_hardened(services []string, iface string, fmt RuleSource) string {
	return match fmt {
		.iptables { generate_iptables_hardened(services, iface) }
		.nftables { generate_nftables_hardened(services, iface) }
	}
}

fn generate_iptables_hardened(services []string, iface string) string {
	mut lines := []string{}
	lines << '*filter'
	lines << ':INPUT DROP [0:0]'
	lines << ':FORWARD DROP [0:0]'
	lines << ':OUTPUT ACCEPT [0:0]'
	lines << ''
	lines << '-A INPUT -i lo -j ACCEPT'
	lines << '-A OUTPUT -o lo -j ACCEPT'
	lines << ''
	lines << '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
	lines << '-A INPUT -m conntrack --ctstate INVALID -j DROP'
	lines << ''
	for cidr in config.private_ranges {
		lines << '-A INPUT -i ${iface} -s ${cidr} -j DROP'
	}
	lines << ''
	lines << '-A INPUT -p icmp --icmp-type echo-request -m limit --limit ${config.icmp_rate_limit} --limit-burst ${config.icmp_rate_burst} -j ACCEPT'
	lines << '-A INPUT -p icmp --icmp-type echo-reply -j ACCEPT'
	lines << '-A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT'
	lines << '-A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT'
	lines << ''
	for svc in services {
		port := config.service_ports[svc] or { continue }
		if svc == 'ssh' {
			lines << '-A INPUT -p tcp --dport ${port} -m conntrack --ctstate NEW -m limit --limit ${config.ssh_rate_limit} --limit-burst ${config.ssh_rate_burst} -j ACCEPT'
		} else if svc == 'dns' {
			lines << '-A INPUT -p tcp --dport ${port} -j ACCEPT'
			lines << '-A INPUT -p udp --dport ${port} -j ACCEPT'
		} else if svc == 'ntp' {
			lines << '-A INPUT -p udp --dport ${port} -j ACCEPT'
		} else {
			lines << '-A INPUT -p tcp --dport ${port} -j ACCEPT'
		}
	}
	lines << ''
	lines << '-A INPUT -m limit --limit 5/minute -j LOG --log-prefix "${config.log_prefix_dropped}"'
	lines << '-A INPUT -j DROP'
	lines << ''
	lines << 'COMMIT'
	return lines.join('\n')
}

fn generate_nftables_hardened(services []string, iface string) string {
	mut lines := []string{}
	lines << 'table inet filter {'
	lines << '    chain input {'
	lines << '        type filter hook input priority 0; policy drop;'
	lines << ''
	lines << '        iifname "lo" accept'
	lines << ''
	lines << '        ct state established,related accept'
	lines << '        ct state invalid drop'
	lines << ''
	for cidr in config.private_ranges {
		lines << '        iifname "${iface}" ip saddr ${cidr} drop'
	}
	lines << ''
	lines << '        icmp type echo-request limit rate ${config.icmp_rate_limit} burst ${config.icmp_rate_burst} packets accept'
	lines << '        icmp type { echo-reply, destination-unreachable, time-exceeded } accept'
	lines << ''
	for svc in services {
		port := config.service_ports[svc] or { continue }
		if svc == 'ssh' {
			lines << '        tcp dport ${port} ct state new limit rate ${config.ssh_rate_limit} burst ${config.ssh_rate_burst} packets accept'
		} else if svc == 'dns' {
			lines << '        tcp dport ${port} accept'
			lines << '        udp dport ${port} accept'
		} else if svc == 'ntp' {
			lines << '        udp dport ${port} accept'
		} else {
			lines << '        tcp dport ${port} accept'
		}
	}
	lines << ''
	lines << '        limit rate 5/minute log prefix "${config.log_prefix_dropped}"'
	lines << '        drop'
	lines << '    }'
	lines << ''
	lines << '    chain forward {'
	lines << '        type filter hook forward priority 0; policy drop;'
	lines << '    }'
	lines << ''
	lines << '    chain output {'
	lines << '        type filter hook output priority 0; policy accept;'
	lines << '    }'
	lines << '}'
	return lines.join('\n')
}

pub fn export_ruleset(rs Ruleset, fmt RuleSource) string {
	return match fmt {
		.iptables { export_as_iptables(rs) }
		.nftables { export_as_nftables(rs) }
	}
}

fn export_as_iptables(rs Ruleset) string {
	mut lines := []string{}
	mut tables_seen := map[string]bool{}
	for rule in rs.rules {
		tbl := rule.table.str()
		if tbl !in tables_seen {
			if tables_seen.len > 0 {
				lines << 'COMMIT'
				lines << ''
			}
			lines << '*${tbl}'
			tables_seen[tbl] = true
			for chain_name, policy in rs.policies {
				lines << ':${chain_name} ${policy.str()} [0:0]'
			}
		}
		lines << rule_to_iptables(rule)
	}
	if tables_seen.len > 0 {
		lines << 'COMMIT'
	}
	return lines.join('\n')
}

fn export_as_nftables(rs Ruleset) string {
	mut lines := []string{}
	mut table_chains := map[string]map[string][]int{}
	for i, rule in rs.rules {
		tbl := rule.table.str()
		if tbl !in table_chains {
			table_chains[tbl] = map[string][]int{}
		}
		table_chains[tbl][rule.chain] << i
	}
	for tbl, chains in table_chains {
		lines << 'table inet ${tbl} {'
		for chain_name, indices in chains {
			policy_str := if p := rs.policies[chain_name] {
				p.str().to_lower()
			} else {
				'accept'
			}
			chain_lower := chain_name.to_lower()
			lines << '    chain ${chain_lower} {'
			hook := match chain_name {
				'INPUT' { 'input' }
				'OUTPUT' { 'output' }
				'FORWARD' { 'forward' }
				'PREROUTING' { 'prerouting' }
				'POSTROUTING' { 'postrouting' }
				else { '' }
			}
			if hook.len > 0 {
				lines << '        type filter hook ${hook} priority 0; policy ${policy_str};'
			}
			for idx in indices {
				lines << '        ${rule_to_nftables(rs.rules[idx])}'
			}
			lines << '    }'
		}
		lines << '}'
	}
	return lines.join('\n')
}

fn rule_to_iptables(r Rule) string {
	mut parts := []string{}
	parts << '-A ${r.chain}'
	if r.criteria.protocol != .all {
		parts << '-p ${r.criteria.protocol.str()}'
	}
	if src := r.criteria.source {
		if src.negated {
			parts << '! -s ${src.address}/${src.cidr}'
		} else {
			parts << '-s ${src.address}/${src.cidr}'
		}
	}
	if dst := r.criteria.destination {
		if dst.negated {
			parts << '! -d ${dst.address}/${dst.cidr}'
		} else {
			parts << '-d ${dst.address}/${dst.cidr}'
		}
	}
	if iface := r.criteria.in_iface {
		parts << '-i ${iface}'
	}
	if oface := r.criteria.out_iface {
		parts << '-o ${oface}'
	}
	if !r.criteria.states.is_empty() {
		mut state_strs := []string{}
		if r.criteria.states.has(.new_conn) {
			state_strs << 'NEW'
		}
		if r.criteria.states.has(.established) {
			state_strs << 'ESTABLISHED'
		}
		if r.criteria.states.has(.related) {
			state_strs << 'RELATED'
		}
		if r.criteria.states.has(.invalid) {
			state_strs << 'INVALID'
		}
		parts << '-m conntrack --ctstate ${state_strs.join(',')}'
	}
	if r.criteria.dst_ports.len == 1 {
		parts << '--dport ${r.criteria.dst_ports[0].str()}'
	} else if r.criteria.dst_ports.len > 1 {
		port_strs := r.criteria.dst_ports.map(it.str())
		parts << '-m multiport --dports ${port_strs.join(',')}'
	}
	if rate := r.criteria.limit_rate {
		parts << '-m limit --limit ${rate}'
		if burst := r.criteria.limit_burst {
			parts << '--limit-burst ${burst}'
		}
	}
	parts << '-j ${r.action.str()}'
	if r.target_args.len > 0 {
		parts << r.target_args
	}
	return parts.join(' ')
}

fn rule_to_nftables(r Rule) string {
	mut parts := []string{}
	if iface := r.criteria.in_iface {
		parts << 'iifname "${iface}"'
	}
	if oface := r.criteria.out_iface {
		parts << 'oifname "${oface}"'
	}
	if src := r.criteria.source {
		prefix := if src.negated { '!= ' } else { '' }
		parts << 'ip saddr ${prefix}${src.address}/${src.cidr}'
	}
	if dst := r.criteria.destination {
		prefix := if dst.negated { '!= ' } else { '' }
		parts << 'ip daddr ${prefix}${dst.address}/${dst.cidr}'
	}
	if !r.criteria.states.is_empty() {
		mut state_strs := []string{}
		if r.criteria.states.has(.new_conn) {
			state_strs << 'new'
		}
		if r.criteria.states.has(.established) {
			state_strs << 'established'
		}
		if r.criteria.states.has(.related) {
			state_strs << 'related'
		}
		if r.criteria.states.has(.invalid) {
			state_strs << 'invalid'
		}
		parts << 'ct state ${state_strs.join(',')}'
	}
	if r.criteria.protocol != .all {
		proto := r.criteria.protocol.str()
		if r.criteria.dst_ports.len == 1 {
			parts << '${proto} dport ${r.criteria.dst_ports[0].start}'
		} else if r.criteria.dst_ports.len > 1 {
			port_strs := r.criteria.dst_ports.map('${it.start}')
			parts << '${proto} dport { ${port_strs.join(', ')} }'
		} else {
			parts << 'ip protocol ${proto}'
		}
	}
	if rate := r.criteria.limit_rate {
		parts << 'limit rate ${rate}'
	}
	action_str := match r.action {
		.accept { 'accept' }
		.drop { 'drop' }
		.reject { 'reject' }
		.log { 'log' }
		.masquerade { 'masquerade' }
		.return_action { 'return' }
		else { r.action.str().to_lower() }
	}
	if r.action == .log && r.target_args.len > 0 {
		parts << 'log ${r.target_args}'
	} else {
		parts << action_str
	}
	return parts.join(' ')
}
