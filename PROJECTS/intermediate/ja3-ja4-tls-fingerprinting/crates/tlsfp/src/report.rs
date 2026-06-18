// ©AngelaMos | 2026
// report.rs

//! The forensic batch report for a capture file.
//!
//! Where the streaming `pcap` output prints one line per handshake as it is
//! read, the report holds the whole capture in mind and answers the questions
//! an analyst asks after the fact: who spoke, what they presented, which
//! fingerprints the intelligence database recognised, what the detection rules
//! flagged, and, just as important, how much of the capture the tool could not
//! read. The last part is the honesty section: a miss rate and a throughput
//! that let a reader tell a clean capture from a clipped one before trusting an
//! absence of fingerprints.
//!
//! The aggregation is fed one event at a time so a multi gigabyte capture never
//! has to be held in memory at once; only the distinct fingerprints, endpoints,
//! and names survive between events. The [`Report`] it produces serialises
//! straight to JSON and renders to aligned text, and the builder is unit tested
//! on synthetic events with no capture file in the picture.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use tlsfp_core::{Counters, FingerprintEvent, StreamEvent};
use tlsfp_intel::{Alert, MatchReport, Verdict};

/// How many rows each ranked section shows by default.
pub const DEFAULT_TOP: usize = 15;

/// One endpoint's running inventory while the capture is being read.
#[derive(Default)]
struct EndpointAgg {
    events: u64,
    ja4: BTreeSet<String>,
    ja4s: BTreeSet<String>,
    ja4t: BTreeSet<String>,
    ja4h: BTreeSet<String>,
    ja4x: BTreeSet<String>,
    sni: BTreeSet<String>,
    user_agents: BTreeSet<String>,
    worst_verdict: Option<Verdict>,
    alerts: u64,
}

/// One intelligence finding's running aggregate, keyed by fingerprint.
struct IntelAgg {
    verdict: Verdict,
    threat_score: f64,
    label: String,
    source: String,
    endpoints: BTreeSet<String>,
}

/// Accumulates a capture into a [`Report`], one event at a time.
pub struct ReportBuilder {
    source: String,
    first_ts: Option<u64>,
    last_ts: Option<u64>,
    endpoints: HashMap<IpAddr, EndpointAgg>,
    by_kind: BTreeMap<&'static str, u64>,
    ja4_counts: HashMap<String, u64>,
    ja4_endpoints: HashMap<String, HashSet<IpAddr>>,
    sni_counts: HashMap<String, u64>,
    intel: HashMap<(String, String), IntelAgg>,
    alerts: Vec<Alert>,
}

impl ReportBuilder {
    #[must_use]
    pub fn new(source: &str) -> Self {
        Self {
            source: source.to_owned(),
            first_ts: None,
            last_ts: None,
            endpoints: HashMap::new(),
            by_kind: BTreeMap::new(),
            ja4_counts: HashMap::new(),
            ja4_endpoints: HashMap::new(),
            sni_counts: HashMap::new(),
            intel: HashMap::new(),
            alerts: Vec::new(),
        }
    }

    /// Folds one event, with any intelligence and alerts it produced, into the
    /// running aggregates.
    pub fn observe(&mut self, event: &FingerprintEvent, reports: &[MatchReport], alerts: &[Alert]) {
        self.first_ts = Some(
            self.first_ts
                .map_or(event.ts_nanos, |t| t.min(event.ts_nanos)),
        );
        self.last_ts = Some(
            self.last_ts
                .map_or(event.ts_nanos, |t| t.max(event.ts_nanos)),
        );

        let ip = event.src.ip();
        *self.by_kind.entry(kind_label(&event.event)).or_insert(0) += 1;
        let endpoint = self.endpoints.entry(ip).or_default();
        endpoint.events += 1;

        match &event.event {
            StreamEvent::ClientHello { ja4, sni, .. } => {
                endpoint.ja4.insert(ja4.hash.clone());
                *self.ja4_counts.entry(ja4.hash.clone()).or_insert(0) += 1;
                self.ja4_endpoints
                    .entry(ja4.hash.clone())
                    .or_default()
                    .insert(ip);
                if let Some(name) = sni {
                    endpoint.sni.insert(name.clone());
                    *self.sni_counts.entry(name.clone()).or_insert(0) += 1;
                }
            }
            StreamEvent::ServerHello { ja4s, .. } => {
                endpoint.ja4s.insert(ja4s.hash.clone());
            }
            StreamEvent::Certificate { ja4x } => {
                endpoint.ja4x.insert(ja4x.clone());
            }
            StreamEvent::HttpRequest {
                ja4h, user_agent, ..
            } => {
                endpoint.ja4h.insert(ja4h.hash.clone());
                if let Some(agent) = user_agent {
                    endpoint.user_agents.insert(agent.clone());
                }
            }
            StreamEvent::TcpSyn { ja4t } => {
                endpoint.ja4t.insert(ja4t.clone());
            }
            StreamEvent::TcpSynAck { .. } => {}
        }

        for report in reports {
            endpoint.worst_verdict = Some(worse(endpoint.worst_verdict, report.verdict));
            let key = (report.kind.as_str().to_owned(), report.observed.clone());
            let best = report
                .hits
                .iter()
                .max_by(|a, b| a.strength.weight().total_cmp(&b.strength.weight()));
            let agg = self.intel.entry(key).or_insert_with(|| IntelAgg {
                verdict: report.verdict,
                threat_score: report.threat_score,
                label: best.map_or_else(|| "-".to_owned(), |hit| hit.label.clone()),
                source: best.map_or_else(|| "-".to_owned(), |hit| hit.source.clone()),
                endpoints: BTreeSet::new(),
            });
            agg.threat_score = agg.threat_score.max(report.threat_score);
            agg.endpoints.insert(ip.to_string());
        }

        endpoint.alerts += u64::try_from(alerts.len()).unwrap_or(u64::MAX);
        self.alerts.extend_from_slice(alerts);
    }

    /// Closes the books and produces the report from the running aggregates,
    /// the pipeline's final counters, and the wall clock the run took.
    #[must_use]
    pub fn finish(
        self,
        counters: Counters,
        truncated: bool,
        elapsed: Duration,
        top: usize,
    ) -> Report {
        let duration_secs = match (self.first_ts, self.last_ts) {
            (Some(first), Some(last)) => nanos_to_secs(last.saturating_sub(first)),
            _ => 0.0,
        };

        let mut endpoints: Vec<EndpointSummary> = self
            .endpoints
            .into_iter()
            .map(|(ip, agg)| EndpointSummary {
                ip: ip.to_string(),
                events: agg.events,
                ja4: agg.ja4.into_iter().collect(),
                ja4s: agg.ja4s.into_iter().collect(),
                ja4t: agg.ja4t.into_iter().collect(),
                ja4h: agg.ja4h.into_iter().collect(),
                ja4x: agg.ja4x.into_iter().collect(),
                sni: agg.sni.into_iter().collect(),
                user_agents: agg.user_agents.into_iter().collect(),
                verdict: agg.worst_verdict.map(|v| v.as_str().to_owned()),
                alerts: agg.alerts,
            })
            .collect();
        endpoints.sort_by(|a, b| b.events.cmp(&a.events).then_with(|| a.ip.cmp(&b.ip)));

        let top_ja4 = rank(&self.ja4_counts, top, |value| FpCount {
            value: value.clone(),
            count: self.ja4_counts[value],
            endpoints: self.ja4_endpoints.get(value).map_or(0, HashSet::len),
        });
        let top_sni = rank(&self.sni_counts, top, |value| NameCount {
            name: value.clone(),
            count: self.sni_counts[value],
        });
        let by_kind = self
            .by_kind
            .iter()
            .map(|(kind, count)| KindCount {
                kind: (*kind).to_owned(),
                count: *count,
            })
            .collect();

        let mut intel: Vec<IntelFinding> = self
            .intel
            .into_iter()
            .map(|((kind, value), agg)| IntelFinding {
                kind,
                value,
                verdict: agg.verdict.as_str().to_owned(),
                threat_score: agg.threat_score,
                label: agg.label,
                source: agg.source,
                endpoints: agg.endpoints.into_iter().collect(),
            })
            .collect();
        intel.sort_by(|a, b| {
            b.threat_score
                .total_cmp(&a.threat_score)
                .then_with(|| a.value.cmp(&b.value))
        });
        intel.truncate(top);

        let alerts = AlertSummary::from_alerts(&self.alerts, top);

        Report {
            capture: CaptureSummary {
                source: self.source,
                frames: counters.frames,
                bytes: counters.bytes,
                tcp_segments: counters.tcp_segments,
                udp_datagrams: counters.udp_datagrams,
                events: counters.events,
                flows: counters.flows_created,
                duration_secs,
                truncated,
            },
            distribution: Distribution {
                by_kind,
                top_ja4,
                top_sni,
            },
            endpoints,
            intel,
            alerts,
            coverage: Coverage::derive(&counters, elapsed),
        }
    }
}

/// The full forensic report, ready to serialise or render.
#[derive(Debug, Serialize)]
pub struct Report {
    pub capture: CaptureSummary,
    pub distribution: Distribution,
    pub endpoints: Vec<EndpointSummary>,
    pub intel: Vec<IntelFinding>,
    pub alerts: AlertSummary,
    pub coverage: Coverage,
}

#[derive(Debug, Serialize)]
pub struct CaptureSummary {
    pub source: String,
    pub frames: u64,
    pub bytes: u64,
    pub tcp_segments: u64,
    pub udp_datagrams: u64,
    pub events: u64,
    pub flows: u64,
    pub duration_secs: f64,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct Distribution {
    pub by_kind: Vec<KindCount>,
    pub top_ja4: Vec<FpCount>,
    pub top_sni: Vec<NameCount>,
}

#[derive(Debug, Serialize)]
pub struct KindCount {
    pub kind: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct FpCount {
    pub value: String,
    pub count: u64,
    pub endpoints: usize,
}

#[derive(Debug, Serialize)]
pub struct NameCount {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct EndpointSummary {
    pub ip: String,
    pub events: u64,
    pub ja4: Vec<String>,
    pub ja4s: Vec<String>,
    pub ja4t: Vec<String>,
    pub ja4h: Vec<String>,
    pub ja4x: Vec<String>,
    pub sni: Vec<String>,
    pub user_agents: Vec<String>,
    pub verdict: Option<String>,
    pub alerts: u64,
}

#[derive(Debug, Serialize)]
pub struct IntelFinding {
    pub kind: String,
    pub value: String,
    pub verdict: String,
    pub threat_score: f64,
    pub label: String,
    pub source: String,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AlertSummary {
    pub total: u64,
    pub by_rule: Vec<RuleCount>,
    pub recent: Vec<Alert>,
}

impl AlertSummary {
    fn from_alerts(alerts: &[Alert], top: usize) -> Self {
        let mut by_rule: BTreeMap<&'static str, u64> = BTreeMap::new();
        for alert in alerts {
            *by_rule.entry(alert.rule.as_str()).or_insert(0) += 1;
        }
        let mut counts: Vec<RuleCount> = by_rule
            .into_iter()
            .map(|(rule, count)| RuleCount {
                rule: rule.to_owned(),
                count,
            })
            .collect();
        counts.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.rule.cmp(&b.rule)));

        let recent = alerts.iter().rev().take(top).cloned().collect();
        Self {
            total: u64::try_from(alerts.len()).unwrap_or(u64::MAX),
            by_rule: counts,
            recent,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RuleCount {
    pub rule: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct Coverage {
    pub counters: Counters,
    pub tls_miss_rate: f64,
    pub quic_decrypt_rate: f64,
    pub events_per_sec: f64,
    pub frames_per_sec: f64,
    pub megabits_per_sec: f64,
}

impl Coverage {
    #[allow(clippy::cast_precision_loss)]
    fn derive(counters: &Counters, elapsed: Duration) -> Self {
        let secs = elapsed.as_secs_f64();
        let per_sec = |n: u64| if secs > 0.0 { n as f64 / secs } else { 0.0 };
        let quic_decrypt_rate = if counters.quic_initials == 0 {
            0.0
        } else {
            counters.quic_decrypted as f64 / counters.quic_initials as f64
        };
        Self {
            counters: *counters,
            tls_miss_rate: counters.tls_miss_rate(),
            quic_decrypt_rate,
            events_per_sec: per_sec(counters.events),
            frames_per_sec: per_sec(counters.frames),
            megabits_per_sec: if secs > 0.0 {
                (counters.bytes as f64 * 8.0) / 1_000_000.0 / secs
            } else {
                0.0
            },
        }
    }
}

impl Report {
    /// Renders the report as aligned, sectioned text for a terminal reader.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        self.render_capture(&mut out);
        self.render_distribution(&mut out);
        self.render_endpoints(&mut out);
        self.render_intel(&mut out);
        self.render_alerts(&mut out);
        self.render_coverage(&mut out);
        out
    }

    fn render_capture(&self, out: &mut String) {
        let c = &self.capture;
        let _ = writeln!(out, "== capture ==");
        let _ = writeln!(out, "  source            {}", c.source);
        let _ = writeln!(out, "  frames            {}", c.frames);
        let _ = writeln!(out, "  bytes             {}", c.bytes);
        let _ = writeln!(out, "  tcp segments      {}", c.tcp_segments);
        let _ = writeln!(out, "  udp datagrams     {}", c.udp_datagrams);
        let _ = writeln!(out, "  flows             {}", c.flows);
        let _ = writeln!(out, "  fingerprints      {}", c.events);
        let _ = writeln!(out, "  capture span      {:.3}s", c.duration_secs);
        if c.truncated {
            let _ = writeln!(out, "  truncated         yes (file ended mid packet)");
        }
    }

    fn render_distribution(&self, out: &mut String) {
        let d = &self.distribution;
        let _ = writeln!(out, "\n== fingerprints by kind ==");
        if d.by_kind.is_empty() {
            let _ = writeln!(out, "  none");
        }
        for row in &d.by_kind {
            let _ = writeln!(out, "  {:<16} {}", row.kind, row.count);
        }

        let _ = writeln!(out, "\n== top client ja4 ==");
        if d.top_ja4.is_empty() {
            let _ = writeln!(out, "  none");
        }
        for row in &d.top_ja4 {
            let _ = writeln!(
                out,
                "  {:<40} {:>5}  across {} endpoint(s)",
                row.value, row.count, row.endpoints
            );
        }

        if !d.top_sni.is_empty() {
            let _ = writeln!(out, "\n== top server names ==");
            for row in &d.top_sni {
                let _ = writeln!(out, "  {:<40} {:>5}", row.name, row.count);
            }
        }
    }

    fn render_endpoints(&self, out: &mut String) {
        let _ = writeln!(out, "\n== endpoints ==");
        if self.endpoints.is_empty() {
            let _ = writeln!(out, "  none");
        }
        for endpoint in &self.endpoints {
            let verdict = endpoint.verdict.as_deref().unwrap_or("-");
            let _ = writeln!(
                out,
                "  {} ({} event(s), verdict {}, {} alert(s))",
                endpoint.ip, endpoint.events, verdict, endpoint.alerts
            );
            write_list(out, "ja4", &endpoint.ja4);
            write_list(out, "ja4s", &endpoint.ja4s);
            write_list(out, "ja4t", &endpoint.ja4t);
            write_list(out, "ja4h", &endpoint.ja4h);
            write_list(out, "ja4x", &endpoint.ja4x);
            write_list(out, "sni", &endpoint.sni);
            write_list(out, "ua", &endpoint.user_agents);
        }
    }

    fn render_intel(&self, out: &mut String) {
        let _ = writeln!(out, "\n== intelligence ==");
        if self.intel.is_empty() {
            let _ = writeln!(out, "  no fingerprints matched the database");
            return;
        }
        for finding in &self.intel {
            let _ = writeln!(
                out,
                "  [{}] {} {} (threat {:.2})",
                finding.verdict, finding.kind, finding.value, finding.threat_score
            );
            let _ = writeln!(
                out,
                "      {} ({}), {} endpoint(s)",
                finding.label,
                finding.source,
                finding.endpoints.len()
            );
        }
    }

    fn render_alerts(&self, out: &mut String) {
        let _ = writeln!(out, "\n== alerts ==");
        if self.alerts.total == 0 {
            let _ = writeln!(out, "  none raised");
            return;
        }
        let _ = writeln!(out, "  {} total", self.alerts.total);
        for row in &self.alerts.by_rule {
            let _ = writeln!(out, "  {:<14} {}", row.rule, row.count);
        }
        let _ = writeln!(out, "  most recent:");
        for alert in &self.alerts.recent {
            let target = alert.ip.as_deref().unwrap_or("-");
            let _ = writeln!(
                out,
                "    [{}] {} {} {}",
                alert.severity.as_str(),
                alert.rule.as_str(),
                target,
                alert.title
            );
        }
    }

    fn render_coverage(&self, out: &mut String) {
        let c = &self.coverage;
        let _ = writeln!(out, "\n== coverage ==");
        let _ = writeln!(
            out,
            "  tls miss rate     {:.1}% ({} read, {} clipped)",
            c.tls_miss_rate * 100.0,
            c.counters.tls_handshakes_fingerprinted,
            c.counters.unfinished_tls_streams
        );
        let _ = writeln!(out, "  streams capped    {}", c.counters.streams_capped);
        let _ = writeln!(out, "  segments dropped  {}", c.counters.segments_dropped);
        let _ = writeln!(
            out,
            "  quic initials     {} ({} decrypted, {:.0}%, {} unsupported version)",
            c.counters.quic_initials,
            c.counters.quic_decrypted,
            c.quic_decrypt_rate * 100.0,
            c.counters.quic_version_unsupported
        );
        let _ = writeln!(
            out,
            "  throughput        {:.0} fp/s, {:.0} frames/s, {:.1} Mb/s",
            c.events_per_sec, c.frames_per_sec, c.megabits_per_sec
        );
    }
}

/// Writes one labelled line listing a set's values, skipping an empty set.
fn write_list(out: &mut String, label: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    let _ = writeln!(out, "      {:<5} {}", label, values.join(", "));
}

/// The snake case name a stream event carries, matching its serialised tag.
fn kind_label(event: &StreamEvent) -> &'static str {
    match event {
        StreamEvent::ClientHello { .. } => "client_hello",
        StreamEvent::ServerHello { .. } => "server_hello",
        StreamEvent::Certificate { .. } => "certificate",
        StreamEvent::HttpRequest { .. } => "http_request",
        StreamEvent::TcpSyn { .. } => "tcp_syn",
        StreamEvent::TcpSynAck { .. } => "tcp_syn_ack",
    }
}

/// Ranks the keys of a count map by count descending then key ascending,
/// keeping the top `n` and mapping each through `build`.
fn rank<T>(counts: &HashMap<String, u64>, n: usize, build: impl Fn(&String) -> T) -> Vec<T> {
    let mut keys: Vec<&String> = counts.keys().collect();
    keys.sort_by(|a, b| counts[*b].cmp(&counts[*a]).then_with(|| a.cmp(b)));
    keys.into_iter().take(n).map(build).collect()
}

/// The more alarming of two verdicts, used to fold an endpoint's worst case.
fn worse(current: Option<Verdict>, next: Verdict) -> Verdict {
    let rank = |v: Verdict| match v {
        Verdict::Malicious => 3,
        Verdict::Suspicious => 2,
        Verdict::Unknown => 1,
        Verdict::Benign => 0,
    };
    match current {
        Some(existing) if rank(existing) >= rank(next) => existing,
        _ => next,
    }
}

/// Converts whole nanoseconds to fractional seconds without the precision loss
/// lint, accepting that a capture span beyond `u32::MAX` seconds is unreachable.
#[allow(clippy::cast_precision_loss)]
fn nanos_to_secs(nanos: u64) -> f64 {
    nanos as f64 / 1_000_000_000.0
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tlsfp_core::{Counters, FingerprintEvent, Ja3, Ja4Family, StreamEvent};
    use tlsfp_intel::{Alert, AlertSeverity, FpKind, IntelHit, MatchReport, MatchStrength, Rule};

    use super::ReportBuilder;

    fn client_hello(ip: &str, ja4: &str, sni: &str) -> FingerprintEvent {
        FingerprintEvent {
            ts_nanos: 1_000_000_000,
            src: format!("{ip}:40000").parse().unwrap(),
            dst: "10.0.0.2:443".parse().unwrap(),
            event: StreamEvent::ClientHello {
                ja3: Ja3::from_digest([0u8; 16]),
                ja3_raw: String::new(),
                ja4: Ja4Family::new(ja4.to_owned(), String::new()),
                sni: Some(sni.to_owned()),
                alpn: None,
            },
        }
    }

    #[test]
    fn aggregates_endpoints_and_distribution() {
        let mut builder = ReportBuilder::new("test.pcap");
        builder.observe(
            &client_hello("10.0.0.1", "t13d1516h2_aaaa_bbbb", "a.example"),
            &[],
            &[],
        );
        builder.observe(
            &client_hello("10.0.0.1", "t13d1516h2_aaaa_bbbb", "b.example"),
            &[],
            &[],
        );
        builder.observe(
            &client_hello("10.0.0.9", "t13d1516h2_aaaa_bbbb", "a.example"),
            &[],
            &[],
        );

        let report = builder.finish(Counters::default(), false, Duration::from_millis(10), 15);

        assert_eq!(report.endpoints.len(), 2);
        assert_eq!(report.endpoints[0].ip, "10.0.0.1");
        assert_eq!(report.endpoints[0].events, 2);
        assert_eq!(report.distribution.top_ja4.len(), 1);
        assert_eq!(report.distribution.top_ja4[0].count, 3);
        assert_eq!(report.distribution.top_ja4[0].endpoints, 2);
        assert_eq!(report.distribution.top_sni[0].count, 2);
    }

    #[test]
    fn folds_intel_and_alerts_into_worst_verdict() {
        let mut builder = ReportBuilder::new("test.pcap");
        let event = client_hello("10.0.0.1", "t13d1516h2_aaaa_bbbb", "evil.example");
        let report = MatchReport::from_hits(
            FpKind::Ja4,
            "t13d1516h2_aaaa_bbbb".to_owned(),
            vec![IntelHit {
                kind: FpKind::Ja4,
                value: "t13d1516h2_aaaa_bbbb".to_owned(),
                label: "Cobalt Strike".to_owned(),
                category: tlsfp_intel::Category::Malware,
                source: "test-feed".to_owned(),
                reference: None,
                strength: MatchStrength::Exact,
            }],
        );
        let alert = Alert {
            ts_nanos: 1_000_000_000,
            rule: Rule::KnownBad,
            severity: AlertSeverity::Critical,
            ip: Some("10.0.0.1".to_owned()),
            fp_kind: Some(FpKind::Ja4),
            fp_value: Some("t13d1516h2_aaaa_bbbb".to_owned()),
            title: "known bad fingerprint".to_owned(),
            detail: "matched test-feed".to_owned(),
            score: Some(1.0),
        };
        builder.observe(&event, &[report], &[alert]);

        let built = builder.finish(Counters::default(), false, Duration::from_millis(5), 15);
        assert_eq!(built.endpoints[0].verdict.as_deref(), Some("malicious"));
        assert_eq!(built.endpoints[0].alerts, 1);
        assert_eq!(built.intel.len(), 1);
        assert_eq!(built.intel[0].label, "Cobalt Strike");
        assert_eq!(built.alerts.total, 1);
        assert_eq!(built.alerts.by_rule[0].rule, "known_bad");

        let text = built.render_text();
        assert!(text.contains("== coverage =="));
        assert!(text.contains("Cobalt Strike"));
    }

    #[test]
    fn miss_rate_and_throughput_reach_the_report() {
        let counters = Counters {
            frames: 1000,
            bytes: 1_000_000,
            events: 200,
            tls_handshakes_fingerprinted: 3,
            unfinished_tls_streams: 1,
            ..Counters::default()
        };
        let builder = ReportBuilder::new("test.pcap");
        let report = builder.finish(counters, true, Duration::from_secs(1), 15);
        assert!((report.coverage.tls_miss_rate - 0.25).abs() < 1e-9);
        assert!((report.coverage.events_per_sec - 200.0).abs() < 1e-9);
        assert!(report.capture.truncated);
        assert!(report.render_text().contains("truncated"));
    }
}
