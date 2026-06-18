// ©AngelaMos | 2026
// cli.rs

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use tlsfp_core::{FingerprintEvent, PcapFileSource, Pipeline, PipelineConfig, SourceError};

use crate::live::{DEFAULT_BPF_FILTER, LiveConfig, LiveSource};
use crate::report::ReportBuilder;
use crate::serve::{self, ServeConfig, Source};
use tlsfp_intel::{Alert, FpKind, IntelStore, MatchReport, MatchStrength, default_db_path};

/// How many alerts `intel alerts` shows when no count is given, and the floor a
/// zero or negative count is raised to.
const DEFAULT_ALERT_LIMIT: i64 = 50;

/// JA3/JA4 TLS fingerprinting tool.
///
/// Fingerprints TLS clients and servers from live capture or packet captures,
/// matches them against a local intelligence database, and flags anomalies such
/// as a fingerprint that disagrees with its own User-Agent.
#[derive(Debug, Parser)]
#[command(name = "tlsfp", version, about, long_about = None)]
pub struct Cli {
    /// Increase log verbosity (repeat for more detail).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Fingerprint every TLS and QUIC handshake in a packet capture file.
    Pcap {
        /// Path to a pcap or pcapng file.
        path: PathBuf,

        /// Emit one JSON object per event instead of readable lines.
        #[arg(long)]
        json: bool,

        /// Match each fingerprint against the intelligence database.
        #[arg(long)]
        intel: bool,

        /// Run the detection rules, recording observations and raising alerts.
        #[arg(long)]
        detect: bool,

        /// Print a single forensic summary of the whole capture instead of one
        /// line per handshake. When an intelligence database is present it also
        /// folds in match verdicts and detection alerts.
        #[arg(long)]
        report: bool,

        /// How many rows each ranked section of the report shows.
        #[arg(long, default_value_t = crate::report::DEFAULT_TOP)]
        top: usize,

        /// Path to the intelligence database, defaulting to the data directory.
        #[arg(long)]
        db: Option<PathBuf>,
    },

    /// Capture live from a network interface and fingerprint in real time.
    ///
    /// Live capture opens a raw socket, which an unprivileged user cannot
    /// do. Rather than running the whole tool as root, grant the binary the
    /// two capabilities libpcap needs:
    ///
    ///   sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tlsfp)"
    ///
    /// cap_net_raw opens the capture socket, cap_net_admin covers
    /// promiscuous mode, and =eip marks both permitted, inheritable, and
    /// effective when the binary runs. File capabilities live on the binary
    /// itself, so repeat the grant after every rebuild, and point it at
    /// target/debug/tlsfp or target/release/tlsfp when running from cargo.
    ///
    /// The default --filter keeps all TCP (TLS lives on any port, JA4T
    /// wants the SYNs) plus UDP 443 for QUIC, and drops everything else in
    /// the kernel. Tighten it on busy links, for example:
    ///
    ///   tlsfp live eth0 --filter "tcp port 443"
    ///
    /// Stop with ctrl-c: the first one drains and prints final counters, a
    /// second one exits immediately.
    #[command(verbatim_doc_comment)]
    Live {
        /// Interface name, for example eth0, or any for every interface.
        interface: String,

        /// Emit one JSON object per event instead of readable lines.
        #[arg(long)]
        json: bool,

        /// BPF filter compiled into the kernel before capture begins.
        #[arg(long, default_value = DEFAULT_BPF_FILTER)]
        filter: String,

        /// Capture only traffic the interface would normally receive
        /// instead of switching it to promiscuous mode.
        #[arg(long)]
        no_promisc: bool,

        /// Match each fingerprint against the intelligence database.
        #[arg(long)]
        intel: bool,

        /// Run the detection rules, recording observations and raising alerts.
        #[arg(long)]
        detect: bool,

        /// Path to the intelligence database, defaulting to the data directory.
        #[arg(long)]
        db: Option<PathBuf>,
    },

    /// Serve the web dashboard and HTTP API.
    ///
    /// The dashboard's live stream is fed one of three ways. With --replay it
    /// pumps a capture file through the pipeline as a synthetic feed, paced and
    /// optionally looping, which needs no privileges and is the simplest way to
    /// see the dashboard alive. With --live it captures from an interface in
    /// process, the same as `tlsfp live` but rendered in the browser. With
    /// neither, the stream tails the database, so a separate
    /// `tlsfp live --detect` writing to the same store surfaces here.
    Serve {
        /// Address to bind, for example 127.0.0.1:8080.
        #[arg(default_value = "127.0.0.1:8080")]
        bind: String,

        /// Path to the intelligence database, defaulting to the data directory.
        #[arg(long)]
        db: Option<PathBuf>,

        /// Directory of built dashboard assets to serve.
        #[arg(long, default_value = "frontend/dist")]
        web: PathBuf,

        /// Replay this capture file as the live feed.
        #[arg(long, value_name = "PCAP")]
        replay: Option<PathBuf>,

        /// Loop the replayed capture instead of stopping at its end.
        #[arg(long = "loop")]
        repeat: bool,

        /// Pause between replayed events, in milliseconds.
        #[arg(long, default_value_t = 400)]
        interval_ms: u64,

        /// Capture live from this interface as the feed instead of replaying.
        #[arg(long, value_name = "IFACE")]
        live: Option<String>,

        /// BPF filter compiled into the kernel for live capture.
        #[arg(long, default_value = DEFAULT_BPF_FILTER)]
        filter: String,

        /// Capture only the interface's own traffic instead of promiscuous mode.
        #[arg(long)]
        no_promisc: bool,
    },

    /// Manage the local threat intelligence database.
    Intel {
        #[command(subcommand)]
        action: IntelCommand,
    },
}

/// The subcommands under `tlsfp intel`.
#[derive(Debug, Subcommand)]
pub enum IntelCommand {
    /// Create the database if needed and load the three bundled feeds.
    Seed {
        /// Path to the intelligence database, defaulting to the data directory.
        #[arg(long)]
        db: Option<PathBuf>,
    },

    /// Import a ja4db.com JSON export, validating every record on the way in.
    Import {
        /// Path to the JSON file, or - to read standard input.
        path: PathBuf,

        /// Path to the intelligence database, defaulting to the data directory.
        #[arg(long)]
        db: Option<PathBuf>,
    },

    /// Look up one fingerprint and print its verdict.
    Lookup {
        /// Fingerprint kind: ja3, ja3s, ja4, ja4s, ja4h, ja4x, ja4t, or ja4ts.
        kind: String,

        /// The fingerprint value to look up.
        value: String,

        /// Emit the report as JSON instead of readable lines.
        #[arg(long)]
        json: bool,

        /// Path to the intelligence database, defaulting to the data directory.
        #[arg(long)]
        db: Option<PathBuf>,
    },

    /// Show what the database holds, by feed and by category.
    Stats {
        /// Emit the summary as JSON instead of readable lines.
        #[arg(long)]
        json: bool,

        /// Path to the intelligence database, defaulting to the data directory.
        #[arg(long)]
        db: Option<PathBuf>,
    },

    /// Show the most recent alerts the detection rules have raised.
    Alerts {
        /// Emit the alerts as JSON instead of readable lines.
        #[arg(long)]
        json: bool,

        /// How many alerts to show, newest first.
        #[arg(long, default_value_t = DEFAULT_ALERT_LIMIT)]
        limit: i64,

        /// Path to the intelligence database, defaulting to the data directory.
        #[arg(long)]
        db: Option<PathBuf>,
    },
}

impl Cli {
    pub fn init_tracing(&self) {
        let default = match self.verbose {
            0 => "tlsfp=info",
            1 => "tlsfp=debug",
            _ => "tlsfp=trace",
        };
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }

    pub fn run(self) -> Result<()> {
        match self.command {
            Command::Pcap {
                path,
                json,
                intel,
                detect,
                report,
                top,
                db,
            } => run_pcap(&path, json, intel, detect, report, top, db.as_deref()),
            Command::Live {
                interface,
                json,
                filter,
                no_promisc,
                intel,
                detect,
                db,
            } => run_live(
                &interface,
                json,
                filter,
                !no_promisc,
                intel,
                detect,
                db.as_deref(),
            ),
            Command::Serve {
                bind,
                db,
                web,
                replay,
                repeat,
                interval_ms,
                live,
                filter,
                no_promisc,
            } => run_serve(
                bind,
                db,
                web,
                replay,
                repeat,
                interval_ms,
                live,
                filter,
                no_promisc,
            ),
            Command::Intel { action } => action.run(),
        }
    }
}

impl IntelCommand {
    fn run(self) -> Result<()> {
        match self {
            IntelCommand::Seed { db } => run_intel_seed(db),
            IntelCommand::Import { path, db } => run_intel_import(&path, db),
            IntelCommand::Lookup {
                kind,
                value,
                json,
                db,
            } => run_intel_lookup(&kind, &value, json, db),
            IntelCommand::Stats { json, db } => run_intel_stats(json, db),
            IntelCommand::Alerts { json, limit, db } => run_intel_alerts(json, limit, db),
        }
    }
}

/// Fingerprints a capture file and prints one event per line on stdout.
///
/// The summary goes to the log rather than stdout so that piping the output
/// into a tool sees only events, while a human still learns how much of the
/// capture was readable and whether the file was cut short mid packet.
#[allow(clippy::fn_params_excessive_bools)]
fn run_pcap(
    path: &Path,
    json: bool,
    intel: bool,
    detect: bool,
    report: bool,
    top: usize,
    db: Option<&Path>,
) -> Result<()> {
    if report {
        return run_pcap_report(path, json, top, db);
    }
    let mut source = PcapFileSource::open(path)
        .with_context(|| format!("cannot open capture {}", path.display()))?;
    let mut store = open_for_run(intel, detect, db)?;
    let mut pipeline = Pipeline::new(PipelineConfig::default());

    let stdout = std::io::stdout().lock();
    let mut out = std::io::BufWriter::new(stdout);
    let mut write_failure: Option<std::io::Error> = None;
    pipeline.run(&mut source, |event| {
        if write_failure.is_some() {
            return;
        }
        let reports = if intel {
            enrich(store.as_ref(), &event)
        } else {
            Vec::new()
        };
        let alerts = detect_event(store.as_mut(), detect, &event);
        if let Err(error) = write_event(&mut out, &event, reports, alerts, json) {
            write_failure = Some(error);
        }
    })?;
    if let Some(error) = write_failure {
        return Err(anyhow::Error::from(error).context("writing events to stdout"));
    }
    out.flush().context("flushing events to stdout")?;

    let counters = pipeline.counters();
    tracing::info!(
        frames = counters.frames,
        tcp_segments = counters.tcp_segments,
        udp_datagrams = counters.udp_datagrams,
        events = counters.events,
        flows = counters.flows_created,
        quic_initials = counters.quic_initials,
        quic_decrypted = counters.quic_decrypted,
        quic_version_unsupported = counters.quic_version_unsupported,
        tls_handshakes = counters.tls_handshakes_fingerprinted,
        unfinished_tls_streams = counters.unfinished_tls_streams,
        tls_miss_rate = counters.tls_miss_rate(),
        segments_dropped = counters.segments_dropped,
        "capture processed"
    );
    if source.truncated() {
        tracing::warn!("capture file ended mid packet; the tail was not read");
    }
    Ok(())
}

/// Reads a whole capture and prints one forensic summary instead of a stream
/// of events.
///
/// Unlike the streaming path, the report builds an in process picture of every
/// endpoint, fingerprint, and miss before printing, so it folds intelligence
/// and detection in automatically whenever a database is present rather than
/// asking for the flags. With no database it falls back to a pure fingerprint
/// inventory. The intel lookups and detection writes are the same calls the
/// streaming path makes, so the report can never disagree with a live sensor
/// pointed at the same store.
fn run_pcap_report(path: &Path, json: bool, top: usize, db: Option<&Path>) -> Result<()> {
    let mut source = PcapFileSource::open(path)
        .with_context(|| format!("cannot open capture {}", path.display()))?;
    let mut store = open_for_report(db)?;
    let enabled = store.is_some();
    let mut pipeline = Pipeline::new(PipelineConfig::default());
    let mut builder = ReportBuilder::new(&path.display().to_string());

    let started = Instant::now();
    pipeline.run(&mut source, |event| {
        let reports = if enabled {
            enrich(store.as_ref(), &event)
        } else {
            Vec::new()
        };
        let alerts = detect_event(store.as_mut(), enabled, &event);
        builder.observe(&event, &reports, &alerts);
    })?;
    let elapsed = started.elapsed();

    let report = builder.finish(*pipeline.counters(), source.truncated(), elapsed, top);
    let stdout = std::io::stdout().lock();
    let mut out = std::io::BufWriter::new(stdout);
    if json {
        serde_json::to_writer_pretty(&mut out, &report).context("writing report as JSON")?;
        writeln!(out).context("writing report as JSON")?;
    } else {
        write!(out, "{}", report.render_text()).context("writing report")?;
    }
    out.flush().context("flushing the report to stdout")?;
    Ok(())
}

/// Opens the store for a report run. A report folds in intelligence and
/// detection whenever a database is there to answer, so this opens an existing
/// database but never creates one: a forensic read of a capture should not
/// quietly leave a new database behind, and with none present the report is
/// still a complete fingerprint inventory.
fn open_for_report(db: Option<&Path>) -> Result<Option<IntelStore>> {
    let path = db.map_or_else(default_db_path, Path::to_path_buf);
    if path.exists() {
        tracing::info!(
            path = %path.display(),
            "matching and recording detections against the intelligence database"
        );
        return Ok(Some(open_or_create(&path)?));
    }
    tracing::info!(
        path = %path.display(),
        "no intelligence database found; reporting fingerprints only, run 'tlsfp intel seed' to add verdicts"
    );
    Ok(None)
}

/// Builds the dashboard configuration from the command line and starts the
/// server. The live feed is a replayed capture, a live interface, or, by
/// default, the alerts an external sensor tails into the same database.
#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn run_serve(
    bind: String,
    db: Option<PathBuf>,
    web: PathBuf,
    replay: Option<PathBuf>,
    repeat: bool,
    interval_ms: u64,
    live: Option<String>,
    filter: String,
    no_promisc: bool,
) -> Result<()> {
    if replay.is_some() && live.is_some() {
        anyhow::bail!("choose either --replay or --live as the live feed, not both");
    }
    let db = resolve_db(db);
    let source = if let Some(path) = replay {
        if !path.exists() {
            anyhow::bail!("replay capture {} does not exist", path.display());
        }
        Source::Replay {
            path,
            looping: repeat,
            interval: Duration::from_millis(interval_ms),
        }
    } else if let Some(interface) = live {
        Source::Live {
            interface,
            filter,
            promiscuous: !no_promisc,
        }
    } else {
        Source::Tail
    };
    serve::run(ServeConfig {
        bind,
        db,
        web,
        source,
    })
}

/// Captures from an interface until ctrl-c and fingerprints in real time.
///
/// The capture itself runs on a dedicated OS thread inside [`LiveSource`];
/// this function owns the tokio side of the bridge. The runtime is built
/// here rather than in main so the file path stays a plain synchronous
/// program.
#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn run_live(
    interface: &str,
    json: bool,
    filter: String,
    promiscuous: bool,
    intel: bool,
    detect: bool,
    db: Option<&Path>,
) -> Result<()> {
    let config = LiveConfig {
        filter,
        promiscuous,
    };
    let store = open_for_run(intel, detect, db)?;
    let source = LiveSource::open(interface, &config)?;
    tracing::info!(interface, filter = %config.filter, "live capture started");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the async runtime")?;
    runtime.block_on(drive_live(source, json, intel, detect, store))
}

/// Drains the live source through the same pipeline the file path uses.
///
/// Events flush per line so the stream is followable as it happens. The
/// first ctrl-c asks the capture thread to stop and lets the channel
/// drain, which makes the final counters trustworthy; a second ctrl-c
/// exits without ceremony. A closed stdout pipe is a normal way for a
/// live session to end, so it stops the capture instead of reporting an
/// error.
async fn drive_live(
    mut source: LiveSource,
    json: bool,
    intel: bool,
    detect: bool,
    mut store: Option<IntelStore>,
) -> Result<()> {
    let stop = source.stop_handle();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("ctrl-c received; draining capture");
            stop.stop();
        }
        if tokio::signal::ctrl_c().await.is_ok() {
            std::process::exit(130);
        }
    });

    let mut pipeline = Pipeline::new(PipelineConfig::default());
    let stdout = std::io::stdout().lock();
    let mut out = std::io::BufWriter::new(stdout);
    let mut write_failure: Option<std::io::Error> = None;

    let capture_failure: Option<SourceError> = loop {
        let received = source.next_frame_async().await;
        let frame = match received {
            Ok(Some(frame)) => frame,
            Ok(None) => break None,
            Err(error) => break Some(error),
        };
        pipeline.feed(&frame, &mut |event| {
            write_live_event(
                &mut out,
                &mut store,
                intel,
                detect,
                &event,
                json,
                &mut write_failure,
            );
        });
        if write_failure.is_some() {
            break None;
        }
    };
    pipeline.finish();

    let counters = pipeline.counters();
    tracing::info!(
        frames = counters.frames,
        tcp_segments = counters.tcp_segments,
        udp_datagrams = counters.udp_datagrams,
        events = counters.events,
        flows = counters.flows_created,
        quic_initials = counters.quic_initials,
        quic_decrypted = counters.quic_decrypted,
        quic_version_unsupported = counters.quic_version_unsupported,
        tls_handshakes = counters.tls_handshakes_fingerprinted,
        unfinished_tls_streams = counters.unfinished_tls_streams,
        tls_miss_rate = counters.tls_miss_rate(),
        segments_dropped = counters.segments_dropped,
        "live capture stopped"
    );

    if let Some(stats) = source.close() {
        tracing::info!(
            received = stats.received,
            kernel_dropped = stats.kernel_dropped,
            interface_dropped = stats.interface_dropped,
            "kernel capture statistics"
        );
        if stats.kernel_dropped > 0 || stats.interface_dropped > 0 {
            tracing::warn!(
                "the kernel dropped frames; an absent fingerprint is not proof of an absent handshake"
            );
        }
    }

    match (write_failure, capture_failure) {
        (Some(error), _) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        (Some(error), _) => Err(anyhow::Error::from(error).context("writing events to stdout")),
        (None, Some(error)) => Err(anyhow::Error::from(error).context("live capture failed")),
        (None, None) => Ok(()),
    }
}

/// Writes one event and flushes it immediately, recording the first
/// failure instead of panicking inside the pipeline's sink. Later calls
/// become no-ops once a write has failed.
#[allow(clippy::too_many_arguments)]
fn write_live_event(
    out: &mut impl std::io::Write,
    store: &mut Option<IntelStore>,
    intel: bool,
    detect: bool,
    event: &FingerprintEvent,
    json: bool,
    failure: &mut Option<std::io::Error>,
) {
    if failure.is_some() {
        return;
    }
    let reports = if intel {
        enrich(store.as_ref(), event)
    } else {
        Vec::new()
    };
    let alerts = detect_event(store.as_mut(), detect, event);
    let result = write_event(out, event, reports, alerts, json).and_then(|()| out.flush());
    if let Err(error) = result {
        *failure = Some(error);
    }
}

/// One event plus any intelligence that matched it, the shape both the file and
/// the live path serialise. The intel field is omitted when nothing matched, so
/// a run without enrichment produces exactly the same JSON as before.
#[derive(serde::Serialize)]
struct EnrichedEvent<'a> {
    #[serde(flatten)]
    event: &'a FingerprintEvent,
    #[serde(rename = "intel", skip_serializing_if = "Vec::is_empty")]
    reports: Vec<MatchReport>,
    #[serde(rename = "alerts", skip_serializing_if = "Vec::is_empty")]
    alerts: Vec<Alert>,
}

/// Looks every fingerprint in an event up against the store, returning the
/// reports that found intelligence. A lookup error degrades to no enrichment
/// with a warning rather than ending the capture.
fn enrich(store: Option<&IntelStore>, event: &FingerprintEvent) -> Vec<MatchReport> {
    let Some(store) = store else {
        return Vec::new();
    };
    match store.match_event(event) {
        Ok(reports) => reports,
        Err(error) => {
            tracing::warn!(%error, "intelligence lookup failed for an event");
            Vec::new()
        }
    }
}

/// Runs the detection rules for one event when detection is enabled, recording
/// the observation and any alerts. A per-event failure degrades to a warning so
/// one bad record cannot end the capture.
fn detect_event(
    store: Option<&mut IntelStore>,
    detect: bool,
    event: &FingerprintEvent,
) -> Vec<Alert> {
    if !detect {
        return Vec::new();
    }
    let Some(store) = store else {
        return Vec::new();
    };
    match store.detect(event) {
        Ok(alerts) => alerts,
        Err(error) => {
            tracing::warn!(%error, "detection failed for an event");
            Vec::new()
        }
    }
}

/// Writes one event, as JSON or as a readable line, followed by any intel.
fn write_event(
    out: &mut impl std::io::Write,
    event: &FingerprintEvent,
    reports: Vec<MatchReport>,
    alerts: Vec<Alert>,
    json: bool,
) -> std::io::Result<()> {
    if json {
        let enriched = EnrichedEvent {
            event,
            reports,
            alerts,
        };
        serde_json::to_writer(&mut *out, &enriched).map_err(std::io::Error::from)?;
        writeln!(out)
    } else {
        writeln!(out, "{event}")?;
        write_intel_lines(out, &reports)?;
        write_alert_lines(out, &alerts)
    }
}

/// Writes one indented pair of lines per alert beneath its event: the rule and
/// severity that name it, then the evidence that tripped it.
fn write_alert_lines(out: &mut impl std::io::Write, alerts: &[Alert]) -> std::io::Result<()> {
    for alert in alerts {
        writeln!(
            out,
            "    alert [{}] {}: {}",
            alert.severity.as_str(),
            alert.rule.as_str(),
            alert.title,
        )?;
        writeln!(out, "      {}", alert.detail)?;
    }
    Ok(())
}

/// Writes one indented line per intel report beneath its event.
fn write_intel_lines(
    out: &mut impl std::io::Write,
    reports: &[MatchReport],
) -> std::io::Result<()> {
    for report in reports {
        let labels = report
            .hits
            .iter()
            .map(|hit| {
                if hit.strength == MatchStrength::Exact {
                    format!("{} ({})", hit.label, hit.source)
                } else {
                    format!("{} ({}, {})", hit.label, hit.source, hit.strength.as_str())
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            out,
            "    intel {}={} score={:.2} confidence={:.2} {labels}",
            report.kind.as_str(),
            report.verdict.as_str(),
            report.threat_score,
            report.confidence,
        )?;
    }
    Ok(())
}

/// Opens the store for a capture run. Enrichment that finds no database runs
/// without annotation rather than failing. Detection needs somewhere to record
/// observations, so it creates the database, warning that known-bad matching
/// stays dark until the feeds are seeded.
fn open_for_run(intel: bool, detect: bool, db: Option<&Path>) -> Result<Option<IntelStore>> {
    if !intel && !detect {
        return Ok(None);
    }
    let path = db.map_or_else(default_db_path, Path::to_path_buf);
    if !path.exists() {
        if detect {
            tracing::warn!(
                path = %path.display(),
                "no intelligence database found; creating one to record detections, run 'tlsfp intel seed' to enable known-bad matching"
            );
            return Ok(Some(open_or_create(&path)?));
        }
        tracing::warn!(
            path = %path.display(),
            "no intelligence database found; run 'tlsfp intel seed' first, continuing without it"
        );
        return Ok(None);
    }
    Ok(Some(open_or_create(&path)?))
}

/// Resolves the database path from the flag or the default data directory.
fn resolve_db(db: Option<PathBuf>) -> PathBuf {
    db.unwrap_or_else(default_db_path)
}

/// Opens or creates a store at `path`, used by the commands allowed to build
/// the database from scratch.
fn open_or_create(path: &Path) -> Result<IntelStore> {
    IntelStore::open(path)
        .with_context(|| format!("opening intelligence database {}", path.display()))
}

/// Opens a store that is expected to already exist, with a hint to seed first.
fn open_existing(path: &Path) -> Result<IntelStore> {
    if !path.exists() {
        anyhow::bail!(
            "no intelligence database at {}; run 'tlsfp intel seed' first",
            path.display()
        );
    }
    open_or_create(path)
}

fn run_intel_seed(db: Option<PathBuf>) -> Result<()> {
    let path = resolve_db(db);
    let mut store = open_or_create(&path)?;
    let summary = store.seed_bundled()?;
    println!(
        "seeded {} fingerprints into {}",
        summary.parsed(),
        path.display()
    );
    for feed in &summary.feeds {
        println!(
            "  {:<24} {} new, {} total",
            feed.name, feed.inserted, feed.parsed
        );
    }
    Ok(())
}

fn run_intel_import(path: &Path, db: Option<PathBuf>) -> Result<()> {
    let json = read_input(path)?;
    let mut store = open_or_create(&resolve_db(db))?;
    let summary = store.import_ja4db(&json)?;
    println!(
        "imported {} fingerprints from {} ja4db records, {} skipped as invalid",
        summary.imported, summary.records, summary.skipped
    );
    Ok(())
}

fn run_intel_lookup(kind: &str, value: &str, json: bool, db: Option<PathBuf>) -> Result<()> {
    let kind = FpKind::from_token(&kind.to_ascii_lowercase()).with_context(|| {
        format!(
            "unknown fingerprint kind '{kind}'; expected ja3, ja3s, ja4, ja4s, ja4h, ja4x, ja4t, or ja4ts"
        )
    })?;
    let store = open_existing(&resolve_db(db))?;
    let report = store.match_fingerprint(kind, value)?;
    if json {
        let stdout = std::io::stdout().lock();
        serde_json::to_writer_pretty(stdout, &report).context("writing report as JSON")?;
        println!();
    } else {
        print_report(&report);
    }
    Ok(())
}

fn run_intel_stats(json: bool, db: Option<PathBuf>) -> Result<()> {
    let store = open_existing(&resolve_db(db))?;
    let stats = store.stats()?;
    if json {
        let stdout = std::io::stdout().lock();
        serde_json::to_writer_pretty(stdout, &stats).context("writing stats as JSON")?;
        println!();
        return Ok(());
    }
    println!("{} fingerprints total", stats.total);
    println!("feeds:");
    for source in &stats.sources {
        println!(
            "  {:<24} {:<8} {:<14} {}",
            source.name,
            source.kind,
            source.license.as_deref().unwrap_or("-"),
            source.records,
        );
    }
    println!("by category:");
    for category in &stats.by_category {
        println!("  {:<10} {}", category.category, category.records);
    }
    Ok(())
}

fn run_intel_alerts(json: bool, limit: i64, db: Option<PathBuf>) -> Result<()> {
    let store = open_existing(&resolve_db(db))?;
    let limit = if limit <= 0 {
        DEFAULT_ALERT_LIMIT
    } else {
        limit
    };
    let alerts = store.recent_alerts(limit)?;
    if json {
        let stdout = std::io::stdout().lock();
        serde_json::to_writer_pretty(stdout, &alerts).context("writing alerts as JSON")?;
        println!();
        return Ok(());
    }
    if alerts.is_empty() {
        println!("no alerts recorded; run a capture with --detect first");
        return Ok(());
    }
    for alert in &alerts {
        print_alert(alert);
    }
    let counts = store.alert_counts()?;
    if !counts.is_empty() {
        println!("by rule:");
        for (rule, count) in &counts {
            println!("  {:<14} {count}", rule.as_str());
        }
    }
    Ok(())
}

/// Prints one alert as readable lines: a header naming when, how urgent, which
/// rule, and the subject, then the evidence beneath it.
fn print_alert(alert: &Alert) {
    let secs = alert.ts_nanos / 1_000_000_000;
    let millis = alert.ts_nanos % 1_000_000_000 / 1_000_000;
    let target = alert.ip.as_deref().unwrap_or("-");
    println!(
        "{secs}.{millis:03} [{}] {} {target} {}",
        alert.severity.as_str(),
        alert.rule.as_str(),
        alert.title,
    );
    println!("    {}", alert.detail);
}

/// Prints a lookup report as readable lines.
fn print_report(report: &MatchReport) {
    println!(
        "{} {} => {} (threat {:.2}, confidence {:.2})",
        report.kind.as_str(),
        report.observed,
        report.verdict.as_str(),
        report.threat_score,
        report.confidence,
    );
    if report.hits.is_empty() {
        println!("  no intelligence on this fingerprint");
        return;
    }
    for hit in &report.hits {
        println!(
            "  {:<8} {:<18} {:<22} {}",
            hit.category.as_str(),
            hit.strength.as_str(),
            hit.label,
            hit.source,
        );
        if let Some(reference) = &hit.reference {
            println!("      {reference}");
        }
    }
}

/// Reads the importer's input from a file or from standard input for `-`.
fn read_input(path: &Path) -> Result<String> {
    if path.as_os_str() == "-" {
        let mut buffer = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buffer)
            .context("reading ja4db JSON from standard input")?;
        Ok(buffer)
    } else {
        std::fs::read_to_string(path)
            .with_context(|| format!("reading ja4db JSON from {}", path.display()))
    }
}
