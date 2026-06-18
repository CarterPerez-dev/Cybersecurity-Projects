// ©AngelaMos | 2026
// mod.rs

//! The passive fingerprinting pipeline: frames in, fingerprint events out.
//!
//! The stages are deliberately separable. A [`PacketSource`] yields raw link
//! layer frames from a capture file or, later, a live interface. The decoder
//! strips the frame down to a TCP segment. The flow table reassembles each
//! direction of each conversation into a contiguous byte stream, surviving
//! reordering, retransmission, and overlap. The protocol layer watches each
//! stream until it recognizes a TLS flight or an HTTP request head and emits
//! fingerprints. Nothing in here touches a network interface, so the whole
//! pipeline runs byte exact in tests against vendored captures.

pub mod decode;
pub mod event;
pub mod flow;
pub mod source;
pub mod tls;

use std::collections::HashMap;

use serde::Serialize;

use crate::ja3::{ja3, ja3_string};
use crate::ja4::{Transport, ja4};
use crate::ja4t::ja4t;
use crate::parse::parse_client_hello;
use crate::pipeline::decode::{Decoded, DecodedDatagram, DecodedSegment, Skip, decode_frame};
use crate::pipeline::event::{FingerprintEvent, StreamEvent};
use crate::pipeline::flow::{FlowKey, PushOutcome, ReassemblyLimits, StreamReassembler};
use crate::pipeline::source::{PacketSource, RawFrame, SourceError};
use crate::pipeline::tls::StreamProtocol;
use crate::quic::{
    ClientHelloState, CryptoAssembler, InitialKeys, InitialPacket, walk_crypto_frames,
};

/// Tuning knobs for the pipeline.
///
/// The defaults are sized for handshake harvesting: generous enough that a
/// fat certificate chain or a multi segment ClientHello always fits, small
/// enough that an adversarial capture cannot turn the flow table into a
/// memory bomb.
#[derive(Debug, Clone, Copy)]
pub struct PipelineConfig {
    /// Flows tracked at once before the table sheds its oldest entries.
    pub max_flows: usize,
    /// A flow untouched for this long is eligible for eviction.
    pub idle_timeout_nanos: u64,
    /// Contiguous bytes kept per direction.
    pub max_assembled_bytes: usize,
    /// Out of order bytes parked per direction.
    pub max_pending_bytes: usize,
    /// Out of order segments parked per direction.
    pub max_pending_segments: usize,
}

impl PipelineConfig {
    pub const DEFAULT_MAX_FLOWS: usize = 65_536;
    pub const DEFAULT_IDLE_TIMEOUT_NANOS: u64 = 60 * 1_000_000_000;
    pub const DEFAULT_MAX_ASSEMBLED_BYTES: usize = 256 * 1024;
    pub const DEFAULT_MAX_PENDING_BYTES: usize = 256 * 1024;
    pub const DEFAULT_MAX_PENDING_SEGMENTS: usize = 128;

    fn limits(&self) -> ReassemblyLimits {
        ReassemblyLimits {
            max_assembled_bytes: self.max_assembled_bytes,
            max_pending_bytes: self.max_pending_bytes,
            max_pending_segments: self.max_pending_segments,
        }
    }
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            max_flows: Self::DEFAULT_MAX_FLOWS,
            idle_timeout_nanos: Self::DEFAULT_IDLE_TIMEOUT_NANOS,
            max_assembled_bytes: Self::DEFAULT_MAX_ASSEMBLED_BYTES,
            max_pending_bytes: Self::DEFAULT_MAX_PENDING_BYTES,
            max_pending_segments: Self::DEFAULT_MAX_PENDING_SEGMENTS,
        }
    }
}

/// What the pipeline saw, for the operator and for the miss rate honesty
/// check: a fingerprinting tool that cannot say what it failed to read is a
/// tool whose silence gets mistaken for absence.
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct Counters {
    pub frames: u64,
    pub bytes: u64,
    pub tcp_segments: u64,
    pub udp_datagrams: u64,
    pub skipped_unsupported_link_type: u64,
    pub skipped_not_ip: u64,
    pub skipped_not_transport: u64,
    pub skipped_malformed: u64,
    pub flows_created: u64,
    pub flows_evicted_idle: u64,
    pub flows_evicted_pressure: u64,
    pub segments_dropped: u64,
    pub events: u64,
    pub streams_capped: u64,
    /// TCP streams recognized as TLS that yielded a complete ClientHello or
    /// ServerHello. The denominator, with `unfinished_tls_streams`, of the miss
    /// rate: how many handshakes the tool actually read.
    pub tls_handshakes_fingerprinted: u64,
    pub unfinished_tls_streams: u64,
    /// QUIC long header Initial packets observed, both directions.
    pub quic_initials: u64,
    /// Client Initials whose protection was removed and payload decrypted.
    /// The gap to `quic_initials` is mostly server Initials, which a passive
    /// observer cannot open, and is exactly the honesty an operator needs.
    pub quic_decrypted: u64,
    /// Initials carrying a QUIC version this build has no salt for.
    pub quic_version_unsupported: u64,
}

impl Counters {
    /// The share of recognized TLS streams the capture clipped before a
    /// complete handshake message could be read.
    ///
    /// A fingerprinting tool that cannot say what it failed to read is one
    /// whose silence gets mistaken for absence. A truncated or multi segment
    /// ClientHello whose later segments never arrived counts as a miss here, so
    /// an operator can tell a clean link from a clipped capture before trusting
    /// the count of fingerprints. Zero recognized streams reports a zero rate
    /// rather than dividing by nothing.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn tls_miss_rate(&self) -> f64 {
        let recognized = self.tls_handshakes_fingerprinted + self.unfinished_tls_streams;
        if recognized == 0 {
            0.0
        } else {
            self.unfinished_tls_streams as f64 / recognized as f64
        }
    }
}

/// One direction of one tracked flow.
struct StreamHalf {
    reassembler: StreamReassembler,
    protocol: StreamProtocol,
    syn_fingerprint_emitted: bool,
}

impl StreamHalf {
    fn new(limits: ReassemblyLimits) -> Self {
        Self {
            reassembler: StreamReassembler::new(limits),
            protocol: StreamProtocol::Undecided,
            syn_fingerprint_emitted: false,
        }
    }
}

struct FlowState {
    halves: [StreamHalf; 2],
    last_seen_nanos: u64,
}

impl FlowState {
    fn new(limits: ReassemblyLimits) -> Self {
        Self {
            halves: [StreamHalf::new(limits), StreamHalf::new(limits)],
            last_seen_nanos: 0,
        }
    }

    fn finished(&self) -> bool {
        self.halves.iter().all(|h| h.protocol.finished())
    }
}

/// One tracked QUIC conversation.
///
/// QUIC needs far less per flow state than TCP. There is one cryptographic
/// stream to reassemble, not two byte streams, and the only message this
/// pipeline reads from it is the ClientHello, which lives entirely in the
/// client's first flight of Initial packets. Once the client keys are locked
/// from the first Initial that authenticates, every later Initial on the flow
/// reuses them, and `done` retires the flow the moment the ClientHello is in
/// hand or the stream proves it will never hold one.
struct QuicFlow {
    keys: Option<InitialKeys>,
    crypto: CryptoAssembler,
    largest_pn: Option<u64>,
    done: bool,
    last_seen_nanos: u64,
}

impl QuicFlow {
    fn new(max_crypto_bytes: usize) -> Self {
        Self {
            keys: None,
            crypto: CryptoAssembler::new(max_crypto_bytes),
            largest_pn: None,
            done: false,
            last_seen_nanos: 0,
        }
    }
}

/// The passive fingerprinting engine.
///
/// Feed it frames, take events out through the sink closure. The pipeline is
/// synchronous and single threaded by design: one pipeline owns its flow
/// table outright, and running one per worker beats sharing a locked table
/// between workers.
pub struct Pipeline {
    config: PipelineConfig,
    flows: HashMap<FlowKey, FlowState>,
    quic_flows: HashMap<FlowKey, QuicFlow>,
    counters: Counters,
}

impl Pipeline {
    #[must_use]
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            config,
            flows: HashMap::new(),
            quic_flows: HashMap::new(),
            counters: Counters::default(),
        }
    }

    #[must_use]
    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// Drains a source through the pipeline, sending every event to `sink`.
    pub fn run<S: PacketSource>(
        &mut self,
        source: &mut S,
        mut sink: impl FnMut(FingerprintEvent),
    ) -> Result<(), SourceError> {
        while let Some(frame) = source.next_frame()? {
            self.feed(&frame, &mut sink);
        }
        self.finish();
        Ok(())
    }

    /// Processes one captured frame, dispatching to the TCP or QUIC path.
    pub fn feed(&mut self, frame: &RawFrame<'_>, sink: &mut impl FnMut(FingerprintEvent)) {
        self.counters.frames += 1;
        self.counters.bytes += frame.data.len() as u64;

        match decode_frame(frame.link_type, frame.data) {
            Ok(Decoded::Tcp(segment)) => {
                self.counters.tcp_segments += 1;
                self.feed_tcp(&segment, frame, sink);
            }
            Ok(Decoded::Udp(datagram)) => {
                self.counters.udp_datagrams += 1;
                self.feed_quic(&datagram, frame, sink);
            }
            Err(skip) => match skip {
                Skip::UnsupportedLinkType => self.counters.skipped_unsupported_link_type += 1,
                Skip::NotIp => self.counters.skipped_not_ip += 1,
                Skip::NotTransport => self.counters.skipped_not_transport += 1,
                Skip::Malformed => self.counters.skipped_malformed += 1,
            },
        }
    }

    /// Feeds one TCP segment into its flow's reassembler and protocol layer.
    fn feed_tcp(
        &mut self,
        segment: &DecodedSegment<'_>,
        frame: &RawFrame<'_>,
        sink: &mut impl FnMut(FingerprintEvent),
    ) {
        let (key, direction) = FlowKey::from_pair(segment.src, segment.dst);
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= self.config.max_flows {
                self.evict(frame.ts_nanos);
            }
            self.flows.insert(key, FlowState::new(self.config.limits()));
            self.counters.flows_created += 1;
        }
        let Some(flow) = self.flows.get_mut(&key) else {
            return;
        };
        flow.last_seen_nanos = flow.last_seen_nanos.max(frame.ts_nanos);

        let (src, dst) = direction.addresses(&key);
        let half = &mut flow.halves[direction.index()];

        if !half.syn_fingerprint_emitted {
            if let Some(input) = &segment.syn_fingerprint {
                half.syn_fingerprint_emitted = true;
                let fingerprint = ja4t(input);
                let event = if segment.tcp.flags.ack() {
                    StreamEvent::TcpSynAck { ja4ts: fingerprint }
                } else {
                    StreamEvent::TcpSyn { ja4t: fingerprint }
                };
                self.counters.events += 1;
                sink(FingerprintEvent {
                    ts_nanos: frame.ts_nanos,
                    src,
                    dst,
                    event,
                });
            }
        }

        if segment.tcp.flags.syn() {
            half.reassembler.anchor(segment.tcp.seq.wrapping_add(1));
        }

        let payload_seq = if segment.tcp.flags.syn() {
            segment.tcp.seq.wrapping_add(1)
        } else {
            segment.tcp.seq
        };
        let outcome = half.reassembler.push(payload_seq, segment.payload);
        if outcome == PushOutcome::Dropped {
            self.counters.segments_dropped += 1;
        }

        if outcome == PushOutcome::Grew {
            let mut emitted = 0u64;
            let mut tls_fingerprinted = 0u64;
            tls::advance(&mut half.protocol, half.reassembler.data(), &mut |event| {
                emitted += 1;
                if matches!(
                    event,
                    StreamEvent::ClientHello { .. } | StreamEvent::ServerHello { .. }
                ) {
                    tls_fingerprinted += 1;
                }
                sink(FingerprintEvent {
                    ts_nanos: frame.ts_nanos,
                    src,
                    dst,
                    event,
                });
            });
            self.counters.events += emitted;
            self.counters.tls_handshakes_fingerprinted += tls_fingerprinted;
            if half.protocol.finished() && !half.reassembler.released() {
                half.reassembler.release();
            }
        }
    }

    /// Feeds one UDP datagram into its QUIC flow, decrypting any client
    /// Initial packets and reassembling the ClientHello they carry.
    ///
    /// A datagram may coalesce several QUIC packets, so the parse walks them
    /// in turn. Each Initial is opened with the flow's locked client keys, or,
    /// before any are locked, with keys derived from that packet's own
    /// Destination Connection ID; the AEAD tag is what confirms a packet was
    /// a client Initial rather than a server one this observer cannot read.
    /// Once the contiguous CRYPTO stream holds a complete ClientHello it is
    /// fingerprinted exactly like a TCP one, only carrying the QUIC transport
    /// marker, and the flow is retired.
    fn feed_quic(
        &mut self,
        datagram: &DecodedDatagram<'_>,
        frame: &RawFrame<'_>,
        sink: &mut impl FnMut(FingerprintEvent),
    ) {
        let (key, direction) = FlowKey::from_pair(datagram.src, datagram.dst);
        if !self.quic_flows.contains_key(&key) {
            if self.quic_flows.len() >= self.config.max_flows {
                self.evict_quic(frame.ts_nanos);
            }
            self.quic_flows
                .insert(key, QuicFlow::new(self.config.max_assembled_bytes));
        }
        let Some(flow) = self.quic_flows.get_mut(&key) else {
            return;
        };
        flow.last_seen_nanos = flow.last_seen_nanos.max(frame.ts_nanos);
        if flow.done {
            return;
        }

        let mut offset = 0usize;
        while offset < datagram.payload.len() {
            let packet = match InitialPacket::parse(datagram.payload, offset) {
                Ok(packet) => packet,
                Err(crate::error::ParseError::UnsupportedQuicVersion(_)) => {
                    self.counters.quic_version_unsupported += 1;
                    break;
                }
                Err(_) => break,
            };
            self.counters.quic_initials += 1;
            offset = packet.next_offset;

            let opened = if let Some(keys) = flow.keys.as_ref() {
                packet.open(keys, flow.largest_pn).ok()
            } else {
                let candidate = InitialKeys::client(packet.dcid);
                match packet.open(&candidate, None) {
                    Ok(opened) => {
                        flow.keys = Some(candidate);
                        Some(opened)
                    }
                    Err(_) => None,
                }
            };

            let Some(opened) = opened else {
                continue;
            };
            self.counters.quic_decrypted += 1;
            flow.largest_pn = Some(
                flow.largest_pn
                    .map_or(opened.packet_number, |seen| seen.max(opened.packet_number)),
            );
            let crypto = &mut flow.crypto;
            let _ = walk_crypto_frames(&opened.frames, |off, data| crypto.push(off, data));
        }

        match flow.crypto.client_hello() {
            ClientHelloState::Ready(body) => {
                if let Ok(hello) = parse_client_hello(body) {
                    let (src, dst) = direction.addresses(&key);
                    sink(FingerprintEvent {
                        ts_nanos: frame.ts_nanos,
                        src,
                        dst,
                        event: StreamEvent::ClientHello {
                            ja3: ja3(&hello),
                            ja3_raw: ja3_string(&hello),
                            ja4: ja4(&hello, Transport::Quic),
                            sni: hello.server_name().map(str::to_owned),
                            alpn: hello
                                .alpn_protocols()
                                .first()
                                .map(|p| String::from_utf8_lossy(p).into_owned()),
                        },
                    });
                    self.counters.events += 1;
                }
                flow.done = true;
            }
            ClientHelloState::NotClientHello | ClientHelloState::Abandoned => flow.done = true,
            ClientHelloState::Incomplete => {}
        }
    }

    /// Settles the books at end of capture.
    ///
    /// Streams that were recognized as TLS but never produced a complete
    /// handshake message are counted: each one is a handshake the capture
    /// clipped, which is exactly the number an operator needs before trusting
    /// an absence of fingerprints.
    pub fn finish(&mut self) {
        for flow in self.flows.values() {
            for half in &flow.halves {
                if half.protocol.unfinished_tls() {
                    self.counters.unfinished_tls_streams += 1;
                }
                if half.reassembler.capped() {
                    self.counters.streams_capped += 1;
                }
            }
        }
        self.flows.clear();
        self.quic_flows.clear();
    }

    /// Sheds flows when the table is full: everything idle past the timeout
    /// or fully harvested goes, and if nothing qualifies, the single stalest
    /// flow goes, so the table never refuses a brand new conversation in
    /// favor of a dead one.
    fn evict(&mut self, now_nanos: u64) {
        let timeout = self.config.idle_timeout_nanos;
        let idle: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, flow)| {
                now_nanos.saturating_sub(flow.last_seen_nanos) > timeout || flow.finished()
            })
            .map(|(key, _)| *key)
            .collect();

        if idle.is_empty() {
            let stalest = self
                .flows
                .iter()
                .min_by_key(|(_, flow)| flow.last_seen_nanos)
                .map(|(key, _)| *key);
            if let Some(key) = stalest {
                self.drop_flow(key);
                self.counters.flows_evicted_pressure += 1;
            }
            return;
        }

        for key in idle {
            self.drop_flow(key);
            self.counters.flows_evicted_idle += 1;
        }
    }

    fn drop_flow(&mut self, key: FlowKey) {
        if let Some(flow) = self.flows.remove(&key) {
            for half in &flow.halves {
                if half.protocol.unfinished_tls() {
                    self.counters.unfinished_tls_streams += 1;
                }
                if half.reassembler.capped() {
                    self.counters.streams_capped += 1;
                }
            }
        }
    }

    /// Sheds QUIC flows under the same policy as the TCP table: retire the
    /// idle and the already harvested first, and if none qualify, the single
    /// stalest flow, so a fresh handshake is never turned away for a dead one.
    fn evict_quic(&mut self, now_nanos: u64) {
        let timeout = self.config.idle_timeout_nanos;
        let idle: Vec<FlowKey> = self
            .quic_flows
            .iter()
            .filter(|(_, flow)| {
                now_nanos.saturating_sub(flow.last_seen_nanos) > timeout || flow.done
            })
            .map(|(key, _)| *key)
            .collect();

        if idle.is_empty() {
            let stalest = self
                .quic_flows
                .iter()
                .min_by_key(|(_, flow)| flow.last_seen_nanos)
                .map(|(key, _)| *key);
            if let Some(key) = stalest {
                self.quic_flows.remove(&key);
                self.counters.flows_evicted_pressure += 1;
            }
            return;
        }

        for key in idle {
            self.quic_flows.remove(&key);
            self.counters.flows_evicted_idle += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Pipeline, PipelineConfig};
    use crate::pipeline::event::FingerprintEvent;
    use crate::pipeline::source::RawFrame;
    use etherparse::PacketBuilder;

    fn tcp_frame(src: ([u8; 4], u16), dst: ([u8; 4], u16), seq: u32, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4(src.0, dst.0, 64)
            .tcp(src.1, dst.1, seq, 64240);
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    fn feed_all(pipeline: &mut Pipeline, frames: &[Vec<u8>]) -> Vec<FingerprintEvent> {
        let mut events = Vec::new();
        for (i, data) in frames.iter().enumerate() {
            let frame = RawFrame {
                ts_nanos: u64::try_from(i).unwrap() * 1_000_000,
                link_type: 1,
                data,
            };
            pipeline.feed(&frame, &mut |e| events.push(e));
        }
        events
    }

    #[test]
    fn http_request_split_across_segments_fingerprints_once() {
        let client = ([10, 0, 0, 1], 40000);
        let server = ([10, 0, 0, 2], 80);
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let (a, b) = request.split_at(20);

        let frames = vec![
            tcp_frame(client, server, 1000, a),
            tcp_frame(client, server, 1000 + u32::try_from(a.len()).unwrap(), b),
        ];

        let mut pipeline = Pipeline::new(PipelineConfig::default());
        let events = feed_all(&mut pipeline, &frames);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].src.to_string(), "10.0.0.1:40000");
        assert_eq!(pipeline.counters().tcp_segments, 2);
    }

    #[test]
    fn out_of_order_delivery_after_a_syn_still_fingerprints() {
        let client = ([10, 0, 0, 1], 40001);
        let server = ([10, 0, 0, 2], 80);
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let (a, b) = request.split_at(20);

        let syn = {
            let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
                .ipv4(client.0, server.0, 64)
                .tcp(client.1, server.1, 999, 64240)
                .syn();
            let mut out = Vec::with_capacity(builder.size(0));
            builder.write(&mut out, &[]).unwrap();
            out
        };

        let frames = vec![
            syn,
            tcp_frame(client, server, 1000 + u32::try_from(a.len()).unwrap(), b),
            tcp_frame(client, server, 1000, a),
        ];

        let mut pipeline = Pipeline::new(PipelineConfig::default());
        let events = feed_all(&mut pipeline, &frames);
        assert_eq!(events.len(), 2);
        assert!(events[0].to_string().contains("tcp_syn ja4t="));
        assert!(events[1].to_string().contains("http_request"));
    }

    #[test]
    fn miss_rate_arithmetic_is_misses_over_recognized() {
        use super::Counters;
        let none = Counters::default();
        assert!(none.tls_miss_rate().abs() < 1e-9);

        let clean = Counters {
            tls_handshakes_fingerprinted: 4,
            unfinished_tls_streams: 0,
            ..Counters::default()
        };
        assert!(clean.tls_miss_rate().abs() < 1e-9);

        let clipped = Counters {
            tls_handshakes_fingerprinted: 3,
            unfinished_tls_streams: 1,
            ..Counters::default()
        };
        assert!((clipped.tls_miss_rate() - 0.25).abs() < 1e-9);
    }

    #[test]
    fn clipped_tls_handshake_counts_as_a_miss() {
        let client = ([10, 0, 0, 1], 40002);
        let server = ([10, 0, 0, 2], 443);
        let clipped_client_hello = [
            0x16, 0x03, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0xfa, 0x03, 0x03,
        ];

        let frames = vec![tcp_frame(client, server, 1000, &clipped_client_hello)];
        let mut pipeline = Pipeline::new(PipelineConfig::default());
        let events = feed_all(&mut pipeline, &frames);
        pipeline.finish();

        assert!(events.is_empty());
        let counters = pipeline.counters();
        assert_eq!(counters.tls_handshakes_fingerprinted, 0);
        assert_eq!(counters.unfinished_tls_streams, 1);
        assert!((counters.tls_miss_rate() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn pressure_eviction_keeps_the_table_bounded() {
        let config = PipelineConfig {
            max_flows: 4,
            ..PipelineConfig::default()
        };
        let mut pipeline = Pipeline::new(config);

        let mut frames = Vec::new();
        for i in 0..8u16 {
            let port = 40000 + i;
            frames.push(tcp_frame(
                ([10, 0, 0, 1], port),
                ([10, 0, 0, 2], 80),
                1,
                b"x",
            ));
        }
        feed_all(&mut pipeline, &frames);

        assert_eq!(pipeline.counters().flows_created, 8);
        assert!(pipeline.counters().flows_evicted_pressure >= 4);
    }
}
