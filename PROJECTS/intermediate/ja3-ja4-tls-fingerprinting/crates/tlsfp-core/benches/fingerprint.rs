// ©AngelaMos | 2026
// fingerprint.rs

//! Throughput benchmarks for the fingerprinting hot path.
//!
//! Two questions matter for a passive sensor: how fast it parses one handshake,
//! and how fast it carries a whole capture through the pipeline. The first
//! benchmark isolates parsing and hashing a single ClientHello; the second
//! replays a vendored capture frame by frame, reporting fingerprints per second
//! against the project target of ten thousand. The capture is read into memory
//! once at setup so the file system never enters the measured loop.

use std::hint::black_box;
use std::path::Path;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

use tlsfp_core::ja3::ja3;
use tlsfp_core::ja4::{Transport, ja4};
use tlsfp_core::parse::parse_client_hello;
use tlsfp_core::pipeline::source::{PacketSource, PcapFileSource, RawFrame};
use tlsfp_core::pipeline::{Pipeline, PipelineConfig};

/// Captures replayed by the pipeline benchmark, named for the report.
const PCAPS: [(&str, &str); 2] = [
    (
        "tls-handshake",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/pcap/tls-handshake.pcapng"
        ),
    ),
    (
        "browsers-x509",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/pcap/browsers-x509.pcapng"
        ),
    ),
];

/// One captured frame copied into an owned buffer for replay.
struct OwnedFrame {
    ts_nanos: u64,
    link_type: i32,
    data: Vec<u8>,
}

/// Reads every frame of a capture into memory so the benchmark loop measures
/// the pipeline rather than the file system.
fn load_frames(path: &str) -> Vec<OwnedFrame> {
    let mut source = PcapFileSource::open(Path::new(path)).expect("open capture");
    let mut frames = Vec::new();
    while let Some(frame) = source.next_frame().expect("read frame") {
        frames.push(OwnedFrame {
            ts_nanos: frame.ts_nanos,
            link_type: frame.link_type,
            data: frame.data.to_vec(),
        });
    }
    frames
}

/// Replays preloaded frames through a fresh pipeline, returning the event count.
fn replay(frames: &[OwnedFrame]) -> u64 {
    let mut pipeline = Pipeline::new(PipelineConfig::default());
    for frame in frames {
        let raw = RawFrame {
            ts_nanos: frame.ts_nanos,
            link_type: frame.link_type,
            data: &frame.data,
        };
        pipeline.feed(&raw, &mut |event| {
            black_box(&event);
        });
    }
    pipeline.finish();
    pipeline.counters().events
}

fn bench_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline");
    for (name, path) in PCAPS {
        let frames = load_frames(path);
        let events = replay(&frames).max(1);
        group.throughput(Throughput::Elements(events));
        group.bench_function(name, |b| {
            b.iter(|| black_box(replay(black_box(&frames))));
        });
    }
    group.finish();
}

fn bench_fingerprint(c: &mut Criterion) {
    let body = client_hello_body();
    let hello = parse_client_hello(&body).expect("the benchmark hello parses");

    let mut group = c.benchmark_group("fingerprint");
    group.bench_function("parse_client_hello", |b| {
        b.iter(|| black_box(parse_client_hello(black_box(&body)).expect("parse")));
    });
    group.bench_function("ja3", |b| b.iter(|| black_box(ja3(black_box(&hello)))));
    group.bench_function("ja4", |b| {
        b.iter(|| black_box(ja4(black_box(&hello), Transport::Tcp)));
    });
    group.finish();
}

/// Assembles a representative TLS 1.3 ClientHello body, the input the parser and
/// the hash functions take. The exact bytes are not pinned to any published
/// vector here: this is a throughput fixture, and the conformance vectors live
/// in the integration tests.
fn client_hello_body() -> Vec<u8> {
    const CIPHERS: [u16; 15] = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
        0x009c, 0x009d, 0x002f, 0x0035,
    ];
    const GROUPS: [u16; 4] = [0x001d, 0x0017, 0x0018, 0x0019];
    const SIG_ALGS: [u16; 8] = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    const VERSIONS: [u16; 2] = [0x0304, 0x0303];
    const OPAQUE: [u16; 4] = [0x0005, 0x0017, 0x0023, 0xff01];

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);

    let mut ciphers = Vec::new();
    for suite in CIPHERS {
        ciphers.extend_from_slice(&suite.to_be_bytes());
    }
    push_u16(&mut body, &ciphers);
    push_u8(&mut body, &[0]);

    let mut exts = Vec::new();
    add_ext(&mut exts, 0x0000, &sni("example.com"));
    add_ext(&mut exts, 0x000a, &u16_list_u16(&GROUPS));
    add_ext(&mut exts, 0x000b, &u8_list(&[0]));
    add_ext(&mut exts, 0x000d, &u16_list_u16(&SIG_ALGS));
    add_ext(&mut exts, 0x0010, &alpn(&[b"h2", b"http/1.1"]));
    add_ext(&mut exts, 0x002b, &u8_list_u16(&VERSIONS));
    for ext in OPAQUE {
        add_ext(&mut exts, ext, &[]);
    }
    push_u16(&mut body, &exts);
    body
}

fn push_u8(out: &mut Vec<u8>, data: &[u8]) {
    out.push(u8::try_from(data.len()).expect("length fits a byte"));
    out.extend_from_slice(data);
}

fn push_u16(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(
        &u16::try_from(data.len())
            .expect("length fits two bytes")
            .to_be_bytes(),
    );
    out.extend_from_slice(data);
}

fn add_ext(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    push_u16(out, data);
}

fn sni(host: &str) -> Vec<u8> {
    let mut entry = vec![0u8];
    push_u16(&mut entry, host.as_bytes());
    let mut data = Vec::new();
    push_u16(&mut data, &entry);
    data
}

fn alpn(protocols: &[&[u8]]) -> Vec<u8> {
    let mut list = Vec::new();
    for protocol in protocols {
        push_u8(&mut list, protocol);
    }
    let mut data = Vec::new();
    push_u16(&mut data, &list);
    data
}

fn u16_list_u16(values: &[u16]) -> Vec<u8> {
    let mut list = Vec::new();
    for value in values {
        list.extend_from_slice(&value.to_be_bytes());
    }
    let mut data = Vec::new();
    push_u16(&mut data, &list);
    data
}

fn u8_list_u16(values: &[u16]) -> Vec<u8> {
    let mut list = Vec::new();
    for value in values {
        list.extend_from_slice(&value.to_be_bytes());
    }
    let mut data = Vec::new();
    push_u8(&mut data, &list);
    data
}

fn u8_list(values: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    push_u8(&mut data, values);
    data
}

criterion_group!(benches, bench_pipeline, bench_fingerprint);
criterion_main!(benches);
