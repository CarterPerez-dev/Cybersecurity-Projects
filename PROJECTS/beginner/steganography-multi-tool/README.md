<!-- ©AngelaMos | 2026 -->
<!-- README.md -->

```json
 ██████╗██████╗ ██╗   ██╗██████╗ ██╗  ██╗ █████╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗██║  ██║██╔══██╗
██║     ██████╔╝ ╚████╔╝ ██████╔╝███████║███████║
██║     ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║██╔══██║
╚██████╗██║  ██║   ██║   ██║     ██║  ██║██║  ██║
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-beginner-8B5CF6?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/steganography-multi-tool)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![Single static binary](https://img.shields.io/badge/binary-single%20static-6D4AFF?style=flat)](https://go.dev)
[![Carriers](https://img.shields.io/badge/carriers-5-4457E8?style=flat)](#the-five-carriers)
[![AEAD](https://img.shields.io/badge/AEAD-ChaCha20--Poly1305-8B5CF6?style=flat)](https://datatracker.ietf.org/doc/html/rfc8439)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)

> A multi-format steganography tool in Go. It takes a message or a file, seals it in a passphrase-encrypted, compressed, integrity-checked envelope, and hides that envelope inside an ordinary-looking carrier: the low bits of an image or an audio file, the Reed-Solomon slack of a QR code, zero-width characters in a block of text, or the structure of a PDF. Point `reveal` at the result and it auto-detects the carrier and hands the message back. It ships as a single static, dependency-free binary and drives from either a scriptable CLI or a guided terminal wizard.

## Why hide an encrypted message

Cryptography and steganography answer two different questions. Encryption makes a message unreadable; steganography makes it unnoticeable. Encryption on its own still announces that a secret exists, and an opaque blob is itself a signal, exactly the thing a data-loss-prevention scanner, an intrusion-detection rule, or a border inspection is trained to flag. Steganography removes the signal: the carrier looks like a holiday photo, a voice memo, a PDF invoice, or a QR code on a poster.

The technique is not academic. In 2022 the Witchetty espionage group concealed a backdoor inside a bitmap of an old Windows logo hosted on a public cloud service, so the payload arrived looking like an image download rather than malware (Symantec). The Stegano exploit kit hid malicious code in the alpha channel of PNG banner ads served to millions of visitors (ESET, 2016). The open-source Invoke-PSImage tool packs a PowerShell script into the pixels of a PNG, and the Stegoloader/Gatak family pulled its own components out of images fetched at runtime to keep obvious code off disk (Dell SecureWorks, 2015). Defenders answer with steganalysis: the statistical hunt for the faint fingerprint that embedding leaves behind.

crypha exists to teach both sides of that exchange honestly. It encrypts first, so a discovered payload is still unreadable, then hides the ciphertext across five very different carriers, each with its own capacity, fragility, and detection story. The `learn/` track walks the steganalysis that breaks each one.

## What it is

Not a stub. Every capability below is exercised by table-driven unit tests, round-trip tests over text and random-binary payloads, and, for the QR carrier, differential tests against reference encoders and decoders.

**The encrypted envelope (every payload, every carrier)**
- A passphrase-derived key via Argon2id (RFC 9106): the 64 MiB default profile, or a 2 GiB profile under `--strength high`
- Authenticated encryption with ChaCha20-Poly1305 by default (constant-time in software on any CPU), or AES-256-GCM behind `--cipher aes256gcm`
- Optional DEFLATE compression before encryption, a CRC32 integrity check, and the header bound in as authenticated associated data, so a single flipped byte fails to open rather than decrypting to garbage
- A passphrase from any source, the `-k` flag, the `CRYPHA_PASSPHRASE` environment variable, or a no-echo terminal prompt, always means the payload is encrypted; crypha never silently writes plaintext when you asked for a key

**Five carriers behind one interface**
- **image**: LSB of RGB in PNG or 24-bit BMP, via the mandatory NRGBA conversion that stops `png.Encode`'s alpha pass from corrupting the low bits; paletted and 16-bit covers are refused rather than silently mangled
- **audio**: LSB of 16-bit PCM samples in WAV; a FLAC cover is decoded, embedded, and re-emitted as WAV
- **qr**: the payload is injected as Reed-Solomon-correctable errors into a QR code's data codewords, so an ordinary scanner silently self-heals to the visible content while crypha reads the injected bytes back. The placement, masking, and block de-interleave are reimplemented from ISO/IEC 18004
- **text**: zero-width U+200B and U+2060 characters appended to any UTF-8 cover; the stego text is visually identical to the original and survives Unicode normalization
- **pdf**: a lossless embedded-file attachment by default, or `--technique metadata` / `--technique append`

**Two frontends over one engine**
- A scriptable cobra CLI: `hide`, `reveal`, `capacity`, `formats`, with a global `--json` for machine consumption
- A guided bubbletea terminal wizard on bare `crypha`, at full parity with the CLI, that walks operation to format to files to options and shows a live capacity meter before it embeds
- `reveal` with no `--format` auto-detects the carrier by trying each one and validating the envelope, so a QR-PNG is never mistaken for an ordinary image

## Quick Start

```bash
curl -fsSL https://angelamos.com/crypha/install.sh | bash
```

One command, zero further steps: it grabs a prebuilt binary for your platform (no Go toolchain needed), drops it on your `PATH`, and leaves `crypha` runnable by name. Then hide your first message:

```bash
crypha                                                    # launch the guided wizard
crypha capacity -i photo.png                              # how much can this cover hold?
crypha hide -i photo.png -o secret.png --format image -m "meet at noon"
crypha reveal secret.png                                  # auto-detects image, prints the message
```

Add a passphrase and `reveal` will ask for it before it decrypts:

```bash
crypha hide -i photo.png -o secret.png --format image -m "coordinates inside" --encrypt --compress
crypha reveal secret.png                                  # prompts for the passphrase, then decrypts
```

Prefer the Go toolchain? `go install github.com/CarterPerez-dev/crypha/cmd/crypha@latest` works too, and `just build` builds from a checkout. Building from source needs Go 1.25+, fetched automatically if you are on an older Go.

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see every recipe.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## The five carriers

| Format | Technique | Cover to output | Capacity (envelope bytes) | Notes |
|--------|-----------|-----------------|---------------------------|-------|
| image | LSB of RGB pixels | PNG / 24-bit BMP to PNG | `width x height x 3 / 8` minus a 4-byte prefix (640x480 holds **115,196**) | alpha untouched; paletted and 16-bit covers refused |
| audio | LSB of 16-bit PCM | WAV / FLAC to WAV | `samples x channels / 8` (2s of 44.1 kHz mono holds **11,021**) | FLAC is decoded and re-emitted as WAV |
| text | zero-width U+200B / U+2060 | any UTF-8 to UTF-8 | effectively **unbounded** | stego text is visually identical; survives NFC/NFKC |
| pdf | attachment / metadata / append | PDF to PDF | effectively **unbounded** | attachment is lossless; append rides after `%%EOF` |
| qr | Reed-Solomon error injection | UTF-8 text to PNG | tens of bytes (a 28-char cover holds **52**) | too small for an encrypted envelope; plaintext only |

Run `crypha capacity -i <cover>` for the exact number on your file. The envelope adds **14 bytes** of framing to a plaintext payload and about **68 bytes** to an encrypted one, which is precisely why a 52-byte QR envelope has no room left for encryption.

## The encrypted envelope

Whatever the carrier, every payload is packed into one versioned envelope before it is hidden. The carrier only ever stores opaque bytes; all crypto, compression, integrity, and versioning live here.

```
plaintext      magic(4) ver(1) flags(1) │ len(4) body(N) │ crc32(4)              +14 bytes

encrypted      magic(4) ver(1) flags(1) cipher(1) params(9) salt(16) nonce(12) │ len(4) ciphertext+tag(N+16) │ crc32(4)
               └──────────────── authenticated as AEAD associated data ───────┘                                        +68 bytes
```

The `params` field carries the Argon2id time, memory, and parallelism used, so `reveal` reproduces the exact key without you re-declaring the profile. Because the whole header up to the nonce is authenticated, tampering with the version, cipher choice, or KDF parameters fails `AEAD.Open` cleanly instead of decrypting to noise. An unknown version is rejected, not guessed. Compression runs before encryption, which is safe for an offline one-shot file tool: the CRIME/BREACH compression oracles need an adaptive network attacker, and there is none here.

## Honest limits

Steganography is a set of trade-offs, not magic. crypha is explicit about them.

- **QR holds tens of bytes.** The channel is the `floor((n - k) / 2)` correctable errors per Reed-Solomon block, which is real but small. An encrypted envelope does not fit, so QR is plaintext-only, and `capacity` says so.
- **Image and audio LSB are fragile.** They survive a byte-for-byte copy, not re-encoding. Re-save the PNG as JPEG, or the WAV as MP3, and the payload is gone. This is a property of LSB steganography, not a bug.
- **Zero-width text is easy to detect and strip.** It is invisible to a human reader, but trivially visible to any tool that looks for U+200B/U+2060. It is a teaching carrier for the technique, not a covert channel against a motivated inspector.
- **FLAC is WAV-primary.** A FLAC cover is decoded and re-emitted as WAV, because the only Go FLAC encoder emits strict-parser-incompatible frames; native FLAC output is deferred by design.

## Architecture

One engine, two frontends. The engine is the brain; cobra and bubbletea are thin, interchangeable faces over it, and neither holds any carrier logic.

```
        cobra CLI ───┐
                     ├──>  engine  ──>  carrier registry  ──>  image  audio  qr  text  pdf
     bubbletea TUI ──┘         │
                               └──>  payload envelope (Argon2id · AEAD · flate · CRC32)  ──>  bitio
```

Each carrier is an isolated package implementing a single `Carrier` interface (`Hide`, `Reveal`, `Capacity`, `Sniff`) and self-registers through a blank import. `hide`, `reveal`, and `capacity` dispatch through the registry; auto-detect walks every carrier's `Sniff` and then confirms by validating the envelope it extracts, so a carrier that merely *could* read the bytes never shadows the one that actually owns them. If the TUI needs a value, it asks the engine for it (that is how the exact capacity meter works); it never reaches into a carrier.

## Build and Test

```bash
just build       # -> ./dist/crypha   (or: go build -o dist/crypha ./cmd/crypha)
just test        # go test ./...
just test-race   # the race detector across the suite
just lint        # golangci-lint, pinned to a Go 1.25 toolchain
```

Coverage is table-driven per carrier. Every carrier round-trips text and random-binary payloads and checks the exact capacity boundary: a payload at the limit succeeds and one byte over fails cleanly. The crypto path is known-answer tested (encrypt-decrypt returns the plaintext, a flipped ciphertext byte fails to open, and the echoed Argon2id parameters reproduce the key). The QR carrier is differentially tested against `skip2/go-qrcode` (its clean matrix must match) and `gozxing` (the stego image must still scan to the cover), so an injection can never exceed the correctable budget without a test noticing.

## Project Structure

```
steganography-multi-tool/
├── cmd/crypha/            # tiny main: cli.Execute()
├── internal/
│   ├── cli/               # cobra: hide reveal capacity formats version tui + secure passphrase
│   ├── tui/               # bubbletea wizard, a pure view over the engine
│   ├── engine/            # the shared brain both frontends call
│   ├── carrier/           # Carrier interface + Register/Get/All/Detect registry
│   │   ├── all/           # blank-import aggregator that registers every carrier
│   │   └── image/ audio/ qr/ text/ pdf/
│   ├── payload/           # the encrypted envelope: Argon2id, AEAD, flate, CRC32, framing
│   ├── bitio/             # MSB-first BitReader / BitWriter
│   ├── config/            # every constant (magic, KDF params, format catalog)
│   └── report/            # human tables and --json rendering
├── learn/                 # the teaching track (public)
├── install.sh             # the one-shot curl-able installer
├── .goreleaser.yaml       # cross-platform release binaries
└── justfile               # every recipe
```

## Learn

This project ships a full teaching track. Read it in order, or jump to what you need.

| Doc | What it covers |
|-----|----------------|
| [`learn/00-OVERVIEW.md`](learn/00-OVERVIEW.md) | What the tool is, prerequisites, the project layout, and a quick tour |
| [`learn/01-CONCEPTS.md`](learn/01-CONCEPTS.md) | Steganography vs cryptography, the LSB and zero-width channels, and steganalysis, grounded in real incidents |
| [`learn/02-ARCHITECTURE.md`](learn/02-ARCHITECTURE.md) | The one-engine-two-frontends design, the carrier registry, and the envelope format |
| [`learn/03-IMPLEMENTATION.md`](learn/03-IMPLEMENTATION.md) | A code walkthrough, with the QR-from-ISO-18004 Reed-Solomon injection as the showpiece |
| [`learn/04-CHALLENGES.md`](learn/04-CHALLENGES.md) | Extension ideas, from a new carrier to 2-LSB density modes and stronger steganalysis resistance |

## License

[AGPL 3.0](LICENSE).
