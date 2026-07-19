<!-- ©AngelaMos | 2026 -->
<!-- DEMO.md -->

# crypha demo

A hands-on tour of every carrier, end to end, with the real output crypha produces. Nothing here is faked; each block is a command you can run and the result it gives back.

Two things to know before you start:

- crypha writes the recovered payload to **stdout** and a one-line status to **stderr**. On a terminal they run together, because the payload has no trailing newline. Redirect with `-o out.bin`, or use `--json`, when you want them cleanly separated.
- A passphrase from any source (`-k`, `CRYPHA_PASSPHRASE`, or the interactive prompt) always encrypts. crypha never writes plaintext when you asked for a key.

## Sample covers

Any files work. To reproduce this page exactly, make a throwaway set with tools you probably already have:

```bash
convert -size 640x480 gradient:navy-white -depth 8 PNG24:cover.png   # an 8-bit truecolor image
ffmpeg -f lavfi -i "sine=frequency=440:duration=2" \
       -ac 1 -c:a pcm_s16le cover.wav                        # 2 seconds of mono audio
ffmpeg -i cover.wav cover.flac                               # the same audio, as FLAC
convert -size 612x792 xc:white cover.pdf                     # a one-page PDF
printf 'The quick brown fox jumps over the lazy dog.' > cover.txt
printf 'https://angelamos.com/crypha' > qr.txt               # the QR's visible content
```

The image carrier wants an 8-bit truecolor PNG (or a 24-bit BMP); the `-depth 8 PNG24:` above forces that, since ImageMagick otherwise defaults to a 16-bit PNG, which crypha refuses.

## What can it hide, and where

```console
$ crypha formats
FORMAT  COVER                                  OUTPUT  OPTIONS                         DESCRIPTION
audio   16-bit PCM WAV or FLAC                 WAV     -                               LSB of 16-bit PCM samples
image   PNG or 24-bit BMP                      PNG     -                               LSB of RGB pixel data
pdf     PDF                                    PDF     attachment | metadata | append  embedded attachment, metadata, or append-after-EOF
qr      UTF-8 text (the QR's visible content)  PNG     -                               Reed-Solomon-correctable error injection
text    any UTF-8 text                         text    -                               zero-width U+200B and U+2060 characters
```

`capacity` tells you how much a specific cover will hold, plaintext and encrypted:

```console
$ crypha capacity -i cover.png --format image
FORMAT  ENVELOPE  MAX PLAINTEXT  MAX ENCRYPTED  NOTE
image   115196    115182         115128

$ crypha capacity -i qr.txt --format qr
FORMAT  ENVELOPE  MAX PLAINTEXT  MAX ENCRYPTED  NOTE
qr      52        38             does not fit
```

Point `capacity` at a cover with no `--format` and it reports every carrier at once, flagging the ones the cover cannot serve:

```console
$ crypha capacity -i cover.png
FORMAT  ENVELOPE   MAX PLAINTEXT  MAX ENCRYPTED  NOTE
audio   n/a        n/a            n/a            cover must be a 16-bit PCM WAV or a FLAC file
image   115196     115182         115128
pdf     n/a        n/a            n/a            cover must be a PDF
qr      0          0              does not fit
text    unbounded  unbounded      unbounded
```

## image: LSB of RGB pixels

```console
$ crypha hide --format image -i cover.png -o stego.png -m "The treasure is buried under the third oak past the old mill."
OUTPUT      stego.png
FORMAT      image
PAYLOAD     61 bytes
ENVELOPE    75 bytes
ENCRYPTED   no
COMPRESSED  no
```

`reveal` needs no `--format`; it detects the carrier itself:

```console
$ crypha reveal stego.png
The treasure is buried under the third oak past the old mill.
revealed 61 bytes via image -> (stdout)
```

`stego.png` is pixel-for-pixel indistinguishable to the eye. The 61-byte message became a 75-byte envelope (a plaintext payload adds 14 bytes of framing) and rode in the low bit of the RGB channels.

## text: zero-width characters

```console
$ crypha hide --format text -i cover.txt -o stego.txt -m "Zero-width characters are invisible to the eye."
OUTPUT      stego.txt
FORMAT      text
PAYLOAD     47 bytes
ENVELOPE    61 bytes
ENCRYPTED   no
COMPRESSED  no
```

The stego file reads identically to the cover, but the byte count gives it away: the cover was 44 bytes and `stego.txt` is far larger, because the envelope was appended as invisible U+200B and U+2060 runes.

```console
$ crypha reveal stego.txt
Zero-width characters are invisible to the eye.
revealed 47 bytes via text -> (stdout)
```

## audio: LSB of PCM samples

```console
$ crypha hide --format audio -i cover.wav -o stego.wav -m "Frequencies carry more than music."
OUTPUT      stego.wav
FORMAT      audio
PAYLOAD     34 bytes
ENVELOPE    48 bytes
ENCRYPTED   no
COMPRESSED  no

$ crypha reveal stego.wav
Frequencies carry more than music.
revealed 34 bytes via audio -> (stdout)
```

The tone sounds the same; the payload lives in the low bit of each 16-bit sample. Hand it a FLAC cover and crypha decodes it, embeds, and writes the result back as a standard WAV:

```console
$ crypha hide --format audio -i cover.flac -o from-flac.wav -m "Decoded from FLAC, embedded, written back as WAV."
OUTPUT      from-flac.wav
FORMAT      audio
PAYLOAD     49 bytes
ENVELOPE    63 bytes
ENCRYPTED   no
COMPRESSED  no

$ crypha reveal from-flac.wav
Decoded from FLAC, embedded, written back as WAV.
revealed 49 bytes via audio -> (stdout)
```

## qr: Reed-Solomon error injection

This is the showpiece. The payload is injected as errors into the QR's data codewords, inside the Reed-Solomon correction budget. An ordinary scanner reads the visible content and silently self-heals the injected errors away; crypha reads the errors back as the hidden bytes.

```console
$ crypha hide --format qr -i qr.txt -o stego-qr.png -m "meet me at the docks, midnight"
OUTPUT      stego-qr.png
FORMAT      qr
PAYLOAD     30 bytes
ENVELOPE    44 bytes
ENCRYPTED   no
COMPRESSED  no
```

Scan `stego-qr.png` with any phone and you get `https://angelamos.com/crypha`. Point crypha at it and you get the secret. Auto-detect has to be careful here, because a QR stego is a PNG: it must not be mistaken for an ordinary image carrier. It is not.

```console
$ crypha reveal stego-qr.png
meet me at the docks, midnight
revealed 30 bytes via qr -> (stdout)
```

The 30-byte message fit in the 38-byte plaintext budget of this cover. An encrypted envelope (68 bytes of overhead) would not, which is exactly what `capacity` warned above.

## pdf: attachment, metadata, or append

The default technique embeds the envelope as a lossless file attachment:

```console
$ crypha hide --format pdf -i cover.pdf -o stego.pdf -m "Attached, not appended. Look inside the file."
OUTPUT      stego.pdf
FORMAT      pdf
PAYLOAD     45 bytes
ENVELOPE    59 bytes
ENCRYPTED   no
COMPRESSED  no

$ crypha reveal stego.pdf
Attached, not appended. Look inside the file.
revealed 45 bytes via pdf -> (stdout)
```

`--technique append` writes the envelope after the `%%EOF` marker instead, where it survives naive copies:

```console
$ crypha hide --format pdf --technique append -i cover.pdf -o stego-append.pdf -m "This rides after the EOF marker."
OUTPUT      stego-append.pdf
FORMAT      pdf (append)
PAYLOAD     32 bytes
ENVELOPE    46 bytes
ENCRYPTED   no
COMPRESSED  no
```

`reveal` tries every technique, so you never have to remember which one you used.

## Encryption, end to end

Set a passphrase, ask to encrypt, and (optionally) compress. Here the passphrase comes from the environment so it never lands in your shell history:

```console
$ export CRYPHA_PASSPHRASE="correct horse battery staple"
$ crypha hide --format image -i cover.png -o enc.png -m "Only the passphrase opens this." --encrypt --compress
OUTPUT      enc.png
FORMAT      image
PAYLOAD     31 bytes
ENVELOPE    105 bytes
ENCRYPTED   yes
COMPRESSED  yes
```

With the right passphrase it comes straight back:

```console
$ crypha reveal enc.png
Only the passphrase opens this.
revealed 31 bytes via image -> (stdout)
```

With the wrong one, it fails closed. The header is authenticated, so a bad key or a tampered byte fails to open rather than returning garbage:

```console
$ CRYPHA_PASSPHRASE="wrong" crypha reveal enc.png
crypha: decryption failed (wrong passphrase or tampered data)
$ echo $?
1
```

## JSON for scripts

Every command takes a global `--json`. `reveal --json` base64-encodes the payload so binary is safe to pipe:

```console
$ crypha hide --format image -i cover.png -o j.png -m "json demo" --json
{
  "format": "image",
  "payload_bytes": 9,
  "envelope_bytes": 23,
  "encrypted": false,
  "compressed": false,
  "output": "j.png"
}

$ crypha reveal j.png --json
{
  "format": "image",
  "bytes": 9,
  "encrypted": false,
  "data": "anNvbiBkZW1v"
}
```

## The interactive wizard

Run `crypha` with no arguments in a terminal and it launches the bubbletea wizard: pick an operation, choose a format, browse to a cover with the file picker, type your message or select a payload file, set the secure options, and watch a live capacity meter fill as it checks the fit before embedding. It is the same engine as the CLI, so anything above works there too, with nothing to memorize.

```bash
crypha
```
