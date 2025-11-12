# Base64 Encoder/Decoder with Detection

## Overview
Build a tool that encodes and decodes multiple encoding formats including Base64, Base32, hexadecimal, and URL encoding with automatic format detection. This project teaches data encoding principles, pattern recognition for format identification, and demonstrates practical utilities for working with encoded data in security testing and analysis.

## Step-by-Step Instructions

1. **Understand encoding standards and their purposes** by learning that encoding (not encryption) transforms data into alternate representations: Base64 uses 64 printable characters for binary-safe text transmission, Base32 uses 32 characters for environments with less character support, hexadecimal represents data as two-character pairs of hex digits, and URL encoding replaces special characters with %HH codes. Recognize that encoding is reversible and doesn't provide security unlike encryption, but enables data transmission through restricted channels.

2. **Implement Base64 encoding and decoding** using Python's built-in `base64` module, creating functions that accept input data and produce Base64-encoded output, and reverse the process to decode Base64 back to original data. Handle padding characters (=), test with various input types (text, binary, Unicode), and verify compatibility with standard Base64 specifications.

3. **Add Base32 encoding and decoding support** using similar approaches, recognizing that Base32 uses a different alphabet and produces longer output than Base64. Implement RFC 4648 compliant Base32 encoding/decoding, including support for both standard and hex alphabet variants used in different contexts.

4. **Implement hexadecimal conversion** allowing conversion between binary data and hex representation (where each byte is represented as two hex characters: 00-FF). Support both uppercase and lowercase hex output formats, and provide options for different hex display formats (no separators, space-separated, colon-separated for MAC addresses).

5. **Add URL encoding/decoding functionality** for handling special characters in URLs and form data, implementing percent-encoding where unsafe characters are converted to %HH codes. Support both form-encoding (application/x-www-form-urlencoded where spaces become +) and standard URL encoding (spaces become %20).

6. **Build automatic format detection** by analyzing input data and identifying which encoding format is likely used: look for Base64 patterns (A-Za-z0-9+/= characters in multiples of 4), Base32 patterns (A-Z2-7= characters), hexadecimal patterns (0-9A-Fa-f sequences), and URL encoding patterns (%XX sequences). Use heuristics and pattern matching to make educated guesses about format, displaying confidence levels and alternative possibilities.

7. **Create a multi-function CLI interface** accepting input as command-line arguments, from piped stdin, or from files, with options to specify encoding format, output format, and handling modes. Support batch processing of multiple values, interactive mode for real-time encoding/decoding, and pipeline-friendly output suitable for command chaining.

8. **Build comprehensive documentation** with examples of each encoding format showing input and output, explaining why different encodings exist and when each is used, and providing use cases in security contexts (Base64 in certificates and tokens, hex in binary analysis, URL encoding in web requests). Include common gotchas (padding issues, Unicode handling, case sensitivity) and provide examples of decoding real-world encoded data from security contexts.

## Key Concepts to Learn
- Data encoding standards and representations
- Pattern recognition and format detection
- Base64, Base32, hexadecimal, and URL encoding
- String manipulation and binary data handling
- Encoding for data transmission and storage
- CLI design for practical utilities

## Deliverables
- Base64 encoding and decoding
- Base32 support with RFC 4648 compliance
- Hexadecimal conversion functionality
- URL encoding/decoding with form variants
- Automatic format detection with confidence scoring
- Batch and interactive processing modes
