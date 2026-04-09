/*
©AngelaMos | 2026
HashDetector.cpp

Hash algorithm detection via hex character validation and length matching

Validates that every character in the input is hexadecimal, then switches
on the string length to identify the algorithm: 32 chars for MD5, 40 for
SHA-1, 64 for SHA-256, 128 for SHA-512. Returns CrackError::InvalidHash
for non-hex input or unrecognized lengths.

Key exports:
  HashDetector::detect - Returns HashType or CrackError based on hex length

Connects to:
  hash/HashDetector.hpp - class declaration and HashType enum
  config/Config.hpp     - MD5_HEX_LENGTH, SHA1_HEX_LENGTH, SHA256_HEX_LENGTH,
                           SHA512_HEX_LENGTH constants
  main.cpp              - called when --type=auto
*/

#include "src/hash/HashDetector.hpp"
#include "src/config/Config.hpp"
#include <algorithm>
#include <cctype>

std::expected<HashType, CrackError> HashDetector::detect(std::string_view hash) {
    auto is_hex = [](char c) {
        return (c >= '0' && c <= '9') ||
               (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    };

    if (!std::ranges::all_of(hash, is_hex)) {
        return std::unexpected(CrackError::InvalidHash);
    }

    switch (hash.size()) {
        case config::MD5_HEX_LENGTH: return HashType::MD5;
        case config::SHA1_HEX_LENGTH: return HashType::SHA1;
        case config::SHA256_HEX_LENGTH: return HashType::SHA256;
        case config::SHA512_HEX_LENGTH: return HashType::SHA512;
        default: return std::unexpected(CrackError::InvalidHash);
    }
}
