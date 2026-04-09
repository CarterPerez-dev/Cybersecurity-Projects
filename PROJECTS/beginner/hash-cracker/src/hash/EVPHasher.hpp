/*
©AngelaMos | 2026
EVPHasher.hpp

OpenSSL EVP-based hash implementation with tag dispatch and compile-time hex table

Uses the EVP high-level API so the same code path handles MD5, SHA-1,
SHA-256, and SHA-512 without per-algorithm boilerplate. Each algorithm is
identified by a tag struct (MD5Tag, SHA1Tag, SHA256Tag, SHA512Tag) that
provides the EVP_MD factory pointer, display name, and expected hex
length. EVPHasher<Tag> satisfies the Hasher concept from Concepts.hpp.
The HEX_TABLE constexpr lookup array converts raw digest bytes to hex
characters in a single indexed load per byte, avoiding the overhead of
std::format or snprintf in the hot path.

Key exports:
  EVPHasher<Tag>  - Template class satisfying the Hasher concept via OpenSSL EVP
  MD5Hasher       - Type alias for EVPHasher<MD5Tag>
  SHA1Hasher      - Type alias for EVPHasher<SHA1Tag>
  SHA256Hasher    - Type alias for EVPHasher<SHA256Tag>
  SHA512Hasher    - Type alias for EVPHasher<SHA512Tag>
  HEX_TABLE       - Compile-time byte-to-hex lookup array

Connects to:
  core/Concepts.hpp      - satisfies the Hasher concept
  core/Engine.hpp        - Engine::crack instantiates EVPHasher<Tag> per thread
  hash/MD5Hasher.hpp     - forwarding header that includes this file
  hash/SHA1Hasher.hpp    - forwarding header
  hash/SHA256Hasher.hpp  - forwarding header
  hash/SHA512Hasher.hpp  - forwarding header
*/

#pragma once

#include <array>
#include <cstddef>
#include <memory>
#include <openssl/evp.h>
#include <string>
#include <string_view>

namespace evp {

struct MD5Tag {
    static const EVP_MD* algorithm() { return EVP_md5(); }
    static constexpr std::string_view name = "MD5";
    static constexpr std::size_t hex_length = 32;
};

struct SHA1Tag {
    static const EVP_MD* algorithm() { return EVP_sha1(); }
    static constexpr std::string_view name = "SHA1";
    static constexpr std::size_t hex_length = 40;
};

struct SHA256Tag {
    static const EVP_MD* algorithm() { return EVP_sha256(); }
    static constexpr std::string_view name = "SHA256";
    static constexpr std::size_t hex_length = 64;
};

struct SHA512Tag {
    static const EVP_MD* algorithm() { return EVP_sha512(); }
    static constexpr std::string_view name = "SHA512";
    static constexpr std::size_t hex_length = 128;
};

}

inline constexpr std::array<std::array<char, 2>, 256> HEX_TABLE = [] {
    std::array<std::array<char, 2>, 256> t{};
    constexpr std::array<char, 17> digits = {
        '0','1','2','3','4','5','6','7',
        '8','9','a','b','c','d','e','f','\0'};
    for (std::size_t i = 0; i < 256; ++i) {
        t.at(i) = {digits.at(i >> 4), digits.at(i & 0xF)};
    }
    return t;
}();

template <typename Tag>
class EVPHasher {
public:
    std::string hash(std::string_view input) const {
        auto ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
            EVP_MD_CTX_new(), EVP_MD_CTX_free);

        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int len = 0;

        if (!ctx
            || !EVP_DigestInit_ex(ctx.get(), Tag::algorithm(), nullptr)
            || !EVP_DigestUpdate(ctx.get(), input.data(), input.size())
            || !EVP_DigestFinal_ex(ctx.get(), digest.data(), &len)) {
            return "";
        }

        std::string hex(static_cast<std::size_t>(len) * 2, '\0');
        for (std::size_t i = 0; i < len; ++i) {
            hex.at(i * 2)     = HEX_TABLE.at(digest.at(i)).at(0);
            hex.at(i * 2 + 1) = HEX_TABLE.at(digest.at(i)).at(1);
        }
        return hex;
    }

    static constexpr std::string_view name() { return Tag::name; }
    static constexpr std::size_t digest_length() { return Tag::hex_length; }
};

using MD5Hasher = EVPHasher<evp::MD5Tag>;
using SHA1Hasher = EVPHasher<evp::SHA1Tag>;
using SHA256Hasher = EVPHasher<evp::SHA256Tag>;
using SHA512Hasher = EVPHasher<evp::SHA512Tag>;
