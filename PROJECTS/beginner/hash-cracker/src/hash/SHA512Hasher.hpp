// ©AngelaMos | 2026
// SHA512Hasher.hpp

#pragma once

#include <cstddef>
#include <string>
#include <string_view>

class SHA512Hasher {
public:
    std::string hash(std::string_view input) const;
    static constexpr std::string_view name() { return "SHA512"; }
    static constexpr std::size_t digest_length() { return 128; }
};
