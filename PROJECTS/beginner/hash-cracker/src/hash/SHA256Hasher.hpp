// ©AngelaMos | 2026
// SHA256Hasher.hpp

#pragma once

#include <cstddef>
#include <string>
#include <string_view>

class SHA256Hasher {
public:
    std::string hash(std::string_view input) const;
    static constexpr std::string_view name() { return "SHA256"; }
    static constexpr std::size_t digest_length() { return 64; }
};
