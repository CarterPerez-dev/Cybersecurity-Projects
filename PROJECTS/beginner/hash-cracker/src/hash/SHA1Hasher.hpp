// ©AngelaMos | 2026
// SHA1Hasher.hpp

#pragma once

#include <cstddef>
#include <string>
#include <string_view>

class SHA1Hasher {
public:
    std::string hash(std::string_view input) const;
    static constexpr std::string_view name() { return "SHA1"; }
    static constexpr std::size_t digest_length() { return 40; }
};
