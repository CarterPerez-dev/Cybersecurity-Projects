// ©AngelaMos | 2026
// MD5Hasher.hpp

#pragma once

#include <cstddef>
#include <string>
#include <string_view>

class MD5Hasher {
public:
    std::string hash(std::string_view input) const;
    static constexpr std::string_view name() { return "MD5"; }
    static constexpr std::size_t digest_length() { return 32; }
};
