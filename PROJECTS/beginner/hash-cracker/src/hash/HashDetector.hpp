// ©AngelaMos | 2026
// HashDetector.hpp

#pragma once

#include <expected>
#include <string_view>
#include "src/core/Concepts.hpp"

enum class HashType { MD5, SHA1, SHA256, SHA512 };

class HashDetector {
public:
    static std::expected<HashType, CrackError> detect(std::string_view hash);
};
