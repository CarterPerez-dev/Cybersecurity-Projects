/*
©AngelaMos | 2026
HashDetector.hpp

Hash algorithm auto-detection by hex digest length

Connects to:
  hash/HashDetector.cpp - implementation of detect()
  core/Concepts.hpp     - CrackError for invalid/unsupported hash errors
  main.cpp              - called when --type=auto (the default)
*/

#pragma once

#include <expected>
#include <string_view>
#include "src/core/Concepts.hpp"

enum class HashType { MD5, SHA1, SHA256, SHA512 };

class HashDetector {
public:
    static std::expected<HashType, CrackError> detect(std::string_view hash);
};
