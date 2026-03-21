// ©AngelaMos | 2026
// HashDetector.cpp

#include "src/hash/HashDetector.hpp"

std::expected<HashType, CrackError> HashDetector::detect(std::string_view) {
    return std::unexpected(CrackError::InvalidHash);
}
