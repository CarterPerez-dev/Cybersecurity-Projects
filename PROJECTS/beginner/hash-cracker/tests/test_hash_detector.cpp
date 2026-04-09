/*
©AngelaMos | 2026
test_hash_detector.cpp

Tests for hash algorithm auto-detection by digest length

Verifies detection of MD5 (32 chars), SHA-1 (40), SHA-256 (64), and
SHA-512 (128) from real and synthetic hex strings. Confirms rejection
of invalid lengths and non-hex characters with CrackError::InvalidHash.

Connects to:
  hash/HashDetector.hpp - HashDetector::detect tested
  core/Concepts.hpp     - CrackError enum for error assertions
*/

#include <gtest/gtest.h>
#include "src/hash/HashDetector.hpp"

TEST(HashDetectorTest, DetectsMD5) {
    auto result = HashDetector::detect("d41d8cd98f00b204e9800998ecf8427e");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, HashType::MD5);
}

TEST(HashDetectorTest, DetectsSHA1) {
    auto result = HashDetector::detect("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, HashType::SHA1);
}

TEST(HashDetectorTest, DetectsSHA256) {
    auto result = HashDetector::detect(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, HashType::SHA256);
}

TEST(HashDetectorTest, DetectsSHA512) {
    auto result = HashDetector::detect(std::string(128, 'a'));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, HashType::SHA512);
}

TEST(HashDetectorTest, RejectsInvalidLength) {
    auto result = HashDetector::detect("abc");
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), CrackError::InvalidHash);
}

TEST(HashDetectorTest, RejectsNonHex) {
    auto result = HashDetector::detect(std::string(64, 'z'));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), CrackError::InvalidHash);
}
