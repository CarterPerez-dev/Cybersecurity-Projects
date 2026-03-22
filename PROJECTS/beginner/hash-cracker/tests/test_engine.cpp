// ©AngelaMos | 2026
// test_engine.cpp

#include <gtest/gtest.h>
#include "src/core/Engine.hpp"
#include "src/hash/SHA256Hasher.hpp"

TEST(EngineTest, CracksSHA256WithDictionary) {
    CrackConfig cfg;
    cfg.target_hash =
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
    cfg.wordlist_path = "tests/data/small_wordlist.txt";
    cfg.thread_count = 2;

    auto result = Engine::crack<SHA256Hasher, DictionaryAttack>(cfg);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->plaintext, "password");
}

TEST(EngineTest, ReturnsExhaustedWhenNotFound) {
    CrackConfig cfg;
    cfg.target_hash = std::string(64, 'f');
    cfg.wordlist_path = "tests/data/small_wordlist.txt";
    cfg.thread_count = 1;

    auto result = Engine::crack<SHA256Hasher, DictionaryAttack>(cfg);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), CrackError::Exhausted);
}

TEST(EngineTest, CracksWithSalt) {
    SHA256Hasher hasher;
    auto salted_hash = hasher.hash("saltpassword");

    CrackConfig cfg;
    cfg.target_hash = salted_hash;
    cfg.wordlist_path = "tests/data/small_wordlist.txt";
    cfg.salt = "salt";
    cfg.salt_position = "prepend";
    cfg.thread_count = 1;

    auto result = Engine::crack<SHA256Hasher, DictionaryAttack>(cfg);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->plaintext, "password");
}
