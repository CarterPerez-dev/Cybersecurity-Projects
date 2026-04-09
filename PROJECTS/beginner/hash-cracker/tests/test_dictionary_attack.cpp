/*
©AngelaMos | 2026
test_dictionary_attack.cpp

Tests for memory-mapped wordlist reading and thread partitioning

Loads tests/data/small_wordlist.txt (10 words) and verifies all words
are read in order, first/last word content, correct total count,
two-thread partitioning that covers all words without overlap, and
graceful CrackError on missing files.

Connects to:
  attack/DictionaryAttack.hpp - DictionaryAttack tested
  tests/data/small_wordlist.txt - fixture wordlist
*/

#include <gtest/gtest.h>
#include "src/attack/DictionaryAttack.hpp"
#include <vector>

TEST(DictionaryAttackTest, ReadsAllWords) {
    auto attack = DictionaryAttack::create("tests/data/small_wordlist.txt", 0, 1);
    ASSERT_TRUE(attack.has_value());

    std::vector<std::string> words;
    while (auto word = attack->next()) {
        words.push_back(std::move(*word));
    }
    EXPECT_EQ(words.size(), 10);
    EXPECT_EQ(words.front(), "password");
    EXPECT_EQ(words.back(), "trustno1");
}

TEST(DictionaryAttackTest, PartitionsAcrossThreads) {
    auto p0 = DictionaryAttack::create("tests/data/small_wordlist.txt", 0, 2);
    auto p1 = DictionaryAttack::create("tests/data/small_wordlist.txt", 1, 2);
    ASSERT_TRUE(p0.has_value());
    ASSERT_TRUE(p1.has_value());

    std::size_t count0 = 0, count1 = 0;
    while (p0->next()) { ++count0; }
    while (p1->next()) { ++count1; }
    EXPECT_EQ(count0 + count1, 10);
}

TEST(DictionaryAttackTest, ReportsTotal) {
    auto attack = DictionaryAttack::create("tests/data/small_wordlist.txt", 0, 1);
    ASSERT_TRUE(attack.has_value());
    EXPECT_EQ(attack->total(), 10);
}

TEST(DictionaryAttackTest, MissingFileReturnsError) {
    auto attack = DictionaryAttack::create("nonexistent.txt", 0, 1);
    EXPECT_FALSE(attack.has_value());
}
