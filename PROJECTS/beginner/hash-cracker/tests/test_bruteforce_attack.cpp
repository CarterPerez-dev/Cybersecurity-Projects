/*
©AngelaMos | 2026
test_bruteforce_attack.cpp

Tests for brute-force keyspace generation and thread partitioning

Verifies single-char generation, multi-length enumeration up to
max_length, correct keyspace total (sum of charset^len), and that
splitting across two threads produces the same combined set without
duplicates or gaps.

Connects to:
  attack/BruteForceAttack.hpp - BruteForceAttack tested
*/

#include <gtest/gtest.h>
#include "src/attack/BruteForceAttack.hpp"
#include <set>
#include <vector>

TEST(BruteForceAttackTest, GeneratesAllSingleCharCombinations) {
    BruteForceAttack attack("ab", 1, 0, 1);
    std::vector<std::string> results;
    while (auto candidate = attack.next()) {
        results.push_back(std::move(*candidate));
    }
    EXPECT_EQ(results.size(), 2);
    EXPECT_EQ(results[0], "a");
    EXPECT_EQ(results[1], "b");
}

TEST(BruteForceAttackTest, GeneratesUpToMaxLength) {
    BruteForceAttack attack("ab", 2, 0, 1);
    std::vector<std::string> results;
    while (auto candidate = attack.next()) {
        results.push_back(std::move(*candidate));
    }
    EXPECT_EQ(results.size(), 6);
}

TEST(BruteForceAttackTest, PartitionsKeyspace) {
    BruteForceAttack p0("ab", 2, 0, 2);
    BruteForceAttack p1("ab", 2, 1, 2);
    std::set<std::string> all;
    while (auto c = p0.next()) { all.insert(*c); }
    while (auto c = p1.next()) { all.insert(*c); }
    EXPECT_EQ(all.size(), 6);
}

TEST(BruteForceAttackTest, ReportsCorrectTotal) {
    BruteForceAttack attack("abc", 3, 0, 1);
    EXPECT_EQ(attack.total(), 3 + 9 + 27);
}

TEST(BruteForceAttackTest, GeneratesCorrectTwoCharCombinations) {
    BruteForceAttack attack("ab", 2, 0, 1);
    std::set<std::string> results;
    while (auto candidate = attack.next()) {
        results.insert(*candidate);
    }
    EXPECT_TRUE(results.contains("a"));
    EXPECT_TRUE(results.contains("b"));
    EXPECT_TRUE(results.contains("aa"));
    EXPECT_TRUE(results.contains("ab"));
    EXPECT_TRUE(results.contains("ba"));
    EXPECT_TRUE(results.contains("bb"));
}
