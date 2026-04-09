/*
©AngelaMos | 2026
BruteForceAttack.hpp

Exhaustive keyspace enumeration with thread-partitioned ranges

Connects to:
  attack/BruteForceAttack.cpp - implementation of next(), index_to_candidate
  core/Concepts.hpp           - satisfies AttackStrategy concept, uses AttackComplete
  core/Engine.hpp             - instantiated when cfg.bruteforce is true
*/

#pragma once

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include "src/core/Concepts.hpp"

class BruteForceAttack {
public:
    BruteForceAttack(std::string_view charset, std::size_t max_length,
                     unsigned thread_index, unsigned total_threads);

    std::expected<std::string, AttackComplete> next();
    std::size_t total() const;
    std::size_t progress() const;

private:
    std::string charset_;
    std::size_t max_length_;
    std::size_t total_keyspace_;
    std::size_t start_index_;
    std::size_t end_index_;
    std::size_t current_index_;

    std::string index_to_candidate(std::size_t index) const;
    static std::size_t compute_keyspace(std::size_t charset_size,
                                        std::size_t max_length);
};
