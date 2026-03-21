// ©AngelaMos | 2026
// BruteForceAttack.hpp

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
    std::size_t total_ = 0;
    std::size_t current_ = 0;
};
