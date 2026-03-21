// ©AngelaMos | 2026
// RuleAttack.hpp

#pragma once

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include "src/core/Concepts.hpp"

class RuleAttack {
public:
    static std::expected<RuleAttack, CrackError> create(
        std::string_view path, bool chain_rules,
        unsigned thread_index, unsigned total_threads);

    std::expected<std::string, AttackComplete> next();
    std::size_t total() const;
    std::size_t progress() const;

private:
    RuleAttack() = default;
};
