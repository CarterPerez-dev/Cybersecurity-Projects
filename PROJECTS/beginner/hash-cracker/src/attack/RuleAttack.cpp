// ©AngelaMos | 2026
// RuleAttack.cpp

#include "src/attack/RuleAttack.hpp"

std::expected<RuleAttack, CrackError> RuleAttack::create(
    std::string_view, bool, unsigned, unsigned) {
    return std::unexpected(CrackError::FileNotFound);
}

std::expected<std::string, AttackComplete> RuleAttack::next() {
    return std::unexpected(AttackComplete{});
}

std::size_t RuleAttack::total() const { return 0; }
std::size_t RuleAttack::progress() const { return 0; }
