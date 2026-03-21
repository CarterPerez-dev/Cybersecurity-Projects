// ©AngelaMos | 2026
// BruteForceAttack.cpp

#include "src/attack/BruteForceAttack.hpp"

BruteForceAttack::BruteForceAttack(std::string_view, std::size_t,
                                   unsigned, unsigned) {}

std::expected<std::string, AttackComplete> BruteForceAttack::next() {
    return std::unexpected(AttackComplete{});
}

std::size_t BruteForceAttack::total() const { return total_; }
std::size_t BruteForceAttack::progress() const { return current_; }
