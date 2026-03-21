// ©AngelaMos | 2026
// DictionaryAttack.cpp

#include "src/attack/DictionaryAttack.hpp"

std::expected<DictionaryAttack, CrackError> DictionaryAttack::create(
    std::string_view, unsigned, unsigned) {
    return std::unexpected(CrackError::FileNotFound);
}

std::expected<std::string, AttackComplete> DictionaryAttack::next() {
    return std::unexpected(AttackComplete{});
}

std::size_t DictionaryAttack::total() const { return 0; }
std::size_t DictionaryAttack::progress() const { return 0; }
