// ©AngelaMos | 2026
// DictionaryAttack.hpp

#pragma once

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include "src/core/Concepts.hpp"

class DictionaryAttack {
public:
    static std::expected<DictionaryAttack, CrackError> create(
        std::string_view path, unsigned thread_index, unsigned total_threads);

    std::expected<std::string, AttackComplete> next();
    std::size_t total() const;
    std::size_t progress() const;

private:
    DictionaryAttack() = default;
};
