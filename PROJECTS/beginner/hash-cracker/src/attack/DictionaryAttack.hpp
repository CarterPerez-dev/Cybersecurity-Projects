/*
©AngelaMos | 2026
DictionaryAttack.hpp

Memory-mapped wordlist attack with line-based thread partitioning

Connects to:
  attack/DictionaryAttack.cpp - implementation of create(), next()
  io/MappedFile.hpp           - MappedFile for zero-copy file access
  core/Concepts.hpp           - satisfies AttackStrategy concept
  core/Engine.hpp             - default attack when no flags set
  attack/RuleAttack.hpp       - RuleAttack wraps DictionaryAttack internally
*/

#pragma once

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include "src/core/Concepts.hpp"
#include "src/io/MappedFile.hpp"

class DictionaryAttack {
public:
    static std::expected<DictionaryAttack, CrackError> create(
        std::string_view path, unsigned thread_index, unsigned total_threads);

    std::expected<std::string, AttackComplete> next();
    std::size_t total() const;
    std::size_t progress() const;

private:
    DictionaryAttack() = default;

    MappedFile file_;

    std::size_t start_offset_ = 0;
    std::size_t end_offset_ = 0;
    std::size_t current_offset_ = 0;

    std::size_t total_words_ = 0;
    std::size_t words_read_ = 0;
};
