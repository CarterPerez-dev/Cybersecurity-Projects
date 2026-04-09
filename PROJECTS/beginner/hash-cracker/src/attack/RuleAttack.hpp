/*
©AngelaMos | 2026
RuleAttack.hpp

Dictionary attack augmented with password mutation rules

Wraps a DictionaryAttack and applies RuleSet mutations to each word.
When chain_rules is enabled, mutations of mutations are also generated,
greatly expanding the candidate space.

Connects to:
  attack/RuleAttack.cpp       - implementation of create(), next(), load_next_word()
  attack/DictionaryAttack.hpp - DictionaryAttack used internally for word iteration
  core/Concepts.hpp           - satisfies AttackStrategy concept
  core/Engine.hpp             - instantiated when cfg.use_rules is true
*/

#pragma once

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <vector>
#include "src/attack/DictionaryAttack.hpp"
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
    RuleAttack(DictionaryAttack dict, bool chain_rules);

    DictionaryAttack dict_;
    bool chain_rules_;
    std::vector<std::string> mutations_;
    std::size_t mutation_index_ = 0;
    std::size_t candidates_yielded_ = 0;

    bool load_next_word();
};
