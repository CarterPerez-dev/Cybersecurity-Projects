/*
©AngelaMos | 2026
Concepts.hpp

C++20 concepts, error types, and contract definitions for the crack pipeline

Defines the two core concepts that Engine::crack is templated on: Hasher
(requires hash(string_view)->string, name()->string_view, digest_length()
->size_t) and AttackStrategy (requires next()->expected<string,
AttackComplete>, total()->size_t, progress()->size_t). CrackError is the
unified error enum propagated via std::expected throughout the tool.
AttackComplete is a sentinel type returned by attack strategies when
their candidate space is exhausted.

Key exports:
  Hasher          - Concept constraining hash algorithm implementations
  AttackStrategy  - Concept constraining candidate generators
  CrackError      - Error enum (FileNotFound, InvalidHash, Exhausted, etc.)
  AttackComplete  - Empty sentinel signaling end of candidate stream
  crack_error_message - Maps CrackError to human-readable string_view

Connects to:
  core/Engine.hpp           - Engine::crack<H, A> constrained by both concepts
  hash/EVPHasher.hpp        - EVPHasher satisfies the Hasher concept
  attack/BruteForceAttack.hpp - BruteForceAttack satisfies AttackStrategy
  attack/DictionaryAttack.hpp - DictionaryAttack satisfies AttackStrategy
  attack/RuleAttack.hpp       - RuleAttack satisfies AttackStrategy
  io/MappedFile.hpp           - returns CrackError on failure
  main.cpp                    - uses crack_error_message for error display
*/

#pragma once

#include <concepts>
#include <cstddef>
#include <expected>
#include <string>
#include <string_view>

struct AttackComplete {};

enum class CrackError {
    FileNotFound,
    InvalidHash,
    UnsupportedAlgorithm,
    OpenSSLError,
    InvalidConfig,
    Exhausted
};

constexpr std::string_view crack_error_message(CrackError e) {
    switch (e) {
        case CrackError::FileNotFound: return "File not found";
        case CrackError::InvalidHash: return "Invalid hash format";
        case CrackError::UnsupportedAlgorithm: return "Unsupported hash algorithm";
        case CrackError::OpenSSLError: return "OpenSSL internal error";
        case CrackError::InvalidConfig: return "Invalid configuration";
        case CrackError::Exhausted: return "All candidates exhausted";
    }
    return "Unknown error";
}

template <typename T>
concept Hasher = requires(T h, std::string_view input) {
    { h.hash(input) } -> std::same_as<std::string>;
    { T::name() } -> std::convertible_to<std::string_view>;
    { T::digest_length() } -> std::same_as<std::size_t>;
};

template <typename T>
concept AttackStrategy = requires(T a) {
    { a.next() } -> std::same_as<std::expected<std::string, AttackComplete>>;
    { a.total() } -> std::same_as<std::size_t>;
    { a.progress() } -> std::same_as<std::size_t>;
};
