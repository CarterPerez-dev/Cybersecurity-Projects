// ©AngelaMos | 2026
// Concepts.hpp

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
