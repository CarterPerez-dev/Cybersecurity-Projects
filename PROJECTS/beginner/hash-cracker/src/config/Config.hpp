// ©AngelaMos | 2026
// Config.hpp

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace config {

constexpr std::string_view VERSION = "1.0.0";
constexpr std::string_view APP_NAME = "HASHCRACKER";

constexpr unsigned DEFAULT_THREAD_COUNT = 0;
constexpr std::size_t DEFAULT_MAX_BRUTE_LENGTH = 6;
constexpr int PROGRESS_UPDATE_MS = 100;
constexpr std::size_t PROGRESS_BAR_MIN_WIDTH = 20;

constexpr std::string_view CHARSET_LOWER = "abcdefghijklmnopqrstuvwxyz";
constexpr std::string_view CHARSET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::string_view CHARSET_DIGITS = "0123456789";
constexpr std::string_view CHARSET_SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?/~`";

constexpr std::size_t MD5_HEX_LENGTH = 32;
constexpr std::size_t SHA1_HEX_LENGTH = 40;
constexpr std::size_t SHA256_HEX_LENGTH = 64;
constexpr std::size_t SHA512_HEX_LENGTH = 128;

constexpr std::size_t MAX_APPEND_DIGIT = 999;
constexpr std::size_t MAX_PREPEND_DIGIT = 999;

namespace color {

constexpr std::string_view RESET = "\033[0m";
constexpr std::string_view RED = "\033[31m";
constexpr std::string_view GREEN = "\033[32m";
constexpr std::string_view YELLOW = "\033[33m";
constexpr std::string_view CYAN = "\033[36m";
constexpr std::string_view BOLD = "\033[1m";
constexpr std::string_view DIM = "\033[2m";

}

namespace box {

constexpr std::string_view TOP_LEFT = "\u250C";
constexpr std::string_view TOP_RIGHT = "\u2510";
constexpr std::string_view BOTTOM_LEFT = "\u2514";
constexpr std::string_view BOTTOM_RIGHT = "\u2518";
constexpr std::string_view HORIZONTAL = "\u2500";
constexpr std::string_view VERTICAL = "\u2502";
constexpr std::string_view BLOCK_FULL = "\u2588";
constexpr std::string_view BLOCK_EMPTY = "\u2591";
constexpr std::string_view BAR_LEFT = "\u2590";
constexpr std::string_view BAR_RIGHT = "\u258C";

}

namespace icon {

constexpr std::string_view BOLT = "\u26A1";
constexpr std::string_view TIMER = "\u23F1";
constexpr std::string_view HOURGLASS = "\u23F3";
constexpr std::string_view CHART = "\U0001F4CA";
constexpr std::string_view CHECK = "\u2714";
constexpr std::string_view CROSS = "\u2716";

}

}

struct CrackConfig {
    std::string target_hash;
    std::string hash_type = "auto";
    std::string wordlist_path;
    std::string charset;
    std::string salt;
    std::string salt_position = "prepend";
    std::string output_path;
    std::size_t max_length = config::DEFAULT_MAX_BRUTE_LENGTH;
    unsigned thread_count = config::DEFAULT_THREAD_COUNT;
    bool bruteforce = false;
    bool use_rules = false;
    bool chain_rules = false;
};

struct CrackResult {
    std::string plaintext;
    std::string hash;
    std::string algorithm;
    double elapsed_seconds;
    std::size_t candidates_tested;
    double hashes_per_second;
};
