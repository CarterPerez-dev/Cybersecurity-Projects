/*
©AngelaMos | 2026
Config.hpp

Application-wide constants and configuration structs

Defines every constant the tool references: character sets for brute-
force, hex digest lengths for hash detection, ANSI color codes for
terminal output, Unicode box-drawing and symbol characters for the
progress display, and numeric defaults (thread count, max brute-force
length, progress update interval). CrackConfig carries all user-facing
options from the CLI into the Engine. CrackResult holds the output of
a successful crack including plaintext, timing, and throughput stats.

Key exports:
  config::VERSION, APP_NAME      - Binary identity
  config::CHARSET_*              - Character sets for brute-force generation
  config::MD5_HEX_LENGTH et al.  - Expected hex digest lengths per algorithm
  config::color::*               - ANSI escape sequences
  config::box::*                 - Box-drawing Unicode characters
  config::symbol::*              - Status symbols (check, cross, arrow, etc.)
  CrackConfig                    - All runtime options for a crack session
  CrackResult                    - Output struct with plaintext and performance metrics

Connects to:
  main.cpp              - CrackConfig populated from CLI args, CrackResult written to JSON
  core/Engine.hpp       - reads CrackConfig, produces CrackResult
  hash/HashDetector.cpp - reads hex length constants for detection
  display/Progress.cpp  - reads color, box, symbol constants for rendering
  rules/RuleSet.cpp     - reads MAX_APPEND_DIGIT, MAX_PREPEND_DIGIT
*/

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

namespace symbol {

constexpr std::string_view ARROW = "\u2192";
constexpr std::string_view ARROW_RIGHT = "\u25B8";
constexpr std::string_view DIAMOND = "\u25C6";
constexpr std::string_view CHECK = "\u2713";
constexpr std::string_view CROSS = "\u2717";
constexpr std::string_view TIMER = "\u23F1";
constexpr std::string_view TRIANGLE_UP = "\u25B2";
constexpr std::string_view STAR = "\u2726";
constexpr std::string_view DIVIDER_CHAR = "\u2501";

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
