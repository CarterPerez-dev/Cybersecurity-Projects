/*
©AngelaMos | 2026
main.cpp

CLI entry point with hash type dispatch and attack mode selection

Parses command-line arguments via boost::program_options for hash target,
algorithm (md5/sha1/sha256/sha512/auto), attack mode (dictionary, brute-
force, or rule-based), charset selection, salt, thread count, and JSON
output. build_charset assembles a character set from comma-separated
tokens (lower, upper, digits, special). dispatch_hasher selects the
concrete EVPHasher instantiation at runtime via a switch on HashType,
then dispatch_attack picks the attack strategy (BruteForceAttack,
RuleAttack, or DictionaryAttack) based on config flags. When auto-
detection is requested, HashDetector identifies the algorithm from hex
digest length.

Key exports:
  main - Entry point, returns 0 on crack success, 1 on failure or exhaustion

Connects to:
  config/Config.hpp         - CrackConfig, CrackResult, charset constants, defaults
  core/Concepts.hpp         - CrackError enum for error propagation
  core/Engine.hpp           - Engine::crack<H, A> template drives the crack session
  hash/HashDetector.hpp     - HashDetector::detect for auto-detection
  hash/MD5Hasher.hpp et al. - Concrete hasher types for dispatch
  attack/BruteForceAttack.hpp - BruteForceAttack for exhaustive mode
  attack/DictionaryAttack.hpp - DictionaryAttack for wordlist mode
  attack/RuleAttack.hpp       - RuleAttack for mutation mode
*/

#include <boost/program_options.hpp>
#include <expected>
#include <iostream>
#include <print>
#include <string>
#include "src/attack/BruteForceAttack.hpp"
#include "src/attack/DictionaryAttack.hpp"
#include "src/attack/RuleAttack.hpp"
#include "src/config/Config.hpp"
#include "src/core/Concepts.hpp"
#include "src/core/Engine.hpp"
#include "src/hash/HashDetector.hpp"
#include "src/hash/MD5Hasher.hpp"
#include "src/hash/SHA1Hasher.hpp"
#include "src/hash/SHA256Hasher.hpp"
#include "src/hash/SHA512Hasher.hpp"

namespace po = boost::program_options;

static std::string build_charset(const std::string& spec) {
    std::string result;

    auto has = [&](std::string_view token) {
        return spec.find(token) != std::string::npos;
    };

    if (has("lower")) { result += config::CHARSET_LOWER; }
    if (has("upper")) { result += config::CHARSET_UPPER; }
    if (has("digits")) { result += config::CHARSET_DIGITS; }
    if (has("special")) { result += config::CHARSET_SPECIAL; }

    if (result.empty()) {
        result += config::CHARSET_LOWER;
        result += config::CHARSET_DIGITS;
    }

    return result;
}

template <Hasher H>
static auto dispatch_attack(const CrackConfig& cfg)
    -> std::expected<CrackResult, CrackError> {
    if (cfg.bruteforce) {
        return Engine::crack<H, BruteForceAttack>(cfg);
    }
    if (cfg.use_rules) {
        return Engine::crack<H, RuleAttack>(cfg);
    }
    return Engine::crack<H, DictionaryAttack>(cfg);
}

static auto dispatch_hasher(HashType type, const CrackConfig& cfg)
    -> std::expected<CrackResult, CrackError> {
    switch (type) {
        case HashType::MD5: return dispatch_attack<MD5Hasher>(cfg);
        case HashType::SHA1: return dispatch_attack<SHA1Hasher>(cfg);
        case HashType::SHA256: return dispatch_attack<SHA256Hasher>(cfg);
        case HashType::SHA512: return dispatch_attack<SHA512Hasher>(cfg);
    }
    return std::unexpected(CrackError::UnsupportedAlgorithm);
}

static std::string json_escape(std::string_view s) {
    std::string result;
    result.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n";  break;
            case '\r': result += "\\r";  break;
            case '\t': result += "\\t";  break;
            default:   result += c;      break;
        }
    }
    return result;
}

static void write_json_result(const std::string& path,
                               const CrackResult& result) {
    auto* f = std::fopen(path.c_str(), "w");
    if (!f) { return; }

    std::fprintf(f,
        "{\n"
        "  \"plaintext\": \"%s\",\n"
        "  \"hash\": \"%s\",\n"
        "  \"algorithm\": \"%s\",\n"
        "  \"elapsed_seconds\": %.4f,\n"
        "  \"candidates_tested\": %zu,\n"
        "  \"hashes_per_second\": %.2f\n"
        "}\n",
        json_escape(result.plaintext).c_str(),
        json_escape(result.hash).c_str(),
        json_escape(result.algorithm).c_str(),
        result.elapsed_seconds,
        result.candidates_tested,
        result.hashes_per_second);

    std::fclose(f);
}

int main(int argc, char* argv[]) {
    po::options_description desc("hashcracker - Multi-threaded hash cracking tool");
    desc.add_options()
        ("help,h", "Show help message")
        ("hash", po::value<std::string>(), "Target hash to crack")
        ("type", po::value<std::string>()->default_value("auto"),
            "Hash type: md5, sha1, sha256, sha512, auto")
        ("wordlist,w", po::value<std::string>(), "Path to wordlist file")
        ("bruteforce,b", "Use brute-force attack mode")
        ("charset", po::value<std::string>()->default_value("lower,digits"),
            "Character sets: lower,upper,digits,special")
        ("max-length", po::value<std::size_t>()->default_value(
            config::DEFAULT_MAX_BRUTE_LENGTH), "Max password length for brute-force")
        ("rules,r", "Apply mutation rules to dictionary words")
        ("chain-rules", "Chain mutation rules in combination")
        ("salt", po::value<std::string>(), "Salt value to prepend/append")
        ("salt-position", po::value<std::string>()->default_value("prepend"),
            "Salt position: prepend or append")
        ("threads,t", po::value<unsigned>()->default_value(
            config::DEFAULT_THREAD_COUNT), "Thread count (0 = auto)")
        ("output,o", po::value<std::string>(), "Write JSON result to file");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (const po::error& e) {
        std::println(stderr, "Error: {}", e.what());
        return 1;
    }

    if (vm.count("help") || !vm.count("hash")) {
        std::cout << desc << std::endl;
        return vm.count("help") ? 0 : 1;
    }

    CrackConfig cfg;
    cfg.target_hash = vm["hash"].as<std::string>();
    cfg.hash_type = vm["type"].as<std::string>();
    cfg.thread_count = vm["threads"].as<unsigned>();
    cfg.bruteforce = vm.count("bruteforce") > 0;
    cfg.use_rules = vm.count("rules") > 0;
    cfg.chain_rules = vm.count("chain-rules") > 0;
    cfg.max_length = vm["max-length"].as<std::size_t>();

    if (vm.count("wordlist")) {
        cfg.wordlist_path = vm["wordlist"].as<std::string>();
    }
    if (vm.count("salt")) {
        cfg.salt = vm["salt"].as<std::string>();
    }
    cfg.salt_position = vm["salt-position"].as<std::string>();
    if (vm.count("output")) {
        cfg.output_path = vm["output"].as<std::string>();
    }

    if (cfg.bruteforce) {
        cfg.charset = build_charset(vm["charset"].as<std::string>());
    } else if (cfg.wordlist_path.empty()) {
        std::println(stderr, "Error: --wordlist required for dictionary/rule attacks");
        return 1;
    }

    HashType hash_type;
    if (cfg.hash_type == "auto") {
        auto detected = HashDetector::detect(cfg.target_hash);
        if (!detected.has_value()) {
            std::println(stderr, "Error: {}",
                crack_error_message(detected.error()));
            return 1;
        }
        hash_type = *detected;
    } else if (cfg.hash_type == "md5") {
        hash_type = HashType::MD5;
    } else if (cfg.hash_type == "sha1") {
        hash_type = HashType::SHA1;
    } else if (cfg.hash_type == "sha256") {
        hash_type = HashType::SHA256;
    } else if (cfg.hash_type == "sha512") {
        hash_type = HashType::SHA512;
    } else {
        std::println(stderr, "Error: Unknown hash type '{}'", cfg.hash_type);
        return 1;
    }

    auto result = dispatch_hasher(hash_type, cfg);

    if (result.has_value() && !cfg.output_path.empty()) {
        write_json_result(cfg.output_path, *result);
    }

    return result.has_value() ? 0 : 1;
}
