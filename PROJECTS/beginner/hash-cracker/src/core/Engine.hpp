/*
©AngelaMos | 2026
Engine.hpp

Template-driven crack engine orchestrating threads, attacks, and progress

Engine::crack<H, A> is the single function that runs an entire crack
session. It creates a ThreadPool, spawns one attack instance per thread
(each partitioned to a disjoint slice of the keyspace or wordlist), and
runs a background jthread for progress display updates. Each worker
thread hashes candidates through the Hasher H, prepending or appending
salt if configured, and checks against the target hash. The first match
sets SharedState::found atomically and stores the plaintext. Candidate
counts are flushed from thread-local accumulators to the shared atomic
counter every 1024 iterations to reduce contention. Returns a CrackResult
on success or CrackError::Exhausted when all candidates are spent.

Key exports:
  Engine::crack<H, A> - Runs a full crack session for Hasher H and AttackStrategy A

Connects to:
  config/Config.hpp           - reads CrackConfig options, produces CrackResult
  core/Concepts.hpp           - Hasher and AttackStrategy concept constraints
  threading/ThreadPool.hpp    - ThreadPool for parallel worker dispatch
  display/Progress.hpp        - Progress for live terminal feedback
  attack/BruteForceAttack.hpp - instantiated when A = BruteForceAttack
  attack/DictionaryAttack.hpp - instantiated when A = DictionaryAttack
  attack/RuleAttack.hpp       - instantiated when A = RuleAttack
  main.cpp                    - called from dispatch_attack
*/

#pragma once

#include <chrono>
#include <cstdio>
#include <expected>
#include <string>
#include <thread>
#include "src/attack/BruteForceAttack.hpp"
#include "src/attack/DictionaryAttack.hpp"
#include "src/attack/RuleAttack.hpp"
#include "src/config/Config.hpp"
#include "src/core/Concepts.hpp"
#include "src/display/Progress.hpp"
#include "src/threading/ThreadPool.hpp"

class Engine {
public:
    template <Hasher H, AttackStrategy A>
    static auto crack(const CrackConfig& cfg)
        -> std::expected<CrackResult, CrackError>;
};

template <Hasher H, AttackStrategy A>
auto Engine::crack(const CrackConfig& cfg)
    -> std::expected<CrackResult, CrackError> {
    unsigned thread_count = cfg.thread_count > 0
        ? cfg.thread_count
        : std::thread::hardware_concurrency();

    ThreadPool pool(thread_count);

    auto attack_name = [&]() -> std::string_view {
        if (cfg.bruteforce) { return "Brute Force"; }
        if (cfg.use_rules) { return "Rules"; }
        return "Dictionary";
    }();

    auto total_estimate = [&]() -> std::size_t {
        if constexpr (std::same_as<A, BruteForceAttack>) {
            BruteForceAttack probe(cfg.charset, cfg.max_length, 0, 1);
            return probe.total();
        } else if constexpr (std::same_as<A, RuleAttack>) {
            auto probe = DictionaryAttack::create(cfg.wordlist_path, 0, 1);
            if (!probe) { return 0; }
            return probe->total() * 2005;
        } else {
            auto probe = DictionaryAttack::create(cfg.wordlist_path, 0, 1);
            if (!probe) { return 0; }
            return probe->total();
        }
    }();

    Progress progress(H::name(), attack_name, thread_count,
                      total_estimate, pool.state().found,
                      pool.state().tested_count);

    if (Progress::is_tty()) {
        progress.print_banner();
        std::puts("");
        std::puts("");
        std::puts("");
    }

    auto start = std::chrono::steady_clock::now();

    std::jthread display_thread;
    if (Progress::is_tty()) {
        display_thread = std::jthread([&](std::stop_token st) {
            while (!st.stop_requested() &&
                   !pool.state().found.load(std::memory_order_relaxed)) {
                progress.update();
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(config::PROGRESS_UPDATE_MS));
            }
        });
    }

    pool.run([&](unsigned tid, unsigned total, SharedState& state) {
        H hasher;

        auto create_attack = [&]() {
            if constexpr (std::same_as<A, BruteForceAttack>) {
                return std::expected<BruteForceAttack, CrackError>(
                    BruteForceAttack(cfg.charset, cfg.max_length, tid, total));
            } else if constexpr (std::same_as<A, RuleAttack>) {
                return RuleAttack::create(
                    cfg.wordlist_path, cfg.chain_rules, tid, total);
            } else {
                return DictionaryAttack::create(cfg.wordlist_path, tid, total);
            }
        };

        auto attack = create_attack();
        if (!attack.has_value()) { return; }

        std::size_t local_count = 0;
        while (!state.found.load(std::memory_order_relaxed)) {
            auto candidate = attack->next();
            if (!candidate.has_value()) { break; }

            std::string to_hash = *candidate;
            if (!cfg.salt.empty()) {
                if (cfg.salt_position == "prepend") {
                    to_hash = cfg.salt + to_hash;
                } else {
                    to_hash = to_hash + cfg.salt;
                }
            }

            if (hasher.hash(to_hash) == cfg.target_hash) {
                state.tested_count.fetch_add(local_count, std::memory_order_relaxed);
                state.set_result(std::move(*candidate));
                break;
            }

            ++local_count;
            if ((local_count & 0x3FF) == 0) {
                state.tested_count.fetch_add(local_count, std::memory_order_relaxed);
                local_count = 0;
            }
        }
        state.tested_count.fetch_add(local_count, std::memory_order_relaxed);
    });

    if (display_thread.joinable()) {
        display_thread.request_stop();
        display_thread.join();
    }

    auto end = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();
    auto tested = pool.state().tested_count.load(std::memory_order_relaxed);
    double speed = (elapsed > 0.0) ? static_cast<double>(tested) / elapsed : 0.0;

    auto& state = pool.state();
    if (state.found.load(std::memory_order_relaxed) && state.result.has_value()) {
        CrackResult result{
            .plaintext = *state.result,
            .hash = cfg.target_hash,
            .algorithm = std::string(H::name()),
            .elapsed_seconds = elapsed,
            .candidates_tested = tested,
            .hashes_per_second = speed
        };

        progress.print_cracked(result);
        return result;
    }

    progress.print_exhausted(cfg.target_hash, H::name());
    return std::unexpected(CrackError::Exhausted);
}
