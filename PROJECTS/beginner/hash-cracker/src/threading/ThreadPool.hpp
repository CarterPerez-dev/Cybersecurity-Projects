/*
©AngelaMos | 2026
ThreadPool.hpp

Lightweight thread pool with shared atomic state for crack coordination

SharedState holds the found flag (atomic<bool>), tested_count (atomic
size_t), and the cracked plaintext behind a mutex. The cache-line
aligned atomics (alignas(64)) prevent false sharing between the hot
found flag and the counter. ThreadPool spawns jthreads that each call
the user's WorkFn with their thread ID, total thread count, and a
reference to SharedState.

Key exports:
  SharedState          - Shared atomic found flag, tested count, and result
  SharedState::set_result - Thread-safe first-writer-wins plaintext storage
  ThreadPool           - Spawns jthreads and joins on destruction
  ThreadPool::run      - Launches work across all threads
  ThreadPool::state    - Access to SharedState for result checking

Connects to:
  threading/ThreadPool.cpp - implementation of set_result, constructor, run
  core/Engine.hpp          - Engine::crack creates and runs the pool
*/

#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

struct SharedState {
    alignas(64) std::atomic<bool> found{false};
    alignas(64) std::atomic<std::size_t> tested_count{0};
    std::mutex result_mutex;
    std::optional<std::string> result;

    void set_result(std::string plaintext);
};

class ThreadPool {
public:
    using WorkFn = std::function<void(unsigned thread_id, unsigned total, SharedState&)>;

    explicit ThreadPool(unsigned thread_count);

    void run(WorkFn work);
    SharedState& state();

private:
    unsigned thread_count_;
    SharedState state_;
};
