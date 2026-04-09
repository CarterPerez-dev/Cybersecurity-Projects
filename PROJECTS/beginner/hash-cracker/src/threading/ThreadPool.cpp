/*
©AngelaMos | 2026
ThreadPool.cpp

Thread pool and shared state implementation

set_result uses a relaxed store on the found flag for speed (all readers
also use relaxed loads) and a mutex guard for the result string to
prevent races when multiple threads find the answer simultaneously; only
the first write wins. The constructor resolves thread_count 0 to
hardware_concurrency. run() spawns jthreads in a vector; they auto-join
on destruction when the vector goes out of scope.

Connects to:
  threading/ThreadPool.hpp - class declarations
  core/Engine.hpp          - Engine::crack calls run() with a lambda
*/

#include "src/threading/ThreadPool.hpp"

void SharedState::set_result(std::string plaintext) {
    found.store(true, std::memory_order_relaxed);
    auto lock = std::lock_guard{result_mutex};
    if (!result.has_value()) {
        result = std::move(plaintext);
    }
}

ThreadPool::ThreadPool(unsigned thread_count)
    : thread_count_(thread_count > 0 ? thread_count
                                     : std::thread::hardware_concurrency()) {}

void ThreadPool::run(WorkFn work) {
    std::vector<std::jthread> threads;
    threads.reserve(thread_count_);

    for (unsigned i = 0; i < thread_count_; ++i) {
        threads.emplace_back([this, &work, i] {
            work(i, thread_count_, state_);
        });
    }
}

SharedState& ThreadPool::state() { return state_; }
