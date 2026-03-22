// ©AngelaMos | 2026
// ThreadPool.cpp

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
