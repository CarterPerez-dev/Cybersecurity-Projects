// ©AngelaMos | 2026
// ThreadPool.hpp

#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

struct SharedState {
    std::atomic<bool> found{false};
    std::atomic<std::size_t> tested_count{0};
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
