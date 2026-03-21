// ©AngelaMos | 2026
// Progress.hpp

#pragma once

#include <atomic>
#include <cstddef>
#include <string>
#include <string_view>

struct CrackResult;

class Progress {
public:
    Progress(std::string_view algorithm, std::string_view attack_mode,
             unsigned thread_count, std::size_t total_candidates,
             const std::atomic<bool>& found,
             const std::atomic<std::size_t>& tested);

    void print_banner() const;
    void update();
    void print_cracked(const CrackResult& result) const;
    void print_exhausted(std::string_view hash, std::string_view algorithm) const;
    static bool is_tty();

private:
    std::string algorithm_;
    std::string attack_mode_;
    unsigned thread_count_;
    std::size_t total_;
    const std::atomic<bool>& found_;
    const std::atomic<std::size_t>& tested_;

    static std::size_t terminal_width();
    std::string render_bar(double fraction, std::size_t width) const;
    static std::string format_count(std::size_t n);
    static std::string format_time(double seconds);
    static std::string format_speed(double hps);
};
