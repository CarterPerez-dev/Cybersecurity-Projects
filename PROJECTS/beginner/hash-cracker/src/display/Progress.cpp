/*
©AngelaMos | 2026
Progress.cpp

ANSI terminal progress bar with speed, ETA, and result formatting

print_banner draws a Unicode box with algorithm, attack mode, and thread
count. update() runs in a background jthread and uses ANSI escape
sequences (\033[3A) to overwrite the previous three lines with an
updated progress bar, hash speed, elapsed time, ETA, and candidate
count. render_bar builds a filled/empty block character bar scaled to
terminal width (queried via ioctl TIOCGWINSZ). format_count humanizes
large numbers (K/M/B suffixes). print_cracked clears the progress area
and shows the cracked password with green highlight. print_exhausted
shows the red failure state. All output is suppressed when stdout is not
a TTY, falling back to a single-line plaintext result.

Key exports:
  Progress::print_banner    - Draw boxed header on session start
  Progress::update          - Refresh progress bar (called from jthread loop)
  Progress::print_cracked   - Display success result
  Progress::print_exhausted - Display exhaustion result
  Progress::is_tty          - Check if stdout is a terminal

Connects to:
  display/Progress.hpp - class declaration
  config/Config.hpp    - color, box, symbol constants, PROGRESS_BAR_MIN_WIDTH
  core/Engine.hpp      - constructs Progress, spawns update jthread, calls print_*
*/

#include "src/display/Progress.hpp"
#include "src/config/Config.hpp"
#include <chrono>
#include <print>
#include <sys/ioctl.h>
#include <unistd.h>

Progress::Progress(std::string_view algorithm, std::string_view attack_mode,
                   unsigned thread_count, std::size_t total_candidates,
                   const std::atomic<bool>& found,
                   const std::atomic<std::size_t>& tested)
    : algorithm_(algorithm), attack_mode_(attack_mode),
      thread_count_(thread_count), total_(total_candidates),
      found_(found), tested_(tested),
      start_time_(std::chrono::steady_clock::now()) {}

bool Progress::is_tty() {
    return isatty(STDOUT_FILENO) != 0;
}

std::size_t Progress::terminal_width() {
    struct winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        return ws.ws_col;
    }
    return 80;
}

std::string Progress::format_count(std::size_t n) {
    if (n >= 1'000'000'000) {
        return std::format("{:.1f}B", static_cast<double>(n) / 1'000'000'000.0);
    }
    if (n >= 1'000'000) {
        return std::format("{:.1f}M", static_cast<double>(n) / 1'000'000.0);
    }
    if (n >= 1'000) {
        return std::format("{:.1f}K", static_cast<double>(n) / 1'000.0);
    }
    return std::format("{}", n);
}

std::string Progress::format_time(double seconds) {
    auto mins = static_cast<int>(seconds) / 60;
    auto secs = seconds - static_cast<double>(mins * 60);
    return std::format("{:02d}:{:05.2f}", mins, secs);
}

std::string Progress::format_speed(double hps) {
    return format_count(static_cast<std::size_t>(hps)) + " h/s";
}

std::string Progress::render_bar(double fraction, std::size_t width) const {
    if (width < config::PROGRESS_BAR_MIN_WIDTH) {
        width = config::PROGRESS_BAR_MIN_WIDTH;
    }

    auto filled = static_cast<std::size_t>(fraction * static_cast<double>(width));
    if (filled > width) { filled = width; }

    std::string bar;
    bar += config::box::BAR_LEFT;
    for (std::size_t i = 0; i < width; ++i) {
        bar += (i < filled) ? config::box::BLOCK_FULL : config::box::BLOCK_EMPTY;
    }
    bar += config::box::BAR_RIGHT;
    return bar;
}

void Progress::print_banner() const {
    if (!is_tty()) { return; }

    auto w = terminal_width();
    auto inner_width = (w > 6) ? w - 6 : 40;

    std::string top_border(inner_width, '\0');
    std::string bot_border(inner_width, '\0');
    top_border.clear();
    bot_border.clear();
    for (std::size_t i = 0; i < inner_width; ++i) {
        top_border += config::box::HORIZONTAL;
        bot_border += config::box::HORIZONTAL;
    }

    auto line1 = std::format("  {}  {}  v{}",
        config::APP_NAME, config::box::VERTICAL, config::VERSION);
    auto line2 = std::format("  {} {} {} {} {} threads",
        config::box::VERTICAL, algorithm_, config::box::VERTICAL,
        attack_mode_, thread_count_);

    std::println("{}{}{}{}{}",
        config::color::CYAN, config::box::TOP_LEFT,
        top_border, config::box::TOP_RIGHT, config::color::RESET);
    std::println("{}{} {:<{}}{}{}", config::color::CYAN,
        config::box::VERTICAL, line1, inner_width - 1,
        config::box::VERTICAL, config::color::RESET);
    std::println("{}{} {:<{}}{}{}", config::color::CYAN,
        config::box::VERTICAL, line2, inner_width - 1,
        config::box::VERTICAL, config::color::RESET);
    std::println("{}{}{}{}{}",
        config::color::CYAN, config::box::BOTTOM_LEFT,
        bot_border, config::box::BOTTOM_RIGHT, config::color::RESET);
    std::println("");
}

void Progress::update() {
    if (!is_tty()) { return; }

    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - start_time_).count();
    auto tested_val = tested_.load(std::memory_order_relaxed);

    double fraction = (total_ > 0)
        ? static_cast<double>(tested_val) / static_cast<double>(total_)
        : 0.0;
    if (fraction > 1.0) { fraction = 1.0; }

    double speed = (elapsed > 0.0)
        ? static_cast<double>(tested_val) / elapsed
        : 0.0;

    double eta = (speed > 0.0 && total_ > tested_val)
        ? static_cast<double>(total_ - tested_val) / speed
        : 0.0;

    auto bar_width = terminal_width();
    bar_width = (bar_width > 30) ? bar_width - 20 : 10;

    std::print("\033[3A");

    std::println("  {}{} {:.1f}%{}",
        config::color::YELLOW, render_bar(fraction, bar_width),
        fraction * 100.0, config::color::RESET);
    std::println("  {} {} {} {}  {} {} {} ~{}{}",
        config::symbol::DIAMOND, config::color::CYAN,
        format_speed(speed), config::color::RESET,
        config::symbol::TIMER, config::color::CYAN,
        format_time(elapsed), format_time(eta),
        config::color::RESET);
    std::println("  {} {} {} / {} candidates{}",
        config::symbol::ARROW_RIGHT, config::color::CYAN,
        format_count(tested_val), format_count(total_),
        config::color::RESET);
}

void Progress::print_cracked(const CrackResult& result) const {
    if (!is_tty()) {
        std::println("{}", result.plaintext);
        return;
    }

    std::print("\033[3A\033[J");

    std::println("  {}{} CRACKED {}{}{}",
        config::color::GREEN, config::symbol::CHECK,
        std::string(30, '-'), config::color::RESET, "");
    std::println("  {}Password:  {}{}{}",
        config::color::BOLD, config::color::GREEN,
        result.plaintext, config::color::RESET);
    std::println("  Hash:      {}", result.hash);
    std::println("  Algorithm: {}", result.algorithm);
    std::println("  Time:      {} {} {}",
        format_time(result.elapsed_seconds),
        config::box::VERTICAL,
        format_speed(result.hashes_per_second));
}

void Progress::print_exhausted(std::string_view hash,
                                std::string_view algorithm) const {
    if (!is_tty()) {
        std::println("NOT FOUND");
        return;
    }

    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - start_time_).count();
    auto tested_val = tested_.load(std::memory_order_relaxed);

    std::print("\033[3A\033[J");

    std::println("  {}{} EXHAUSTED {}{}{}",
        config::color::RED, config::symbol::CROSS,
        std::string(30, '-'), config::color::RESET, "");
    std::println("  Hash:      {}", hash);
    std::println("  Algorithm: {}", algorithm);
    std::println("  Tested:    {} candidates in {}",
        format_count(tested_val), format_time(elapsed));
}
