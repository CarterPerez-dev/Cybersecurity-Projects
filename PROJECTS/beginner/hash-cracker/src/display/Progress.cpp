// ©AngelaMos | 2026
// Progress.cpp

#include "src/display/Progress.hpp"
#include "src/config/Config.hpp"

Progress::Progress(std::string_view algorithm, std::string_view attack_mode,
                   unsigned thread_count, std::size_t total_candidates,
                   const std::atomic<bool>& found,
                   const std::atomic<std::size_t>& tested)
    : algorithm_(algorithm), attack_mode_(attack_mode),
      thread_count_(thread_count), total_(total_candidates),
      found_(found), tested_(tested) {}

void Progress::print_banner() const {}
void Progress::update() {}
void Progress::print_cracked(const CrackResult&) const {}
void Progress::print_exhausted(std::string_view, std::string_view) const {}
bool Progress::is_tty() { return false; }
std::size_t Progress::terminal_width() { return 80; }
std::string Progress::render_bar(double, std::size_t) const { return ""; }
std::string Progress::format_count(std::size_t) { return ""; }
std::string Progress::format_time(double) { return ""; }
std::string Progress::format_speed(double) { return ""; }
