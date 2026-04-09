/*
©AngelaMos | 2026
DictionaryAttack.cpp

Wordlist reading over a memory-mapped file with thread-safe partitioning

create() opens the wordlist via MappedFile, counts total lines, divides
them evenly among threads (with remainder distribution), then walks
forward through the mapped buffer to find each thread's start and end
byte offsets. next() scans forward from current_offset_ to the next
newline, strips trailing \r for Windows-format wordlists, and returns
the word. Skips blank lines. Returns AttackComplete when the thread's
partition is exhausted.

Key exports:
  DictionaryAttack::create   - Factory that opens and partitions a wordlist file
  DictionaryAttack::next     - Returns next word or AttackComplete
  DictionaryAttack::total    - Total words in this thread's partition
  DictionaryAttack::progress - Words read so far

Connects to:
  attack/DictionaryAttack.hpp - class declaration
  io/MappedFile.hpp           - MappedFile for zero-copy file access
  core/Concepts.hpp           - CrackError and AttackComplete types
*/

#include "src/attack/DictionaryAttack.hpp"
#include <algorithm>

static std::size_t count_lines_in_range(const char* data,
                                        std::size_t start,
                                        std::size_t end) {
    std::size_t count = 0;
    for (std::size_t i = start; i < end; ++i) {
        if (data[i] == '\n') {
            ++count;
        }
    }
    return count;
}

static std::size_t find_next_newline(const char* data,
                                     std::size_t pos,
                                     std::size_t size) {
    while (pos < size && data[pos] != '\n') {
        ++pos;
    }
    return pos < size ? pos + 1 : size;
}

std::expected<DictionaryAttack, CrackError> DictionaryAttack::create(
    std::string_view path, unsigned thread_index, unsigned total_threads) {
    auto file = MappedFile::open(path);
    if (!file.has_value()) {
        return std::unexpected(file.error());
    }

    auto* data = file->data();
    auto file_size = file->size();

    std::size_t total_lines = count_lines_in_range(data, 0, file_size);
    if (file_size > 0 && data[file_size - 1] != '\n') {
        ++total_lines;
    }

    std::size_t lines_per_thread = total_lines / total_threads;
    std::size_t remainder = total_lines % total_threads;

    std::size_t my_start_line = thread_index * lines_per_thread
        + std::min(static_cast<std::size_t>(thread_index), remainder);
    std::size_t my_line_count = lines_per_thread
        + (thread_index < remainder ? 1 : 0);

    std::size_t start_offset = 0;
    for (std::size_t i = 0; i < my_start_line; ++i) {
        start_offset = find_next_newline(data, start_offset, file_size);
    }

    std::size_t end_offset = start_offset;
    for (std::size_t i = 0; i < my_line_count; ++i) {
        end_offset = find_next_newline(data, end_offset, file_size);
    }

    DictionaryAttack attack;
    attack.file_ = std::move(*file);
    attack.start_offset_ = start_offset;
    attack.end_offset_ = end_offset;
    attack.current_offset_ = start_offset;
    attack.total_words_ = my_line_count;
    attack.words_read_ = 0;

    return attack;
}

std::expected<std::string, AttackComplete> DictionaryAttack::next() {
    while (current_offset_ < end_offset_) {
        std::size_t line_start = current_offset_;
        std::size_t line_end = line_start;

        while (line_end < end_offset_ && file_.data()[line_end] != '\n') {
            ++line_end;
        }

        std::size_t word_end = line_end;
        if (word_end > line_start && file_.data()[word_end - 1] == '\r') {
            --word_end;
        }

        current_offset_ = (line_end < end_offset_) ? line_end + 1 : end_offset_;
        ++words_read_;

        if (word_end > line_start) {
            return std::string(file_.data() + line_start, word_end - line_start);
        }
    }
    return std::unexpected(AttackComplete{});
}

std::size_t DictionaryAttack::total() const { return total_words_; }
std::size_t DictionaryAttack::progress() const { return words_read_; }
