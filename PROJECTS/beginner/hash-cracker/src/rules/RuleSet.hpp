// ©AngelaMos | 2026
// RuleSet.hpp

#pragma once

#include <generator>
#include <string>
#include <string_view>

class RuleSet {
public:
    static std::generator<std::string> capitalize_first(std::string_view word);
    static std::generator<std::string> uppercase_all(std::string_view word);
    static std::generator<std::string> leet_speak(std::string_view word);
    static std::generator<std::string> append_digits(std::string_view word);
    static std::generator<std::string> prepend_digits(std::string_view word);
    static std::generator<std::string> reverse(std::string_view word);
    static std::generator<std::string> toggle_case(std::string_view word);
    static std::generator<std::string> apply_all(std::string_view word);
};
