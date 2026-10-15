// =============================================================================
// FILE: tests/test_harness.hpp
// WHAT   A tiny test framework (about 30 lines of logic) so the project needs no external library.
// HOW    TEST(name) { ... } registers a function in a global list at start-up. CHECK(cond),
//        CHECK_EQ(a, b) and CHECK_THROWS(expr) COUNT failures and print file:line instead of
//        stopping, so one run lists every problem. test_main.cpp runs the list and sets the exit code.
// NOTE   CHECK_EQ copies its operands: keeping a reference to a temporary (e.g. f()[0]) would dangle.
// =============================================================================
#pragma once
#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;  // function-local: safe init order
    return tests;
}
inline int& failureCount() {
    static int n = 0;
    return n;
}
struct Registrar {
    Registrar(std::string name, std::function<void()> fn) {
        registry().push_back({std::move(name), std::move(fn)});
    }
};

#define TEST(name)                                  \
    static void name();                             \
    static Registrar registrar_##name(#name, name); \
    static void name()

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            ++failureCount();                                                  \
            std::cerr << "    FAIL " << __FILE__ << ":" << __LINE__ << "  "    \
                      << #cond << "\n";                                        \
        }                                                                      \
    } while (0)

#define CHECK_EQ(a, b)                                                         \
    do {                                                                       \
        const auto va = (a);  /* copy: avoids dangling refs to temporaries */                                                  \
        const auto vb = (b);                                                  \
        if (!(va == vb)) {                                                     \
            ++failureCount();                                                  \
            std::cerr << "    FAIL " << __FILE__ << ":" << __LINE__ << "  "    \
                      << #a << " == " << #b << "  (got " << va << " vs "       \
                      << vb << ")\n";                                          \
        }                                                                      \
    } while (0)

#define CHECK_THROWS(expr)                                                     \
    do {                                                                       \
        bool threw = false;                                                    \
        try { (void)(expr); } catch (...) { threw = true; }                    \
        CHECK(threw);                                                          \
    } while (0)
