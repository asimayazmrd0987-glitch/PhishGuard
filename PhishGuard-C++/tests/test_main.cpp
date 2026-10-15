// =============================================================================
// FILE: tests/test_main.cpp
// WHAT   main() for the test program: runs every registered TEST, prints [PASS]/[FAIL] per test and a
//        total, and returns a non-zero exit code on any failure (so CI turns red).
// =============================================================================

#include "test_harness.hpp"

int main() {
    int failedTests = 0;
    for (const auto& t : registry()) {
        const int before = failureCount();
        t.fn();
        const bool ok = failureCount() == before;
        std::cout << (ok ? "[PASS] " : "[FAIL] ") << t.name << "\n";
        if (!ok) ++failedTests;
    }
    std::cout << "\n" << registry().size() - failedTests << "/" << registry().size()
              << " tests passed\n";
    return failedTests == 0 ? 0 : 1;
}
