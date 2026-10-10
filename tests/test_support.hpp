// =============================================================================
// FILE: tests/test_support.hpp
// WHAT   testData(): loads the real data/ folder ONCE and shares it between all tests.
// WHY    Integration-style tests should exercise the same word lists and weights users get.
// =============================================================================
#pragma once
#include "phishguard/security/detection_data.hpp"

// Loads the real data/ folder once for all tests.
inline const phishguard::DetectionData& testData() {
    static const phishguard::DetectionData d = phishguard::DetectionData::loadFromDirectory(PG_DATA_DIR);
    return d;
}
