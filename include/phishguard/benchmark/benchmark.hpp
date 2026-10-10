// =============================================================================
// FILE: include/phishguard/benchmark/benchmark.hpp
// WHAT   The experiments that prove WHY these data structures were chosen:
//        A) linear vs binary search vs hash table, B) plain array vs Trie,
//        C) naive vs KMP vs Rabin-Karp, D) repeated linear scan vs heap vs full sort.
// NOTE   Data is synthetic and generated with a fixed random seed, so comparison COUNTS are
//        repeatable; times vary by machine. Memory numbers are sizeof-based estimates.
// =============================================================================
#pragma once
#include <cstddef>
#include <iosfwd>
#include <vector>

namespace phishguard {

// Educational experiments (all data synthetic and deterministic):
//  A. linear vs binary search vs hash table   B. array vs Trie
//  C. naive vs KMP vs Rabin-Karp              D. linear ranking vs heap vs full sort
// Memory numbers are sizeof-based ESTIMATES, not measurements.
void runBenchmarks(std::ostream& out, const std::vector<std::size_t>& sizes = {100, 1000, 10000, 100000});

}  // namespace phishguard
