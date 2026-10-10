// =============================================================================
// FILE: include/phishguard/algorithms/string_match.hpp
// WHAT   Three ways to find every position where a pattern occurs inside a text.
// HOW    * NAIVE      : try every start position and compare letter by letter. Simple, but
//                       O(n x m) in the worst case (text "aaaa...", pattern "aaa...b").
//        * KMP        : first builds a "prefix table" saying how much of the pattern can be reused
//                       after a mismatch, so the text index NEVER moves backward. O(n + m).
//        * RABIN-KARP : slides a window over the text keeping a ROLLING HASH (drop the left
//                       letter, add the right letter in O(1)); only when hashes are equal does it
//                       compare letters, because different strings can share a hash (collision).
//                       O(n + m) on average, O(n x m) in the worst case.
//        Every function can count its comparisons so the benchmark can PROVE the difference.
// WHY    PhishGuard searches messages for scam phrases (KMP) and searches host names for a whole
//        trusted domain hidden inside them (Rabin-Karp). An empty pattern returns no matches.
// COMPLEXITY  see the list above; KMP space O(m), Rabin-Karp and naive O(1).
// =============================================================================
#pragma once
#include <cstddef>
#include <string>
#include <vector>

namespace phishguard {

std::vector<std::size_t> buildPrefixTable(const std::string& pattern);  // KMP "lps" array

std::vector<std::size_t> naiveSearch(const std::string& text, const std::string& pattern,
                                     std::size_t* comparisons = nullptr);
std::vector<std::size_t> kmpSearch(const std::string& text, const std::string& pattern,
                                   std::size_t* comparisons = nullptr);
std::vector<std::size_t> rabinKarpSearch(const std::string& text, const std::string& pattern,
                                         std::size_t* comparisons = nullptr);

}  // namespace phishguard
