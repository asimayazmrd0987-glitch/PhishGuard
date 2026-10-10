// =============================================================================
// FILE: include/phishguard/algorithms/levenshtein.hpp
// WHAT   Levenshtein (edit) distance: the minimum number of single-character insertions,
//        deletions and substitutions needed to turn string a into string b.
//        Example: "paypa1" -> "paypal" = 1 (one substitution).
// HOW    DYNAMIC PROGRAMMING. dp[i][j] = distance between the first i letters of a and the first
//        j letters of b. It is filled row by row from three smaller answers:
//            dp[i-1][j] + 1        delete a[i-1]
//            dp[i][j-1] + 1        insert b[j-1]
//            dp[i-1][j-1] + cost   substitute (cost 0 if the letters already match)
//        and the final answer is dp[m][n]. Sub-problems overlap, which is why a table beats
//        plain recursion (which would be exponential).
//        Two versions: the full table (easy to explain / draw in a viva) and a two-row version
//        that needs only O(min(m,n)) memory. Tests prove they give identical answers.
// WHY    It measures "how close" a suspicious domain is to a trusted one (typosquatting).
//        Similarity alone does NOT prove malicious intent; it is one signal among many.
// COMPLEXITY  Time O(m x n). Space O(m x n) full table, O(min(m,n)) two rows.
// =============================================================================
#pragma once
#include <string>
#include <vector>

namespace phishguard {

std::vector<std::vector<int>> editDistanceTable(const std::string& a, const std::string& b);
int editDistance(const std::string& a, const std::string& b);        // uses the full table
int editDistanceTwoRow(const std::string& a, const std::string& b);  // memory-optimised
double similarity(const std::string& a, const std::string& b);       // 1 - d/max(len), in [0,1]
const char* similarityLabel(double similarity);                      // Very High / High / Moderate / Low

}  // namespace phishguard
