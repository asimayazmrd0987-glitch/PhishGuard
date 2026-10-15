// =============================================================================
// FILE: src/algorithms/levenshtein.cpp
// WHAT   Implementation of edit distance, similarity (1 - distance / longest length) and the
//        human label ("Very High" >= 0.85, "High" >= 0.70, "Moderate" >= 0.50, else "Low").
// HOW    Row 0 and column 0 are the base cases: turning a prefix into an empty string costs its
//        length. The two-row version keeps only the previous row and the current row and swaps
//        them, and always puts the SHORTER string on the inner loop to minimise memory.
// LIMITATION  Plain Levenshtein counts a swap of two neighbouring letters ("googel") as 2 edits;
//        Damerau-Levenshtein would count 1 (listed as future work).
// =============================================================================

#include "phishguard/algorithms/levenshtein.hpp"

#include <algorithm>

namespace phishguard {

std::vector<std::vector<int>> editDistanceTable(const std::string& a, const std::string& b) {
    const std::size_t m = a.size(), n = b.size();
    std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1, 0));
    for (std::size_t i = 0; i <= m; ++i) dp[i][0] = static_cast<int>(i);  // delete all of a
    for (std::size_t j = 0; j <= n; ++j) dp[0][j] = static_cast<int>(j);  // insert all of b
    for (std::size_t i = 1; i <= m; ++i) {
        for (std::size_t j = 1; j <= n; ++j) {
            const int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
            dp[i][j] = std::min({dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost});
        }
    }
    return dp;
}

int editDistance(const std::string& a, const std::string& b) {
    return editDistanceTable(a, b)[a.size()][b.size()];
}

int editDistanceTwoRow(const std::string& a, const std::string& b) {
    const std::string& longer = (a.size() >= b.size()) ? a : b;
    const std::string& shorter = (a.size() >= b.size()) ? b : a;
    std::vector<int> prev(shorter.size() + 1), cur(shorter.size() + 1);
    for (std::size_t j = 0; j <= shorter.size(); ++j) prev[j] = static_cast<int>(j);
    for (std::size_t i = 1; i <= longer.size(); ++i) {
        cur[0] = static_cast<int>(i);
        for (std::size_t j = 1; j <= shorter.size(); ++j) {
            const int cost = (longer[i - 1] == shorter[j - 1]) ? 0 : 1;
            cur[j] = std::min({prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost});
        }
        std::swap(prev, cur);
    }
    return prev[shorter.size()];
}

double similarity(const std::string& a, const std::string& b) {
    const std::size_t longest = std::max(a.size(), b.size());
    if (longest == 0) return 1.0;
    return 1.0 - static_cast<double>(editDistance(a, b)) / static_cast<double>(longest);
}

const char* similarityLabel(double s) {
    if (s >= 0.85) return "Very High";
    if (s >= 0.70) return "High";
    if (s >= 0.50) return "Moderate";
    return "Low";
}

}  // namespace phishguard
