// =============================================================================
// FILE: src/algorithms/string_match.cpp
// WHAT   Implementations of naive search, KMP and Rabin-Karp.
// HOW    * buildPrefixTable(): lps[i] = length of the longest proper prefix of pattern[0..i] that
//          is also a suffix. For "abcabd" it is 0 0 0 1 2 0.
//        * kmpSearch(): on a mismatch with j > 0 it falls back to lps[j-1] instead of restarting;
//          after a full match it also falls back, which allows OVERLAPPING matches ("aa" in "aaaa").
//        * rabinKarpSearch(): hash = sum(char x 256^k) mod 1,000,000,007. Rolling update:
//          remove the left letter times 256^(m-1), multiply by 256, add the new letter.
//          The subtraction adds the modulus first so the unsigned value never underflows.
//        Comparison counts: naive/KMP count letter comparisons; Rabin-Karp counts one hash
//        comparison per window plus the letters it verifies.
// =============================================================================

#include "phishguard/algorithms/string_match.hpp"

#include <cstdint>

namespace phishguard {

namespace {
inline void tick(std::size_t* c) {
    if (c) ++*c;
}
}  // namespace

std::vector<std::size_t> buildPrefixTable(const std::string& p) {
    std::vector<std::size_t> lps(p.size(), 0);  // lps[i] = longest proper prefix of p[0..i] that is also a suffix
    std::size_t len = 0, i = 1;
    while (i < p.size()) {
        if (p[i] == p[len]) {
            lps[i++] = ++len;
        } else if (len > 0) {
            len = lps[len - 1];
        } else {
            lps[i++] = 0;
        }
    }
    return lps;
}

std::vector<std::size_t> naiveSearch(const std::string& t, const std::string& p, std::size_t* comparisons) {
    std::vector<std::size_t> out;
    if (p.empty() || p.size() > t.size()) return out;
    for (std::size_t i = 0; i + p.size() <= t.size(); ++i) {
        std::size_t j = 0;
        while (j < p.size()) {
            tick(comparisons);
            if (t[i + j] != p[j]) break;
            ++j;
        }
        if (j == p.size()) out.push_back(i);
    }
    return out;
}

std::vector<std::size_t> kmpSearch(const std::string& t, const std::string& p, std::size_t* comparisons) {
    std::vector<std::size_t> out;
    if (p.empty() || p.size() > t.size()) return out;
    const auto lps = buildPrefixTable(p);
    std::size_t i = 0, j = 0;
    while (i < t.size()) {
        tick(comparisons);
        if (t[i] == p[j]) {
            ++i;
            ++j;
            if (j == p.size()) {
                out.push_back(i - j);
                j = lps[j - 1];  // keep going: allows overlapping matches
            }
        } else if (j > 0) {
            j = lps[j - 1];  // reuse what already matched; i does not move back
        } else {
            ++i;
        }
    }
    return out;
}

std::vector<std::size_t> rabinKarpSearch(const std::string& t, const std::string& p, std::size_t* comparisons) {
    std::vector<std::size_t> out;
    const std::size_t n = t.size(), m = p.size();
    if (m == 0 || m > n) return out;
    constexpr std::uint64_t kBase = 256, kMod = 1000000007ULL;
    std::uint64_t highPow = 1;  // kBase^(m-1) mod kMod
    for (std::size_t i = 1; i < m; ++i) highPow = (highPow * kBase) % kMod;
    std::uint64_t hp = 0, ht = 0;
    for (std::size_t i = 0; i < m; ++i) {
        hp = (hp * kBase + static_cast<unsigned char>(p[i])) % kMod;
        ht = (ht * kBase + static_cast<unsigned char>(t[i])) % kMod;
    }
    for (std::size_t i = 0; i + m <= n; ++i) {
        tick(comparisons);  // one hash comparison
        if (hp == ht) {     // equal hashes: verify, because collisions are possible
            std::size_t j = 0;
            while (j < m) {
                tick(comparisons);
                if (t[i + j] != p[j]) break;
                ++j;
            }
            if (j == m) out.push_back(i);
        }
        if (i + m < n) {  // roll the window: drop t[i], add t[i+m] in O(1)
            ht = (ht + kMod - (static_cast<unsigned char>(t[i]) * highPow) % kMod) % kMod;
            ht = (ht * kBase + static_cast<unsigned char>(t[i + m])) % kMod;
        }
    }
    return out;
}

}  // namespace phishguard
