// =============================================================================
// FILE: src/benchmark/benchmark.cpp
// WHAT   Implementation of the four experiments.
// HOW    Rng is a tiny xorshift random generator (deterministic). Each experiment counts comparisons
//        with the counters built into the algorithms, and measures time with std::chrono::steady_clock.
// HONESTY  The results include cases where the "clever" structure does NOT win in wall-clock time
//        (hash vs binary search at 100,000 entries; KMP on ordinary text). Report them as they are.
// =============================================================================

#include "phishguard/benchmark/benchmark.hpp"

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <ostream>
#include <string>

#include "phishguard/algorithms/sorting.hpp"
#include "phishguard/algorithms/string_match.hpp"
#include "phishguard/ds/hash_table.hpp"
#include "phishguard/ds/heap.hpp"
#include "phishguard/ds/trie.hpp"

namespace phishguard {

namespace {

using Clock = std::chrono::steady_clock;
double msSince(Clock::time_point t0) { return std::chrono::duration<double, std::milli>(Clock::now() - t0).count(); }

struct Rng {  // xorshift64: deterministic, so runs are repeatable
    std::uint64_t s;
    explicit Rng(std::uint64_t seed) : s(seed) {}
    std::uint64_t next() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }
};

std::string base36(std::uint64_t v) {
    static const char* digits = "0123456789abcdefghijklmnopqrstuvwxyz";
    std::string out;
    do {
        out += digits[v % 36];
        v /= 36;
    } while (v);
    return out;
}

std::vector<std::string> makeDomains(std::size_t n, Rng& rng) {
    std::vector<std::string> v;
    v.reserve(n);
    for (std::size_t i = 0; i < n; ++i) v.push_back("d" + base36(rng.next() % 2000000000ULL) + "x" + std::to_string(i) + ".test");
    return v;
}

std::string randomWord(Rng& rng, std::size_t minLen, std::size_t maxLen) {
    const std::size_t len = minLen + rng.next() % (maxLen - minLen + 1);
    std::string w;
    for (std::size_t i = 0; i < len; ++i) w += static_cast<char>('a' + rng.next() % 26);
    return w;
}

std::size_t estimateStringBytes(const std::vector<std::string>& v) {
    std::size_t b = 0;
    for (const auto& s : v) b += sizeof(std::string) + (s.size() > 15 ? s.size() + 1 : 0);  // SSO threshold
    return b;
}

void row(std::ostream& o, const std::string& a, const std::string& b, double ms, double cmp, double kb) {
    o << std::left << std::setw(9) << a << std::setw(15) << b << std::right << std::fixed << std::setprecision(3) << std::setw(12) << ms
      << std::setprecision(1) << std::setw(16) << cmp << std::setw(14) << kb << "\n";
}

void lookupExperiment(std::ostream& o, const std::vector<std::size_t>& sizes) {
    o << "\n=== A. Domain lookup: linear vs binary search vs hash table (1000 queries, half hits / half misses) ===\n";
    o << std::left << std::setw(9) << "domains" << std::setw(15) << "method" << std::right << std::setw(12) << "total ms" << std::setw(16)
      << "avg compares" << std::setw(14) << "est. KB" << "\n";
    const std::size_t kQueries = 1000;
    for (std::size_t n : sizes) {
        Rng rng(12345);
        const auto domains = makeDomains(n, rng);
        std::vector<std::string> queries;
        for (std::size_t q = 0; q < kQueries; ++q)
            queries.push_back(q % 2 == 0 ? domains[(q * 7919ULL) % n] : "absent-" + std::to_string(q) + ".test");

        std::size_t cmps = 0, found = 0;
        auto t0 = Clock::now();
        for (const auto& q : queries)
            for (const auto& d : domains) {
                ++cmps;
                if (d == q) { ++found; break; }
            }
        row(o, std::to_string(n), "linear", msSince(t0), double(cmps) / kQueries, estimateStringBytes(domains) / 1024.0);

        auto sortedCopy = domains;
        mergeSort(sortedCopy);
        cmps = 0;
        t0 = Clock::now();
        for (const auto& q : queries) found += binarySearch(sortedCopy, q, &cmps) >= 0;
        row(o, "", "binary (sorted)", msSince(t0), double(cmps) / kQueries, estimateStringBytes(sortedCopy) / 1024.0);

        HashTable<std::string, int> table;
        for (std::size_t i = 0; i < n; ++i) table.insert(domains[i], static_cast<int>(i));
        table.resetComparisons();
        t0 = Clock::now();
        for (const auto& q : queries) found += table.contains(q);
        const double hashKb = (table.bucketCount() * sizeof(void*) + n * (sizeof(std::string) + 16) + estimateStringBytes(domains) - n * sizeof(std::string)) / 1024.0;
        row(o, "", "hash table", msSince(t0), double(table.comparisons()) / kQueries, hashKb);
        o << "          (hash: buckets=" << table.bucketCount() << " load=" << std::setprecision(2) << table.loadFactor()
          << " longest chain=" << table.maxChainLength() << " collisions=" << table.collisionCount() << ")  [hits found=" << found << "]\n";
    }
}

void trieExperiment(std::ostream& o) {
    o << "\n=== B. Keyword lookup: plain array vs Trie (5,000 keywords, 20,000 lookups) ===\n";
    Rng rng(777);
    std::vector<std::string> words;
    Trie trie;
    for (int i = 0; i < 5000; ++i) {
        words.push_back(randomWord(rng, 4, 10));
        trie.insert(words.back());
    }
    std::vector<std::string> queries;
    for (int i = 0; i < 20000; ++i) queries.push_back(i % 2 == 0 ? words[(i * 31ULL) % words.size()] : randomWord(rng, 4, 10) + "q");
    std::size_t hits = 0, cmps = 0;
    auto t0 = Clock::now();
    for (const auto& q : queries)
        for (const auto& w : words) {
            ++cmps;
            if (w == q) { ++hits; break; }
        }
    o << "array : " << std::fixed << std::setprecision(2) << msSince(t0) << " ms, avg " << double(cmps) / queries.size() << " word comparisons/lookup (hits=" << hits << ")\n";
    hits = 0;
    t0 = Clock::now();
    for (const auto& q : queries) hits += trie.contains(q);
    o << "trie  : " << msSince(t0) << " ms, at most one step per character (<= 11 here), " << trie.nodeCount() << " nodes (hits=" << hits << ")\n";
}

void stringExperiment(std::ostream& o) {
    o << "\n=== C. Substring search on 200,000-character text (character/hash comparisons) ===\n";
    Rng rng(99);
    std::string random;
    for (int i = 0; i < 200000; ++i) random += static_cast<char>('a' + rng.next() % 4);
    const std::string pat1 = random.substr(150000, 8);
    const std::string worstText(200000, 'a');
    const std::string worstPat = std::string(400, 'a') + "b";
    struct Case { const char* name; const std::string* text; const std::string* pat; };
    const Case cases[] = {{"random text, pattern length 8", &random, &pat1}, {"worst case: aaaa... vs a^400+b", &worstText, &worstPat}};
    o << std::left << std::setw(34) << "case" << std::setw(13) << "algorithm" << std::right << std::setw(14) << "comparisons" << std::setw(12) << "ms" << std::setw(10) << "matches" << "\n";
    for (const auto& c : cases) {
        for (int alg = 0; alg < 3; ++alg) {
            std::size_t cmp = 0;
            const auto t0 = Clock::now();
            auto res = alg == 0 ? naiveSearch(*c.text, *c.pat, &cmp) : alg == 1 ? kmpSearch(*c.text, *c.pat, &cmp) : rabinKarpSearch(*c.text, *c.pat, &cmp);
            o << std::left << std::setw(34) << (alg == 0 ? c.name : "") << std::setw(13) << (alg == 0 ? "naive" : alg == 1 ? "KMP" : "Rabin-Karp")
              << std::right << std::setw(14) << cmp << std::fixed << std::setprecision(3) << std::setw(12) << msSince(t0) << std::setw(10) << res.size() << "\n";
        }
    }
}

struct Item {
    int score;
    int id;
};

void rankingExperiment(std::ostream& o) {
    o << "\n=== D. Ranking the 10 riskiest of 100,000 scans: repeated linear scan vs heap vs full sort ===\n";
    Rng rng(4242);
    std::vector<Item> items;
    for (int i = 0; i < 100000; ++i) items.push_back({static_cast<int>(rng.next() % 101), i});
    const std::size_t k = 10;

    std::size_t cmp = 0;
    auto t0 = Clock::now();
    {
        std::vector<char> used(items.size(), 0);
        for (std::size_t r = 0; r < k; ++r) {
            long best = -1;
            for (std::size_t i = 0; i < items.size(); ++i) {
                if (used[i]) continue;
                ++cmp;
                if (best < 0 || items[i].score > items[static_cast<std::size_t>(best)].score) best = static_cast<long>(i);
            }
            used[static_cast<std::size_t>(best)] = 1;
        }
    }
    o << std::left << std::setw(26) << "linear scan x10" << std::right << std::fixed << std::setprecision(3) << std::setw(10) << msSince(t0) << " ms " << std::setw(12) << cmp << " comparisons\n";

    cmp = 0;
    t0 = Clock::now();
    {
        auto less = [&cmp](const Item& a, const Item& b) { ++cmp; return a.score < b.score; };
        MaxHeap<Item, decltype(less)> heap(items, less);
        for (std::size_t r = 0; r < k; ++r) heap.pop();
    }
    o << std::left << std::setw(26) << "max-heap (heapify+10 pops)" << std::right << std::setw(10) << msSince(t0) << " ms " << std::setw(12) << cmp << " comparisons\n";

    cmp = 0;
    t0 = Clock::now();
    {
        auto copy = items;
        mergeSort(copy, [&cmp](const Item& a, const Item& b) { ++cmp; return a.score > b.score; });
    }
    o << std::left << std::setw(26) << "full merge sort" << std::right << std::setw(10) << msSince(t0) << " ms " << std::setw(12) << cmp << " comparisons\n";
}

}  // namespace

void runBenchmarks(std::ostream& out, const std::vector<std::size_t>& sizes) {
    out << "PhishGuard benchmarks (synthetic data, single run, times vary by machine)\n";
    lookupExperiment(out, sizes);
    trieExperiment(out);
    stringExperiment(out);
    rankingExperiment(out);
    out << "\nMemory figures are sizeof-based estimates, not measured resident memory.\n";
}

}  // namespace phishguard
