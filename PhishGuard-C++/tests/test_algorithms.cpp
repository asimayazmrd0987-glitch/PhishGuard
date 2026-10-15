// =============================================================================
// FILE: tests/test_algorithms.cpp
// WHAT   Tests for Levenshtein, KMP, Rabin-Karp and sorting.
// HOW    Besides fixed examples, random inputs are checked against a trusted reference: both
//        edit-distance versions must agree; KMP and Rabin-Karp must equal naive search on 300 random
//        cases; our sorts must equal std::sort. Also checks KMP is linear on a worst case.
// =============================================================================

#include <algorithm>
#include <string>
#include <vector>

#include "phishguard/algorithms/levenshtein.hpp"
#include "phishguard/algorithms/sorting.hpp"
#include "phishguard/algorithms/string_match.hpp"
#include "test_harness.hpp"

using namespace phishguard;

namespace {
unsigned long long seed = 88172645463325252ULL;
unsigned long long rnd() {
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    return seed;
}
}  // namespace

TEST(levenshtein_known_values) {
    CHECK_EQ(editDistance("kitten", "sitting"), 3);
    CHECK_EQ(editDistance("", ""), 0);
    CHECK_EQ(editDistance("abc", ""), 3);
    CHECK_EQ(editDistance("", "abc"), 3);
    CHECK_EQ(editDistance("paypal.com", "paypa1.com"), 1);
    CHECK_EQ(editDistance("microsoft.com", "micr0soft.com"), 1);
    CHECK_EQ(editDistance("google.com", "g00gle.com"), 2);
    CHECK_EQ(editDistance("same", "same"), 0);
}

TEST(levenshtein_symmetry_and_two_row_agree) {
    for (int i = 0; i < 200; ++i) {
        std::string a, b;
        for (unsigned long long n = rnd() % 12; n > 0; --n) a += static_cast<char>('a' + rnd() % 4);
        for (unsigned long long n = rnd() % 12; n > 0; --n) b += static_cast<char>('a' + rnd() % 4);
        CHECK_EQ(editDistance(a, b), editDistance(b, a));
        CHECK_EQ(editDistance(a, b), editDistanceTwoRow(a, b));
    }
}

TEST(similarity_scale_and_labels) {
    CHECK(similarity("paypal.com", "paypa1.com") > 0.85);
    CHECK_EQ(std::string(similarityLabel(similarity("paypal.com", "paypa1.com"))), std::string("Very High"));
    CHECK_EQ(std::string(similarityLabel(similarity("abcdef", "uvwxyz"))), std::string("Low"));
    CHECK(similarity("", "") == 1.0);
}

TEST(string_match_known_cases) {
    using V = std::vector<std::size_t>;
    CHECK(naiveSearch("aaaaa", "aa") == (V{0, 1, 2, 3}));  // overlapping
    CHECK(kmpSearch("aaaaa", "aa") == (V{0, 1, 2, 3}));
    CHECK(rabinKarpSearch("aaaaa", "aa") == (V{0, 1, 2, 3}));
    CHECK(kmpSearch("ababcabcab", "abcab") == (V{2, 5}));
    CHECK(kmpSearch("hello", "xyz").empty());
    CHECK(kmpSearch("abc", "abcd").empty());  // pattern longer than text
    CHECK(kmpSearch("abc", "").empty());      // empty pattern: no matches by definition
    CHECK(buildPrefixTable("abcabd") == (std::vector<std::size_t>{0, 0, 0, 1, 2, 0}));
}

TEST(string_match_algorithms_agree_on_random_inputs) {
    for (int i = 0; i < 300; ++i) {
        std::string t, p;
        for (unsigned long long n = 5 + rnd() % 60; n > 0; --n) t += static_cast<char>('a' + rnd() % 3);
        for (unsigned long long n = 1 + rnd() % 4; n > 0; --n) p += static_cast<char>('a' + rnd() % 3);
        const auto expected = naiveSearch(t, p);
        CHECK(kmpSearch(t, p) == expected);
        CHECK(rabinKarpSearch(t, p) == expected);
    }
}

TEST(kmp_does_fewer_comparisons_than_naive_in_worst_case) {
    const std::string text(5000, 'a');
    const std::string pat = std::string(50, 'a') + "b";
    std::size_t cn = 0, ck = 0;
    naiveSearch(text, pat, &cn);
    kmpSearch(text, pat, &ck);
    CHECK(ck < cn / 10);
    CHECK(ck <= 2 * text.size());  // linear
}

TEST(sorting_matches_std_sort) {
    for (int round = 0; round < 50; ++round) {
        std::vector<int> v;
        for (unsigned long long n = rnd() % 200; n > 0; --n) v.push_back(static_cast<int>(rnd() % 50));
        auto expected = v;
        std::sort(expected.begin(), expected.end());
        auto m = v, q = v;
        mergeSort(m);
        quickSort(q);
        CHECK(m == expected);
        CHECK(q == expected);
    }
    std::vector<int> empty, one{7};
    mergeSort(empty);
    quickSort(one);
    CHECK(empty.empty());
    CHECK_EQ(one[0], 7);
}

TEST(merge_sort_is_stable) {
    struct P { int key; int order; };
    std::vector<P> v;
    for (int i = 0; i < 100; ++i) v.push_back({static_cast<int>(rnd() % 5), i});
    mergeSort(v, [](const P& a, const P& b) { return a.key < b.key; });
    for (std::size_t i = 1; i < v.size(); ++i) {
        CHECK(v[i - 1].key <= v[i].key);
        if (v[i - 1].key == v[i].key) CHECK(v[i - 1].order < v[i].order);
    }
}

TEST(quick_sort_handles_sorted_reverse_and_duplicates) {
    std::vector<int> asc, desc, dup(100, 3);
    for (int i = 0; i < 1000; ++i) { asc.push_back(i); desc.push_back(1000 - i); }
    quickSort(asc);
    quickSort(desc);
    quickSort(dup);
    CHECK(std::is_sorted(asc.begin(), asc.end()));
    CHECK(std::is_sorted(desc.begin(), desc.end()));
    CHECK(std::is_sorted(dup.begin(), dup.end()));
}

TEST(binary_search_finds_and_misses) {
    std::vector<std::string> v{"a.test", "c.test", "e.test", "g.test"};
    CHECK_EQ(binarySearch(v, "e.test"), 2L);
    CHECK_EQ(binarySearch(v, "a.test"), 0L);
    CHECK_EQ(binarySearch(v, "g.test"), 3L);
    CHECK_EQ(binarySearch(v, "b.test"), -1L);
    CHECK_EQ(binarySearch({}, "x"), -1L);
}
