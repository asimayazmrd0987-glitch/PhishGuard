// =============================================================================
// FILE: include/phishguard/algorithms/sorting.hpp
// WHAT   Educational sorting and searching code (templates, so it works for any element type).
// HOW    cmp(a, b) must return true when a belongs BEFORE b.
//        * mergeSort : split in halves, sort each, merge. STABLE (equal items keep their original
//                      order). Always O(n log n), needs O(n) extra memory. Used for history,
//                      indicators and lists shown to the user.
//        * quickSort : pick a pivot (median of first/middle/last), partition, recurse on the
//                      SMALLER side and loop on the bigger one (keeps the stack O(log n)); small
//                      ranges use insertion sort. Average O(n log n), worst case O(n^2).
//        * binarySearch : on a SORTED vector, halve the search range each step. O(log n).
// WHY    Sorting is needed to show history by score/date and to rank threats; binary search is
//        the middle option in the lookup benchmark (linear vs binary vs hash).
// TESTED  against std::sort on random data, plus sorted, reversed, all-equal and stability tests.
// =============================================================================
#pragma once
#include <cstddef>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace phishguard {

namespace detail {

template <class T, class Cmp>
void mergeRec(std::vector<T>& v, std::vector<T>& tmp, std::size_t lo, std::size_t hi, Cmp& cmp) {
    if (hi - lo < 2) return;
    const std::size_t mid = lo + (hi - lo) / 2;
    mergeRec(v, tmp, lo, mid, cmp);
    mergeRec(v, tmp, mid, hi, cmp);
    std::size_t i = lo, j = mid, k = lo;
    while (i < mid && j < hi) tmp[k++] = cmp(v[j], v[i]) ? std::move(v[j++]) : std::move(v[i++]);  // ties: left first => stable
    while (i < mid) tmp[k++] = std::move(v[i++]);
    while (j < hi) tmp[k++] = std::move(v[j++]);
    for (k = lo; k < hi; ++k) v[k] = std::move(tmp[k]);
}

template <class T, class Cmp>
void insertionSort(std::vector<T>& v, long lo, long hi, Cmp& cmp) {
    for (long i = lo + 1; i <= hi; ++i) {
        T key = std::move(v[static_cast<std::size_t>(i)]);
        long j = i - 1;
        while (j >= lo && cmp(key, v[static_cast<std::size_t>(j)])) {
            v[static_cast<std::size_t>(j + 1)] = std::move(v[static_cast<std::size_t>(j)]);
            --j;
        }
        v[static_cast<std::size_t>(j + 1)] = std::move(key);
    }
}

template <class T, class Cmp>
void quickRec(std::vector<T>& v, long lo, long hi, Cmp& cmp) {
    auto at = [&v](long i) -> T& { return v[static_cast<std::size_t>(i)]; };
    while (hi - lo > 16) {
        const long mid = lo + (hi - lo) / 2;
        if (cmp(at(mid), at(lo))) std::swap(at(mid), at(lo));  // median of three
        if (cmp(at(hi), at(lo))) std::swap(at(hi), at(lo));
        if (cmp(at(hi), at(mid))) std::swap(at(hi), at(mid));
        std::swap(at(mid), at(hi - 1));
        const T pivot = at(hi - 1);
        long i = lo, j = hi - 1;
        for (;;) {
            while (cmp(at(++i), pivot)) {}
            while (cmp(pivot, at(--j))) {}
            if (i >= j) break;
            std::swap(at(i), at(j));
        }
        std::swap(at(i), at(hi - 1));
        if (i - lo < hi - i) {
            quickRec(v, lo, i - 1, cmp);
            lo = i + 1;
        } else {
            quickRec(v, i + 1, hi, cmp);
            hi = i - 1;
        }
    }
    insertionSort(v, lo, hi, cmp);
}

}  // namespace detail

template <class T, class Cmp = std::less<T>>
void mergeSort(std::vector<T>& v, Cmp cmp = Cmp()) {
    std::vector<T> tmp(v.size());
    detail::mergeRec(v, tmp, 0, v.size(), cmp);
}

template <class T, class Cmp = std::less<T>>
void quickSort(std::vector<T>& v, Cmp cmp = Cmp()) {
    if (v.size() < 2) return;
    detail::quickRec(v, 0, static_cast<long>(v.size()) - 1, cmp);
}

// Returns the index of key in the SORTED vector, or -1.
inline long binarySearch(const std::vector<std::string>& sorted, const std::string& key,
                         std::size_t* comparisons = nullptr) {
    long lo = 0, hi = static_cast<long>(sorted.size()) - 1;
    while (lo <= hi) {
        const long mid = lo + (hi - lo) / 2;
        if (comparisons) ++*comparisons;
        const int c = sorted[static_cast<std::size_t>(mid)].compare(key);
        if (c == 0) return mid;
        if (c < 0) lo = mid + 1;
        else hi = mid - 1;
    }
    return -1;
}

}  // namespace phishguard
