// =============================================================================
// FILE: include/phishguard/ds/heap.hpp
// WHAT   A binary MAX-HEAP (priority queue): the "largest" element is always on top.
// HOW    The tree is stored in a plain vector: the children of index i live at 2i+1 and 2i+2,
//        its parent at (i-1)/2.
//        * push: add at the end, then "sift up" while it is bigger than its parent.
//        * pop : take the root, move the last element to the root, then "sift down" while a
//                child is bigger.
//        * building from a whole vector uses Floyd's bottom-up heapify, which is O(n).
//        The comparison is a template parameter, so the same heap can rank ints, scan records
//        or batch results by score.
// WHY    A security tool must show the most dangerous items first. A heap hands them over one by
//        one in O(log n) each, without re-sorting everything whenever a new alert arrives.
// COMPLEXITY  push/pop O(log n), top O(1), heapify O(n), space O(n).
// USED BY  batch scanning (rank results) and "highest-risk scans" in the statistics view.
// =============================================================================
#pragma once
#include <functional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace phishguard {

template <class T, class Compare = std::less<T>>
class MaxHeap {
public:
    explicit MaxHeap(Compare cmp = Compare()) : cmp_(cmp) {}

    // Floyd's bottom-up heap construction: O(n), better than n pushes (O(n log n)).
    explicit MaxHeap(std::vector<T> items, Compare cmp = Compare()) : data_(std::move(items)), cmp_(cmp) {
        for (std::size_t i = data_.size() / 2; i-- > 0;) siftDown(i);
    }

    void push(T value) {
        data_.push_back(std::move(value));
        siftUp(data_.size() - 1);
    }

    T pop() {
        if (data_.empty()) throw std::out_of_range("MaxHeap::pop on empty heap");
        T best = std::move(data_.front());
        data_.front() = std::move(data_.back());
        data_.pop_back();
        if (!data_.empty()) siftDown(0);
        return best;
    }

    const T& top() const {
        if (data_.empty()) throw std::out_of_range("MaxHeap::top on empty heap");
        return data_.front();
    }

    std::size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }

    std::vector<T> drainSorted() {  // repeatedly pop: O(n log n), highest first
        std::vector<T> out;
        out.reserve(data_.size());
        while (!data_.empty()) out.push_back(pop());
        return out;
    }

private:
    void siftUp(std::size_t i) {
        while (i > 0) {
            const std::size_t parent = (i - 1) / 2;
            if (!cmp_(data_[parent], data_[i])) break;
            std::swap(data_[parent], data_[i]);
            i = parent;
        }
    }
    void siftDown(std::size_t i) {
        const std::size_t n = data_.size();
        for (;;) {
            std::size_t largest = i;
            const std::size_t l = 2 * i + 1, r = 2 * i + 2;
            if (l < n && cmp_(data_[largest], data_[l])) largest = l;
            if (r < n && cmp_(data_[largest], data_[r])) largest = r;
            if (largest == i) return;
            std::swap(data_[i], data_[largest]);
            i = largest;
        }
    }

    std::vector<T> data_;
    Compare cmp_;
};

}  // namespace phishguard
