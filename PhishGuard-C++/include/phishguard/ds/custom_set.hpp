// =============================================================================
// FILE: include/phishguard/ds/custom_set.hpp
// WHAT   A set (a collection with no duplicates) built on our HashTable.
// HOW    Each element is stored as a KEY in the hash table with a dummy value (a single char).
//        insert() returns true only if the element was new, which is exactly what we need for
//        "have I already counted this indicator?".
// WHY    Reuses the hash table instead of duplicating its logic, and gives O(1) membership tests
//        for the TLD list, shortener list and indicator de-duplication.
// COMPLEXITY  insert/contains/remove: average O(1).  Space: O(n).
// =============================================================================
#pragma once
#include <vector>

#include "phishguard/ds/hash_table.hpp"

namespace phishguard {

template <class T, class Hash = Fnv1aHash>
class CustomSet {
public:
    bool insert(const T& value) { return table_.insert(value, 1); }  // true if newly added
    bool contains(const T& value) const { return table_.contains(value); }
    bool remove(const T& value) { return table_.remove(value); }
    std::size_t size() const { return table_.size(); }
    bool empty() const { return table_.empty(); }
    void clear() { table_.clear(); }
    std::vector<T> toVector() const {
        std::vector<T> out;
        table_.forEach([&](const T& key, const char&) { out.push_back(key); });
        return out;
    }

private:
    HashTable<T, char, Hash> table_;
};

}  // namespace phishguard
