// =============================================================================
// FILE: include/phishguard/ds/hash_table.hpp
// WHAT   A hash table written from scratch (key -> value), using SEPARATE CHAINING.
// HOW    * The table is a vector of "buckets"; each bucket is a singly linked list.
//        * hash(key) % bucketCount picks the bucket; we walk that short list to find the key.
//        * Two keys landing in one bucket is a COLLISION; chaining simply keeps both in the list.
//        * When size/buckets would exceed the max load factor (0.75) we REHASH: allocate about
//          twice as many buckets (always a prime number) and move every node over.
//        * Hash function: FNV-1a (xor each byte, multiply by a large prime): fast and well mixed.
// WHY    Threat lookups happen on every scan. Scanning a list costs O(n); a hash table costs
//        about O(1). Chaining was chosen over open addressing because deletion is simple.
// COMPLEXITY  insert/find/remove: average O(1), worst case O(n) if every key collides.
//             Rehash: O(n) but rare, so amortised O(1) per insert.  Space: O(n + buckets).
// USED BY  threat database, trusted domains, config values, the graph's label index,
//          the custom set, history statistics.
// TESTED   tests/test_ds.cpp, including a hash function that sends every key to ONE bucket.
// =============================================================================
#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace phishguard {

// FNV-1a 64-bit string hash: xor the byte, multiply by a large prime. Cheap and well mixed.
struct Fnv1aHash {
    std::size_t operator()(const std::string& s) const noexcept {
        std::uint64_t h = 14695981039346656037ULL;
        for (unsigned char c : s) {
            h ^= c;
            h *= 1099511628211ULL;
        }
        return static_cast<std::size_t>(h);
    }
};

// Smallest prime >= n. Prime bucket counts spread poorly-distributed hashes better.
inline std::size_t nextPrime(std::size_t n) {
    if (n <= 2) return 2;
    if (n % 2 == 0) ++n;
    for (;; n += 2) {
        bool prime = true;
        for (std::size_t d = 3; d * d <= n; d += 2)
            if (n % d == 0) { prime = false; break; }
        if (prime) return n;
    }
}

template <class K, class V, class Hash = Fnv1aHash>
class HashTable {
    struct Node {
        K key;
        V value;
        std::unique_ptr<Node> next;
        Node(const K& k, V v) : key(k), value(std::move(v)) {}
    };

public:
    explicit HashTable(std::size_t initialBuckets = 17, double maxLoadFactor = 0.75, Hash hash = Hash())
        : buckets_(nextPrime(initialBuckets < 3 ? 3 : initialBuckets)),
          maxLoad_(maxLoadFactor),
          hash_(hash) {}

    HashTable(const HashTable&) = delete;
    HashTable& operator=(const HashTable&) = delete;
    HashTable(HashTable&&) noexcept = default;
    HashTable& operator=(HashTable&&) noexcept = default;
    ~HashTable() { clear(); }

    // Returns true if the key was new, false if an existing value was replaced.
    bool insert(const K& key, V value) {
        if (V* existing = find(key)) {
            *existing = std::move(value);
            return false;
        }
        if (static_cast<double>(size_ + 1) > maxLoad_ * static_cast<double>(buckets_.size()))
            rehash(nextPrime(buckets_.size() * 2));
        auto node = std::make_unique<Node>(key, std::move(value));
        auto& head = buckets_[indexFor(key)];
        node->next = std::move(head);  // insert at head: O(1)
        head = std::move(node);
        ++size_;
        return true;
    }

    const V* find(const K& key) const {
        for (const Node* n = buckets_[indexFor(key)].get(); n != nullptr; n = n->next.get()) {
            ++comparisons_;
            if (n->key == key) return &n->value;
        }
        return nullptr;
    }
    V* find(const K& key) { return const_cast<V*>(static_cast<const HashTable&>(*this).find(key)); }

    bool contains(const K& key) const { return find(key) != nullptr; }

    bool remove(const K& key) {
        std::unique_ptr<Node>* link = &buckets_[indexFor(key)];
        while (*link) {
            ++comparisons_;
            if ((*link)->key == key) {
                std::unique_ptr<Node> dead = std::move(*link);
                *link = std::move(dead->next);  // unlink; 'dead' now has no chain to destroy
                --size_;
                return true;
            }
            link = &(*link)->next;
        }
        return false;
    }

    template <class F>
    void forEach(F&& f) const {  // f(const K&, const V&)
        for (const auto& head : buckets_)
            for (const Node* n = head.get(); n != nullptr; n = n->next.get()) f(n->key, n->value);
    }

    void clear() {  // iterative: avoids deep recursion when destroying long chains
        for (auto& head : buckets_) {
            while (head) {
                std::unique_ptr<Node> next = std::move(head->next);
                head = std::move(next);
            }
        }
        size_ = 0;
    }

    std::size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }
    std::size_t bucketCount() const { return buckets_.size(); }
    double loadFactor() const {
        return buckets_.empty() ? 0.0 : static_cast<double>(size_) / static_cast<double>(buckets_.size());
    }

    std::size_t maxChainLength() const {
        std::size_t best = 0;
        for (const auto& head : buckets_) {
            std::size_t len = 0;
            for (const Node* n = head.get(); n != nullptr; n = n->next.get()) ++len;
            if (len > best) best = len;
        }
        return best;
    }
    // Number of keys that share a bucket with an earlier key = size - non-empty buckets.
    std::size_t collisionCount() const {
        std::size_t used = 0;
        for (const auto& head : buckets_)
            if (head) ++used;
        return size_ - used;
    }

    std::size_t comparisons() const { return comparisons_; }
    void resetComparisons() { comparisons_ = 0; }

private:
    std::size_t indexFor(const K& key) const { return hash_(key) % buckets_.size(); }

    void rehash(std::size_t newCount) {
        std::vector<std::unique_ptr<Node>> fresh(newCount);
        for (auto& head : buckets_) {
            while (head) {
                std::unique_ptr<Node> node = std::move(head);
                head = std::move(node->next);
                const std::size_t idx = hash_(node->key) % newCount;
                node->next = std::move(fresh[idx]);
                fresh[idx] = std::move(node);
            }
        }
        buckets_ = std::move(fresh);
    }

    std::vector<std::unique_ptr<Node>> buckets_;
    std::size_t size_ = 0;
    double maxLoad_;
    Hash hash_;
    mutable std::size_t comparisons_ = 0;
};

}  // namespace phishguard
