// =============================================================================
// FILE: include/phishguard/ds/trie.hpp
// WHAT   A TRIE (prefix tree) that stores the suspicious keywords ("verify", "otp", "password" ...).
// HOW    Each node represents one letter; a path from the root spells a word; a flag marks
//        where a real keyword ends. Words that share a beginning share nodes, so
//        "verify", "verified" and "verification" reuse the path v-e-r-i-f-y.
//        * contains/find: follow the letters; O(L) where L = word length.
//        * startsWith / wordsWithPrefix: follow the prefix, then list everything below it.
//        * remove: unmark the word, then delete nodes on the way back up only if nothing else
//          needs them (so deleting "banker" keeps "bank").
//        * scanText: from every word start in a message, walk down the trie and accept a match
//          only if the next character is not a letter/digit (so "pin" matches in "your PIN"
//          but not in "pinterest").
// WHY    The lookup cost depends on the word length, not on how many keywords exist, and a trie
//        supports prefix queries, which a hash table cannot do.
// TRADE-OFF  Each node holds 128 child pointers: very fast, but memory-hungry for huge
//        dictionaries (a compressed/radix trie would save space).
// COMPLEXITY  insert/search/remove O(L); scanText O(n x longest keyword); space O(total letters x 128).
// =============================================================================
#pragma once
#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace phishguard {

struct KeywordInfo {
    std::string category;
    int weight = 0;
};

struct KeywordMatch {
    std::string word;
    std::size_t position = 0;
    KeywordInfo info;
};

class Trie {
public:
    static constexpr std::size_t kAlphabet = 128;

    Trie();

    bool insert(const std::string& word, KeywordInfo info = {});  // true if new; throws on empty/non-ASCII
    bool contains(const std::string& word) const;
    const KeywordInfo* find(const std::string& word) const;
    bool startsWith(const std::string& prefix) const;
    std::vector<std::string> wordsWithPrefix(const std::string& prefix, std::size_t limit = 100) const;
    bool remove(const std::string& word);  // prunes nodes no longer needed

    std::size_t size() const { return size_; }
    std::size_t nodeCount() const { return nodeCount_; }

    // Finds every whole-word keyword occurrence in text. Cost O(n * Lmax) worst case.
    std::vector<KeywordMatch> scanText(const std::string& text) const;

private:
    struct Node {
        std::array<std::unique_ptr<Node>, kAlphabet> next;
        bool end = false;
        KeywordInfo info;
    };

    const Node* walk(const std::string& s) const;
    bool removeRec(Node* node, const std::string& w, std::size_t depth, bool& removed);
    static bool hasChildren(const Node* n);
    void collect(const Node* n, std::string& prefix, std::vector<std::string>& out, std::size_t limit) const;

    std::unique_ptr<Node> root_;
    std::size_t size_ = 0;
    std::size_t nodeCount_ = 1;
};

}  // namespace phishguard
