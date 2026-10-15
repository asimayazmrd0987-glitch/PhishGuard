// =============================================================================
// FILE: src/ds/trie.cpp
// WHAT   Implementation of the Trie declared in include/phishguard/ds/trie.hpp.
// HOW    * slot(c) lower-cases a character and turns it into an array index 0..127 (or -1 for
//          non-ASCII, which the trie does not store).
//        * insert() validates the whole word first, so a bad word can never leave half-built
//          nodes behind. Inserting an existing word keeps the original info (like std::set).
//        * removeRec() is recursive: it returns "true" to its parent when the child node is now
//          useless (no children and not the end of another word) so the parent can delete it.
//        * scanText() skips positions inside a word (previous char alphanumeric) so it only
//          tests real word starts.
// BUGS TO WATCH  Any change to removeRec must keep the nodeCount_/size_ counters in step;
//          tests/test_ds.cpp::trie_remove_keeps_shared_prefixes guards this.
// =============================================================================

#include "phishguard/ds/trie.hpp"

#include <cctype>
#include <stdexcept>

#include "phishguard/common/text_utils.hpp"

namespace phishguard {

namespace {
int slot(char c) {
    const auto u = static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(c)));
    return u < Trie::kAlphabet ? static_cast<int>(u) : -1;
}
}  // namespace

Trie::Trie() : root_(std::make_unique<Node>()) {}

bool Trie::insert(const std::string& word, KeywordInfo info) {
    if (word.empty()) throw std::invalid_argument("keyword must not be empty");
    for (char c : word)
        if (slot(c) < 0) throw std::invalid_argument("keyword must be ASCII: " + word);

    Node* cur = root_.get();
    for (char c : word) {
        const int i = slot(c);
        if (!cur->next[static_cast<std::size_t>(i)]) {
            cur->next[static_cast<std::size_t>(i)] = std::make_unique<Node>();
            ++nodeCount_;
        }
        cur = cur->next[static_cast<std::size_t>(i)].get();
    }
    if (cur->end) return false;  // already present: keep the existing info (like std::set)
    cur->end = true;
    cur->info = std::move(info);
    ++size_;
    return true;
}

const Trie::Node* Trie::walk(const std::string& s) const {
    const Node* cur = root_.get();
    for (char c : s) {
        const int i = slot(c);
        if (i < 0 || !cur->next[static_cast<std::size_t>(i)]) return nullptr;
        cur = cur->next[static_cast<std::size_t>(i)].get();
    }
    return cur;
}

bool Trie::contains(const std::string& word) const { return find(word) != nullptr; }

const KeywordInfo* Trie::find(const std::string& word) const {
    if (word.empty()) return nullptr;
    const Node* n = walk(word);
    return (n && n->end) ? &n->info : nullptr;
}

bool Trie::startsWith(const std::string& prefix) const { return walk(prefix) != nullptr; }

void Trie::collect(const Node* n, std::string& prefix, std::vector<std::string>& out, std::size_t limit) const {
    if (out.size() >= limit) return;
    if (n->end) out.push_back(prefix);
    for (std::size_t i = 0; i < kAlphabet; ++i) {
        if (!n->next[i]) continue;
        prefix.push_back(static_cast<char>(i));
        collect(n->next[i].get(), prefix, out, limit);
        prefix.pop_back();
    }
}

std::vector<std::string> Trie::wordsWithPrefix(const std::string& prefix, std::size_t limit) const {
    std::vector<std::string> out;
    const Node* n = walk(prefix);
    if (!n) return out;
    std::string p = text::toLower(prefix);
    collect(n, p, out, limit);
    return out;
}

bool Trie::hasChildren(const Node* n) {
    for (const auto& c : n->next)
        if (c) return true;
    return false;
}

bool Trie::removeRec(Node* node, const std::string& w, std::size_t depth, bool& removed) {
    if (depth == w.size()) {
        if (!node->end) return false;
        node->end = false;
        node->info = {};
        removed = true;
        --size_;
        return !hasChildren(node);  // prune if nothing hangs below
    }
    const int i = slot(w[depth]);
    if (i < 0 || !node->next[static_cast<std::size_t>(i)]) return false;
    if (removeRec(node->next[static_cast<std::size_t>(i)].get(), w, depth + 1, removed)) {
        node->next[static_cast<std::size_t>(i)].reset();
        --nodeCount_;
        return !node->end && !hasChildren(node);  // keep nodes that end another word
    }
    return false;
}

bool Trie::remove(const std::string& word) {
    if (word.empty()) return false;
    bool removed = false;
    removeRec(root_.get(), word, 0, removed);
    return removed;
}

std::vector<KeywordMatch> Trie::scanText(const std::string& text) const {
    std::vector<KeywordMatch> matches;
    const std::size_t n = text.size();
    for (std::size_t start = 0; start < n; ++start) {
        if (start > 0 && text::isAlnumChar(text[start - 1])) continue;  // only at word starts
        const Node* cur = root_.get();
        std::size_t j = start;
        std::size_t lastEnd = 0;
        bool found = false;
        while (j < n) {
            const int i = slot(text[j]);
            if (i < 0 || !cur->next[static_cast<std::size_t>(i)]) break;
            cur = cur->next[static_cast<std::size_t>(i)].get();
            ++j;
            if (cur->end && (j == n || !text::isAlnumChar(text[j]))) {  // whole word only
                lastEnd = j;
                found = true;
            }
        }
        if (found) {
            const std::string word = text.substr(start, lastEnd - start);
            matches.push_back({text::toLower(word), start, walk(word)->info});
        }
    }
    return matches;
}

}  // namespace phishguard
