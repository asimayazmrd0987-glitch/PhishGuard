// =============================================================================
// FILE: tests/test_ds.cpp
// WHAT   Tests for the hand-written data structures: hash table (including FORCED collisions and
//        rehashing), set, trie (prefix sharing, deletion, whole-word scan), heap (equal priorities,
//        heapify), graph (idempotent nodes, BFS depth, DFS order, cycles, unreachable nodes).
// =============================================================================

#include <string>
#include <vector>

#include "phishguard/ds/custom_set.hpp"
#include "phishguard/ds/graph.hpp"
#include "phishguard/ds/hash_table.hpp"
#include "phishguard/ds/heap.hpp"
#include "phishguard/ds/trie.hpp"
#include "test_harness.hpp"

using namespace phishguard;

namespace {
struct ConstantHash {  // forces EVERY key into one bucket: worst-case collision test
    std::size_t operator()(const std::string&) const { return 7; }
};
}  // namespace

TEST(hash_insert_find_update_remove) {
    HashTable<std::string, int> t;
    CHECK(t.insert("a.com", 1));
    CHECK(!t.insert("a.com", 2));  // update, not new
    CHECK_EQ(*t.find("a.com"), 2);
    CHECK_EQ(t.size(), 1u);
    CHECK(t.find("b.com") == nullptr);
    CHECK(t.remove("a.com"));
    CHECK(!t.remove("a.com"));
    CHECK(t.empty());
}

TEST(hash_collisions_are_handled_by_chaining) {
    HashTable<std::string, int, ConstantHash> t(17, 100.0);  // huge load limit: never rehash
    for (int i = 0; i < 50; ++i) t.insert("k" + std::to_string(i), i);
    CHECK_EQ(t.size(), 50u);
    CHECK_EQ(t.maxChainLength(), 50u);
    CHECK_EQ(t.collisionCount(), 49u);
    for (int i = 0; i < 50; ++i) CHECK_EQ(*t.find("k" + std::to_string(i)), i);
    CHECK(t.remove("k25"));  // middle of the chain
    CHECK(t.find("k25") == nullptr);
    CHECK(t.find("k24") != nullptr && t.find("k26") != nullptr);
    CHECK(t.remove("k49"));  // head of chain (inserted last)
    CHECK(t.remove("k0"));   // tail of chain
    CHECK_EQ(t.size(), 47u);
}

TEST(hash_rehash_keeps_load_factor_and_data) {
    HashTable<std::string, int> t(5);
    const std::size_t start = t.bucketCount();
    for (int i = 0; i < 1000; ++i) t.insert("host" + std::to_string(i), i);
    CHECK(t.bucketCount() > start);
    CHECK(t.loadFactor() <= 0.75 + 1e-9);
    for (int i = 0; i < 1000; ++i) CHECK(t.contains("host" + std::to_string(i)));
    std::size_t visited = 0;
    t.forEach([&](const std::string&, const int&) { ++visited; });
    CHECK_EQ(visited, 1000u);
}

TEST(set_basic_operations) {
    CustomSet<std::string> s;
    CHECK(s.insert("x"));
    CHECK(!s.insert("x"));
    CHECK(s.contains("x"));
    CHECK(s.insert("y"));
    CHECK_EQ(s.size(), 2u);
    CHECK(s.remove("x"));
    CHECK(!s.contains("x"));
    CHECK_EQ(s.toVector().size(), 1u);
}

TEST(trie_insert_search_prefix) {
    Trie t;
    CHECK(t.insert("verify", {"credential", 8}));
    CHECK(t.insert("verification"));
    CHECK(t.insert("verified"));
    CHECK(!t.insert("VERIFY"));  // case-insensitive duplicate
    CHECK(t.contains("Verify"));
    CHECK(!t.contains("veri"));  // prefix only
    CHECK(t.startsWith("veri"));
    CHECK(!t.startsWith("xyz"));
    CHECK_EQ(t.find("verify")->weight, 8);
    const auto words = t.wordsWithPrefix("verif");
    CHECK_EQ(words.size(), 3u);
    CHECK_EQ(words[0], std::string("verification"));  // alphabetical order
    CHECK_THROWS(t.insert(""));
}

TEST(trie_remove_keeps_shared_prefixes) {
    Trie t;
    t.insert("bank");
    t.insert("banker");
    t.insert("bar");
    const std::size_t nodes = t.nodeCount();
    CHECK(t.remove("banker"));
    CHECK(t.contains("bank"));  // shorter word survives
    CHECK(!t.contains("banker"));
    CHECK(t.nodeCount() < nodes);  // pruned the 'e','r' nodes
    CHECK(t.remove("bank"));
    CHECK(t.contains("bar"));
    CHECK(!t.remove("bank"));
    CHECK(!t.remove("missing"));
    CHECK_EQ(t.size(), 1u);
}

TEST(trie_scan_finds_whole_words_only) {
    Trie t;
    t.insert("pin", {"credential", 10});
    t.insert("bank", {"financial", 6});
    const auto m = t.scanText("Send your PIN to the Bank, not to pinterest or banking!");
    CHECK_EQ(m.size(), 2u);
    CHECK_EQ(m[0].word, std::string("pin"));
    CHECK_EQ(m[1].word, std::string("bank"));
    CHECK(t.scanText("").empty());
}

TEST(heap_orders_by_priority) {
    MaxHeap<int> h;
    for (int v : {42, 18, 92, 88, 74, 69}) h.push(v);
    CHECK_EQ(h.top(), 92);
    CHECK_EQ(h.pop(), 92);
    CHECK_EQ(h.pop(), 88);
    CHECK_EQ(h.pop(), 74);
    CHECK_EQ(h.size(), 3u);
    CHECK_THROWS(MaxHeap<int>().pop());
}

TEST(heap_handles_equal_priorities_and_heapify) {
    MaxHeap<int> h(std::vector<int>{5, 5, 5, 1, 9, 5});
    const auto sorted = h.drainSorted();
    CHECK_EQ(sorted.size(), 6u);
    for (std::size_t i = 1; i < sorted.size(); ++i) CHECK(sorted[i - 1] >= sorted[i]);
}

TEST(graph_nodes_edges_and_idempotence) {
    Graph g;
    const int a = g.addNode("A", NodeType::Message);
    CHECK_EQ(g.addNode("A", NodeType::Url), a);  // same label => same node
    const int b = g.addNode("B", NodeType::Url);
    CHECK(g.addEdge(a, b, "contains"));
    CHECK(!g.addEdge(a, b));   // duplicate
    CHECK(!g.addEdge(a, a));   // self loop
    CHECK(!g.addEdge(a, 99));  // invalid index
    CHECK_EQ(g.nodeCount(), 2u);
    CHECK_EQ(g.edgeCount(), 1u);
    CHECK(g.indexOf("zzz") == -1);
}

TEST(graph_bfs_depths_and_dfs_order) {
    // A - B - D,  A - C,  E isolated
    Graph g;
    for (const char* n : {"A", "B", "C", "D", "E"}) g.addNode(n, NodeType::Domain);
    g.addEdge("A", "B");
    g.addEdge("A", "C");
    g.addEdge("B", "D");
    const auto bfs = g.bfs(g.indexOf("A"));
    CHECK_EQ(bfs.size(), 4u);  // E unreachable
    CHECK_EQ(g.node(bfs[0].node).label, std::string("A"));
    CHECK_EQ(bfs[1].depth, 1);
    CHECK_EQ(g.node(bfs[3].node).label, std::string("D"));
    CHECK_EQ(bfs[3].depth, 2);
    CHECK_EQ(g.bfs(g.indexOf("A"), 1).size(), 3u);  // depth limit
    const auto dfs = g.dfs(g.indexOf("A"));
    CHECK_EQ(dfs.size(), 4u);
    CHECK_EQ(g.node(dfs[1].node).label, std::string("B"));  // follows B before C
    CHECK_EQ(g.node(dfs[2].node).label, std::string("D"));
    CHECK_EQ(g.node(dfs[3].node).label, std::string("C"));
    CHECK(g.bfs(-1).empty());
}

TEST(graph_handles_cycles) {
    Graph g;
    for (const char* n : {"X", "Y", "Z"}) g.addNode(n, NodeType::Domain);
    g.addEdge("X", "Y");
    g.addEdge("Y", "Z");
    g.addEdge("Z", "X");
    CHECK_EQ(g.bfs(0).size(), 3u);
    CHECK_EQ(g.dfs(0).size(), 3u);
}
