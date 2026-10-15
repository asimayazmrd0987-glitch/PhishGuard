// =============================================================================
// FILE: include/phishguard/ds/graph.hpp
// WHAT   An undirected GRAPH stored as an ADJACENCY LIST, used to show how scans, links,
//        websites, keywords and trusted sites are related.
// HOW    * Nodes are numbered 0..V-1; a hash table maps a text label to its number.
//        * adj_[i] is the list of neighbours of node i (each edge is stored twice, once per end).
//        * BFS (breadth-first): uses a queue; visits the nearest nodes first and records the hop
//          distance ("depth"). Good for "what is closely related to this?".
//        * DFS (depth-first): uses an explicit stack; follows one chain as far as it goes before
//          backing up. Good for "what is the whole chain connected to this?".
// WHY    The relationships are SPARSE (a message links to a few URLs, not to every node).
//        An adjacency list needs O(V + E) memory; an adjacency matrix would need O(V^2).
//        Because labels are shared, the same website in two scans becomes ONE node, which
//        automatically connects those two scans.
// COMPLEXITY  addNode ~O(1); addEdge O(degree) (duplicate check); BFS/DFS O(V + E) time, O(V) space.
// =============================================================================
#pragma once
#include <cstddef>
#include <string>
#include <vector>

#include "phishguard/ds/hash_table.hpp"

namespace phishguard {

enum class NodeType { Message, Url, Domain, Ip, Keyword, TrustedDomain, SuspiciousDomain };
const char* toString(NodeType type);

struct GraphNode {
    std::string label;
    NodeType type;
};

struct Visit {
    int node;
    int depth;
};

class Graph {
public:
    int addNode(const std::string& label, NodeType type);  // idempotent on label, returns index
    bool addEdge(int a, int b, const std::string& relation = "");  // false: invalid, self-loop or duplicate
    bool addEdge(const std::string& a, const std::string& b, const std::string& relation = "");

    int indexOf(const std::string& label) const;  // -1 if missing
    const GraphNode& node(int index) const { return nodes_.at(static_cast<std::size_t>(index)); }
    std::vector<int> neighbors(int index) const;
    std::string relationBetween(int a, int b) const;

    std::size_t nodeCount() const { return nodes_.size(); }
    std::size_t edgeCount() const { return edgeCount_; }

    // Breadth-first: nearest nodes first, depth = hop distance. maxDepth<0 means unlimited.
    std::vector<Visit> bfs(int start, int maxDepth = -1) const;
    // Depth-first (iterative, explicit stack): follows one chain as far as it goes.
    std::vector<Visit> dfs(int start) const;

private:
    struct Edge {
        int to;
        std::string relation;
    };
    bool valid(int i) const { return i >= 0 && static_cast<std::size_t>(i) < nodes_.size(); }

    HashTable<std::string, int> index_;
    std::vector<GraphNode> nodes_;
    std::vector<std::vector<Edge>> adj_;
    std::size_t edgeCount_ = 0;
};

}  // namespace phishguard
