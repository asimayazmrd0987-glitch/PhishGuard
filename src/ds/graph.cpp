// =============================================================================
// FILE: src/ds/graph.cpp
// WHAT   Implementation of the graph.
// HOW    * addNode() is idempotent: asking for an existing label returns the existing index.
//        * bfs() keeps a `depth` array initialised to -1; -1 doubles as "not visited yet".
//          The queue is a vector with a moving head index (no std::queue needed).
//        * dfs() pushes neighbours in REVERSE order onto the stack, so nodes are visited in the
//          same order the edges were added (easier to read and to test).
//        * Both traversals handle cycles because every node is marked visited once.
// NOTE   Edge relation text ("contains link", "looks like" ...) is only a label for display.
// =============================================================================

#include "phishguard/ds/graph.hpp"

namespace phishguard {

const char* toString(NodeType type) {
    switch (type) {
        case NodeType::Message:          return "Message";
        case NodeType::Url:              return "Link";
        case NodeType::Domain:           return "Website";
        case NodeType::Ip:               return "IP address";
        case NodeType::Keyword:          return "Keyword";
        case NodeType::TrustedDomain:    return "Trusted website";
        case NodeType::SuspiciousDomain: return "Known scam example";
    }
    return "Unknown";
}

int Graph::addNode(const std::string& label, NodeType type) {
    if (const int* existing = index_.find(label)) return *existing;
    const int idx = static_cast<int>(nodes_.size());
    nodes_.push_back({label, type});
    adj_.emplace_back();
    index_.insert(label, idx);
    return idx;
}

bool Graph::addEdge(int a, int b, const std::string& relation) {
    if (!valid(a) || !valid(b) || a == b) return false;
    for (const Edge& e : adj_[static_cast<std::size_t>(a)])
        if (e.to == b) return false;  // O(degree) duplicate check
    adj_[static_cast<std::size_t>(a)].push_back({b, relation});
    adj_[static_cast<std::size_t>(b)].push_back({a, relation});
    ++edgeCount_;
    return true;
}

bool Graph::addEdge(const std::string& a, const std::string& b, const std::string& relation) {
    return addEdge(indexOf(a), indexOf(b), relation);
}

int Graph::indexOf(const std::string& label) const {
    const int* p = index_.find(label);
    return p ? *p : -1;
}

std::vector<int> Graph::neighbors(int index) const {
    std::vector<int> out;
    if (!valid(index)) return out;
    for (const Edge& e : adj_[static_cast<std::size_t>(index)]) out.push_back(e.to);
    return out;
}

std::string Graph::relationBetween(int a, int b) const {
    if (!valid(a)) return "";
    for (const Edge& e : adj_[static_cast<std::size_t>(a)])
        if (e.to == b) return e.relation;
    return "";
}

std::vector<Visit> Graph::bfs(int start, int maxDepth) const {
    std::vector<Visit> order;
    if (!valid(start)) return order;
    std::vector<int> depth(nodes_.size(), -1);
    std::vector<int> queue{start};  // vector + head index = simple FIFO queue
    depth[static_cast<std::size_t>(start)] = 0;
    for (std::size_t head = 0; head < queue.size(); ++head) {
        const int u = queue[head];
        const int d = depth[static_cast<std::size_t>(u)];
        order.push_back({u, d});
        if (maxDepth >= 0 && d >= maxDepth) continue;
        for (const Edge& e : adj_[static_cast<std::size_t>(u)]) {
            if (depth[static_cast<std::size_t>(e.to)] < 0) {
                depth[static_cast<std::size_t>(e.to)] = d + 1;
                queue.push_back(e.to);
            }
        }
    }
    return order;
}

std::vector<Visit> Graph::dfs(int start) const {
    std::vector<Visit> order;
    if (!valid(start)) return order;
    std::vector<char> seen(nodes_.size(), 0);
    std::vector<Visit> stack{{start, 0}};
    while (!stack.empty()) {
        const Visit cur = stack.back();
        stack.pop_back();
        if (seen[static_cast<std::size_t>(cur.node)]) continue;
        seen[static_cast<std::size_t>(cur.node)] = 1;
        order.push_back(cur);
        const auto& edges = adj_[static_cast<std::size_t>(cur.node)];
        for (auto it = edges.rbegin(); it != edges.rend(); ++it)  // reverse: keeps natural order
            if (!seen[static_cast<std::size_t>(it->to)]) stack.push_back({it->to, cur.depth + 1});
    }
    return order;
}

}  // namespace phishguard
