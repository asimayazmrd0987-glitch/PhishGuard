// =============================================================================
// FILE: include/phishguard/security/graph_builder.hpp
// WHAT   Adds one scan to the session graph.
// HOW    Scan #N -> links -> websites -> keywords, plus website -> trusted site ("looks like" /
//        "hides name of"). Labels are shared, so the same website seen in two scans joins them.
// WHY    Lets the user ask: "what else is connected to this website?" (BFS/DFS in the UI).
// =============================================================================
#pragma once
#include "phishguard/common/types.hpp"
#include "phishguard/ds/graph.hpp"

namespace phishguard {

// Adds "Scan #id" -> links -> websites -> keywords / trusted look-alikes to the session graph.
// Because node labels are shared, a domain seen in several scans links those scans together.
void addScanToGraph(Graph& graph, int scanId, const AnalysisResult& result);

}  // namespace phishguard
