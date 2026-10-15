// =============================================================================
// FILE: src/security/graph_builder.cpp
// WHAT   Converts an AnalysisResult into graph nodes and edges.
// HOW    Website nodes are typed: IP address, known scam example (if it matches a threat entry or a
//        subdomain of one) or ordinary website. urls[i] pairs with domains[i] (empty if the link
//        could not be parsed). The look-alike edge goes to the website the match came from.
// =============================================================================

#include "phishguard/security/graph_builder.hpp"

#include "phishguard/common/text_utils.hpp"
#include "phishguard/ds/custom_set.hpp"

namespace phishguard {

void addScanToGraph(Graph& g, int scanId, const AnalysisResult& r) {
    const std::string root = "Scan #" + std::to_string(scanId);
    const int rootIdx = g.addNode(root, NodeType::Message);

    CustomSet<std::string> ips;
    for (const auto& ip : r.findings.ips) ips.insert(ip);

    for (std::size_t i = 0; i < r.findings.urls.size(); ++i) {
        const int u = g.addNode(r.findings.urls[i], NodeType::Url);
        g.addEdge(rootIdx, u, "contains link");
        const std::string& host = i < r.findings.domains.size() ? r.findings.domains[i] : "";
        if (host.empty()) continue;

        NodeType type = ips.contains(host) ? NodeType::Ip : NodeType::Domain;
        for (const auto& threat : r.findings.threatDomains)
            if (host == threat || text::endsWith(host, "." + threat)) type = NodeType::SuspiciousDomain;
        const int d = g.addNode(host, type);
        g.addEdge(u, d, "points to");

        if (r.findings.impersonation && r.findings.impersonation->inputPart.find(host) != std::string::npos) {
            const int t = g.addNode(r.findings.impersonation->trustedDomain, NodeType::TrustedDomain);
            g.addEdge(d, t, r.findings.impersonation->embedded ? "hides name of" : "looks like");
        }
    }
    // Look-alike found via a token/registered domain of a host not matched textually above.
    if (r.findings.impersonation && r.findings.domains.size() == 1 && !r.findings.domains[0].empty()) {
        const int d = g.indexOf(r.findings.domains[0]);
        const int t = g.addNode(r.findings.impersonation->trustedDomain, NodeType::TrustedDomain);
        g.addEdge(d, t, r.findings.impersonation->embedded ? "hides name of" : "looks like");
    }
    for (const auto& kw : r.findings.keywords) {
        const int k = g.addNode(kw, NodeType::Keyword);
        g.addEdge(rootIdx, k, "mentions");
    }
}

}  // namespace phishguard
