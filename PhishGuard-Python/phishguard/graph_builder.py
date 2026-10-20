"""Builds a relationship graph from a single scan result."""
from __future__ import annotations
from .ds import Graph, NodeType, CustomSet
from .types import AnalysisResult

def add_scan_to_graph(graph: Graph, scan_id: int, result: AnalysisResult) -> None:
    root_label = f'Scan #{scan_id}'
    root_idx = graph.add_node(root_label, NodeType.MESSAGE)
    ips = CustomSet(result.findings.ips)
    for i, url in enumerate(result.findings.urls):
        url_idx = graph.add_node(url, NodeType.URL)
        graph.add_edge(root_idx, url_idx, 'contains link')
        host = result.findings.domains[i] if i < len(result.findings.domains) else ''
        if not host: continue
        node_type = NodeType.IP if ips.contains(host) else NodeType.DOMAIN
        for threat in result.findings.threat_domains:
            if host == threat or host.endswith('.' + threat): node_type = NodeType.SUSPICIOUS_DOMAIN
        domain_idx = graph.add_node(host, node_type)
        graph.add_edge(url_idx, domain_idx, 'points to')
        match = result.findings.impersonation
        if match and match.input_part.find(host) != -1:
            target = graph.add_node(match.trusted_domain, NodeType.TRUSTED_DOMAIN)
            graph.add_edge(domain_idx, target, 'hides name of' if match.embedded else 'looks like')
    match = result.findings.impersonation
    if match and len(result.findings.domains) == 1 and result.findings.domains[0]:
        domain_idx = graph.index_of(result.findings.domains[0])
        target = graph.add_node(match.trusted_domain, NodeType.TRUSTED_DOMAIN)
        graph.add_edge(domain_idx, target, 'hides name of' if match.embedded else 'looks like')
    for keyword in result.findings.keywords:
        idx = graph.add_node(keyword, NodeType.KEYWORD)
        graph.add_edge(root_idx, idx, 'mentions')
