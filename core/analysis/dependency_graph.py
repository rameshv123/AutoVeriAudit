from __future__ import annotations
from typing import List, Dict, Tuple
import networkx as nx
from utils.helpers import Vulnerability

def build_dependency_graph(vulns: List[Vulnerability]) -> nx.DiGraph:
    g = nx.DiGraph()
    for v in vulns:
        g.add_node(v.vuln_id, contract_id=v.contract_id, vtype=v.vtype)

    by_contract: Dict[str, List[Vulnerability]] = {}
    for v in vulns:
        by_contract.setdefault(v.contract_id, []).append(v)

    # Heuristic dependencies within a contract (extend with real trace/call graph evidence)
    for cid, vs in by_contract.items():
        ids = {}
        for v in vs:
            ids.setdefault(v.vtype, []).append(v.vuln_id)
        # access_control can amplify reentrancy risk
        for ac in ids.get("access_control", []):
            for reid in ids.get("reentrancy", []):
                g.add_edge(ac, reid)
    return g

def dependency_edges(g: nx.DiGraph) -> List[Tuple[str, str]]:
    return list(g.edges())

def propagate_severity(scores: Dict[str, float], edges: List[Tuple[str,str]], lam: float, max_iter: int, normalize: bool) -> Dict[str, float]:
    # Iterative propagation: score[u] += lam * score[v] for edges u->v
    cur = dict(scores)
    for _ in range(max_iter):
        nxt = dict(cur)
        for u, v in edges:
            if u in cur and v in cur:
                nxt[u] = min(1.0, nxt[u] + lam * cur[v])
        cur = nxt
        if normalize:
            mx = max(cur.values()) if cur else 1.0
            if mx > 0:
                cur = {k: min(1.0, v / mx) for k, v in cur.items()}
    return cur
