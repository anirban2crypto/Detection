"""
Graph Algorithms for Threat Detection

Applies graph-theoretic algorithms to the security knowledge graph:

1. PageRank           — Identify high-influence / pivotal nodes
2. Community Detection — Find clusters of related suspicious entities (Louvain)
3. Shortest Path      — Trace attack paths from entry to exfiltration
4. Node Centrality    — Betweenness centrality to find bottleneck devices
5. Anomaly Scoring    — Degree-based anomaly detection

All algorithms operate on a NetworkX projection of the Neo4j graph.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import networkx as nx
import pandas as pd
from loguru import logger
from config.neo4j_connection import get_session


# ─────────────────────────────────────────────────────────────────────────────
# Graph Projection: Neo4j → NetworkX
# ─────────────────────────────────────────────────────────────────────────────

def project_graph_from_neo4j(session) -> nx.DiGraph:
    """
    Project the full threat graph from Neo4j into a NetworkX DiGraph.
    Nodes carry label and properties; edges carry relationship type and properties.
    """
    G = nx.DiGraph()

    # Project nodes
    node_query = """
    MATCH (n)
    WHERE n:User OR n:Device OR n:IP OR n:Technique OR n:Campaign OR n:Malware
    RETURN id(n) AS nid,
           labels(n)[0] AS label,
           properties(n) AS props
    """
    result = session.run(node_query)
    for record in result:
        nid = record["nid"]
        label = record["label"]
        props = dict(record["props"])
        display_id = (
            props.get("user_id")
            or props.get("hostname")
            or props.get("address")
            or props.get("mitre_id")
            or props.get("name")
            or props.get("hash")
            or str(nid)
        )
        G.add_node(display_id, neo4j_id=nid, label=label, **props)

    # Project relationships
    rel_query = """
    MATCH (a)-[r]->(b)
    WHERE (a:User OR a:Device OR a:IP OR a:Technique OR a:Campaign OR a:Malware)
      AND (b:User OR b:Device OR b:IP OR b:Technique OR b:Campaign OR b:Malware)
    WITH a, r, b, labels(a)[0] AS a_label, labels(b)[0] AS b_label
    RETURN
        COALESCE(a.user_id, a.hostname, a.address, a.mitre_id, a.name, a.hash, toString(id(a))) AS src,
        COALESCE(b.user_id, b.hostname, b.address, b.mitre_id, b.name, b.hash, toString(id(b))) AS dst,
        type(r) AS rel_type,
        properties(r) AS rel_props
    """
    result = session.run(rel_query)
    for record in result:
        G.add_edge(
            record["src"],
            record["dst"],
            rel_type=record["rel_type"],
            **dict(record["rel_props"]),
        )

    logger.info(f"Projected graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


# ─────────────────────────────────────────────────────────────────────────────
# 1. PageRank — Identify high-influence nodes
# ─────────────────────────────────────────────────────────────────────────────

def compute_pagerank(G: nx.DiGraph, top_n: int = 20) -> pd.DataFrame:
    """
    Compute PageRank to identify the most influential/pivotal nodes.
    High PageRank = many important nodes point to this node.
    In a threat graph: high-PR devices may be pivot points in an attack chain.
    """
    logger.info("Computing PageRank...")
    pr = nx.pagerank(G, alpha=0.85)

    records = []
    for node, score in sorted(pr.items(), key=lambda x: x[1], reverse=True)[:top_n]:
        node_data = G.nodes.get(node, {})
        records.append({
            "node": node,
            "label": node_data.get("label", "Unknown"),
            "pagerank": round(score, 6),
            "in_degree": G.in_degree(node),
            "out_degree": G.out_degree(node),
        })

    df = pd.DataFrame(records)
    logger.info(f"  Top PageRank node: {df.iloc[0]['node']} ({df.iloc[0]['pagerank']})")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# 2. Community Detection (Louvain on undirected projection)
# ─────────────────────────────────────────────────────────────────────────────

def detect_communities(G: nx.DiGraph) -> pd.DataFrame:
    """
    Detect communities using the Louvain method on an undirected projection.
    Communities that mix Users, Devices, and external IPs can indicate
    coordinated attack campaigns.
    """
    logger.info("Detecting communities (Louvain)...")
    G_undirected = G.to_undirected()

    # Use greedy modularity (works without optional louvain dependency)
    from networkx.algorithms.community import greedy_modularity_communities

    communities = list(greedy_modularity_communities(G_undirected))

    records = []
    for i, community in enumerate(communities):
        labels_in_community = {}
        for node in community:
            label = G.nodes[node].get("label", "Unknown")
            labels_in_community[label] = labels_in_community.get(label, 0) + 1

        # Check for attack tags
        attack_nodes = [
            n for n in community
            if G.nodes[n].get("attack_tag") == "SYNTHETIC_ATTACK"
        ]

        records.append({
            "community_id": i,
            "size": len(community),
            "composition": labels_in_community,
            "attack_nodes": len(attack_nodes),
            "is_suspicious": len(attack_nodes) > 0,
            "members_sample": list(community)[:10],
        })

    df = pd.DataFrame(records).sort_values("size", ascending=False).reset_index(drop=True)
    suspicious = df[df["is_suspicious"]].shape[0]
    logger.info(f"  Found {len(communities)} communities, {suspicious} suspicious")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# 3. Shortest Path — Trace attack paths
# ─────────────────────────────────────────────────────────────────────────────

def find_attack_paths(G: nx.DiGraph, max_paths: int = 10) -> list:
    """
    Find shortest paths between entry points (Users with attack tags)
    and exfiltration endpoints (external IPs with large transfers).

    This models the full kill chain: Initial Access → Lateral Movement → Exfiltration.
    """
    logger.info("Finding attack paths (entry → exfiltration)...")

    # Entry points: users involved in attacks
    entry_nodes = [
        n for n in G.nodes
        if G.nodes[n].get("label") == "User"
        and G.nodes[n].get("attack_tag") == "SYNTHETIC_ATTACK"
    ]

    # Exfiltration targets: external IPs
    exit_nodes = [
        n for n in G.nodes
        if G.nodes[n].get("label") == "IP"
        and G.nodes[n].get("is_external") is True
    ]

    paths_found = []
    for entry in entry_nodes:
        for exit_node in exit_nodes:
            try:
                path = nx.shortest_path(G, source=entry, target=exit_node)
                path_details = []
                for node in path:
                    path_details.append({
                        "node": node,
                        "label": G.nodes[node].get("label", "Unknown"),
                    })

                paths_found.append({
                    "source": entry,
                    "target": exit_node,
                    "length": len(path) - 1,
                    "path": [p["node"] for p in path_details],
                    "path_labels": [p["label"] for p in path_details],
                })

                if len(paths_found) >= max_paths:
                    break
            except nx.NetworkXNoPath:
                continue

        if len(paths_found) >= max_paths:
            break

    logger.info(f"  Found {len(paths_found)} attack paths")
    return paths_found


# ─────────────────────────────────────────────────────────────────────────────
# 4. Betweenness Centrality — Find bottleneck / pivot nodes
# ─────────────────────────────────────────────────────────────────────────────

def compute_betweenness_centrality(G: nx.DiGraph, top_n: int = 20) -> pd.DataFrame:
    """
    Compute betweenness centrality to identify nodes that act as bridges
    or bottlenecks in attack paths. High betweenness = critical pivot point.
    """
    logger.info("Computing betweenness centrality...")

    # Use approximate betweenness for performance on large graphs
    k = min(100, G.number_of_nodes())
    bc = nx.betweenness_centrality(G, k=k)

    records = []
    for node, score in sorted(bc.items(), key=lambda x: x[1], reverse=True)[:top_n]:
        node_data = G.nodes.get(node, {})
        records.append({
            "node": node,
            "label": node_data.get("label", "Unknown"),
            "betweenness": round(score, 6),
            "in_degree": G.in_degree(node),
            "out_degree": G.out_degree(node),
        })

    df = pd.DataFrame(records)
    if not df.empty:
        logger.info(f"  Top bottleneck: {df.iloc[0]['node']} (betweenness={df.iloc[0]['betweenness']})")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# 5. Degree-Based Anomaly Scoring
# ─────────────────────────────────────────────────────────────────────────────

def compute_anomaly_scores(G: nx.DiGraph, z_threshold: float = 2.0) -> pd.DataFrame:
    """
    Score nodes by how anomalous their connectivity is relative to peers
    of the same label type. Uses z-score on degree distribution.

    Nodes with z-score > threshold are flagged as anomalous.
    """
    logger.info(f"Computing degree-based anomaly scores (z > {z_threshold})...")

    # Group by label
    label_groups = {}
    for node in G.nodes:
        label = G.nodes[node].get("label", "Unknown")
        degree = G.degree(node)
        if label not in label_groups:
            label_groups[label] = []
        label_groups[label].append((node, degree))

    records = []
    for label, nodes in label_groups.items():
        degrees = [d for _, d in nodes]
        if len(degrees) < 2:
            continue

        mean_deg = sum(degrees) / len(degrees)
        std_deg = (sum((d - mean_deg) ** 2 for d in degrees) / len(degrees)) ** 0.5

        if std_deg == 0:
            continue

        for node, degree in nodes:
            z_score = (degree - mean_deg) / std_deg
            if z_score > z_threshold:
                records.append({
                    "node": node,
                    "label": label,
                    "degree": degree,
                    "mean_degree": round(mean_deg, 2),
                    "z_score": round(z_score, 2),
                    "is_anomalous": True,
                })

    df = pd.DataFrame(records).sort_values("z_score", ascending=False).reset_index(drop=True)
    logger.info(f"  Found {len(df)} anomalous nodes (z > {z_threshold})")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# Run all algorithms
# ─────────────────────────────────────────────────────────────────────────────

def run_all_algorithms():
    """Project graph from Neo4j and run all graph algorithms."""
    with get_session() as session:
        G = project_graph_from_neo4j(session)

    if G.number_of_nodes() == 0:
        logger.warning("Graph is empty. Run attack injection first.")
        return {}

    results = {
        "pagerank": compute_pagerank(G),
        "communities": detect_communities(G),
        "attack_paths": find_attack_paths(G),
        "betweenness": compute_betweenness_centrality(G),
        "anomalies": compute_anomaly_scores(G),
    }

    logger.success("All graph algorithms complete.")
    return results


if __name__ == "__main__":
    results = run_all_algorithms()

    print("\n=== PageRank (Top 10) ===")
    print(results["pagerank"].head(10).to_string(index=False))

    print("\n=== Communities ===")
    print(results["communities"].to_string(index=False))

    print("\n=== Attack Paths ===")
    for p in results["attack_paths"][:5]:
        print(f"  {p['source']} → {p['target']} (hops={p['length']}): {' → '.join(p['path'])}")

    print("\n=== Betweenness Centrality (Top 10) ===")
    print(results["betweenness"].head(10).to_string(index=False))

    print("\n=== Anomalous Nodes ===")
    print(results["anomalies"].to_string(index=False))
