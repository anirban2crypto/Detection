"""
Campaign Clustering & Threat Attribution

Groups related attack events into campaigns using graph connectivity,
then attributes campaigns to likely threat actor profiles.

Pipeline:
    1. Identify connected components of attack-tagged subgraph
    2. Cluster related attacks into campaigns
    3. Compute campaign metadata (TTPs, scope, timeline)
    4. Generate campaign attribution profiles
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd
import networkx as nx
from loguru import logger
from config.neo4j_connection import get_session


# ─────────────────────────────────────────────────────────────────────────────
# Extract attack subgraph from Neo4j
# ─────────────────────────────────────────────────────────────────────────────

def extract_attack_subgraph(session) -> nx.DiGraph:
    """
    Extract only the attack-tagged portion of the graph.
    Returns a directed graph of entities involved in synthetic attacks.
    """
    logger.info("Extracting attack subgraph...")

    G = nx.DiGraph()

    # Get attack nodes
    node_query = """
    MATCH (n)
    WHERE n.attack_tag = 'SYNTHETIC_ATTACK'
    RETURN COALESCE(n.user_id, n.hostname, n.address, toString(id(n))) AS node_id,
           labels(n)[0] AS label,
           properties(n) AS props
    """
    result = session.run(node_query)
    for record in result:
        G.add_node(record["node_id"], label=record["label"], **dict(record["props"]))

    # Get attack relationships
    rel_query = """
    MATCH (a)-[r]->(b)
    WHERE r.attack_tag = 'SYNTHETIC_ATTACK'
       OR r.attack_type IS NOT NULL
    RETURN COALESCE(a.user_id, a.hostname, a.address, toString(id(a))) AS src,
           COALESCE(b.user_id, b.hostname, b.address, toString(id(b))) AS dst,
           type(r) AS rel_type,
           properties(r) AS rel_props
    """
    result = session.run(rel_query)
    for record in result:
        src = record["src"]
        dst = record["dst"]
        # Ensure nodes exist in the graph
        if src not in G:
            G.add_node(src, label="Unknown")
        if dst not in G:
            G.add_node(dst, label="Unknown")
        G.add_edge(src, dst, rel_type=record["rel_type"], **dict(record["rel_props"]))

    logger.info(f"  Attack subgraph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


# ─────────────────────────────────────────────────────────────────────────────
# Campaign Clustering via Connected Components
# ─────────────────────────────────────────────────────────────────────────────

def cluster_campaigns(G: nx.DiGraph) -> pd.DataFrame:
    """
    Cluster attack events into campaigns using weakly connected components.
    Each connected component = one campaign (group of related attack activity).
    """
    logger.info("Clustering attacks into campaigns...")

    G_undirected = G.to_undirected()
    components = list(nx.connected_components(G_undirected))

    campaigns = []
    for i, component in enumerate(sorted(components, key=len, reverse=True)):
        # Analyze composition
        labels = {}
        attack_types = set()
        timestamps = []
        users = []
        devices = []
        ips = []

        for node in component:
            node_data = G.nodes.get(node, {})
            label = node_data.get("label", "Unknown")
            labels[label] = labels.get(label, 0) + 1

            if label == "User":
                users.append(node)
            elif label == "Device":
                devices.append(node)
            elif label == "IP":
                ips.append(node)

        # Get attack types from edges
        for u, v, data in G.subgraph(component).edges(data=True):
            at = data.get("attack_type")
            if at:
                attack_types.add(at)
            ts = data.get("timestamp")
            if ts:
                timestamps.append(ts)

        campaigns.append({
            "campaign_id": f"CAMP-{i:03d}",
            "size": len(component),
            "composition": labels,
            "attack_types": list(attack_types),
            "num_users": len(users),
            "num_devices": len(devices),
            "num_ips": len(ips),
            "users": users[:5],
            "devices": devices[:5],
            "ips": ips[:5],
            "time_start": min(timestamps) if timestamps else None,
            "time_end": max(timestamps) if timestamps else None,
            "duration": (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0,
            "members": list(component),
        })

    df = pd.DataFrame(campaigns)
    logger.info(f"  Identified {len(campaigns)} campaigns")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# Campaign Attribution — Map campaigns to MITRE ATT&CK kill chain
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_TYPE_TO_KILL_CHAIN = {
    "impossible_travel": {
        "stage": "Initial Access",
        "tactics": ["Initial Access", "Defense Evasion"],
        "techniques": ["T1078 - Valid Accounts", "T1078.004 - Cloud Accounts"],
        "sophistication": "medium",
    },
    "credential_stuffing": {
        "stage": "Credential Access",
        "tactics": ["Credential Access", "Initial Access"],
        "techniques": ["T1110 - Brute Force", "T1110.004 - Credential Stuffing"],
        "sophistication": "low",
    },
    "lateral_movement": {
        "stage": "Lateral Movement",
        "tactics": ["Lateral Movement", "Discovery"],
        "techniques": ["T1021 - Remote Services", "T1021.002 - SMB/Windows Admin Shares"],
        "sophistication": "high",
    },
    "data_exfiltration": {
        "stage": "Exfiltration",
        "tactics": ["Exfiltration", "Collection"],
        "techniques": ["T1041 - Exfiltration Over C2 Channel", "T1048 - Exfiltration Over Alternative Protocol"],
        "sophistication": "high",
    },
}


def attribute_campaigns(campaigns_df: pd.DataFrame) -> pd.DataFrame:
    """
    Enrich campaigns with kill chain stage, MITRE mappings, and threat profile.
    """
    logger.info("Attributing campaigns to threat profiles...")

    attributions = []
    for _, campaign in campaigns_df.iterrows():
        attack_types = campaign["attack_types"]

        # Determine kill chain coverage
        stages = set()
        all_tactics = set()
        all_techniques = set()
        max_sophistication = "low"
        sophistication_order = {"low": 0, "medium": 1, "high": 2}

        for at in attack_types:
            mapping = ATTACK_TYPE_TO_KILL_CHAIN.get(at, {})
            if mapping:
                stages.add(mapping["stage"])
                all_tactics.update(mapping["tactics"])
                all_techniques.update(mapping["techniques"])
                if sophistication_order.get(mapping.get("sophistication", "low"), 0) > sophistication_order.get(max_sophistication, 0):
                    max_sophistication = mapping["sophistication"]

        # Determine if this is a full kill chain
        kill_chain_stages = ["Initial Access", "Credential Access", "Lateral Movement", "Exfiltration"]
        covered_stages = [s for s in kill_chain_stages if s in stages]
        kill_chain_coverage = len(covered_stages) / len(kill_chain_stages)

        # Threat profile
        if kill_chain_coverage >= 0.75:
            threat_profile = "Advanced Persistent Threat (APT)"
            severity = "Critical"
        elif kill_chain_coverage >= 0.5:
            threat_profile = "Organized Cybercrime"
            severity = "High"
        elif "data_exfiltration" in attack_types:
            threat_profile = "Data Theft Operation"
            severity = "High"
        elif "credential_stuffing" in attack_types:
            threat_profile = "Credential Harvesting"
            severity = "Medium"
        else:
            threat_profile = "Opportunistic Attack"
            severity = "Medium"

        attributions.append({
            "campaign_id": campaign["campaign_id"],
            "attack_types": attack_types,
            "kill_chain_stages": covered_stages,
            "kill_chain_coverage": round(kill_chain_coverage, 2),
            "tactics": list(all_tactics),
            "techniques": list(all_techniques),
            "sophistication": max_sophistication,
            "threat_profile": threat_profile,
            "severity": severity,
            "num_entities": campaign["size"],
        })

    df = pd.DataFrame(attributions)
    logger.info(f"  Attributed {len(df)} campaigns")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# Infrastructure Overlap Analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_infrastructure_overlap(campaigns_df: pd.DataFrame) -> pd.DataFrame:
    """
    Find shared infrastructure (IPs, devices) across campaigns.
    Shared infra = potential same threat actor behind multiple campaigns.
    """
    logger.info("Analyzing infrastructure overlap...")

    overlaps = []
    for i in range(len(campaigns_df)):
        for j in range(i + 1, len(campaigns_df)):
            camp_a = campaigns_df.iloc[i]
            camp_b = campaigns_df.iloc[j]

            shared_ips = set(camp_a["ips"]) & set(camp_b["ips"])
            shared_devices = set(camp_a["devices"]) & set(camp_b["devices"])
            shared_users = set(camp_a["users"]) & set(camp_b["users"])

            if shared_ips or shared_devices or shared_users:
                overlaps.append({
                    "campaign_a": camp_a["campaign_id"],
                    "campaign_b": camp_b["campaign_id"],
                    "shared_ips": list(shared_ips),
                    "shared_devices": list(shared_devices),
                    "shared_users": list(shared_users),
                    "overlap_score": len(shared_ips) + len(shared_devices) + len(shared_users),
                    "likely_same_actor": (len(shared_ips) + len(shared_devices)) > 0,
                })

    df = pd.DataFrame(overlaps)
    if not df.empty:
        df = df.sort_values("overlap_score", ascending=False).reset_index(drop=True)
    logger.info(f"  Found {len(df)} infrastructure overlaps")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# Full campaign analysis pipeline
# ─────────────────────────────────────────────────────────────────────────────

def run_campaign_analysis():
    """Full campaign analysis: cluster → attribute → overlap."""
    logger.info("Starting campaign analysis...")

    with get_session() as session:
        G = extract_attack_subgraph(session)

    if G.number_of_nodes() == 0:
        logger.warning("No attack data found.")
        return {}, pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    campaigns = cluster_campaigns(G)
    attributions = attribute_campaigns(campaigns)
    overlaps = analyze_infrastructure_overlap(campaigns)

    logger.success("Campaign analysis complete.")
    return G, campaigns, attributions, overlaps


if __name__ == "__main__":
    G, campaigns, attributions, overlaps = run_campaign_analysis()

    print("\n=== Campaigns ===")
    for _, c in campaigns.iterrows():
        print(f"\n{c['campaign_id']}: {c['size']} entities, attacks={c['attack_types']}")
        print(f"  Users: {c['num_users']}, Devices: {c['num_devices']}, IPs: {c['num_ips']}")
        print(f"  Duration: {c['duration']}s")

    print("\n=== Campaign Attribution ===")
    for _, a in attributions.iterrows():
        print(f"\n{a['campaign_id']}: {a['threat_profile']} (Severity: {a['severity']})")
        print(f"  Kill chain: {a['kill_chain_stages']} ({a['kill_chain_coverage']*100:.0f}% coverage)")
        print(f"  Techniques: {a['techniques'][:3]}")

    if not overlaps.empty:
        print("\n=== Infrastructure Overlaps ===")
        print(overlaps.to_string(index=False))
