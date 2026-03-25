"""
Streamlit Dashboard — Threat Detection via Graph + RAG + LLM

Layout:
    Sidebar:  Detection type selector, run controls, graph stats
    Center:   Interactive graph visualization
    Right:    LLM-generated analyst report
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import networkx as nx
import pandas as pd
from pyvis.network import Network
import tempfile

from config.neo4j_connection import get_session
from detection.cypher_queries import (
    DETECTIONS,
    get_graph_summary,
    detect_impossible_travel,
    detect_credential_stuffing,
    detect_lateral_movement,
    detect_data_exfiltration,
)
from detection.graph_algorithms import (
    project_graph_from_neo4j,
    compute_pagerank,
    detect_communities,
    find_attack_paths,
    compute_betweenness_centrality,
    compute_anomaly_scores,
)
from detection.graph_ml import (
    generate_random_walks,
    train_node2vec_embeddings,
    detect_embedding_anomalies,
    find_similar_nodes,
)
from detection.campaign_clustering import (
    extract_attack_subgraph,
    cluster_campaigns,
    attribute_campaigns,
    analyze_infrastructure_overlap,
)
from rag_pipeline.generate_report import (
    generate_single_report,
    generate_full_report,
    format_findings,
    format_graph_summary,
)

# ─────────────────────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Threat Detection — Graph + RAG + LLM",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Threat Detection via Graph + RAG + LLM")

# ─────────────────────────────────────────────────────────────────────────────
# Session state initialization
# ─────────────────────────────────────────────────────────────────────────────

if "findings" not in st.session_state:
    st.session_state.findings = {}
if "report" not in st.session_state:
    st.session_state.report = None
if "graph_summary" not in st.session_state:
    st.session_state.graph_summary = {}

# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("⚙️ Controls")

    detection_type = st.selectbox(
        "Detection Type",
        ["All Detections", "Impossible Travel", "Credential Stuffing", "Lateral Movement", "Data Exfiltration"],
    )

    detection_key_map = {
        "All Detections": "all",
        "Impossible Travel": "impossible_travel",
        "Credential Stuffing": "credential_stuffing",
        "Lateral Movement": "lateral_movement",
        "Data Exfiltration": "data_exfiltration",
    }
    selected_key = detection_key_map[detection_type]

    run_detection = st.button("🔍 Run Detection", type="primary", use_container_width=True)
    run_analysis = st.button("🧠 Generate AI Report", use_container_width=True)

    st.divider()
    st.header("📊 Graph Stats")

    if st.button("Refresh Stats", use_container_width=True):
        try:
            with get_session() as session:
                st.session_state.graph_summary = get_graph_summary(session)
        except Exception as e:
            st.error(f"Cannot connect to Neo4j: {e}")

    if st.session_state.graph_summary:
        for label, count in st.session_state.graph_summary.items():
            st.metric(label, count)
    else:
        st.caption("Click 'Refresh Stats' to load graph summary")

# ─────────────────────────────────────────────────────────────────────────────
# Detection execution
# ─────────────────────────────────────────────────────────────────────────────

if run_detection:
    with st.spinner("Running detection queries against Neo4j..."):
        try:
            with get_session() as session:
                st.session_state.graph_summary = get_graph_summary(session)

                if selected_key == "all":
                    st.session_state.findings = {
                        "impossible_travel": detect_impossible_travel(session),
                        "credential_stuffing": detect_credential_stuffing(session),
                        "lateral_movement": detect_lateral_movement(session),
                        "data_exfiltration": detect_data_exfiltration(session),
                    }
                else:
                    detect_fn = DETECTIONS[selected_key]
                    st.session_state.findings = {selected_key: detect_fn(session)}

            st.session_state.report = None  # reset report when new detection runs
            st.success("Detection complete!")
        except Exception as e:
            st.error(f"Detection failed: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# AI report generation
# ─────────────────────────────────────────────────────────────────────────────

if run_analysis:
    if not st.session_state.findings:
        st.warning("Run a detection first before generating a report.")
    else:
        with st.spinner("Generating AI-powered threat analysis..."):
            try:
                if selected_key == "all" or len(st.session_state.findings) > 1:
                    st.session_state.report = generate_full_report(
                        st.session_state.findings,
                        st.session_state.graph_summary,
                    )
                else:
                    key = list(st.session_state.findings.keys())[0]
                    st.session_state.report = generate_single_report(
                        key,
                        st.session_state.findings[key],
                        st.session_state.graph_summary,
                    )
                st.success("Report generated!")
            except Exception as e:
                st.error(f"Report generation failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Helper: build NetworkX graph from findings
# ─────────────────────────────────────────────────────────────────────────────

def build_graph_from_findings(findings: dict) -> nx.DiGraph:
    """Convert detection findings into a NetworkX directed graph for visualization."""
    G = nx.DiGraph()

    color_map = {
        "impossible_travel": "#FF6B6B",
        "credential_stuffing": "#FFA726",
        "lateral_movement": "#AB47BC",
        "data_exfiltration": "#42A5F5",
    }

    for attack_type, alerts in findings.items():
        color = color_map.get(attack_type, "#888888")
        for alert in alerts:
            # Impossible travel
            if "user_id" in alert and "unique_locations" in alert:
                uid = alert["user_id"]
                G.add_node(uid, label=uid, color="#4CAF50", title=f"User: {uid}", group="User")
                for loc in alert.get("unique_locations", []):
                    loc_id = f"📍{loc}"
                    G.add_node(loc_id, label=loc, color=color, title=f"Location: {loc}", group="Location")
                    G.add_edge(uid, loc_id, color=color, title=attack_type.replace("_", " "))

            # Credential stuffing
            if "attacker_ip" in alert:
                ip = alert["attacker_ip"]
                G.add_node(ip, label=ip, color=color, title=f"Attacker IP: {ip}", group="IP")
                for user in alert.get("targeted_users", [])[:10]:
                    G.add_node(user, label=user, color="#4CAF50", title=f"User: {user}", group="User")
                    G.add_edge(ip, user, color=color, title="credential stuffing")

            # Lateral movement
            if "user_id" in alert and "device_chain" in alert:
                uid = alert["user_id"]
                G.add_node(uid, label=uid, color="#4CAF50", title=f"User: {uid}", group="User")
                devices = alert.get("device_chain", [])
                for j, dev in enumerate(devices):
                    G.add_node(dev, label=dev, color=color, title=f"Device: {dev}", group="Device")
                    if j == 0:
                        G.add_edge(uid, dev, color=color, title="lateral movement start")
                    if j > 0:
                        G.add_edge(devices[j - 1], dev, color=color, title=f"hop {j}")

            # Data exfiltration
            if "source_device" in alert and "destination_ip" in alert:
                dev = alert["source_device"]
                ip = alert["destination_ip"]
                mb = alert.get("megabytes", "?")
                G.add_node(dev, label=dev, color="#78909C", title=f"Device: {dev}", group="Device")
                G.add_node(ip, label=ip, color=color, title=f"External IP: {ip}", group="IP")
                G.add_edge(dev, ip, color=color, title=f"exfil {mb:.0f} MB" if isinstance(mb, (int, float)) else "exfil")

    return G


def render_pyvis_graph(G: nx.DiGraph) -> str:
    """Render NetworkX graph as interactive HTML using PyVis."""
    net = Network(
        height="500px",
        width="100%",
        directed=True,
        bgcolor="#0E1117",
        font_color="white",
    )
    net.from_nx(G)
    net.set_options("""
    {
        "physics": {
            "forceAtlas2Based": {
                "gravitationalConstant": -80,
                "centralGravity": 0.01,
                "springLength": 120,
                "springConstant": 0.08
            },
            "solver": "forceAtlas2Based",
            "stabilization": {"iterations": 100}
        },
        "interaction": {
            "hover": true,
            "tooltipDelay": 100
        }
    }
    """)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode="w") as f:
        net.save_graph(f.name)
        return f.name


# ─────────────────────────────────────────────────────────────────────────────
# Main content area
# ─────────────────────────────────────────────────────────────────────────────

if st.session_state.findings:
    col_graph, col_report = st.columns([3, 2])

    # ── Graph visualization ─────────────────────────────────────────────────
    with col_graph:
        st.subheader("🕸️ Threat Graph")

        G = build_graph_from_findings(st.session_state.findings)

        if G.number_of_nodes() == 0:
            st.info("No graph entities to display.")
        else:
            st.caption(f"{G.number_of_nodes()} nodes · {G.number_of_edges()} edges")
            html_path = render_pyvis_graph(G)
            with open(html_path, "r") as f:
                html_content = f.read()
            st.components.v1.html(html_content, height=520, scrolling=False)
            os.unlink(html_path)

        # Alert summary table
        st.subheader("📋 Alert Summary")
        for attack_type, alerts in st.session_state.findings.items():
            display_name = attack_type.replace("_", " ").title()
            with st.expander(f"{display_name} — {len(alerts)} alert(s)", expanded=len(alerts) > 0):
                if not alerts:
                    st.write("No alerts.")
                else:
                    for i, alert in enumerate(alerts[:10], 1):
                        st.markdown(f"**Alert {i}**")
                        st.json(alert)

    # ── AI Report ───────────────────────────────────────────────────────────
    with col_report:
        st.subheader("🧠 AI Analyst Report")

        if st.session_state.report:
            st.markdown(st.session_state.report)
        else:
            st.info("Click **'Generate AI Report'** in the sidebar to analyze findings with GPT-4.")

else:
    st.info("👈 Select a detection type and click **'Run Detection'** in the sidebar to start.")
    st.markdown("""
    ### How it works

    1. **Run Detection** — Executes Cypher queries against your Neo4j graph to find anomalies
    2. **View Graph** — Visualizes suspicious entities and relationships interactively
    3. **Generate AI Report** — Sends graph context to GPT-4 via RAG for analyst-friendly reporting

    ### Attack Types

    | Detection | What it finds |
    |---|---|
    | **Impossible Travel** | Same user in multiple locations within minutes |
    | **Credential Stuffing** | Mass failed logins from a single IP |
    | **Lateral Movement** | User hopping across many devices sequentially |
    | **Data Exfiltration** | Large outbound transfers to external IPs |
    """)

# ─────────────────────────────────────────────────────────────────────────────
# Advanced Analytics Tabs
# ─────────────────────────────────────────────────────────────────────────────

st.divider()
st.header("🔬 Advanced Analytics")

tab_algo, tab_ml, tab_campaigns = st.tabs([
    "📊 Graph Algorithms",
    "🧬 Graph ML (Node2Vec)",
    "🎯 Campaign Clustering",
])

# ── Tab 1: Graph Algorithms ─────────────────────────────────────────────────

with tab_algo:
    if st.button("▶ Run Graph Algorithms", key="run_algo"):
        with st.spinner("Projecting graph and running algorithms..."):
            try:
                with get_session() as session:
                    G_proj = project_graph_from_neo4j(session)

                if G_proj.number_of_nodes() == 0:
                    st.warning("Graph is empty. Run detection first.")
                else:
                    st.session_state["algo_pagerank"] = compute_pagerank(G_proj)
                    st.session_state["algo_communities"] = detect_communities(G_proj)
                    st.session_state["algo_paths"] = find_attack_paths(G_proj)
                    st.session_state["algo_betweenness"] = compute_betweenness_centrality(G_proj)
                    st.session_state["algo_anomalies"] = compute_anomaly_scores(G_proj)
                    st.success(f"Algorithms complete on {G_proj.number_of_nodes()} nodes, {G_proj.number_of_edges()} edges")
            except Exception as e:
                st.error(f"Error: {e}")

    col_pr, col_bw = st.columns(2)

    with col_pr:
        st.subheader("PageRank — Pivotal Nodes")
        if "algo_pagerank" in st.session_state:
            st.dataframe(st.session_state["algo_pagerank"], use_container_width=True)
        else:
            st.caption("Run algorithms to see results")

    with col_bw:
        st.subheader("Betweenness — Bottleneck Nodes")
        if "algo_betweenness" in st.session_state:
            st.dataframe(st.session_state["algo_betweenness"], use_container_width=True)
        else:
            st.caption("Run algorithms to see results")

    st.subheader("Communities")
    if "algo_communities" in st.session_state:
        df_comm = st.session_state["algo_communities"]
        for _, row in df_comm.iterrows():
            flag = "🔴" if row["is_suspicious"] else "🟢"
            with st.expander(f"{flag} Community {row['community_id']} — {row['size']} nodes"):
                st.write(f"**Composition:** {row['composition']}")
                st.write(f"**Attack nodes:** {row['attack_nodes']}")
                st.write(f"**Sample members:** {row['members_sample']}")

    st.subheader("Attack Paths (Entry → Exfiltration)")
    if "algo_paths" in st.session_state:
        paths = st.session_state["algo_paths"]
        if paths:
            for p in paths[:5]:
                st.code(f"{' → '.join(p['path'])}  (hops={p['length']})")
        else:
            st.info("No complete attack paths found.")

    st.subheader("Degree Anomalies")
    if "algo_anomalies" in st.session_state:
        df_anom = st.session_state["algo_anomalies"]
        if not df_anom.empty:
            st.dataframe(df_anom, use_container_width=True)
        else:
            st.info("No degree anomalies detected.")


# ── Tab 2: Graph ML ─────────────────────────────────────────────────────────

with tab_ml:
    col_params, _ = st.columns([1, 2])
    with col_params:
        emb_dim = st.slider("Embedding dimensions", 16, 128, 64, key="emb_dim")
        num_walks = st.slider("Walks per node", 5, 20, 10, key="num_walks")

    if st.button("▶ Run Node2Vec + Anomaly Detection", key="run_ml"):
        with st.spinner("Training Node2Vec embeddings..."):
            try:
                with get_session() as session:
                    G_ml = project_graph_from_neo4j(session)

                walks = generate_random_walks(G_ml, num_walks=num_walks, walk_length=20)
                embeddings = train_node2vec_embeddings(walks, embedding_dim=emb_dim)
                anomalies = detect_embedding_anomalies(embeddings, G_ml)

                st.session_state["ml_embeddings"] = embeddings
                st.session_state["ml_anomalies"] = anomalies
                st.session_state["ml_graph"] = G_ml
                st.success(f"Trained embeddings for {len(embeddings)} nodes")
            except Exception as e:
                st.error(f"Error: {e}")

    st.subheader("Embedding Anomalies")
    if "ml_anomalies" in st.session_state:
        df_ml = st.session_state["ml_anomalies"]
        if not df_ml.empty:
            anomalous_only = df_ml[df_ml["is_anomalous"]]
            true_pos = anomalous_only[anomalous_only["has_attack_tag"]].shape[0]

            col_m1, col_m2, col_m3 = st.columns(3)
            col_m1.metric("Total Nodes", len(df_ml))
            col_m2.metric("Anomalies Flagged", len(anomalous_only))
            col_m3.metric("True Positives", true_pos)

            st.dataframe(anomalous_only.head(20), use_container_width=True)
        else:
            st.info("No anomalies detected.")

    st.subheader("Node Similarity Search")
    if "ml_embeddings" in st.session_state:
        query_node = st.text_input("Enter node name to find similar nodes:", key="sim_query")
        if query_node and query_node in st.session_state["ml_embeddings"]:
            similar = find_similar_nodes(
                st.session_state["ml_embeddings"],
                query_node, top_n=10,
                G=st.session_state.get("ml_graph"),
            )
            st.dataframe(similar, use_container_width=True)
        elif query_node:
            st.warning(f"Node '{query_node}' not found in embeddings.")


# ── Tab 3: Campaign Clustering ──────────────────────────────────────────────

with tab_campaigns:
    if st.button("▶ Run Campaign Analysis", key="run_campaigns"):
        with st.spinner("Clustering attacks into campaigns..."):
            try:
                with get_session() as session:
                    G_attack = extract_attack_subgraph(session)

                campaigns = cluster_campaigns(G_attack)
                attributions = attribute_campaigns(campaigns)
                overlaps = analyze_infrastructure_overlap(campaigns)

                st.session_state["campaigns"] = campaigns
                st.session_state["attributions"] = attributions
                st.session_state["overlaps"] = overlaps
                st.success(f"Identified {len(campaigns)} campaigns")
            except Exception as e:
                st.error(f"Error: {e}")

    if "attributions" in st.session_state:
        st.subheader("Campaign Attribution")
        for _, attr in st.session_state["attributions"].iterrows():
            severity_color = {
                "Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"
            }.get(attr["severity"], "⚪")

            with st.expander(
                f"{severity_color} {attr['campaign_id']} — {attr['threat_profile']} "
                f"({attr['severity']})",
                expanded=True,
            ):
                col_c1, col_c2, col_c3 = st.columns(3)
                col_c1.metric("Entities", attr["num_entities"])
                col_c2.metric("Kill Chain Coverage", f"{attr['kill_chain_coverage']*100:.0f}%")
                col_c3.metric("Sophistication", attr["sophistication"].title())

                st.write(f"**Attack types:** {', '.join(attr['attack_types'])}")
                st.write(f"**Kill chain stages:** {' → '.join(attr['kill_chain_stages'])}")
                st.write(f"**MITRE techniques:** {', '.join(attr['techniques'][:5])}")

    if "overlaps" in st.session_state and not st.session_state["overlaps"].empty:
        st.subheader("Infrastructure Overlaps")
        st.caption("Shared infrastructure across campaigns may indicate the same threat actor")
        st.dataframe(st.session_state["overlaps"], use_container_width=True)
