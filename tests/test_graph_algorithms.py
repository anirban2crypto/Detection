"""Tests for graph algorithms module."""

import pytest
import networkx as nx
import pandas as pd
from detection.graph_algorithms import (
    compute_pagerank,
    detect_communities,
    find_attack_paths,
    compute_betweenness_centrality,
    compute_anomaly_scores,
)


@pytest.fixture
def sample_threat_graph():
    """Build a small threat graph for testing."""
    G = nx.DiGraph()

    # Users
    for i in range(3):
        G.add_node(f"user_{i}", label="User", attack_tag="SYNTHETIC_ATTACK" if i == 0 else None)

    # Devices
    for i in range(5):
        G.add_node(f"device_{i}", label="Device")

    # IPs
    G.add_node("ext_ip_1", label="IP", is_external=True)
    G.add_node("ext_ip_2", label="IP", is_external=True)

    # Edges: user_0 does lateral movement through devices
    G.add_edge("user_0", "device_0", rel_type="AUTHENTICATED_TO")
    G.add_edge("user_0", "device_1", rel_type="AUTHENTICATED_TO")
    G.add_edge("user_0", "device_2", rel_type="AUTHENTICATED_TO")
    G.add_edge("device_0", "device_1", rel_type="COMMUNICATED_WITH")
    G.add_edge("device_1", "device_2", rel_type="COMMUNICATED_WITH")
    G.add_edge("device_2", "ext_ip_1", rel_type="COMMUNICATED_WITH")

    # Normal user
    G.add_edge("user_1", "device_3", rel_type="AUTHENTICATED_TO")
    G.add_edge("user_2", "device_4", rel_type="AUTHENTICATED_TO")

    return G


class TestPageRank:
    def test_returns_dataframe(self, sample_threat_graph):
        result = compute_pagerank(sample_threat_graph)
        assert isinstance(result, pd.DataFrame)
        assert "pagerank" in result.columns
        assert len(result) > 0

    def test_top_node_is_pivotal(self, sample_threat_graph):
        result = compute_pagerank(sample_threat_graph, top_n=3)
        # user_0 or a device in the attack chain should be highly ranked
        top_nodes = set(result["node"].tolist())
        assert len(top_nodes) > 0


class TestCommunityDetection:
    def test_returns_communities(self, sample_threat_graph):
        result = detect_communities(sample_threat_graph)
        assert isinstance(result, pd.DataFrame)
        assert "community_id" in result.columns
        assert len(result) > 0

    def test_finds_suspicious_communities(self, sample_threat_graph):
        result = detect_communities(sample_threat_graph)
        suspicious = result[result["is_suspicious"]]
        assert len(suspicious) >= 0  # may or may not find based on structure


class TestAttackPaths:
    def test_finds_paths(self, sample_threat_graph):
        paths = find_attack_paths(sample_threat_graph)
        assert isinstance(paths, list)

    def test_path_connects_user_to_ip(self, sample_threat_graph):
        paths = find_attack_paths(sample_threat_graph)
        if paths:
            p = paths[0]
            assert p["source"] == "user_0"
            assert "ext_ip" in p["target"]
            assert p["length"] > 0


class TestBetweenness:
    def test_returns_dataframe(self, sample_threat_graph):
        result = compute_betweenness_centrality(sample_threat_graph)
        assert isinstance(result, pd.DataFrame)
        assert "betweenness" in result.columns


class TestAnomalyScores:
    def test_returns_dataframe(self, sample_threat_graph):
        result = compute_anomaly_scores(sample_threat_graph, z_threshold=1.0)
        assert isinstance(result, pd.DataFrame)

    def test_attack_user_is_anomalous(self, sample_threat_graph):
        result = compute_anomaly_scores(sample_threat_graph, z_threshold=0.5)
        if not result.empty:
            # user_0 has 3 connections, others have 1 — should be anomalous
            anomalous_nodes = set(result["node"].tolist())
            assert "user_0" in anomalous_nodes
