"""Tests for Graph ML (Node2Vec) module."""

import pytest
import numpy as np
import networkx as nx
import pandas as pd
from detection.graph_ml import (
    generate_random_walks,
    train_node2vec_embeddings,
    detect_embedding_anomalies,
    find_similar_nodes,
)


@pytest.fixture
def small_graph():
    """Small graph for testing ML pipeline."""
    G = nx.DiGraph()
    for i in range(10):
        G.add_node(f"node_{i}", label="User" if i < 5 else "Device",
                   attack_tag="SYNTHETIC_ATTACK" if i == 0 else None)
    for i in range(9):
        G.add_edge(f"node_{i}", f"node_{i+1}")
    # Add extra edges to node_0 to make it anomalous
    G.add_edge("node_0", "node_5")
    G.add_edge("node_0", "node_7")
    G.add_edge("node_0", "node_9")
    return G


class TestRandomWalks:
    def test_generates_walks(self, small_graph):
        walks = generate_random_walks(small_graph, num_walks=2, walk_length=5)
        assert len(walks) > 0
        assert all(isinstance(w, list) for w in walks)

    def test_walk_length_respected(self, small_graph):
        walks = generate_random_walks(small_graph, num_walks=1, walk_length=5)
        for walk in walks:
            assert len(walk) <= 5

    def test_walks_contain_valid_nodes(self, small_graph):
        valid = set(str(n) for n in small_graph.nodes)
        walks = generate_random_walks(small_graph, num_walks=1, walk_length=5)
        for walk in walks:
            for node in walk:
                assert node in valid


class TestNode2VecEmbeddings:
    def test_returns_embeddings(self, small_graph):
        walks = generate_random_walks(small_graph, num_walks=2, walk_length=5)
        embeddings = train_node2vec_embeddings(walks, embedding_dim=16, epochs=2)
        assert len(embeddings) > 0

    def test_embedding_dimensions(self, small_graph):
        walks = generate_random_walks(small_graph, num_walks=2, walk_length=5)
        embeddings = train_node2vec_embeddings(walks, embedding_dim=32, epochs=2)
        for emb in embeddings.values():
            assert len(emb) == 32

    def test_embeddings_are_numpy(self, small_graph):
        walks = generate_random_walks(small_graph, num_walks=2, walk_length=5)
        embeddings = train_node2vec_embeddings(walks, embedding_dim=16, epochs=2)
        for emb in embeddings.values():
            assert isinstance(emb, np.ndarray)


class TestEmbeddingAnomalies:
    def test_returns_dataframe(self, small_graph):
        walks = generate_random_walks(small_graph, num_walks=3, walk_length=10)
        embeddings = train_node2vec_embeddings(walks, embedding_dim=16, epochs=3)
        anomalies = detect_embedding_anomalies(embeddings, small_graph)
        assert isinstance(anomalies, pd.DataFrame)

    def test_has_required_columns(self, small_graph):
        walks = generate_random_walks(small_graph, num_walks=3, walk_length=10)
        embeddings = train_node2vec_embeddings(walks, embedding_dim=16, epochs=3)
        anomalies = detect_embedding_anomalies(embeddings, small_graph)
        if not anomalies.empty:
            assert "is_anomalous" in anomalies.columns
            assert "distance_from_centroid" in anomalies.columns


class TestSimilaritySearch:
    def test_returns_results(self, small_graph):
        walks = generate_random_walks(small_graph, num_walks=2, walk_length=5)
        embeddings = train_node2vec_embeddings(walks, embedding_dim=16, epochs=2)
        similar = find_similar_nodes(embeddings, "node_0", top_n=5, G=small_graph)
        assert isinstance(similar, pd.DataFrame)
        assert len(similar) <= 5

    def test_missing_node_returns_empty(self, small_graph):
        walks = generate_random_walks(small_graph, num_walks=2, walk_length=5)
        embeddings = train_node2vec_embeddings(walks, embedding_dim=16, epochs=2)
        similar = find_similar_nodes(embeddings, "nonexistent", top_n=5)
        assert similar.empty
