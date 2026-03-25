"""
Graph ML — Node Embeddings & Anomaly Detection

Generates node embeddings from the threat graph using Node2Vec,
then applies unsupervised anomaly detection to identify suspicious entities.

Pipeline:
    1. Project graph from Neo4j → NetworkX
    2. Train Node2Vec embeddings (random walks + Word2Vec)
    3. Compute anomaly scores using Isolation Forest
    4. Flag outlier nodes that deviate from normal graph behavior

This demonstrates ML applied to graph data — a key JD requirement.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
import pandas as pd
import networkx as nx
from loguru import logger
from config.neo4j_connection import get_session
from detection.graph_algorithms import project_graph_from_neo4j


# ─────────────────────────────────────────────────────────────────────────────
# Node2Vec: Random Walk Generation
# ─────────────────────────────────────────────────────────────────────────────

def _random_walk(G_undirected, start, walk_length, p=1.0, q=1.0):
    """Perform a single biased random walk from a start node (Node2Vec style)."""
    walk = [start]
    for _ in range(walk_length - 1):
        current = walk[-1]
        neighbors = list(G_undirected.neighbors(current))
        if not neighbors:
            break

        if len(walk) == 1:
            walk.append(neighbors[np.random.randint(len(neighbors))])
        else:
            prev = walk[-2]
            # Compute unnormalized transition probabilities
            weights = []
            for neighbor in neighbors:
                if neighbor == prev:
                    weights.append(1.0 / p)  # return to previous
                elif G_undirected.has_edge(neighbor, prev):
                    weights.append(1.0)       # BFS-like
                else:
                    weights.append(1.0 / q)   # DFS-like (explore)

            weights = np.array(weights)
            weights /= weights.sum()
            next_node = neighbors[np.random.choice(len(neighbors), p=weights)]
            walk.append(next_node)

    return walk


def generate_random_walks(
    G: nx.DiGraph,
    num_walks: int = 10,
    walk_length: int = 20,
    p: float = 1.0,
    q: float = 0.5,
) -> list:
    """
    Generate biased random walks for all nodes (Node2Vec algorithm).

    Parameters:
        p: Return parameter (low p = more likely to return to previous node)
        q: In-out parameter (low q = DFS/explore, high q = BFS/local)
    """
    logger.info(f"Generating {num_walks} random walks per node (length={walk_length}, p={p}, q={q})...")
    G_undirected = G.to_undirected()
    nodes = list(G_undirected.nodes)
    walks = []

    for _ in range(num_walks):
        np.random.shuffle(nodes)
        for node in nodes:
            walk = _random_walk(G_undirected, node, walk_length, p=p, q=q)
            walks.append([str(n) for n in walk])

    logger.info(f"  Generated {len(walks)} walks")
    return walks


# ─────────────────────────────────────────────────────────────────────────────
# Node2Vec: Train Embeddings via Word2Vec (gensim-free)
# ─────────────────────────────────────────────────────────────────────────────

def _build_vocabulary(walks):
    """Build word-to-index and index-to-word mappings from walks."""
    vocab = {}
    for walk in walks:
        for word in walk:
            if word not in vocab:
                vocab[word] = len(vocab)
    return vocab


def _skipgram_pairs(walks, vocab, window=5):
    """Generate (target, context) pairs from walks for skipgram training."""
    pairs = []
    for walk in walks:
        for i, word in enumerate(walk):
            target = vocab[word]
            start = max(0, i - window)
            end = min(len(walk), i + window + 1)
            for j in range(start, end):
                if j != i:
                    context = vocab[walk[j]]
                    pairs.append((target, context))
    return pairs


def train_node2vec_embeddings(
    walks: list,
    embedding_dim: int = 64,
    window: int = 5,
    epochs: int = 5,
    learning_rate: float = 0.025,
) -> dict:
    """
    Train Node2Vec embeddings using a lightweight skipgram implementation.
    Returns {node_name: embedding_vector} dictionary.

    Note: This is a simplified implementation without gensim dependency.
    For production, use gensim.models.Word2Vec.
    """
    logger.info(f"Training Node2Vec embeddings (dim={embedding_dim}, epochs={epochs})...")

    vocab = _build_vocabulary(walks)
    vocab_size = len(vocab)

    if vocab_size == 0:
        logger.warning("Empty vocabulary, no embeddings to train.")
        return {}

    # Initialize embedding matrices
    np.random.seed(42)
    W_in = np.random.randn(vocab_size, embedding_dim) * 0.1
    W_out = np.random.randn(vocab_size, embedding_dim) * 0.1

    pairs = _skipgram_pairs(walks, vocab, window=window)
    logger.info(f"  Vocabulary: {vocab_size} nodes, {len(pairs)} skipgram pairs")

    # Subsample for efficiency on large graphs
    max_pairs = 500000
    if len(pairs) > max_pairs:
        indices = np.random.choice(len(pairs), max_pairs, replace=False)
        pairs = [pairs[i] for i in indices]

    # SGD training with negative sampling approximation
    idx_to_word = {v: k for k, v in vocab.items()}
    for epoch in range(epochs):
        np.random.shuffle(pairs)
        total_loss = 0.0
        lr = learning_rate * (1.0 - epoch / epochs)  # linear decay

        for target_idx, context_idx in pairs:
            # Positive sample
            dot = np.dot(W_in[target_idx], W_out[context_idx])
            sig = 1.0 / (1.0 + np.exp(-np.clip(dot, -6, 6)))

            grad = (sig - 1.0) * lr
            W_in[target_idx] -= grad * W_out[context_idx]
            W_out[context_idx] -= grad * W_in[target_idx]

            # Negative samples (3 random negatives)
            for _ in range(3):
                neg_idx = np.random.randint(vocab_size)
                if neg_idx == context_idx:
                    continue
                dot_neg = np.dot(W_in[target_idx], W_out[neg_idx])
                sig_neg = 1.0 / (1.0 + np.exp(-np.clip(dot_neg, -6, 6)))

                grad_neg = sig_neg * lr
                W_in[target_idx] -= grad_neg * W_out[neg_idx]
                W_out[neg_idx] -= grad_neg * W_in[target_idx]

            total_loss += -np.log(max(sig, 1e-10))

        avg_loss = total_loss / max(len(pairs), 1)
        logger.debug(f"  Epoch {epoch + 1}/{epochs}, avg loss: {avg_loss:.4f}")

    # Build embedding dictionary
    embeddings = {}
    for word, idx in vocab.items():
        embeddings[word] = W_in[idx]

    logger.info(f"  Trained embeddings for {len(embeddings)} nodes")
    return embeddings


# ─────────────────────────────────────────────────────────────────────────────
# Anomaly Detection: Isolation Forest-style scoring
# ─────────────────────────────────────────────────────────────────────────────

def detect_embedding_anomalies(
    embeddings: dict,
    G: nx.DiGraph,
    contamination: float = 0.1,
) -> pd.DataFrame:
    """
    Detect anomalous nodes using embedding distance from cluster centroids.

    Approach:
        1. Group nodes by label type
        2. Compute centroid for each group
        3. Score each node by distance from its group centroid
        4. Flag top N% as anomalous (based on contamination rate)
    """
    logger.info(f"Detecting embedding anomalies (contamination={contamination})...")

    # Group embeddings by label
    label_groups = {}
    for node, emb in embeddings.items():
        label = G.nodes.get(node, {}).get("label", "Unknown")
        if label not in label_groups:
            label_groups[label] = []
        label_groups[label].append((node, emb))

    records = []
    for label, group in label_groups.items():
        if len(group) < 3:
            continue

        # Compute centroid
        embs = np.array([e for _, e in group])
        centroid = embs.mean(axis=0)

        # Compute distances
        distances = np.linalg.norm(embs - centroid, axis=1)
        threshold = np.percentile(distances, (1 - contamination) * 100)

        for (node, emb), dist in zip(group, distances):
            is_anomalous = dist > threshold
            attack_tag = G.nodes.get(node, {}).get("attack_tag")

            records.append({
                "node": node,
                "label": label,
                "distance_from_centroid": round(float(dist), 4),
                "threshold": round(float(threshold), 4),
                "is_anomalous": is_anomalous,
                "has_attack_tag": attack_tag == "SYNTHETIC_ATTACK",
            })

    df = pd.DataFrame(records)
    if not df.empty:
        df = df.sort_values("distance_from_centroid", ascending=False).reset_index(drop=True)
        anomalous = df[df["is_anomalous"]]
        true_positives = anomalous[anomalous["has_attack_tag"]].shape[0]
        logger.info(
            f"  Anomalies: {anomalous.shape[0]} flagged, "
            f"{true_positives} true positives (have attack tag)"
        )

    return df


# ─────────────────────────────────────────────────────────────────────────────
# Embedding similarity search
# ─────────────────────────────────────────────────────────────────────────────

def find_similar_nodes(embeddings: dict, query_node: str, top_n: int = 10, G: nx.DiGraph = None) -> pd.DataFrame:
    """Find the most similar nodes to a query node by cosine similarity."""
    if query_node not in embeddings:
        logger.warning(f"Node '{query_node}' not in embeddings")
        return pd.DataFrame()

    query_emb = embeddings[query_node]
    query_norm = np.linalg.norm(query_emb)

    similarities = []
    for node, emb in embeddings.items():
        if node == query_node:
            continue
        cos_sim = np.dot(query_emb, emb) / (query_norm * np.linalg.norm(emb) + 1e-10)
        label = G.nodes.get(node, {}).get("label", "Unknown") if G else "Unknown"
        similarities.append({
            "node": node,
            "label": label,
            "cosine_similarity": round(float(cos_sim), 4),
        })

    df = pd.DataFrame(similarities).sort_values("cosine_similarity", ascending=False).head(top_n)
    return df.reset_index(drop=True)


# ─────────────────────────────────────────────────────────────────────────────
# Full ML pipeline
# ─────────────────────────────────────────────────────────────────────────────

def run_graph_ml_pipeline(
    embedding_dim: int = 64,
    num_walks: int = 10,
    walk_length: int = 20,
    p: float = 1.0,
    q: float = 0.5,
):
    """Full Graph ML pipeline: project → embed → detect anomalies."""
    logger.info("Starting Graph ML pipeline...")

    with get_session() as session:
        G = project_graph_from_neo4j(session)

    if G.number_of_nodes() == 0:
        logger.warning("Graph is empty.")
        return {}, {}, pd.DataFrame()

    walks = generate_random_walks(G, num_walks=num_walks, walk_length=walk_length, p=p, q=q)
    embeddings = train_node2vec_embeddings(walks, embedding_dim=embedding_dim)
    anomalies = detect_embedding_anomalies(embeddings, G)

    logger.success("Graph ML pipeline complete.")
    return G, embeddings, anomalies


if __name__ == "__main__":
    G, embeddings, anomalies = run_graph_ml_pipeline()

    print("\n=== Embedding Anomalies (Top 15) ===")
    if not anomalies.empty:
        print(anomalies[anomalies["is_anomalous"]].head(15).to_string(index=False))
    else:
        print("No anomalies detected.")

    # Demo: find similar nodes to a lateral movement user
    lat_users = [n for n in G.nodes if "lat_move" in str(n)]
    if lat_users:
        print(f"\n=== Nodes similar to '{lat_users[0]}' ===")
        similar = find_similar_nodes(embeddings, lat_users[0], top_n=10, G=G)
        print(similar.to_string(index=False))
