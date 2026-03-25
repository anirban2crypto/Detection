# Methodology: Graph-Based Threat Detection in Cloud Environments

## Abstract

This document describes a graph-based approach to detecting, attributing, and disrupting cyber threats in heterogeneous cloud environments. By modeling security entities (users, devices, IPs, applications, malware, and threat intelligence) as a knowledge graph, we enable relational pattern discovery that traditional log-based SIEM approaches cannot achieve. We combine rule-based Cypher detection queries, graph algorithms (PageRank, community detection, centrality analysis), and machine learning on graph embeddings (Node2Vec) to identify sophisticated attack patterns including lateral movement, credential abuse, and data exfiltration.

---

## 1. Problem Statement

Modern cloud environments generate vast volumes of heterogeneous security telemetry:
- **Identity logs** (Azure AD sign-ins, MFA events, conditional access)
- **Network flows** (device-to-device, device-to-external-IP)
- **Endpoint events** (process execution, authentication)
- **Threat intelligence** (MITRE ATT&CK, malware hashes, IOCs)

Traditional approaches analyze these data sources in isolation. Graph-based modeling captures the **relationships** between entities, enabling detection of multi-stage attacks that span multiple data sources and tenants.

## 2. Graph Schema Design

### 2.1 Node Types

| Node | Description | Key Properties |
|---|---|---|
| **User** | Identity entity | user_id, department, tenant_id |
| **Device** | Endpoint/workstation | hostname, os, ip_address |
| **IP** | Network address | address, geo_location, is_external |
| **Tenant** | Cloud organization | tenant_id, domain |
| **CloudApp** | SaaS/PaaS application | app_id, name |
| **Malware** | Malicious artifact | hash, family, tags |
| **Technique** | MITRE ATT&CK TTP | mitre_id, name, tactic |
| **Campaign** | Threat campaign | name, threat_actor |

### 2.2 Relationship Types

| Relationship | Source → Target | Semantics |
|---|---|---|
| AUTHENTICATED_TO | User → Device | On-premise auth event |
| SIGNED_IN_TO | User → CloudApp | Azure AD sign-in |
| AUTHENTICATED_FROM | User → IP | Source IP of authentication |
| COMMUNICATED_WITH | Device → IP | Network flow |
| BELONGS_TO | User → Tenant | Tenant membership |
| MATCHES_MALWARE | Device → Malware | Malware detection on endpoint |
| MAPS_TO_TECHNIQUE | Entity → Technique | MITRE ATT&CK mapping |
| USES_TECHNIQUE | Campaign → Technique | Campaign TTP |

## 3. Detection Methodology

### 3.1 Rule-Based Detection (Cypher Queries)

We implement four primary detection rules as parameterized Cypher queries:

1. **Impossible Travel**: Identify users with authentication events from geographically distant locations within a short time window (< 30 minutes).

2. **Credential Stuffing**: Find external IPs with high failed authentication counts (≥ 10) targeting multiple user accounts.

3. **Lateral Movement**: Detect users accessing an unusually high number of distinct devices (≥ 4) in sequence.

4. **Data Exfiltration**: Flag outbound transfers exceeding 10 MB to external IPs.

### 3.2 Graph Algorithm-Based Detection

Beyond rule-based queries, we apply graph-theoretic algorithms:

- **PageRank**: Identifies pivotal nodes — devices or IPs that many entities interact with. High PageRank in the attack subgraph indicates a central pivot point in the attack chain.

- **Community Detection (Greedy Modularity)**: Partitions the graph into communities. Communities containing attack-tagged entities alongside normal entities may indicate compromised segments.

- **Betweenness Centrality**: Finds bottleneck nodes that lie on many shortest paths. In security: these are choke points an attacker must traverse.

- **Attack Path Analysis**: Computes shortest paths from entry points (compromised users) to exfiltration endpoints (external IPs), modeling the complete kill chain.

- **Degree Anomaly Scoring**: Flags nodes whose connectivity (degree) is statistically anomalous (z-score > 2.0) compared to peers of the same type.

### 3.3 Graph ML-Based Detection (Node2Vec)

We apply unsupervised machine learning to graph structure:

1. **Random Walk Generation**: Biased random walks (Node2Vec, with parameters p and q controlling BFS/DFS balance) capture structural neighborhood information.

2. **Embedding Training**: A skipgram model learns low-dimensional vector representations for each node based on walk co-occurrence patterns.

3. **Anomaly Detection**: Nodes are grouped by type; we compute the centroid of each group's embedding distribution. Nodes whose embedding distance from the centroid exceeds the (1 - contamination) percentile are flagged as anomalous.

4. **Similarity Search**: Cosine similarity between embeddings enables "find nodes behaviorally similar to this known-bad entity" queries.

## 4. Campaign Clustering & Attribution

### 4.1 Clustering

We extract the attack-tagged subgraph and compute weakly connected components. Each connected component represents a distinct attack campaign — a group of entities and events linked by shared infrastructure or actors.

### 4.2 Attribution

Each campaign is attributed based on:
- **Kill chain coverage**: What fraction of the MITRE ATT&CK kill chain does the campaign span?
  - ≥ 75% → Advanced Persistent Threat (APT)
  - ≥ 50% → Organized Cybercrime
  - Exfiltration-only → Data Theft Operation
  - Credential-only → Credential Harvesting
- **Sophistication scoring**: Based on the complexity of techniques used.

### 4.3 Infrastructure Overlap

We analyze shared IPs, devices, and users across campaigns. Shared infrastructure between campaigns suggests a single threat actor operating multiple campaigns.

## 5. Multi-Tenant Cloud Context

### 5.1 Azure AD Integration

The system ingests Azure AD sign-in logs (modeled per Microsoft Entra ID schema) including:
- Risk levels (none/low/medium/high)
- Conditional access status
- MFA completion
- Application context (admin tools flagged separately)

### 5.2 Cross-Tenant Analysis

Users belonging to multiple tenants are flagged. Cross-tenant activity from shared IPs or devices may indicate compromised service accounts or supply chain attacks.

## 6. RAG-Powered Reporting

Detection findings are fed to an LLM (GPT-4o-mini) via Retrieval-Augmented Generation:

1. **Retrieve**: Cypher queries extract suspicious subgraphs
2. **Augment**: Findings are formatted as structured context with entity details
3. **Generate**: LLM produces an analyst report with:
   - Executive summary
   - Per-attack-type analysis
   - MITRE ATT&CK technique mapping
   - Attacker intent assessment
   - Prioritized response recommendations
   - Severity rating

## 7. Evaluation

| Metric | Value |
|---|---|
| Detection rules | 4 Cypher-based |
| Graph algorithms | 5 (PageRank, community, centrality, paths, anomaly) |
| ML methods | Node2Vec + centroid anomaly detection |
| Test coverage | 49+ tests |
| Data sources | LANL, Azure AD, MalwareBazaar, MITRE ATT&CK, synthetic |
| Multi-tenant support | 3 tenants, cross-tenant detection |
| MITRE techniques mapped | 10 |

## 8. Future Work

- **GNN-based classification**: Train graph neural networks for supervised malicious node classification
- **Real-time streaming**: Kafka/Spark integration for live log ingestion
- **Threat hunting notebooks**: Interactive Jupyter workflows for SOC analysts
- **SOAR integration**: Automated response playbooks triggered by graph detections
- **Cross-cloud support**: AWS CloudTrail and GCP audit log ingestion

---

## References

1. MITRE ATT&CK Framework — https://attack.mitre.org/
2. LANL Cyber Security Dataset — https://csr.lanl.gov/data/cyber1/
3. MalwareBazaar — https://bazaar.abuse.ch/
4. Grover, A., & Leskovec, J. (2016). node2vec: Scalable Feature Learning for Networks. KDD.
5. Microsoft Entra ID Sign-In Logs — https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-sign-ins-log-schema
