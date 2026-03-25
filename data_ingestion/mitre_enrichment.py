"""
MITRE ATT&CK Enrichment Module

Maps detection findings to MITRE ATT&CK techniques and ingests
Technique nodes + relationships into the Neo4j graph.

Reference: https://attack.mitre.org/
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from loguru import logger
from config.neo4j_connection import get_session


# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Technique Definitions
# ─────────────────────────────────────────────────────────────────────────────

TECHNIQUES = [
    # Initial Access
    {
        "mitre_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may use credentials of existing accounts to gain access.",
        "url": "https://attack.mitre.org/techniques/T1078",
    },
    # Credential Access
    {
        "mitre_id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "url": "https://attack.mitre.org/techniques/T1110",
    },
    {
        "mitre_id": "T1110.004",
        "name": "Credential Stuffing",
        "tactic": "Credential Access",
        "description": "Adversaries may use credentials obtained from breach dumps to gain access.",
        "url": "https://attack.mitre.org/techniques/T1110/004",
    },
    # Lateral Movement
    {
        "mitre_id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid accounts to log into remote services.",
        "url": "https://attack.mitre.org/techniques/T1021",
    },
    {
        "mitre_id": "T1021.002",
        "name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use SMB to move laterally between systems.",
        "url": "https://attack.mitre.org/techniques/T1021/002",
    },
    {
        "mitre_id": "T1550",
        "name": "Use Alternate Authentication Material",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use alternate authentication material to move laterally.",
        "url": "https://attack.mitre.org/techniques/T1550",
    },
    # Exfiltration
    {
        "mitre_id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an existing C2 channel.",
        "url": "https://attack.mitre.org/techniques/T1041",
    },
    {
        "mitre_id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol.",
        "url": "https://attack.mitre.org/techniques/T1048",
    },
    # Defense Evasion
    {
        "mitre_id": "T1078.004",
        "name": "Cloud Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may use cloud accounts to maintain access.",
        "url": "https://attack.mitre.org/techniques/T1078/004",
    },
    # Discovery
    {
        "mitre_id": "T1087",
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of accounts on a system.",
        "url": "https://attack.mitre.org/techniques/T1087",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Attack Type → MITRE Technique Mapping
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_TECHNIQUE_MAP = {
    "impossible_travel": [
        {"mitre_id": "T1078", "confidence": "high"},
        {"mitre_id": "T1078.004", "confidence": "medium"},
    ],
    "credential_stuffing": [
        {"mitre_id": "T1110", "confidence": "high"},
        {"mitre_id": "T1110.004", "confidence": "high"},
        {"mitre_id": "T1087", "confidence": "medium"},
    ],
    "lateral_movement": [
        {"mitre_id": "T1021", "confidence": "high"},
        {"mitre_id": "T1021.002", "confidence": "high"},
        {"mitre_id": "T1550", "confidence": "medium"},
        {"mitre_id": "T1078", "confidence": "medium"},
    ],
    "data_exfiltration": [
        {"mitre_id": "T1041", "confidence": "high"},
        {"mitre_id": "T1048", "confidence": "medium"},
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# Ingest techniques into Neo4j
# ─────────────────────────────────────────────────────────────────────────────

def ingest_techniques(session):
    """Create MITRE ATT&CK Technique nodes in Neo4j."""
    logger.info(f"Ingesting {len(TECHNIQUES)} MITRE ATT&CK techniques...")

    query = """
    UNWIND $techniques AS t
    MERGE (tech:Technique {mitre_id: t.mitre_id})
    SET tech.name = t.name,
        tech.tactic = t.tactic,
        tech.description = t.description,
        tech.url = t.url
    """
    session.run(query, techniques=TECHNIQUES)
    logger.info("  ✓ Techniques ingested")


def link_attacks_to_techniques(session):
    """
    Create MAPS_TO_TECHNIQUE relationships between
    attack-tagged relationships/nodes and Technique nodes.
    """
    logger.info("Linking synthetic attacks to MITRE techniques...")

    for attack_type, techniques in ATTACK_TECHNIQUE_MAP.items():
        for tech in techniques:
            # Link users involved in this attack type to the technique
            query = """
            MATCH (u:User)-[r:AUTHENTICATED_TO]->()
            WHERE r.attack_type = $attack_type
            WITH DISTINCT u
            MATCH (t:Technique {mitre_id: $mitre_id})
            MERGE (u)-[:MAPS_TO_TECHNIQUE {
                attack_type: $attack_type,
                confidence: $confidence
            }]->(t)
            """
            session.run(query, {
                "attack_type": attack_type,
                "mitre_id": tech["mitre_id"],
                "confidence": tech["confidence"],
            })

        # For data exfiltration, link devices instead
        if attack_type == "data_exfiltration":
            for tech in techniques:
                query = """
                MATCH (d:Device)-[r:COMMUNICATED_WITH]->()
                WHERE r.attack_type = $attack_type
                WITH DISTINCT d
                MATCH (t:Technique {mitre_id: $mitre_id})
                MERGE (d)-[:MAPS_TO_TECHNIQUE {
                    attack_type: $attack_type,
                    confidence: $confidence
                }]->(t)
                """
                session.run(query, {
                    "attack_type": attack_type,
                    "mitre_id": tech["mitre_id"],
                    "confidence": tech["confidence"],
                })

    logger.info("  ✓ Attack-to-technique mappings created")


def get_technique_summary(session) -> list:
    """Return a summary of techniques and their linked entities."""
    query = """
    MATCH (n)-[r:MAPS_TO_TECHNIQUE]->(t:Technique)
    RETURN t.mitre_id AS mitre_id,
           t.name AS name,
           t.tactic AS tactic,
           r.attack_type AS attack_type,
           r.confidence AS confidence,
           count(n) AS linked_entities
    ORDER BY t.tactic, t.mitre_id
    """
    result = session.run(query)
    return [record.data() for record in result]


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def run_mitre_enrichment():
    """Full MITRE ATT&CK enrichment pipeline."""
    logger.info("Starting MITRE ATT&CK enrichment...")
    with get_session() as session:
        ingest_techniques(session)
        link_attacks_to_techniques(session)

        summary = get_technique_summary(session)
        logger.info(f"\nMITRE ATT&CK Mapping Summary ({len(summary)} mappings):")
        for row in summary:
            logger.info(
                f"  [{row['tactic']}] {row['mitre_id']} {row['name']} "
                f"← {row['attack_type']} ({row['confidence']}, {row['linked_entities']} entities)"
            )

    logger.success("MITRE ATT&CK enrichment complete.")


if __name__ == "__main__":
    run_mitre_enrichment()
