"""
Neo4j Graph Schema Setup

Creates constraints, indexes, and the graph schema for the threat detection pipeline.

Node Labels:
    - User: Identity entity (user_id, department, role)
    - Device: Endpoint (hostname, os, ip_address)
    - IP: Network address (address, geo_location, is_external)
    - Malware: Malicious artifact (hash, family, first_seen)
    - Technique: MITRE ATT&CK technique (mitre_id, name, tactic)
    - Campaign: Threat campaign (name, start_date, threat_actor)

Relationships:
    - AUTHENTICATED_TO: User -> Device (timestamp, location, status, auth_type)
    - COMMUNICATED_WITH: Device -> IP (timestamp, port, protocol, bytes_sent, bytes_received)
    - MATCHES_MALWARE: Device -> Malware (timestamp, detection_method)
    - USES_TECHNIQUE: Campaign -> Technique (confidence)
    - ASSOCIATED_WITH: Malware -> Campaign ()
    - TARGETED_BY: User -> Campaign ()
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from loguru import logger
from config.neo4j_connection import get_session


# ── Constraints (uniqueness) ───────────────────────────────────────────────────

CONSTRAINTS = [
    ("user_id_unique", "CREATE CONSTRAINT user_id_unique IF NOT EXISTS FOR (u:User) REQUIRE u.user_id IS UNIQUE"),
    ("device_hostname_unique", "CREATE CONSTRAINT device_hostname_unique IF NOT EXISTS FOR (d:Device) REQUIRE d.hostname IS UNIQUE"),
    ("ip_address_unique", "CREATE CONSTRAINT ip_address_unique IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE"),
    ("malware_hash_unique", "CREATE CONSTRAINT malware_hash_unique IF NOT EXISTS FOR (m:Malware) REQUIRE m.hash IS UNIQUE"),
    ("technique_mitre_id_unique", "CREATE CONSTRAINT technique_mitre_id_unique IF NOT EXISTS FOR (t:Technique) REQUIRE t.mitre_id IS UNIQUE"),
    ("campaign_name_unique", "CREATE CONSTRAINT campaign_name_unique IF NOT EXISTS FOR (c:Campaign) REQUIRE c.name IS UNIQUE"),
    ("tenant_id_unique", "CREATE CONSTRAINT tenant_id_unique IF NOT EXISTS FOR (t:Tenant) REQUIRE t.tenant_id IS UNIQUE"),
    ("cloudapp_id_unique", "CREATE CONSTRAINT cloudapp_id_unique IF NOT EXISTS FOR (a:CloudApp) REQUIRE a.app_id IS UNIQUE"),
]

# ── Indexes (for query performance) ────────────────────────────────────────────

INDEXES = [
    ("idx_user_department", "CREATE INDEX idx_user_department IF NOT EXISTS FOR (u:User) ON (u.department)"),
    ("idx_user_tenant", "CREATE INDEX idx_user_tenant IF NOT EXISTS FOR (u:User) ON (u.tenant_id)"),
    ("idx_device_os", "CREATE INDEX idx_device_os IF NOT EXISTS FOR (d:Device) ON (d.os)"),
    ("idx_ip_is_external", "CREATE INDEX idx_ip_is_external IF NOT EXISTS FOR (i:IP) ON (i.is_external)"),
    ("idx_malware_family", "CREATE INDEX idx_malware_family IF NOT EXISTS FOR (m:Malware) ON (m.family)"),
    ("idx_technique_tactic", "CREATE INDEX idx_technique_tactic IF NOT EXISTS FOR (t:Technique) ON (t.tactic)"),
    ("idx_tenant_domain", "CREATE INDEX idx_tenant_domain IF NOT EXISTS FOR (t:Tenant) ON (t.domain)"),
]


def create_constraints(session):
    """Create uniqueness constraints on node labels."""
    for name, cypher in CONSTRAINTS:
        session.run(cypher)
        logger.info(f"Constraint created: {name}")


def create_indexes(session):
    """Create indexes for frequently queried properties."""
    for name, cypher in INDEXES:
        session.run(cypher)
        logger.info(f"Index created: {name}")


def verify_schema(session):
    """Print current constraints and indexes to verify setup."""
    result = session.run("SHOW CONSTRAINTS")
    constraints = [record.data() for record in result]
    logger.info(f"Active constraints: {len(constraints)}")
    for c in constraints:
        logger.debug(f"  {c.get('name', 'unknown')}: {c.get('type', '')}")

    result = session.run("SHOW INDEXES")
    indexes = [record.data() for record in result]
    logger.info(f"Active indexes: {len(indexes)}")
    for i in indexes:
        logger.debug(f"  {i.get('name', 'unknown')}: {i.get('type', '')}")


def setup_schema():
    """Run the full schema setup: constraints, indexes, and verification."""
    logger.info("Setting up Neo4j graph schema...")
    with get_session() as session:
        create_constraints(session)
        create_indexes(session)
        verify_schema(session)
    logger.success("Schema setup complete.")


if __name__ == "__main__":
    setup_schema()
