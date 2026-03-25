"""
Cypher-Based Detection Queries

Each function returns a list of suspicious findings from Neo4j.
Used by the RAG pipeline to retrieve graph context before prompting the LLM.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from loguru import logger
from config.neo4j_connection import get_session


# ─────────────────────────────────────────────────────────────────────────────
# 1. Impossible Travel Detection
# ─────────────────────────────────────────────────────────────────────────────

IMPOSSIBLE_TRAVEL_QUERY = """
MATCH (u:User)-[r:AUTHENTICATED_TO]->(d:Device)
WHERE r.location IS NOT NULL
WITH u,
     collect({
         device: d.hostname,
         location: r.location,
         country: r.country,
         timestamp: r.timestamp,
         status: r.status
     }) AS events
WHERE size(events) >= 2
WITH u, events,
     [e IN events | e.location] AS locations
WHERE size(apoc.coll.toSet(locations)) > 1
WITH u, events,
     apoc.coll.toSet(locations) AS unique_locations,
     reduce(minT = events[0].timestamp, e IN events | CASE WHEN e.timestamp < minT THEN e.timestamp ELSE minT END) AS min_ts,
     reduce(maxT = events[0].timestamp, e IN events | CASE WHEN e.timestamp > maxT THEN e.timestamp ELSE maxT END) AS max_ts
WHERE (max_ts - min_ts) < 1800
RETURN u.user_id AS user_id,
       unique_locations,
       min_ts,
       max_ts,
       (max_ts - min_ts) / 60 AS delta_minutes,
       size(events) AS event_count,
       events
ORDER BY delta_minutes ASC
LIMIT 50
"""


def detect_impossible_travel(session):
    """Find users authenticating from multiple distant locations in < 30 min."""
    logger.info("Running impossible travel detection...")
    result = session.run(IMPOSSIBLE_TRAVEL_QUERY)
    findings = [record.data() for record in result]
    logger.info(f"  Found {len(findings)} impossible travel alerts")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 2. Credential Stuffing Detection
# ─────────────────────────────────────────────────────────────────────────────

CREDENTIAL_STUFFING_QUERY = """
MATCH (d:Device)-[c:COMMUNICATED_WITH]->(ip:IP)
WHERE ip.is_external = true
WITH ip, d, collect(c) AS connections
MATCH (u:User)-[r:AUTHENTICATED_TO]->(d)
WHERE r.status = 'Fail'
WITH ip,
     collect(DISTINCT u.user_id) AS targeted_users,
     count(r) AS fail_count
WHERE fail_count >= 10
RETURN ip.address AS attacker_ip,
       ip.geo_location AS ip_location,
       targeted_users,
       size(targeted_users) AS unique_users_targeted,
       fail_count
ORDER BY fail_count DESC
LIMIT 50
"""


def detect_credential_stuffing(session):
    """Find IPs with high failed login counts across multiple users."""
    logger.info("Running credential stuffing detection...")
    result = session.run(CREDENTIAL_STUFFING_QUERY)
    findings = [record.data() for record in result]
    logger.info(f"  Found {len(findings)} credential stuffing alerts")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 3. Lateral Movement Detection
# ─────────────────────────────────────────────────────────────────────────────

LATERAL_MOVEMENT_QUERY = """
MATCH (u:User)-[r:AUTHENTICATED_TO]->(d:Device)
WHERE r.status = 'Success'
WITH u,
     collect({device: d.hostname, timestamp: r.timestamp}) AS auths
WHERE size(auths) >= 4
WITH u, auths,
     [a IN auths | a.device] AS devices
WHERE size(apoc.coll.toSet(devices)) >= 4
RETURN u.user_id AS user_id,
       size(apoc.coll.toSet(devices)) AS unique_devices,
       apoc.coll.toSet(devices) AS device_chain,
       size(auths) AS total_auths,
       reduce(minT = auths[0].timestamp, a IN auths | CASE WHEN a.timestamp < minT THEN a.timestamp ELSE minT END) AS first_seen,
       reduce(maxT = auths[0].timestamp, a IN auths | CASE WHEN a.timestamp > maxT THEN a.timestamp ELSE maxT END) AS last_seen
ORDER BY unique_devices DESC
LIMIT 50
"""


def detect_lateral_movement(session):
    """Find users accessing unusually many devices in sequence."""
    logger.info("Running lateral movement detection...")
    result = session.run(LATERAL_MOVEMENT_QUERY)
    findings = [record.data() for record in result]
    logger.info(f"  Found {len(findings)} lateral movement alerts")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 4. Data Exfiltration Detection
# ─────────────────────────────────────────────────────────────────────────────

DATA_EXFILTRATION_QUERY = """
MATCH (d:Device)-[r:COMMUNICATED_WITH]->(ip:IP)
WHERE ip.is_external = true
  AND r.byte_count IS NOT NULL
  AND r.byte_count > 10000000
RETURN d.hostname AS source_device,
       ip.address AS destination_ip,
       ip.geo_location AS destination_geo,
       r.byte_count AS bytes_transferred,
       r.byte_count / 1000000.0 AS megabytes,
       r.duration AS duration_seconds,
       r.timestamp AS timestamp,
       r.protocol AS protocol
ORDER BY r.byte_count DESC
LIMIT 50
"""


def detect_data_exfiltration(session):
    """Find large outbound transfers to external IPs (> 10MB)."""
    logger.info("Running data exfiltration detection...")
    result = session.run(DATA_EXFILTRATION_QUERY)
    findings = [record.data() for record in result]
    logger.info(f"  Found {len(findings)} data exfiltration alerts")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# 5. Graph Summary (useful for RAG context)
# ─────────────────────────────────────────────────────────────────────────────

GRAPH_SUMMARY_QUERY = """
CALL {
    MATCH (u:User) RETURN 'User' AS label, count(u) AS cnt
    UNION ALL
    MATCH (d:Device) RETURN 'Device' AS label, count(d) AS cnt
    UNION ALL
    MATCH (i:IP) RETURN 'IP' AS label, count(i) AS cnt
    UNION ALL
    MATCH (m:Malware) RETURN 'Malware' AS label, count(m) AS cnt
    UNION ALL
    MATCH (t:Technique) RETURN 'Technique' AS label, count(t) AS cnt
    UNION ALL
    MATCH (c:Campaign) RETURN 'Campaign' AS label, count(c) AS cnt
}
RETURN label, cnt
ORDER BY cnt DESC
"""


def get_graph_summary(session):
    """Return node counts per label for context."""
    result = session.run(GRAPH_SUMMARY_QUERY)
    return {record["label"]: record["cnt"] for record in result}


# ─────────────────────────────────────────────────────────────────────────────
# Run all detections
# ─────────────────────────────────────────────────────────────────────────────

DETECTIONS = {
    "impossible_travel": detect_impossible_travel,
    "credential_stuffing": detect_credential_stuffing,
    "lateral_movement": detect_lateral_movement,
    "data_exfiltration": detect_data_exfiltration,
}


def run_all_detections():
    """Execute all detection queries and return combined results."""
    all_findings = {}
    with get_session() as session:
        summary = get_graph_summary(session)
        logger.info(f"Graph summary: {summary}")
        for name, detect_fn in DETECTIONS.items():
            all_findings[name] = detect_fn(session)
    return all_findings, summary


if __name__ == "__main__":
    findings, summary = run_all_detections()
    print("\n=== Graph Summary ===")
    for label, count in summary.items():
        print(f"  {label}: {count}")
    print()
    for attack_type, alerts in findings.items():
        print(f"=== {attack_type.upper()} ({len(alerts)} alerts) ===")
        for alert in alerts[:3]:
            print(f"  {alert}")
        if len(alerts) > 3:
            print(f"  ... and {len(alerts) - 3} more")
        print()
