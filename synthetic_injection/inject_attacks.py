"""
Synthetic Attack Injection

Generates and injects simulated attack scenarios into Neo4j:
    1. Impossible Travel — same user authenticates from distant locations within minutes
    2. Credential Stuffing — many failed logins from a single IP
    3. Lateral Movement — sequential device hopping by one user
    4. Data Exfiltration — large outbound byte transfers to suspicious external IPs
"""

import os
import sys
import random
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from faker import Faker
from loguru import logger
from config.neo4j_connection import get_session

fake = Faker()

# ── Attack tag label applied to injected nodes/relationships ───────────────────
ATTACK_TAG = "SYNTHETIC_ATTACK"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Impossible Travel
# ─────────────────────────────────────────────────────────────────────────────

def inject_impossible_travel(session, count: int = 5):
    """
    Inject impossible travel events: same user authenticates from two
    distant geolocations within a short time window (< 10 minutes).
    """
    logger.info(f"Injecting {count} impossible travel scenarios...")

    cities = [
        ("New York", "US"), ("Tokyo", "JP"), ("London", "GB"),
        ("Sydney", "AU"), ("São Paulo", "BR"), ("Mumbai", "IN"),
        ("Berlin", "DE"), ("Lagos", "NG"), ("Seoul", "KR"),
    ]

    for i in range(count):
        user_id = f"imp_travel_user_{i}"
        device_a = f"WS-{fake.lexify('????').upper()}"
        device_b = f"WS-{fake.lexify('????').upper()}"
        loc_a, loc_b = random.sample(cities, 2)
        base_ts = 1000000 + i * 100
        delta_minutes = random.randint(1, 9)

        query = """
        MERGE (u:User {user_id: $user_id})
        SET u.attack_tag = $tag

        MERGE (d1:Device {hostname: $device_a})
        MERGE (d2:Device {hostname: $device_b})

        CREATE (u)-[:AUTHENTICATED_TO {
            timestamp: $ts1,
            location: $loc_a,
            country: $country_a,
            status: 'Success',
            auth_type: 'NTLM',
            attack_tag: $tag,
            attack_type: 'impossible_travel'
        }]->(d1)

        CREATE (u)-[:AUTHENTICATED_TO {
            timestamp: $ts2,
            location: $loc_b,
            country: $country_b,
            status: 'Success',
            auth_type: 'NTLM',
            attack_tag: $tag,
            attack_type: 'impossible_travel'
        }]->(d2)
        """
        session.run(query, {
            "user_id": user_id,
            "device_a": device_a,
            "device_b": device_b,
            "ts1": base_ts,
            "ts2": base_ts + delta_minutes * 60,
            "loc_a": loc_a[0],
            "country_a": loc_a[1],
            "loc_b": loc_b[0],
            "country_b": loc_b[1],
            "tag": ATTACK_TAG,
        })

    logger.info(f"  ✓ {count} impossible travel scenarios injected")


# ─────────────────────────────────────────────────────────────────────────────
# 2. Credential Stuffing
# ─────────────────────────────────────────────────────────────────────────────

def inject_credential_stuffing(session, count: int = 3, attempts_per_ip: int = 50):
    """
    Inject credential stuffing: many failed auth attempts from a single IP
    targeting multiple user accounts.
    """
    logger.info(f"Injecting {count} credential stuffing campaigns ({attempts_per_ip} attempts each)...")

    for i in range(count):
        attacker_ip = fake.ipv4_public()
        base_ts = 2000000 + i * 10000

        events = []
        for j in range(attempts_per_ip):
            events.append({
                "user_id": f"target_user_{random.randint(0, 200)}",
                "device": f"SRV-AUTH-{random.randint(1, 5)}",
                "ip": attacker_ip,
                "timestamp": base_ts + j * 2,
                "status": "Fail" if j < attempts_per_ip - 2 else "Success",
                "tag": ATTACK_TAG,
            })

        query = """
        UNWIND $events AS e
        MERGE (u:User {user_id: e.user_id})
        MERGE (d:Device {hostname: e.device})
        MERGE (ip:IP {address: e.ip})
        SET ip.is_external = true, ip.attack_tag = e.tag

        CREATE (u)-[:AUTHENTICATED_TO {
            timestamp: e.timestamp,
            status: e.status,
            auth_type: 'Kerberos',
            attack_tag: e.tag,
            attack_type: 'credential_stuffing'
        }]->(d)

        CREATE (d)-[:COMMUNICATED_WITH {
            timestamp: e.timestamp,
            src_port: toString(toInteger(rand() * 60000 + 1024)),
            dst_port: '443',
            protocol: 'TCP',
            attack_tag: e.tag,
            attack_type: 'credential_stuffing'
        }]->(ip)
        """
        session.run(query, events=events)

    logger.info(f"  ✓ {count} credential stuffing campaigns injected")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Lateral Movement
# ─────────────────────────────────────────────────────────────────────────────

def inject_lateral_movement(session, count: int = 4, hops: int = 6):
    """
    Inject lateral movement: one user sequentially accesses a chain of devices.
    """
    logger.info(f"Injecting {count} lateral movement chains ({hops} hops each)...")

    for i in range(count):
        user_id = f"lat_move_user_{i}"
        devices = [f"SRV-{fake.lexify('???').upper()}-{j}" for j in range(hops)]
        base_ts = 3000000 + i * 10000

        for j in range(len(devices)):
            query = """
            MERGE (u:User {user_id: $user_id})
            SET u.attack_tag = $tag
            MERGE (d:Device {hostname: $device})
            CREATE (u)-[:AUTHENTICATED_TO {
                timestamp: $ts,
                status: 'Success',
                auth_type: 'NTLM',
                hop_index: $hop,
                attack_tag: $tag,
                attack_type: 'lateral_movement'
            }]->(d)
            """
            session.run(query, {
                "user_id": user_id,
                "device": devices[j],
                "ts": base_ts + j * random.randint(60, 600),
                "hop": j,
                "tag": ATTACK_TAG,
            })

            # Connect sequential devices to each other
            if j > 0:
                flow_query = """
                MATCH (d1:Device {hostname: $src}), (d2:Device {hostname: $dst})
                CREATE (d1)-[:COMMUNICATED_WITH {
                    timestamp: $ts,
                    protocol: 'SMB',
                    dst_port: '445',
                    attack_tag: $tag,
                    attack_type: 'lateral_movement'
                }]->(d2)
                """
                session.run(flow_query, {
                    "src": devices[j - 1],
                    "dst": devices[j],
                    "ts": base_ts + j * random.randint(60, 600),
                    "tag": ATTACK_TAG,
                })

    logger.info(f"  ✓ {count} lateral movement chains injected")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Data Exfiltration
# ─────────────────────────────────────────────────────────────────────────────

def inject_data_exfiltration(session, count: int = 5):
    """
    Inject data exfiltration: large byte transfers from internal devices
    to suspicious external IPs.
    """
    logger.info(f"Injecting {count} data exfiltration events...")

    for i in range(count):
        device = f"SRV-DB-{random.randint(1, 10)}"
        ext_ip = fake.ipv4_public()
        base_ts = 4000000 + i * 5000
        # Large transfer: 50MB–500MB
        byte_count = random.randint(50_000_000, 500_000_000)

        query = """
        MERGE (d:Device {hostname: $device})
        MERGE (ip:IP {address: $ip})
        SET ip.is_external = true,
            ip.geo_location = $geo,
            ip.attack_tag = $tag

        CREATE (d)-[:COMMUNICATED_WITH {
            timestamp: $ts,
            dst_port: '443',
            protocol: 'TCP',
            byte_count: $bytes,
            duration: $duration,
            attack_tag: $tag,
            attack_type: 'data_exfiltration'
        }]->(ip)
        """
        session.run(query, {
            "device": device,
            "ip": ext_ip,
            "geo": fake.country(),
            "ts": base_ts,
            "bytes": byte_count,
            "duration": random.randint(300, 3600),
            "tag": ATTACK_TAG,
        })

    logger.info(f"  ✓ {count} data exfiltration events injected")


# ─────────────────────────────────────────────────────────────────────────────
# Cleanup utility
# ─────────────────────────────────────────────────────────────────────────────

def remove_synthetic_attacks(session):
    """Remove all synthetic attack data by tag."""
    logger.warning("Removing all synthetic attack data...")
    session.run("""
        MATCH ()-[r]->() WHERE r.attack_tag = $tag DELETE r
    """, tag=ATTACK_TAG)
    session.run("""
        MATCH (n) WHERE n.attack_tag = $tag DETACH DELETE n
    """, tag=ATTACK_TAG)
    logger.info("Synthetic attack data removed.")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def inject_all_attacks(
    impossible_travel: int = 5,
    credential_stuffing: int = 3,
    lateral_movement: int = 4,
    data_exfiltration: int = 5,
):
    """Run all attack injection routines."""
    logger.info("Starting synthetic attack injection...")
    with get_session() as session:
        inject_impossible_travel(session, count=impossible_travel)
        inject_credential_stuffing(session, count=credential_stuffing)
        inject_lateral_movement(session, count=lateral_movement)
        inject_data_exfiltration(session, count=data_exfiltration)
    logger.success("All synthetic attacks injected.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Inject synthetic attacks into Neo4j")
    parser.add_argument("--clean", action="store_true", help="Remove all synthetic data instead of injecting")
    parser.add_argument("--impossible-travel", type=int, default=5)
    parser.add_argument("--credential-stuffing", type=int, default=3)
    parser.add_argument("--lateral-movement", type=int, default=4)
    parser.add_argument("--data-exfiltration", type=int, default=5)
    args = parser.parse_args()

    if args.clean:
        with get_session() as s:
            remove_synthetic_attacks(s)
    else:
        inject_all_attacks(
            impossible_travel=args.impossible_travel,
            credential_stuffing=args.credential_stuffing,
            lateral_movement=args.lateral_movement,
            data_exfiltration=args.data_exfiltration,
        )
