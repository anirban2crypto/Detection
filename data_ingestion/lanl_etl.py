"""
LANL Cyber Security Dataset — ETL Pipeline

Ingests the Los Alamos National Lab authentication and network flow logs
into Neo4j as graph nodes and relationships.

LANL Dataset files expected in data/raw/lanl/:
    - auth.txt     → Authentication events (user, src_device, dst_device, auth_type, status, timestamp)
    - flows.txt    → Network flows (timestamp, duration, src_device, src_port, dst_device, dst_port, protocol, bytes)
    - proc.txt     → Process events (timestamp, user, device, process)

Download from: https://csr.lanl.gov/data/cyber1/

File format (auth.txt):
    timestamp,source_user@domain,destination_user@domain,source_computer,destination_computer,auth_type,logon_type,auth_orientation,success_or_failure

File format (flows.txt):
    timestamp,duration,source_computer,source_port,destination_computer,destination_port,protocol,packet_count,byte_count
"""

import os
import sys
import csv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd
from loguru import logger
from config.neo4j_connection import get_session

LANL_DATA_DIR = os.getenv("LANL_DATA_DIR", "data/raw/lanl")
BATCH_SIZE = 5000


def parse_user_id(raw: str) -> str:
    """Extract user ID from 'user@domain' format."""
    return raw.split("@")[0] if "@" in raw else raw


def ingest_auth_logs(session, filepath: str, max_rows: int = None):
    """
    Ingest LANL auth.txt into Neo4j.

    Creates User and Device nodes and AUTHENTICATED_TO relationships.
    """
    logger.info(f"Ingesting auth logs from {filepath}")

    if not os.path.isfile(filepath):
        logger.error(f"Auth file not found: {filepath}")
        return

    batch = []
    count = 0

    with open(filepath, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 9:
                continue

            timestamp = int(row[0])
            src_user = parse_user_id(row[1])
            dst_user = parse_user_id(row[2])
            src_device = row[3]
            dst_device = row[4]
            auth_type = row[5]
            logon_type = row[6]
            orientation = row[7]
            status = row[8]

            batch.append({
                "timestamp": timestamp,
                "src_user": src_user,
                "dst_user": dst_user,
                "src_device": src_device,
                "dst_device": dst_device,
                "auth_type": auth_type,
                "logon_type": logon_type,
                "orientation": orientation,
                "status": status,
            })

            if len(batch) >= BATCH_SIZE:
                _write_auth_batch(session, batch)
                count += len(batch)
                logger.info(f"  Auth records ingested: {count}")
                batch = []

            if max_rows and count + len(batch) >= max_rows:
                break

    if batch:
        _write_auth_batch(session, batch)
        count += len(batch)

    logger.info(f"Auth ingestion complete. Total records: {count}")


def _write_auth_batch(session, batch: list):
    """Write a batch of auth events to Neo4j."""
    query = """
    UNWIND $batch AS row
    MERGE (src_user:User {user_id: row.src_user})
    MERGE (dst_user:User {user_id: row.dst_user})
    MERGE (src_dev:Device {hostname: row.src_device})
    MERGE (dst_dev:Device {hostname: row.dst_device})
    CREATE (src_user)-[:AUTHENTICATED_TO {
        timestamp: row.timestamp,
        auth_type: row.auth_type,
        logon_type: row.logon_type,
        orientation: row.orientation,
        status: row.status
    }]->(dst_dev)
    """
    session.run(query, batch=batch)


def ingest_network_flows(session, filepath: str, max_rows: int = None):
    """
    Ingest LANL flows.txt into Neo4j.

    Creates Device and IP nodes and COMMUNICATED_WITH relationships.
    """
    logger.info(f"Ingesting network flows from {filepath}")

    if not os.path.isfile(filepath):
        logger.error(f"Flows file not found: {filepath}")
        return

    batch = []
    count = 0

    with open(filepath, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 9:
                continue

            batch.append({
                "timestamp": int(row[0]),
                "duration": int(row[1]),
                "src_device": row[2],
                "src_port": row[3],
                "dst_device": row[4],
                "dst_port": row[5],
                "protocol": row[6],
                "packet_count": int(row[7]),
                "byte_count": int(row[8]),
            })

            if len(batch) >= BATCH_SIZE:
                _write_flow_batch(session, batch)
                count += len(batch)
                logger.info(f"  Flow records ingested: {count}")
                batch = []

            if max_rows and count + len(batch) >= max_rows:
                break

    if batch:
        _write_flow_batch(session, batch)
        count += len(batch)

    logger.info(f"Flow ingestion complete. Total records: {count}")


def _write_flow_batch(session, batch: list):
    """Write a batch of network flow events to Neo4j."""
    query = """
    UNWIND $batch AS row
    MERGE (src:Device {hostname: row.src_device})
    MERGE (dst:Device {hostname: row.dst_device})
    CREATE (src)-[:COMMUNICATED_WITH {
        timestamp: row.timestamp,
        duration: row.duration,
        src_port: row.src_port,
        dst_port: row.dst_port,
        protocol: row.protocol,
        packet_count: row.packet_count,
        byte_count: row.byte_count
    }]->(dst)
    """
    session.run(query, batch=batch)


def run_lanl_etl(max_rows: int = None):
    """Run the full LANL ETL pipeline."""
    auth_path = os.path.join(LANL_DATA_DIR, "auth.txt")
    flows_path = os.path.join(LANL_DATA_DIR, "flows.txt")

    with get_session() as session:
        ingest_auth_logs(session, auth_path, max_rows=max_rows)
        ingest_network_flows(session, flows_path, max_rows=max_rows)

    logger.success("LANL ETL pipeline complete.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="LANL dataset ETL into Neo4j")
    parser.add_argument("--max-rows", type=int, default=None, help="Limit rows per file (for testing)")
    args = parser.parse_args()

    run_lanl_etl(max_rows=args.max_rows)
