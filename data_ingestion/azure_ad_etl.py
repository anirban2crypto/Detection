"""
Azure AD Sign-In Log ETL — Synthetic Generator + Neo4j Ingestion

Generates realistic Azure AD sign-in logs and ingests them into Neo4j.
Demonstrates knowledge of Microsoft Entra ID (Azure AD) log schemas
and multi-tenant cloud security.

Azure AD Sign-In Log schema modeled:
    - tenantId, userId, userPrincipalName
    - appDisplayName, resourceDisplayName
    - ipAddress, location (city, state, country)
    - status (errorCode, failureReason)
    - deviceDetail (deviceId, displayName, operatingSystem, browser)
    - conditionalAccessStatus, riskLevelDuringSignIn, riskState
    - mfaDetail

Reference: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-sign-ins-log-schema
"""

import os
import sys
import uuid
import random
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from faker import Faker
from loguru import logger
from config.neo4j_connection import get_session

fake = Faker()

# ─────────────────────────────────────────────────────────────────────────────
# Azure AD Tenant Configuration
# ─────────────────────────────────────────────────────────────────────────────

TENANTS = [
    {"tenant_id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "contoso.com")), "name": "Contoso Corp", "domain": "contoso.com"},
    {"tenant_id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "fabrikam.com")), "name": "Fabrikam Inc", "domain": "fabrikam.com"},
    {"tenant_id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "woodgrove.com")), "name": "Woodgrove Bank", "domain": "woodgrove.com"},
]

CLOUD_APPS = [
    {"app_id": "00000003-0000-0000-c000-000000000000", "name": "Microsoft Graph"},
    {"app_id": "00000002-0000-0ff1-ce00-000000000000", "name": "Office 365 Exchange Online"},
    {"app_id": "00000003-0000-0ff1-ce00-000000000000", "name": "Microsoft SharePoint Online"},
    {"app_id": "797f4846-ba00-4fd7-ba43-dac1f8f63013", "name": "Azure Service Management"},
    {"app_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "name": "Azure CLI"},
    {"app_id": "1950a258-227b-4e31-a9cf-717495945fc2", "name": "Azure PowerShell"},
]

RISK_LEVELS = ["none", "low", "medium", "high"]
RISK_STATES = ["none", "confirmedSafe", "remediated", "dismissed", "atRisk", "confirmedCompromised"]
CA_STATUSES = ["success", "failure", "notApplied"]
OS_LIST = ["Windows 10", "Windows 11", "macOS 14", "iOS 17", "Android 14", "Linux"]
BROWSERS = ["Chrome 120", "Edge 120", "Safari 17", "Firefox 121", "Mobile Safari"]

LOCATIONS = [
    {"city": "Seattle", "state": "WA", "country": "US", "lat": 47.6, "lon": -122.3},
    {"city": "Redmond", "state": "WA", "country": "US", "lat": 47.7, "lon": -122.1},
    {"city": "New York", "state": "NY", "country": "US", "lat": 40.7, "lon": -74.0},
    {"city": "London", "state": "England", "country": "GB", "lat": 51.5, "lon": -0.1},
    {"city": "Tokyo", "state": "Tokyo", "country": "JP", "lat": 35.7, "lon": 139.7},
    {"city": "Mumbai", "state": "MH", "country": "IN", "lat": 19.1, "lon": 72.9},
    {"city": "São Paulo", "state": "SP", "country": "BR", "lat": -23.5, "lon": -46.6},
    {"city": "Lagos", "state": "LA", "country": "NG", "lat": 6.5, "lon": 3.4},
]


# ─────────────────────────────────────────────────────────────────────────────
# Generate Synthetic Azure AD Sign-In Logs
# ─────────────────────────────────────────────────────────────────────────────

def generate_sign_in_logs(
    num_users_per_tenant: int = 20,
    num_events: int = 500,
    attack_ratio: float = 0.15,
) -> list:
    """
    Generate realistic Azure AD sign-in log entries.
    A portion will be injected as attack scenarios.
    """
    logger.info(f"Generating {num_events} Azure AD sign-in logs across {len(TENANTS)} tenants...")

    # Create users per tenant
    users = []
    for tenant in TENANTS:
        for i in range(num_users_per_tenant):
            first = fake.first_name()
            last = fake.last_name()
            users.append({
                "user_id": str(uuid.uuid4()),
                "upn": f"{first.lower()}.{last.lower()}@{tenant['domain']}",
                "display_name": f"{first} {last}",
                "tenant_id": tenant["tenant_id"],
                "tenant_name": tenant["name"],
                "department": random.choice(["Engineering", "Finance", "HR", "Sales", "IT", "Security"]),
                "job_title": random.choice(["Engineer", "Manager", "Analyst", "Director", "VP"]),
                "home_location": random.choice(LOCATIONS[:4]),  # normal locations
            })

    base_time = datetime(2026, 3, 1, 8, 0, 0)
    events = []
    num_attacks = int(num_events * attack_ratio)

    # Normal sign-in events
    for _ in range(num_events - num_attacks):
        user = random.choice(users)
        app = random.choice(CLOUD_APPS)
        loc = user["home_location"]
        ts = base_time + timedelta(seconds=random.randint(0, 30 * 24 * 3600))

        events.append(_build_sign_in_event(
            user=user, app=app, location=loc, timestamp=ts,
            status_code=0, risk_level="none", risk_state="none",
            ca_status="success", is_attack=False,
        ))

    # Attack events
    for _ in range(num_attacks):
        user = random.choice(users)
        attack_type = random.choice([
            "impossible_travel",
            "credential_stuffing",
            "suspicious_app_access",
            "risky_sign_in",
        ])

        if attack_type == "impossible_travel":
            loc = random.choice(LOCATIONS[4:])  # distant location
            ts = base_time + timedelta(seconds=random.randint(0, 30 * 24 * 3600))
            events.append(_build_sign_in_event(
                user=user, app=random.choice(CLOUD_APPS), location=loc, timestamp=ts,
                status_code=0, risk_level="high", risk_state="atRisk",
                ca_status="success", is_attack=True, attack_type="impossible_travel",
            ))

        elif attack_type == "credential_stuffing":
            loc = random.choice(LOCATIONS[4:])
            ts = base_time + timedelta(seconds=random.randint(0, 30 * 24 * 3600))
            events.append(_build_sign_in_event(
                user=user, app=random.choice(CLOUD_APPS), location=loc, timestamp=ts,
                status_code=50126, failure_reason="Invalid username or password",
                risk_level="medium", risk_state="atRisk",
                ca_status="failure", is_attack=True, attack_type="credential_stuffing",
            ))

        elif attack_type == "suspicious_app_access":
            # Access sensitive apps like Azure CLI / PowerShell
            app = random.choice([a for a in CLOUD_APPS if "CLI" in a["name"] or "PowerShell" in a["name"]])
            loc = random.choice(LOCATIONS)
            ts = base_time + timedelta(seconds=random.randint(0, 30 * 24 * 3600))
            events.append(_build_sign_in_event(
                user=user, app=app, location=loc, timestamp=ts,
                status_code=0, risk_level="medium", risk_state="atRisk",
                ca_status="success", is_attack=True, attack_type="suspicious_app_access",
            ))

        elif attack_type == "risky_sign_in":
            loc = random.choice(LOCATIONS)
            ts = base_time + timedelta(seconds=random.randint(0, 30 * 24 * 3600))
            events.append(_build_sign_in_event(
                user=user, app=random.choice(CLOUD_APPS), location=loc, timestamp=ts,
                status_code=0, risk_level=random.choice(["high", "medium"]),
                risk_state="confirmedCompromised",
                ca_status="success", is_attack=True, attack_type="risky_sign_in",
            ))

    logger.info(f"  Generated {len(events)} events ({num_attacks} attack events)")
    return events


def _build_sign_in_event(
    user, app, location, timestamp,
    status_code=0, failure_reason=None,
    risk_level="none", risk_state="none",
    ca_status="success", is_attack=False, attack_type=None,
):
    """Build a single Azure AD sign-in log event."""
    return {
        "id": str(uuid.uuid4()),
        "timestamp": timestamp.isoformat(),
        "tenant_id": user["tenant_id"],
        "tenant_name": user["tenant_name"],
        "user_id": user["user_id"],
        "user_principal_name": user["upn"],
        "user_display_name": user["display_name"],
        "department": user["department"],
        "app_id": app["app_id"],
        "app_display_name": app["name"],
        "ip_address": fake.ipv4_public(),
        "location_city": location["city"],
        "location_state": location["state"],
        "location_country": location["country"],
        "latitude": location["lat"],
        "longitude": location["lon"],
        "status_error_code": status_code,
        "status_failure_reason": failure_reason or "",
        "device_os": random.choice(OS_LIST),
        "device_browser": random.choice(BROWSERS),
        "device_id": str(uuid.uuid4()),
        "conditional_access_status": ca_status,
        "risk_level_during_sign_in": risk_level,
        "risk_state": risk_state,
        "mfa_completed": random.choice([True, False]) if status_code == 0 else False,
        "is_attack": is_attack,
        "attack_type": attack_type,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Ingest into Neo4j
# ─────────────────────────────────────────────────────────────────────────────

BATCH_SIZE = 200


def ingest_tenants(session):
    """Create Tenant nodes."""
    query = """
    UNWIND $tenants AS t
    MERGE (tenant:Tenant {tenant_id: t.tenant_id})
    SET tenant.name = t.name,
        tenant.domain = t.domain
    """
    session.run(query, tenants=TENANTS)
    logger.info(f"  ✓ {len(TENANTS)} tenants ingested")


def ingest_cloud_apps(session):
    """Create CloudApp nodes."""
    query = """
    UNWIND $apps AS a
    MERGE (app:CloudApp {app_id: a.app_id})
    SET app.name = a.name
    """
    session.run(query, apps=CLOUD_APPS)
    logger.info(f"  ✓ {len(CLOUD_APPS)} cloud apps ingested")


def ingest_sign_in_events(session, events: list):
    """Ingest Azure AD sign-in events into Neo4j graph."""
    logger.info(f"Ingesting {len(events)} sign-in events...")

    for i in range(0, len(events), BATCH_SIZE):
        batch = events[i:i + BATCH_SIZE]
        query = """
        UNWIND $batch AS e
        MERGE (tenant:Tenant {tenant_id: e.tenant_id})
        MERGE (user:User {user_id: e.user_principal_name})
        SET user.display_name = e.user_display_name,
            user.department = e.department,
            user.tenant_id = e.tenant_id
        MERGE (user)-[:BELONGS_TO]->(tenant)

        MERGE (ip:IP {address: e.ip_address})
        SET ip.is_external = true,
            ip.geo_location = e.location_city + ', ' + e.location_country,
            ip.latitude = e.latitude,
            ip.longitude = e.longitude

        MERGE (app:CloudApp {app_id: e.app_id})
        SET app.name = e.app_display_name

        MERGE (device:Device {hostname: e.device_id})
        SET device.os = e.device_os,
            device.browser = e.device_browser

        CREATE (user)-[:SIGNED_IN_TO {
            timestamp: e.timestamp,
            ip_address: e.ip_address,
            location: e.location_city,
            country: e.location_country,
            status_code: e.status_error_code,
            failure_reason: e.status_failure_reason,
            risk_level: e.risk_level_during_sign_in,
            risk_state: e.risk_state,
            conditional_access: e.conditional_access_status,
            mfa_completed: e.mfa_completed,
            is_attack: e.is_attack,
            attack_type: COALESCE(e.attack_type, '')
        }]->(app)

        CREATE (user)-[:AUTHENTICATED_FROM {
            timestamp: e.timestamp,
            location: e.location_city,
            country: e.location_country,
            risk_level: e.risk_level_during_sign_in,
            is_attack: e.is_attack,
            attack_type: COALESCE(e.attack_type, '')
        }]->(ip)
        """
        session.run(query, batch=batch)
        logger.info(f"  Batch {i // BATCH_SIZE + 1}: {len(batch)} events")

    logger.info(f"  ✓ All {len(events)} sign-in events ingested")


# ─────────────────────────────────────────────────────────────────────────────
# Azure-specific detection queries
# ─────────────────────────────────────────────────────────────────────────────

def detect_risky_sign_ins(session) -> list:
    """Find high-risk Azure AD sign-ins."""
    query = """
    MATCH (u:User)-[r:SIGNED_IN_TO]->(app:CloudApp)
    WHERE r.risk_level IN ['high', 'medium']
    RETURN u.user_id AS user,
           app.name AS application,
           r.risk_level AS risk_level,
           r.risk_state AS risk_state,
           r.location AS location,
           r.country AS country,
           r.timestamp AS timestamp,
           r.conditional_access AS conditional_access,
           r.mfa_completed AS mfa_completed
    ORDER BY r.risk_level DESC
    LIMIT 50
    """
    result = session.run(query)
    return [record.data() for record in result]


def detect_cross_tenant_activity(session) -> list:
    """Find users with sign-in activity across multiple tenants."""
    query = """
    MATCH (u:User)-[:BELONGS_TO]->(t:Tenant)
    WITH u, collect(DISTINCT t.name) AS tenants
    WHERE size(tenants) > 1
    RETURN u.user_id AS user,
           tenants,
           size(tenants) AS tenant_count
    ORDER BY tenant_count DESC
    LIMIT 20
    """
    result = session.run(query)
    return [record.data() for record in result]


def detect_suspicious_app_access(session) -> list:
    """Find sign-ins to admin tools (Azure CLI, PowerShell) from risky locations."""
    query = """
    MATCH (u:User)-[r:SIGNED_IN_TO]->(app:CloudApp)
    WHERE app.name IN ['Azure CLI', 'Azure PowerShell', 'Azure Service Management']
      AND (r.risk_level <> 'none' OR r.is_attack = true)
    RETURN u.user_id AS user,
           app.name AS admin_tool,
           r.location AS location,
           r.country AS country,
           r.risk_level AS risk_level,
           r.timestamp AS timestamp
    ORDER BY r.timestamp DESC
    LIMIT 30
    """
    result = session.run(query)
    return [record.data() for record in result]


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def run_azure_ad_etl(num_users: int = 20, num_events: int = 500):
    """Full Azure AD ETL pipeline: generate → ingest → detect."""
    logger.info("Starting Azure AD sign-in log ETL...")

    events = generate_sign_in_logs(
        num_users_per_tenant=num_users,
        num_events=num_events,
    )

    with get_session() as session:
        ingest_tenants(session)
        ingest_cloud_apps(session)
        ingest_sign_in_events(session, events)

        logger.info("\nRunning Azure-specific detections...")
        risky = detect_risky_sign_ins(session)
        cross_tenant = detect_cross_tenant_activity(session)
        suspicious_apps = detect_suspicious_app_access(session)

    logger.info(f"  Risky sign-ins: {len(risky)}")
    logger.info(f"  Cross-tenant activity: {len(cross_tenant)}")
    logger.info(f"  Suspicious admin tool access: {len(suspicious_apps)}")
    logger.success("Azure AD ETL complete.")

    return {"risky_sign_ins": risky, "cross_tenant": cross_tenant, "suspicious_apps": suspicious_apps}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Azure AD sign-in log ETL")
    parser.add_argument("--users", type=int, default=20, help="Users per tenant")
    parser.add_argument("--events", type=int, default=500, help="Total sign-in events")
    args = parser.parse_args()

    findings = run_azure_ad_etl(num_users=args.users, num_events=args.events)

    for category, items in findings.items():
        print(f"\n=== {category.upper()} ({len(items)}) ===")
        for item in items[:3]:
            print(f"  {item}")
        if len(items) > 3:
            print(f"  ... and {len(items) - 3} more")
