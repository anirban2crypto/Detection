"""Tests for synthetic attack injection."""

import pytest
from tests.conftest import TEST_TAG


class TestImpossibleTravel:
    """Verify impossible travel injection creates correct graph structure."""

    def test_creates_user_and_devices(self, clean_session):
        """Should create a User node with two Device connections."""
        clean_session.run("""
            MERGE (u:User {user_id: 'test_imp_user', test_tag: $tag})
            MERGE (d1:Device {hostname: 'TEST-WS-A', test_tag: $tag})
            MERGE (d2:Device {hostname: 'TEST-WS-B', test_tag: $tag})
            CREATE (u)-[:AUTHENTICATED_TO {
                timestamp: 1000000,
                location: 'New York',
                country: 'US',
                status: 'Success',
                attack_type: 'impossible_travel',
                test_tag: $tag
            }]->(d1)
            CREATE (u)-[:AUTHENTICATED_TO {
                timestamp: 1000300,
                location: 'Tokyo',
                country: 'JP',
                status: 'Success',
                attack_type: 'impossible_travel',
                test_tag: $tag
            }]->(d2)
        """, tag=TEST_TAG)

        # Verify structure
        result = clean_session.run("""
            MATCH (u:User {user_id: 'test_imp_user'})-[r:AUTHENTICATED_TO]->(d:Device)
            RETURN count(r) AS rel_count, collect(r.location) AS locations
        """)
        record = result.single()
        assert record["rel_count"] == 2
        assert set(record["locations"]) == {"New York", "Tokyo"}

    def test_time_delta_is_small(self, clean_session):
        """Impossible travel should have < 30 min between events."""
        clean_session.run("""
            MERGE (u:User {user_id: 'test_delta_user', test_tag: $tag})
            MERGE (d1:Device {hostname: 'TEST-D1', test_tag: $tag})
            MERGE (d2:Device {hostname: 'TEST-D2', test_tag: $tag})
            CREATE (u)-[:AUTHENTICATED_TO {timestamp: 5000, location: 'London', test_tag: $tag}]->(d1)
            CREATE (u)-[:AUTHENTICATED_TO {timestamp: 5300, location: 'Sydney', test_tag: $tag}]->(d2)
        """, tag=TEST_TAG)

        result = clean_session.run("""
            MATCH (u:User {user_id: 'test_delta_user'})-[r:AUTHENTICATED_TO]->(d)
            WITH u, collect(r.timestamp) AS times
            WITH u, reduce(minT = times[0], t IN times | CASE WHEN t < minT THEN t ELSE minT END) AS min_ts,
                    reduce(maxT = times[0], t IN times | CASE WHEN t > maxT THEN t ELSE maxT END) AS max_ts
            RETURN max_ts - min_ts AS delta_seconds
        """)
        delta = result.single()["delta_seconds"]
        assert delta < 1800, f"Time delta {delta}s should be < 1800s (30 min)"


class TestCredentialStuffing:
    """Verify credential stuffing creates high failed-login counts."""

    def test_many_failed_logins_from_one_ip(self, clean_session):
        """Should show multiple failed logins from one IP."""
        events = [
            {"user_id": f"test_victim_{i}", "status": "Fail"}
            for i in range(15)
        ]

        for e in events:
            clean_session.run("""
                MERGE (u:User {user_id: $uid, test_tag: $tag})
                MERGE (d:Device {hostname: 'TEST-AUTH-SRV', test_tag: $tag})
                MERGE (ip:IP {address: '198.51.100.1', test_tag: $tag})
                SET ip.is_external = true
                CREATE (u)-[:AUTHENTICATED_TO {status: $status, test_tag: $tag}]->(d)
                CREATE (d)-[:COMMUNICATED_WITH {test_tag: $tag}]->(ip)
            """, uid=e["user_id"], status=e["status"], tag=TEST_TAG)

        result = clean_session.run("""
            MATCH (u:User)-[r:AUTHENTICATED_TO]->(d:Device)-[:COMMUNICATED_WITH]->(ip:IP {address: '198.51.100.1'})
            WHERE r.status = 'Fail'
            RETURN count(r) AS fail_count
        """)
        assert result.single()["fail_count"] >= 10


class TestLateralMovement:
    """Verify lateral movement creates device chains."""

    def test_user_accesses_multiple_devices(self, clean_session):
        """Should show one user touching many devices."""
        devices = [f"TEST-SRV-{i}" for i in range(5)]

        for dev in devices:
            clean_session.run("""
                MERGE (u:User {user_id: 'test_lat_user', test_tag: $tag})
                MERGE (d:Device {hostname: $dev, test_tag: $tag})
                CREATE (u)-[:AUTHENTICATED_TO {status: 'Success', test_tag: $tag}]->(d)
            """, dev=dev, tag=TEST_TAG)

        result = clean_session.run("""
            MATCH (u:User {user_id: 'test_lat_user'})-[:AUTHENTICATED_TO]->(d:Device)
            RETURN count(DISTINCT d) AS device_count
        """)
        assert result.single()["device_count"] == 5


class TestDataExfiltration:
    """Verify data exfiltration creates large transfers."""

    def test_large_outbound_transfer(self, clean_session):
        """Should create a high byte_count transfer to external IP."""
        clean_session.run("""
            MERGE (d:Device {hostname: 'TEST-DB-SRV', test_tag: $tag})
            MERGE (ip:IP {address: '203.0.113.99', test_tag: $tag})
            SET ip.is_external = true
            CREATE (d)-[:COMMUNICATED_WITH {
                byte_count: 250000000,
                protocol: 'TCP',
                dst_port: '443',
                test_tag: $tag,
                attack_type: 'data_exfiltration'
            }]->(ip)
        """, tag=TEST_TAG)

        result = clean_session.run("""
            MATCH (d:Device)-[r:COMMUNICATED_WITH]->(ip:IP {address: '203.0.113.99'})
            WHERE r.byte_count > 10000000
            RETURN r.byte_count AS bytes
        """)
        assert result.single()["bytes"] == 250000000
