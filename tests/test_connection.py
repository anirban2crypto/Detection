"""Tests for Neo4j connection and schema setup."""

import pytest
from config.neo4j_connection import get_driver, get_session


class TestNeo4jConnection:
    """Verify Neo4j connectivity."""

    def test_driver_connects(self, neo4j_driver):
        """Driver should connect and verify connectivity."""
        neo4j_driver.verify_connectivity()

    def test_session_runs_query(self, neo4j_session):
        """Session should execute a simple Cypher query."""
        result = neo4j_session.run("RETURN 1 AS n")
        record = result.single()
        assert record["n"] == 1

    def test_get_session_context_manager(self):
        """get_session() context manager should work."""
        with get_session() as session:
            result = session.run("RETURN 'hello' AS msg")
            assert result.single()["msg"] == "hello"


class TestSchemaSetup:
    """Verify schema constraints and indexes exist."""

    def test_constraints_exist(self, neo4j_session):
        """Schema should have uniqueness constraints."""
        result = neo4j_session.run("SHOW CONSTRAINTS")
        constraints = [r.data() for r in result]
        constraint_names = [c.get("name", "") for c in constraints]

        expected = [
            "user_id_unique",
            "device_hostname_unique",
            "ip_address_unique",
            "malware_hash_unique",
            "technique_mitre_id_unique",
            "campaign_name_unique",
        ]
        for name in expected:
            assert name in constraint_names, f"Missing constraint: {name}"

    def test_indexes_exist(self, neo4j_session):
        """Schema should have performance indexes."""
        result = neo4j_session.run("SHOW INDEXES")
        indexes = [r.data() for r in result]
        index_names = [i.get("name", "") for i in indexes]

        expected = [
            "idx_user_department",
            "idx_device_os",
            "idx_ip_is_external",
        ]
        for name in expected:
            assert name in index_names, f"Missing index: {name}"
