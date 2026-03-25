"""Tests for MITRE ATT&CK enrichment."""

import pytest
from data_ingestion.mitre_enrichment import (
    TECHNIQUES,
    ATTACK_TECHNIQUE_MAP,
    ingest_techniques,
    get_technique_summary,
)
from tests.conftest import TEST_TAG


class TestMitreTechniques:
    """Verify MITRE technique data integrity."""

    def test_all_techniques_have_required_fields(self):
        """Each technique should have mitre_id, name, tactic, description."""
        for tech in TECHNIQUES:
            assert "mitre_id" in tech, f"Missing mitre_id in {tech}"
            assert "name" in tech, f"Missing name in {tech}"
            assert "tactic" in tech, f"Missing tactic in {tech}"
            assert tech["mitre_id"].startswith("T"), f"Invalid ID: {tech['mitre_id']}"

    def test_attack_map_references_valid_techniques(self):
        """All mapped technique IDs should exist in TECHNIQUES."""
        valid_ids = {t["mitre_id"] for t in TECHNIQUES}
        for attack_type, mappings in ATTACK_TECHNIQUE_MAP.items():
            for m in mappings:
                assert m["mitre_id"] in valid_ids, (
                    f"{attack_type} references unknown technique: {m['mitre_id']}"
                )

    def test_all_attack_types_are_mapped(self):
        """Every known attack type should have at least one technique mapping."""
        expected = ["impossible_travel", "credential_stuffing", "lateral_movement", "data_exfiltration"]
        for attack in expected:
            assert attack in ATTACK_TECHNIQUE_MAP, f"Missing mapping for {attack}"
            assert len(ATTACK_TECHNIQUE_MAP[attack]) > 0

    def test_confidence_values_are_valid(self):
        """Confidence should be 'high', 'medium', or 'low'."""
        valid = {"high", "medium", "low"}
        for attack_type, mappings in ATTACK_TECHNIQUE_MAP.items():
            for m in mappings:
                assert m["confidence"] in valid, (
                    f"Invalid confidence '{m['confidence']}' in {attack_type}"
                )


class TestMitreIngestion:
    """Verify MITRE techniques are ingested into Neo4j."""

    def test_techniques_ingested(self, neo4j_session):
        """Technique nodes should exist after ingestion."""
        ingest_techniques(neo4j_session)

        result = neo4j_session.run("MATCH (t:Technique) RETURN count(t) AS cnt")
        count = result.single()["cnt"]
        assert count >= len(TECHNIQUES), f"Expected >= {len(TECHNIQUES)} techniques, got {count}"

    def test_technique_has_properties(self, neo4j_session):
        """T1078 should exist with correct properties."""
        result = neo4j_session.run("""
            MATCH (t:Technique {mitre_id: 'T1078'})
            RETURN t.name AS name, t.tactic AS tactic
        """)
        record = result.single()
        assert record is not None, "T1078 not found"
        assert record["name"] == "Valid Accounts"
        assert record["tactic"] == "Initial Access"
