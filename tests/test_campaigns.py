"""Tests for campaign clustering module."""

import pytest
import pandas as pd
from detection.campaign_clustering import (
    ATTACK_TYPE_TO_KILL_CHAIN,
    attribute_campaigns,
    analyze_infrastructure_overlap,
)


class TestKillChainMapping:
    def test_all_attack_types_mapped(self):
        expected = ["impossible_travel", "credential_stuffing", "lateral_movement", "data_exfiltration"]
        for at in expected:
            assert at in ATTACK_TYPE_TO_KILL_CHAIN

    def test_mappings_have_required_fields(self):
        for at, mapping in ATTACK_TYPE_TO_KILL_CHAIN.items():
            assert "stage" in mapping, f"Missing 'stage' in {at}"
            assert "tactics" in mapping, f"Missing 'tactics' in {at}"
            assert "techniques" in mapping, f"Missing 'techniques' in {at}"
            assert "sophistication" in mapping, f"Missing 'sophistication' in {at}"


class TestCampaignAttribution:
    def test_single_attack_type(self):
        campaigns = pd.DataFrame([{
            "campaign_id": "CAMP-001",
            "size": 10,
            "attack_types": ["credential_stuffing"],
            "users": [], "devices": [], "ips": [],
        }])
        result = attribute_campaigns(campaigns)
        assert len(result) == 1
        assert result.iloc[0]["severity"] in ["Critical", "High", "Medium", "Low"]

    def test_full_kill_chain_is_critical(self):
        campaigns = pd.DataFrame([{
            "campaign_id": "CAMP-APT",
            "size": 50,
            "attack_types": ["impossible_travel", "credential_stuffing", "lateral_movement", "data_exfiltration"],
            "users": [], "devices": [], "ips": [],
        }])
        result = attribute_campaigns(campaigns)
        assert result.iloc[0]["severity"] == "Critical"
        assert result.iloc[0]["kill_chain_coverage"] == 1.0
        assert "APT" in result.iloc[0]["threat_profile"]


class TestInfrastructureOverlap:
    def test_detects_shared_ips(self):
        campaigns = pd.DataFrame([
            {"campaign_id": "A", "ips": ["1.2.3.4", "5.6.7.8"], "devices": [], "users": []},
            {"campaign_id": "B", "ips": ["1.2.3.4", "9.0.1.2"], "devices": [], "users": []},
        ])
        overlaps = analyze_infrastructure_overlap(campaigns)
        assert len(overlaps) == 1
        assert "1.2.3.4" in overlaps.iloc[0]["shared_ips"]

    def test_no_overlap(self):
        campaigns = pd.DataFrame([
            {"campaign_id": "A", "ips": ["1.1.1.1"], "devices": ["d1"], "users": ["u1"]},
            {"campaign_id": "B", "ips": ["2.2.2.2"], "devices": ["d2"], "users": ["u2"]},
        ])
        overlaps = analyze_infrastructure_overlap(campaigns)
        assert overlaps.empty
