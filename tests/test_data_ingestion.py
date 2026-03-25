"""Tests for Azure AD ETL and MalwareBazaar ETL."""

import pytest
from data_ingestion.azure_ad_etl import (
    TENANTS,
    CLOUD_APPS,
    generate_sign_in_logs,
    detect_risky_sign_ins,
    detect_cross_tenant_activity,
    detect_suspicious_app_access,
)
from data_ingestion.malwarebazaar_etl import (
    _generate_fallback_samples,
)


class TestAzureADLogGeneration:
    def test_generates_correct_count(self):
        events = generate_sign_in_logs(num_users_per_tenant=5, num_events=100)
        assert len(events) == 100

    def test_events_have_required_fields(self):
        events = generate_sign_in_logs(num_users_per_tenant=3, num_events=10)
        required = ["tenant_id", "user_principal_name", "app_id", "ip_address",
                     "risk_level_during_sign_in", "location_city"]
        for event in events:
            for field in required:
                assert field in event, f"Missing field: {field}"

    def test_attack_events_included(self):
        events = generate_sign_in_logs(num_users_per_tenant=5, num_events=100, attack_ratio=0.2)
        attacks = [e for e in events if e["is_attack"]]
        assert len(attacks) > 0
        assert all(e["attack_type"] is not None for e in attacks)

    def test_multiple_tenants_represented(self):
        events = generate_sign_in_logs(num_users_per_tenant=5, num_events=100)
        tenant_ids = set(e["tenant_id"] for e in events)
        assert len(tenant_ids) == len(TENANTS)

    def test_upn_format(self):
        events = generate_sign_in_logs(num_users_per_tenant=3, num_events=10)
        for event in events:
            assert "@" in event["user_principal_name"]
            domain = event["user_principal_name"].split("@")[1]
            valid_domains = [t["domain"] for t in TENANTS]
            assert domain in valid_domains


class TestTenantConfig:
    def test_tenants_have_required_fields(self):
        for tenant in TENANTS:
            assert "tenant_id" in tenant
            assert "name" in tenant
            assert "domain" in tenant

    def test_cloud_apps_have_required_fields(self):
        for app in CLOUD_APPS:
            assert "app_id" in app
            assert "name" in app


class TestMalwareBazaarFallback:
    def test_generates_samples(self):
        samples = _generate_fallback_samples(20)
        assert len(samples) == 20

    def test_samples_have_required_fields(self):
        samples = _generate_fallback_samples(5)
        for s in samples:
            assert "hash" in s
            assert "family" in s
            assert "file_type" in s
            assert "tags" in s
            assert len(s["hash"]) == 64  # SHA256

    def test_samples_have_valid_families(self):
        samples = _generate_fallback_samples(50)
        families = set(s["family"] for s in samples)
        assert len(families) > 1  # Should have multiple families
