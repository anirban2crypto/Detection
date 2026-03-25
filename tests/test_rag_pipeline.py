"""Tests for the RAG pipeline prompt construction."""

import pytest
from rag_pipeline.generate_report import (
    format_findings,
    format_graph_summary,
    SYSTEM_PROMPT,
    ANALYSIS_PROMPT_TEMPLATE,
)


class TestFormatFindings:
    """Verify findings are formatted correctly for LLM prompts."""

    def test_empty_findings(self):
        """Empty list should return no-alerts message."""
        result = format_findings([])
        assert "No alerts" in result

    def test_single_finding(self):
        """Single finding should be formatted as Alert 1."""
        findings = [{"user_id": "alice", "location": "NYC"}]
        result = format_findings(findings)
        assert "Alert 1" in result
        assert "alice" in result
        assert "NYC" in result

    def test_truncation(self):
        """Findings beyond max_items should be truncated."""
        findings = [{"id": i} for i in range(30)]
        result = format_findings(findings, max_items=5)
        assert "Alert 5" in result
        assert "25 more" in result

    def test_large_list_truncated_in_value(self):
        """Lists with >10 items should show count + preview."""
        findings = [{"users": list(range(20))}]
        result = format_findings(findings)
        assert "20 items" in result


class TestFormatGraphSummary:
    """Verify graph summary formatting."""

    def test_empty_summary(self):
        """Empty dict should indicate empty graph."""
        result = format_graph_summary({})
        assert "empty" in result.lower()

    def test_normal_summary(self):
        """Should list each label with count."""
        summary = {"User": 100, "Device": 50, "IP": 25}
        result = format_graph_summary(summary)
        assert "User: 100" in result
        assert "Device: 50" in result
        assert "IP: 25" in result


class TestPromptTemplates:
    """Verify prompt templates are well-formed."""

    def test_system_prompt_has_key_instructions(self):
        """System prompt should mention MITRE ATT&CK and severity."""
        assert "MITRE" in SYSTEM_PROMPT
        assert "severity" in SYSTEM_PROMPT.lower()

    def test_analysis_template_has_placeholders(self):
        """Template should have all required format placeholders."""
        placeholders = [
            "graph_summary",
            "impossible_travel_count",
            "impossible_travel_data",
            "credential_stuffing_count",
            "lateral_movement_count",
            "data_exfiltration_count",
        ]
        for p in placeholders:
            assert f"{{{p}}}" in ANALYSIS_PROMPT_TEMPLATE, f"Missing placeholder: {p}"
