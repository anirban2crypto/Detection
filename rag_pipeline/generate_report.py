"""
RAG Pipeline — Retrieval-Augmented Generation for Threat Analysis

1. Retrieve: Run detection queries against Neo4j to gather suspicious subgraphs
2. Augment: Format entities and relationships into structured prompt context
3. Generate: Send the augmented prompt to GPT-4 for analyst-friendly reporting
"""

import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI
from loguru import logger

from detection.cypher_queries import (
    detect_impossible_travel,
    detect_credential_stuffing,
    detect_lateral_movement,
    detect_data_exfiltration,
    get_graph_summary,
)
from config.neo4j_connection import get_session

load_dotenv(Path.home() / ".env")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")


# ─────────────────────────────────────────────────────────────────────────────
# Prompt templates
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior cybersecurity analyst specializing in threat detection and incident response. 
You analyze graph-based security data and produce clear, actionable reports.

When given detection findings from a security knowledge graph, you must:
1. Summarize the suspicious activity in plain language
2. Map findings to MITRE ATT&CK techniques (provide technique IDs)
3. Assess the likely attacker goals and campaign stage
4. Recommend specific response actions prioritized by urgency
5. Rate the overall severity: Critical / High / Medium / Low

Be concise but thorough. Use bullet points for clarity. Cite specific entities (users, devices, IPs) from the data."""

ANALYSIS_PROMPT_TEMPLATE = """## Security Detection Report Request

### Graph Summary
{graph_summary}

### Detection Findings

#### Impossible Travel Alerts ({impossible_travel_count})
{impossible_travel_data}

#### Credential Stuffing Alerts ({credential_stuffing_count})
{credential_stuffing_data}

#### Lateral Movement Alerts ({lateral_movement_count})
{lateral_movement_data}

#### Data Exfiltration Alerts ({data_exfiltration_count})
{data_exfiltration_data}

---

Please analyze these findings and produce a structured threat report covering:
1. Executive Summary
2. Detailed Findings (per attack type)
3. MITRE ATT&CK Mapping
4. Attacker Intent Assessment
5. Recommended Response Actions
6. Overall Severity Rating"""

SINGLE_QUERY_PROMPT_TEMPLATE = """## Security Detection Analysis

### Graph Summary
{graph_summary}

### Detection Type: {detection_type}

### Findings ({finding_count})
{findings_data}

---

Analyze these findings and provide:
1. Summary of suspicious activity
2. MITRE ATT&CK technique mapping
3. Likely attacker goals
4. Recommended response actions
5. Severity rating"""


# ─────────────────────────────────────────────────────────────────────────────
# Context formatting
# ─────────────────────────────────────────────────────────────────────────────

def format_findings(findings: list, max_items: int = 20) -> str:
    """Format detection findings into readable text for the LLM prompt."""
    if not findings:
        return "No alerts detected."

    truncated = findings[:max_items]
    lines = []
    for i, finding in enumerate(truncated, 1):
        lines.append(f"**Alert {i}:**")
        for key, value in finding.items():
            if isinstance(value, list) and len(value) > 10:
                lines.append(f"  - {key}: [{len(value)} items] {value[:5]}...")
            else:
                lines.append(f"  - {key}: {value}")
        lines.append("")

    if len(findings) > max_items:
        lines.append(f"... and {len(findings) - max_items} more alerts")

    return "\n".join(lines)


def format_graph_summary(summary: dict) -> str:
    """Format graph node counts into a readable summary."""
    if not summary:
        return "Graph is empty."
    lines = [f"- {label}: {count} nodes" for label, count in summary.items()]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Retrieval
# ─────────────────────────────────────────────────────────────────────────────

def retrieve_all_findings():
    """Run all detection queries and return structured findings + summary."""
    with get_session() as session:
        summary = get_graph_summary(session)
        findings = {
            "impossible_travel": detect_impossible_travel(session),
            "credential_stuffing": detect_credential_stuffing(session),
            "lateral_movement": detect_lateral_movement(session),
            "data_exfiltration": detect_data_exfiltration(session),
        }
    return findings, summary


def retrieve_single_detection(detection_type: str):
    """Run a single detection query and return findings + summary."""
    from detection.cypher_queries import DETECTIONS

    if detection_type not in DETECTIONS:
        raise ValueError(f"Unknown detection type: {detection_type}. Choose from: {list(DETECTIONS.keys())}")

    with get_session() as session:
        summary = get_graph_summary(session)
        findings = DETECTIONS[detection_type](session)
    return findings, summary


# ─────────────────────────────────────────────────────────────────────────────
# Generation
# ─────────────────────────────────────────────────────────────────────────────

def generate_full_report(findings: dict, summary: dict) -> str:
    """Build prompt from all findings and generate a comprehensive report."""
    prompt = ANALYSIS_PROMPT_TEMPLATE.format(
        graph_summary=format_graph_summary(summary),
        impossible_travel_count=len(findings.get("impossible_travel", [])),
        impossible_travel_data=format_findings(findings.get("impossible_travel", [])),
        credential_stuffing_count=len(findings.get("credential_stuffing", [])),
        credential_stuffing_data=format_findings(findings.get("credential_stuffing", [])),
        lateral_movement_count=len(findings.get("lateral_movement", [])),
        lateral_movement_data=format_findings(findings.get("lateral_movement", [])),
        data_exfiltration_count=len(findings.get("data_exfiltration", [])),
        data_exfiltration_data=format_findings(findings.get("data_exfiltration", [])),
    )

    logger.info(f"Sending full analysis prompt to {MODEL} ({len(prompt)} chars)...")
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
        max_tokens=4000,
    )
    report = response.choices[0].message.content
    logger.info("Full report generated.")
    return report


def generate_single_report(detection_type: str, findings: list, summary: dict) -> str:
    """Build prompt from a single detection type and generate a focused report."""
    display_name = detection_type.replace("_", " ").title()
    prompt = SINGLE_QUERY_PROMPT_TEMPLATE.format(
        graph_summary=format_graph_summary(summary),
        detection_type=display_name,
        finding_count=len(findings),
        findings_data=format_findings(findings),
    )

    logger.info(f"Sending {display_name} analysis prompt to {MODEL}...")
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
        max_tokens=2500,
    )
    report = response.choices[0].message.content
    logger.info(f"{display_name} report generated.")
    return report


# ─────────────────────────────────────────────────────────────────────────────
# End-to-end pipeline
# ─────────────────────────────────────────────────────────────────────────────

def run_full_pipeline() -> str:
    """Retrieve all findings → generate comprehensive threat report."""
    findings, summary = retrieve_all_findings()
    total_alerts = sum(len(v) for v in findings.values())
    logger.info(f"Total alerts retrieved: {total_alerts}")

    if total_alerts == 0:
        return "No suspicious activity detected in the current graph."

    return generate_full_report(findings, summary)


def run_single_pipeline(detection_type: str) -> str:
    """Retrieve findings for one detection type → generate focused report."""
    findings, summary = retrieve_single_detection(detection_type)

    if not findings:
        return f"No {detection_type.replace('_', ' ')} alerts detected."

    return generate_single_report(detection_type, findings, summary)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="RAG pipeline: graph → LLM → threat report")
    parser.add_argument(
        "--detection",
        choices=["all", "impossible_travel", "credential_stuffing", "lateral_movement", "data_exfiltration"],
        default="all",
        help="Which detection to analyze (default: all)",
    )
    parser.add_argument("--output", type=str, default=None, help="Save report to file")
    args = parser.parse_args()

    if args.detection == "all":
        report = run_full_pipeline()
    else:
        report = run_single_pipeline(args.detection)

    print("\n" + "=" * 80)
    print(report)
    print("=" * 80)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        logger.info(f"Report saved to {args.output}")
