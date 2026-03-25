#!/usr/bin/env bash
# ============================================================================
# 🛡️ Threat Detection via Graph + RAG + LLM — Full Pipeline Runner
# ============================================================================
#
# This script runs the entire project pipeline end-to-end:
#
#   1. Start Neo4j       — Launches Neo4j in Docker with APOC plugin
#   2. Schema Setup      — Creates constraints and indexes in the graph DB
#   3. Inject Attacks    — Generates synthetic attack data (impossible travel,
#                          credential stuffing, lateral movement, exfiltration)
#   4. MITRE Enrichment  — Maps attacks to MITRE ATT&CK techniques
#   5. Run Detections    — Executes Cypher queries to find anomalies
#   6. Generate Report   — Sends findings to GPT-4 via RAG for analysis
#   7. Launch Dashboard  — Starts Streamlit UI with graph viz + AI reports
#
# Usage:
#   ./run.sh              — Run full pipeline (steps 1–6)
#   ./run.sh --skip-neo4j — Skip Neo4j startup (already running)
#   ./run.sh --step 3     — Run from step 3 onward
#   ./run.sh --dashboard  — Jump straight to dashboard
#   ./run.sh --clean      — Remove synthetic data and stop Neo4j
#
# Prerequisites:
#   - Docker installed and running
#   - Python 3.9+ with dependencies: pip install -r requirements.txt
#   - .env file with OPENAI_API_KEY (copy from .env.example)
#
# ============================================================================

set -e

cd "$(dirname "$0")"

# ── Colors ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ── Defaults ────────────────────────────────────────────────────────────────
SKIP_NEO4J=false
START_STEP=1
DASHBOARD_ONLY=false
CLEAN=false
NEO4J_CONTAINER="neo4j"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-changeme}"
NEO4J_WAIT=20

# ── Parse arguments ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-neo4j)  SKIP_NEO4J=true; shift ;;
        --step)        START_STEP="$2"; shift 2 ;;
        --dashboard)   DASHBOARD_ONLY=true; shift ;;
        --clean)       CLEAN=true; shift ;;
        -h|--help)
            head -30 "$0" | tail -25
            exit 0
            ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

# ── Helper functions ────────────────────────────────────────────────────────
step_header() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  Step $1: $2${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

check_env() {
    if [ ! -f .env ]; then
        echo -e "${YELLOW}⚠ No .env file found. Copying from .env.example...${NC}"
        cp .env.example .env
        echo -e "${YELLOW}  → Edit .env and set your OPENAI_API_KEY before step 5.${NC}"
    fi
}

# ── Clean mode ──────────────────────────────────────────────────────────────
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}🧹 Cleaning up...${NC}"
    echo "  Removing synthetic attack data from Neo4j..."
    python synthetic_injection/inject_attacks.py --clean 2>/dev/null || true
    echo "  Stopping Neo4j container..."
    docker stop "$NEO4J_CONTAINER" 2>/dev/null || true
    docker rm "$NEO4J_CONTAINER" 2>/dev/null || true
    echo -e "${GREEN}✓ Cleanup complete.${NC}"
    exit 0
fi

# ── Dashboard-only mode ────────────────────────────────────────────────────
if [ "$DASHBOARD_ONLY" = true ]; then
    echo -e "${GREEN}🚀 Launching dashboard...${NC}"
    streamlit run dashboard/dashboard.py
    exit 0
fi

# ── Check prerequisites ────────────────────────────────────────────────────
check_env

# ════════════════════════════════════════════════════════════════════════════
# STEP 1: Start Neo4j
# ════════════════════════════════════════════════════════════════════════════
if [ "$START_STEP" -le 1 ]; then
    step_header 1 "Start Neo4j Database"

    if [ "$SKIP_NEO4J" = true ]; then
        echo -e "${YELLOW}  Skipping (--skip-neo4j flag)${NC}"
    elif docker ps --format '{{.Names}}' | grep -q "^${NEO4J_CONTAINER}$"; then
        echo -e "${YELLOW}  Neo4j container already running.${NC}"
    else
        # Remove stopped container if exists
        docker rm "$NEO4J_CONTAINER" 2>/dev/null || true

        echo "  Starting Neo4j with APOC plugin..."
        docker run -d --name "$NEO4J_CONTAINER" \
            -p 7474:7474 -p 7687:7687 \
            -e NEO4J_AUTH="neo4j/${NEO4J_PASSWORD}" \
            -e NEO4J_PLUGINS='["apoc"]' \
            neo4j:5

        echo -e "  Waiting ${NEO4J_WAIT}s for Neo4j to start..."
        sleep "$NEO4J_WAIT"
        echo -e "${GREEN}  ✓ Neo4j started → http://localhost:7474${NC}"
    fi
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 2: Schema Setup
# ════════════════════════════════════════════════════════════════════════════
if [ "$START_STEP" -le 2 ]; then
    step_header 2 "Create Graph Schema (constraints + indexes)"
    python config/schema_setup.py
    echo -e "${GREEN}  ✓ Schema ready${NC}"
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 3: Inject Synthetic Attacks
# ════════════════════════════════════════════════════════════════════════════
if [ "$START_STEP" -le 3 ]; then
    step_header 3 "Inject Synthetic Attack Scenarios"
    echo "  → Impossible Travel (5 scenarios)"
    echo "  → Credential Stuffing (3 campaigns, 50 attempts each)"
    echo "  → Lateral Movement (4 chains, 6 hops each)"
    echo "  → Data Exfiltration (5 large transfers)"
    python synthetic_injection/inject_attacks.py
    echo -e "${GREEN}  ✓ Attacks injected${NC}"
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 4: MITRE ATT&CK Enrichment
# ════════════════════════════════════════════════════════════════════════════
if [ "$START_STEP" -le 4 ]; then
    step_header 4 "Map Attacks to MITRE ATT&CK Techniques"
    python data_ingestion/mitre_enrichment.py
    echo -e "${GREEN}  ✓ MITRE enrichment complete${NC}"
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 5: Run Detection Queries
# ════════════════════════════════════════════════════════════════════════════
if [ "$START_STEP" -le 5 ]; then
    step_header 5 "Run Cypher Detection Queries"
    python detection/cypher_queries.py
    echo -e "${GREEN}  ✓ Detections complete${NC}"
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 6: Generate AI Report
# ════════════════════════════════════════════════════════════════════════════
if [ "$START_STEP" -le 6 ]; then
    step_header 6 "Generate AI Threat Report (RAG → GPT-4)"

    if grep -q "sk-your-key-here" .env 2>/dev/null; then
        echo -e "${YELLOW}  ⚠ Skipping — OPENAI_API_KEY not set in .env${NC}"
        echo -e "${YELLOW}    Edit .env and re-run: ./run.sh --step 6${NC}"
    else
        python rag_pipeline/generate_report.py --detection all --output data/processed/threat_report.md
        echo -e "${GREEN}  ✓ Report saved to data/processed/threat_report.md${NC}"
    fi
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 7: Launch Dashboard
# ════════════════════════════════════════════════════════════════════════════
if [ "$START_STEP" -le 7 ]; then
    step_header 7 "Launch Streamlit Dashboard"
    echo -e "${GREEN}  🚀 Opening dashboard...${NC}"
    echo -e "  ${CYAN}Press Ctrl+C to stop${NC}"
    echo ""
    streamlit run dashboard/dashboard.py
fi
