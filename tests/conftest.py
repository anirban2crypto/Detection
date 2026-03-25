"""
Pytest configuration and shared fixtures.

Uses a real Neo4j instance (same Docker container) with test isolation:
all test data is cleaned up after each test session.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config.neo4j_connection import get_driver

TEST_TAG = "TEST_DATA"


@pytest.fixture(scope="session")
def neo4j_driver():
    """Provide a Neo4j driver for the entire test session."""
    driver = get_driver()
    yield driver
    driver.close()


@pytest.fixture(scope="session")
def neo4j_session(neo4j_driver):
    """Provide a Neo4j session for the entire test session."""
    session = neo4j_driver.session()
    yield session
    # Cleanup: remove all test data
    session.run("MATCH (n) WHERE n.test_tag = $tag DETACH DELETE n", tag=TEST_TAG)
    session.close()


@pytest.fixture
def clean_session(neo4j_driver):
    """Provide a fresh session per test, with cleanup after."""
    session = neo4j_driver.session()
    yield session
    session.run("MATCH (n) WHERE n.test_tag = $tag DETACH DELETE n", tag=TEST_TAG)
    session.close()
