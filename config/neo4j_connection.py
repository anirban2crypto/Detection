"""Neo4j database connection manager."""

import os
from contextlib import contextmanager

from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv(Path.home() / ".env")

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "changeme")


def get_driver():
    """Create and return a Neo4j driver instance."""
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


@contextmanager
def get_session():
    """Context manager that yields a Neo4j session and closes it after use."""
    driver = get_driver()
    session = driver.session()
    try:
        yield session
    finally:
        session.close()
        driver.close()
