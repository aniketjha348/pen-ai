"""BloodHound neo4j attack-path queries.

Runs real Cypher queries against a BloodHound neo4j database so PEN-AI
prioritizes genuine Active Directory attack paths instead of guessing.
The driver is optional: call connect_bloodhound() with credentials first,
otherwise queries return empty results without crashing.
"""

import os
from typing import Any

_driver: Any = None


def connect_bloodhound(
    uri: str = "bolt://localhost:7687",
    user: str = "neo4j",
    password: str = "bloodhound",
) -> bool:
    """Connect to the BloodHound neo4j database (lazy import of neo4j)."""
    global _driver
    try:
        from neo4j import GraphDatabase
    except ImportError:
        return False
    try:
        _driver = GraphDatabase.driver(uri, auth=(user, password))
        return True
    except Exception:
        return False


def get_session() -> Any:
    """Return a neo4j session, or a no-op stub when not connected."""
    if _driver is None:
        return _NullSession()
    return _driver.session()


class _NullSession:
    def run(self, query: str, **params) -> Any:
        return None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def find_shortest_paths(domain: str, limit: int = 5) -> list[dict]:
    """Find the shortest attack paths from any user to Domain Admins."""
    query = """
    MATCH p = shortestPath(
        (n)-[r:MemberOf|HasSession|AdminTo|GenericAll|WriteDacl*1..5]->(da)
    )
    WHERE da.name CONTAINS $domain AND da.objectid ENDS WITH '-512'
    RETURN p AS path LIMIT $limit
    """
    result = get_session().run(query, domain=domain, limit=limit)
    if result is None:
        return []
    return [r.data() for r in result.records()]


def find_high_value_targets(limit: int = 10) -> list[dict]:
    """List high-value targets (Domain Admins, admins with sessions)."""
    query = """
    MATCH (n)
    WHERE n.highvalue = true OR toLower(n.name) CONTAINS 'domain admin'
    RETURN n.name AS name, labels(n) AS type
    LIMIT $limit
    """
    result = get_session().run(query, limit=limit)
    if result is None:
        return []
    return [r.data() for r in result.records()]


def _env_connect() -> bool:
    """Connect using BLOODHOUND_* environment variables if present."""
    uri = os.environ.get("BLOODHOUND_URI", "")
    if not uri:
        return False
    user = os.environ.get("BLOODHOUND_USER", "neo4j")
    password = os.environ.get("BLOODHOUND_PASSWORD", "bloodhound")
    return connect_bloodhound(uri, user, password)
