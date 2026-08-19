"""Tests for BloodHound neo4j attack-path queries."""

import pytest

from enterprise.bloodhound_queries import (
    find_shortest_paths,
    find_high_value_targets,
    get_session,
)


class FakeRecord:
    def __init__(self, **data):
        self._data = data

    def data(self):
        return dict(self._data)


class FakeResult:
    def __init__(self, records):
        self._records = records

    def records(self):
        return self._records


class FakeGraph:
    def __init__(self, records):
        self._records = records
        self.queries = []

    def run(self, query, **params):
        self.queries.append((query, params))
        return FakeResult(self._records)


class FakeDriver:
    def __init__(self, records):
        self.graph = FakeGraph(records)

    def session(self):
        return self.graph


def test_find_shortest_paths_runs_cypher(monkeypatch):
    records = [FakeRecord(path=[{"name": "a", "type": "User"}])]
    driver = FakeDriver(records)
    monkeypatch.setattr("enterprise.bloodhound_queries._driver", driver)

    result = find_shortest_paths("corp.local")

    assert result == [records[0].data()]
    assert any("MATCH p = shortestPath" in q for q, _ in driver.graph.queries)


def test_find_high_value_targets_runs_cypher(monkeypatch):
    records = [FakeRecord(name="DOMAIN ADMINS", type="Group", sessions=3)]
    driver = FakeDriver(records)
    monkeypatch.setattr("enterprise.bloodhound_queries._driver", driver)

    result = find_high_value_targets()

    assert result == [records[0].data()]
    assert any("MemberOf" in q or "highvalue" in q.lower() for q, _ in driver.graph.queries)


def test_get_session_returns_session(monkeypatch):
    import enterprise.bloodhound_queries as bh

    class FakeSess:
        def run(self, q, **p):
            return None

    class FakeDrv:
        def session(self):
            return FakeSess()

    monkeypatch.setattr(bh, "_driver", FakeDrv())
    assert isinstance(get_session(), FakeSess)