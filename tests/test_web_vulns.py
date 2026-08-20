"""Tests for the new bug-bounty web vulnerability modules."""

import pytest

from exploitation.modules.base import ExploitCategory
from exploitation.modules.web_vulns import (
    BusinessLogicTest,
    CSRFDetectionTest,
    FileUploadTest,
    GraphQLInjectionTest,
    IDORTest,
    OpenRedirectTest,
    SSRFDetectionTest,
    SSTITest,
)
from exploitation.orchestrator import ExploitOrchestrator

NEW_MODULES = [
    "graphql_injection",
    "csrf_detector",
    "file_upload_test",
    "business_logic_test",
    "ssrf_test",
    "idor_test",
    "open_redirect_test",
    "ssti_test",
]

ALL_WEB_MODULES = [
    GraphQLInjectionTest(),
    CSRFDetectionTest(),
    FileUploadTest(),
    BusinessLogicTest(),
    SSRFDetectionTest(),
    IDORTest(),
    OpenRedirectTest(),
    SSTITest(),
]


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class FakeClient:
    """Async context-manager httpx client stand-in."""

    def __init__(self, routes):
        self.routes = routes
        self.default = FakeResponse(404, "not found")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def _dispatch(self, method, url, **kwargs):
        for (m, key), resp in self.routes.items():
            if m != method:
                continue
            if key in url or url.endswith(key):
                return resp
        return self.default

    async def get(self, url, **kwargs):
        return self._dispatch("GET", url, **kwargs)

    async def post(self, url, json=None, files=None, **kwargs):
        return self._dispatch("POST", url, **kwargs)


class TestWebVulnInfo:
    def test_all_modules_have_correct_info(self):
        assert [m.info.name for m in ALL_WEB_MODULES] == NEW_MODULES
        assert all(m.info.category == ExploitCategory.WEB for m in ALL_WEB_MODULES)

    def test_each_module_exposes_references(self):
        assert GraphQLInjectionTest().info.references
        assert SSTITest().info.references
        assert CSRFDetectionTest().info.references


class TestOrchestratorRegistration:
    def test_new_modules_registered(self):
        orch = ExploitOrchestrator()
        for name in NEW_MODULES:
            assert orch.get_module(name) is not None, f"{name} not registered"

    def test_web_category_includes_new_modules(self):
        orch = ExploitOrchestrator()
        web_names = [m.info.name for m in orch.get_modules_by_category(ExploitCategory.WEB)]
        for name in NEW_MODULES:
            assert name in web_names

    def test_orchestrator_has_13_web_modules(self):
        orch = ExploitOrchestrator()
        web_names = [m.info.name for m in orch.get_modules_by_category(ExploitCategory.WEB)]
        assert len(web_names) >= 13


@pytest.mark.asyncio
async def test_graphql_injection_finds_endpoint():
    routes = {
        ("POST", "/graphql"): FakeResponse(200, '{"data":{"__typename":"Query"}}'),
    }
    fake = FakeClient(routes)
    async with fake as c:
        endpoint = await GraphQLInjectionTest()._find_endpoint(c, "http://10.0.0.9")
        assert endpoint == "/graphql"


@pytest.mark.asyncio
async def test_graphql_injection_no_endpoint_returns_none():
    fake = FakeClient(routes={})
    async with fake as c:
        endpoint = await GraphQLInjectionTest()._find_endpoint(c, "http://10.0.0.9")
        assert endpoint is None


def test_new_web_tools_registered_in_tool_registry():
    import ranges.web.agent  # noqa: F401 - decorators register the tools

    from ai.tool_registry import registry

    names = set(registry.list_names())
    for tool in [
        "web_graphql_test",
        "web_csrf_check",
        "web_upload_test",
        "web_business_logic_test",
        "web_ssrf_test",
        "web_idor_test",
        "web_open_redirect_test",
        "web_ssti_test",
    ]:
        assert tool in names, f"{tool} missing from tool registry"