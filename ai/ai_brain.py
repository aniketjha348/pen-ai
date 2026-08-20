"""AI Brain v3 - Human-Like Decision Making Engine.

The CORE intelligence that makes PEN-AI think like a human pentester.

Unlike the v2 regex/heuristic engine, this brain is LLM-driven and rule-free:
- Every command output is ANALYZED in context (what did it reveal?)
- The NEXT step is DECIDED from that output (never a fixed scan list)
- Failed attacks trigger ALTERNATIVE techniques automatically
- Vulnerability findings get CHAINED into multi-step attack paths
- Every success AND failure is REMEMBERED on disk for future engagements

Architecture:
    AIBrain
      +-- BrainMemory            continuous learning (persisted JSON per target)
      +-- BrainAnalysis          analysis of one command output
      +-- analyze_output()       LLM reads output -> findings + next steps
      +-- decide_next()          intelligent recon: what to scan next
      +-- suggest_alternatives() adaptive exploitation on failure
      +-- plan_attack_chain()    chain multiple vulns into one attack path
      +-- heuristic fallback     keeps moving when no LLM is available
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

DEFAULT_MEMORY_DIR = Path(__file__).resolve().parent.parent / "knowledge" / "ai_brain"


@dataclass
class BrainFinding:
    """A vulnerability or interesting discovery made by the brain."""

    category: str = ""
    severity: str = "info"
    title: str = ""
    evidence: str = ""
    target: str = ""
    exploitable: bool = False
    exploited: bool = False
    chain_with: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "evidence": self.evidence[:500],
            "target": self.target,
            "exploitable": self.exploitable,
            "exploited": self.exploited,
            "chain_with": self.chain_with,
        }


@dataclass
class BrainDecision:
    """A single reasoned next-step the brain wants to run."""

    command: str = ""
    reasoning: str = ""
    priority: str = "high"  # critical | high | medium | low
    confidence: float = 0.5
    category: str = "recon"  # recon | enumerate | exploit | post_exploit | pivot | loot
    expected_outcome: str = ""
    alternatives: list = field(default_factory=list)  # fallback commands

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "reasoning": self.reasoning,
            "priority": self.priority,
            "confidence": self.confidence,
            "category": self.category,
            "expected_outcome": self.expected_outcome,
            "alternatives": self.alternatives,
        }
@dataclass
class BrainAnalysis:
    """Full analysis of a single command output."""

    hypothesis: str = ""
    findings: list = field(default_factory=list)  # list[BrainFinding]
    next_actions: list = field(default_factory=list)  # list[BrainDecision]
    new_hosts: list = field(default_factory=list)
    new_services: list = field(default_factory=list)
    new_credentials: list = field(default_factory=list)
    phase: str = ""
    done: bool = False
    lesson: str = ""

    def to_dict(self) -> dict:
        return {
            "hypothesis": self.hypothesis,
            "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings],
            "next_actions": [a.to_dict() if hasattr(a, "to_dict") else a for a in self.next_actions],
            "new_hosts": self.new_hosts,
            "new_services": self.new_services,
            "new_credentials": self.new_credentials,
            "phase": self.phase,
            "done": self.done,
            "lesson": self.lesson,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Continuous learning memory
# ─────────────────────────────────────────────────────────────────────────────
class BrainMemory:
    """Remembers what worked and failed; persists per target to JSON.

    Files live under knowledge/ai_brain/<target>.json so lessons survive
    across separate engagements against similar targets.
    """

    def __init__(self, target: str = "", memory_dir: str | Path = DEFAULT_MEMORY_DIR):
        self.target = target
        self.memory_dir = Path(memory_dir)
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.lessons: list[dict] = []
        self.failed_techniques: set = set()
        self.successful_techniques: set = set()
        self._loaded = False
        self.load()

    def load(self) -> None:
        """Load memory for the current target from disk."""
        if self._loaded:
            return
        self._loaded = True
        if not self.target:
            return
        path = self._memory_file()
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.lessons = data.get("lessons", [])
            self.failed_techniques = set(data.get("failed_techniques", []))
            self.successful_techniques = set(data.get("successful_techniques", []))
        except (json.JSONDecodeError, OSError):
            pass

    def _memory_file(self) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", self.target)[:80] or "anonymous"
        return self.memory_dir / f"{safe}.json"

    def record(self, command: str, success: bool, reasoning: str = "", context: str = "") -> None:
        """Remember the outcome of a technique."""
        self.lessons.append(
            {
                "command": command[:300],
                "reasoning": reasoning[:300],
                "context": context[:300],
                "success": bool(success),
                "timestamp": datetime.now().isoformat(),
            }
        )
        signature = self._signature(command)
        if success:
            self.successful_techniques.add(signature)
        else:
            self.failed_techniques.add(signature)
        try:
            data = {
                "target": self.target,
                "lessons": self.lessons[-500:],
                "failed_techniques": sorted(self.failed_techniques),
                "successful_techniques": sorted(self.successful_techniques),
                "updated": datetime.now().isoformat(),
            }
            self._memory_file().write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        except OSError:
            pass

    @staticmethod
    def _signature(command: str) -> str:
        """Coarse technique fingerprint: tool + leading flags."""
        tokens = command.split()
        tool = tokens[0].strip().split("/")[-1] if tokens else "?"
        flags = [t for t in tokens if t.startswith("-")][:3]
        return " ".join([tool] + flags)

    def avoid(self, command: str) -> bool:
        """True if the same technique already failed (don't repeat ourselves)."""
        if not command:
            return False
        return self._signature(command) in self.failed_techniques

    def get_recent_lessons(self, limit: int = 10) -> list[dict]:
        return list(reversed(self.lessons[-limit:]))

    def stats(self) -> dict:
        return {
            "lessons_recorded": len(self.lessons),
            "techniques_that_worked": len(self.successful_techniques),
            "techniques_that_failed": len(self.failed_techniques),
            "file": str(self._memory_file()),
        }
class AIBrain:
    """Human-like decision making engine (LLM-driven, rule-free).

    Synchronous flow: take output -> analyze in context -> decide next.
    With an LLM attached it reasons like a pentester; without one it still
    moves the engagement forward via heuristic fallbacks.
    """

    def __init__(
        self,
        llm: Any = None,
        target: str = "",
        scope: str = "",
        memory_dir: str | Path = DEFAULT_MEMORY_DIR,
        max_cycles: int = 200,
    ):
        self.llm = llm
        self.target = target
        self.scope = scope
        self.memory = BrainMemory(target=target, memory_dir=memory_dir)

        # Engagement knowledge
        self.hosts: list[str] = []
        self.services: dict = {}  # host -> [service dicts]
        self.credentials: list[dict] = []
        self.access_levels: dict = {}
        self.findings: list[BrainFinding] = []

        # History
        self.decisions: list[BrainDecision] = []
        self.actions_history: list[dict] = []
        self.phase: str = "recon"
        self.cycle: int = 0
        self.max_cycles = max_cycles

    # ── State helpers ────────────────────────────────────────────────────────
    def set_target(self, target: str) -> None:
        self.target = target
        self.memory = BrainMemory(target=target, memory_dir=self.memory.memory_dir)

    def link_state(self, hosts: list | None, services: dict | None, creds: list | None, access: dict | None) -> None:
        """Adopt state tracked by the outer agent (FreewillAgent / REPL)."""
        if hosts:
            self.hosts = list(hosts)
        if services:
            self.services = services
        if creds:
            self.credentials = list(creds)
        if access:
            self.access_levels = dict(access)

    def services_flat(self) -> list[dict]:
        flat: list[dict] = []
        for host, svcs in (self.services or {}).items():
            for svc in svcs:
                item = dict(svc)
                item["_host"] = host
                flat.append(item)
        return flat

    def compress_state(self) -> str:
        """Compact state summary used in LLM prompts."""
        lines = [f"TARGET: {self.target}", f"PHASE: {self.phase}", f"CYCLE: {self.cycle}"]
        lines.append(f"HOSTS ({len(self.hosts)}): " + (", ".join(sorted(self.hosts)[:20]) or "none"))
        flat = self.services_flat()
        if flat:
            lines.append(f"SERVICES ({len(flat)}):")
            for svc in flat[:25]:
                ver = svc.get("version") or ""
                lines.append(f"  {svc.get('_host')}:{svc.get('port')} {svc.get('service', '?')} {ver}".rstrip())
        if self.credentials:
            lines.append(f"CREDENTIALS ({len(self.credentials)}):")
            for c in self.credentials[:8]:
                u = c.get("username", "")
                v = str(c.get("value", ""))[:30]
                lines.append(f"  [{c.get('type', '?')}] {u}:{v}".rstrip(":"))
        if self.access_levels:
            parts = ", ".join(f"{h}={lvl}" for h, lvl in list(self.access_levels.items())[:8])
            lines.append(f"ACCESS: {parts}")
        if self.findings:
            lines.append(f"FINDINGS ({len(self.findings)}):")
            for f in self.findings[-8:]:
                tag = "exploitable" if f.exploitable else "not exploitable"
                lines.append(f"  [{f.severity}] {f.title.strip()[:90]} ({tag})")
        if self.actions_history:
            lines.append("RECENT ACTIONS:")
            for a in self.actions_history[-3:]:
                status = "OK" if a.get("success") else "FAIL"
                lines.append(f"  $ {a.get('command', '')[:90]} -> {status}")
        lessons = self.memory.get_recent_lessons(5)
        if lessons:
            lines.append("MEMORY LESSONS:")
            for l in lessons:
                tag = "OK" if l["success"] else "FAIL"
                lines.append(f"  [{tag}] {l['command'][:60]}")
        return "\n".join(lines)

    # ── LLM plumbing ─────────────────────────────────────────────────────────
    def _llm_available(self) -> bool:
        return bool(self.llm)

    async def _call_llm(self, system: str, prompt: str) -> str:
        """Fire a single prompt through the LLM; returns raw text or ''."""
        if not self._llm_available():
            return ""

        async def _complete() -> str:
            from ai.llm_client import Message, MessageRole

            response = await self.llm.chat(
                [
                    Message(role=MessageRole.SYSTEM, content=system),
                    Message(role=MessageRole.USER, content=prompt),
                ]
            )
            return response.content or ""

        try:
            return await asyncio.wait_for(_complete(), timeout=90)
        except Exception:
            return ""

    @staticmethod
    def _robust_json(text: str) -> dict:
        """Extract the first JSON object from arbitrary LLM text."""
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fenced:
            text = fenced.group(1)
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            return {}
        candidate = text[start : end + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
        cleaned = re.sub(r",\s*([}\]])", r"\1", candidate)  # trailing commas
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return {}

    @staticmethod
    def _as_finding(raw: dict) -> BrainFinding:
        return BrainFinding(
            category=str(raw.get("category", "")),
            severity=str(raw.get("severity", "info")),
            title=str(raw.get("title", raw.get("name", ""))),
            evidence=str(raw.get("evidence", "")),
            target=str(raw.get("target", "")),
            exploitable=bool(raw.get("exploitable", False)),
            chain_with=list(raw.get("chain_with", []) or []),
        )

    @staticmethod
    def _as_decision(raw: dict, category_guess: str = "recon") -> BrainDecision:
        return BrainDecision(
            command=str(raw.get("command", "")).strip(),
            reasoning=str(raw.get("reasoning", "")),
            priority=str(raw.get("priority", "high")),
            confidence=float(raw.get("confidence", 0.5) or 0.5),
            category=str(raw.get("category", category_guess)),
            expected_outcome=str(raw.get("expected_outcome", "")),
            alternatives=list(raw.get("alternatives", []) or []),
        )
# ── Public API ───────────────────────────────────────────────────────────
    async def analyze_output(self, command: str, output: str, exit_code: int = 0) -> BrainAnalysis:
        """Analyze one command output and decide the next step.

        With LLM: full contextual reasoning. Without LLM: heuristics.
        Always updates engagement state and memory for continuous learning.
        """
        self.cycle += 1
        state = self.compress_state()

        if self._llm_available():
            analysis = await self._llm_analyze(command, output, exit_code, state)
        else:
            analysis = self._heuristic_analyze(command, output, exit_code)

        self._extract_facts(command, output)

        # Merge explicit discoveries returned by the LLM into live state.
        for host in analysis.new_hosts:
            if host and host not in self.hosts:
                self.hosts.append(host)

        for svc in analysis.new_services:
            # Accept either [host, port, service, version] or [host, "80/http", version]
            if not svc:
                continue
            host = str(svc[0]) if len(svc) >= 1 else (self.hosts[0] if self.hosts else self.target)
            port = 0
            service = "unknown"
            version = ""

            if len(svc) >= 2:
                second = str(svc[1])
                if "/" in second:
                    port_part, service_part = second.split("/", 1)
                    try:
                        port = int(port_part)
                    except ValueError:
                        port = 0
                    service = service_part or service
                else:
                    try:
                        port = int(second)
                    except ValueError:
                        port = 0

            if len(svc) >= 3 and str(svc[2]):
                if service == "unknown":
                    service = str(svc[2])
                else:
                    version = str(svc[2])

            if len(svc) >= 4 and str(svc[3]):
                version = str(svc[3])

            self._record_service(
                {"_host": host, "port": port, "service": service, "version": version}
            )

        for cred in analysis.new_credentials:
            if isinstance(cred, dict) and cred not in self.credentials:
                self.credentials.append(dict(cred))

        analysis.phase = analysis.phase or self.phase
        self.actions_history.append(
            {"command": command, "exit_code": exit_code, "success": exit_code == 0}
        )
        for f in analysis.findings:
            if not any(existing.title == f.title for existing in self.findings):
                self.findings.append(f)
        if analysis.phase:
            self.phase = analysis.phase

        self.memory.record(
            command,
            success=exit_code == 0,
            reasoning=analysis.lesson or analysis.hypothesis,
            context=output[:300],
        )
        return analysis

    async def decide_next(self, state: Optional[dict] = None) -> list[BrainDecision]:
        """Decide the next action(s) based on current engagement state.

        This is intelligent recon: the AI looks at results so far and picks
        the next scan accordingly (no fixed scan sequence).
        """
        if state:
            self.link_state(
                state.get("hosts") or state.get("known_hosts", []),
                state.get("services") or state.get("known_services", {}),
                state.get("credentials", []),
                state.get("access_map", {}),
            )
        if self._llm_available():
            decisions = await self._llm_decide()
        else:
            decisions = self._heuristic_decide()
        # Never repeat a technique we already know fails
        decisions = [
            d for d in decisions if d.command and not self.memory.avoid(d.command)
        ]
        self.decisions.extend(decisions)
        return decisions[:5]

    async def suggest_alternatives(self, failed_command: str, output: str = "") -> list[str]:
        """Adaptive exploitation - when one attack fails, propose different ones."""
        if self._llm_available():
            alternatives = await self._llm_alternatives(failed_command, output)
            if alternatives:
                return alternatives
        return self._heuristic_alternatives(failed_command, output)

    async def plan_attack_chain(self) -> list[dict]:
        """Chain discovered vulnerabilities into a coherent attack path."""
        if not self.findings:
            return []
        if self._llm_available():
            chain = await self._llm_chain()
            if chain:
                return chain
        return self._heuristic_chain()

    def get_insights(self) -> list[str]:
        """Summarize lessons learned so far (for the UI / reports)."""
        return [
            f"{'OK' if l['success'] else 'FAIL'} {l['command'][:70]} -> {l['reasoning'][:60]}"
            for l in self.memory.get_recent_lessons(8)
        ]

    def print_status(self) -> str:
        m = self.memory.stats()
        return "\n".join(
            [
                "=" * 60,
                "  AI BRAIN STATUS",
                "=" * 60,
                f"  Cycle: {self.cycle} | Phase: {self.phase}",
                f"  Hosts: {len(self.hosts)} | Services: {len(self.services_flat())}",
                f"  Credentials: {len(self.credentials)} | Access: {self.access_levels or 'none'}",
                f"  Findings: {len(self.findings)}",
                f"  Learned: {m['lessons_recorded']} lessons "
                f"({m['techniques_that_worked']} worked, {m['techniques_that_failed']} failed)",
                "=" * 60,
            ]
        )
# ── LLM-driven sections ───────────────────────────────────────────────────
    _SYSTEM = (
        "You are the AI Brain of PEN-AI, an autonomous penetration tester. "
        "You think like an experienced senior pentester. You NEVER follow fixed rules; "
        "you reason from concrete evidence and adapt to whatever the target reveals. "
        "You always respond with STRICT JSON only - no markdown, no prose outside the JSON."
    )

    async def _llm_analyze(self, command: str, output: str, exit_code: int, state: str) -> BrainAnalysis:
        prompt = f"""Analyze this penetration-testing command output and decide the NEXT step.

COMMAND:
{command[:500]}

EXIT CODE: {exit_code}

OUTPUT (first 3000 chars):
{output[:3000]}

CURRENT ENGAGEMENT STATE:
{state}

Reason like a human pentester:
1. What did this output actually reveal? (hosts/services/creds/vulns/opportunities?)
2. What is the most promising next action (1-4 commands)?
3. What would a real pentester try NEXT if this attack failed?
4. What did we learn for future engagements?

Respond with exactly this JSON schema:
{{
  "hypothesis": "one-sentence theory of the situation",
  "findings": [
    {{"category": "sqli|xss|recon|credential|privesc|config|other", "severity": "critical|high|medium|low|info",
      "title": "short title", "evidence": "quote from output", "exploitable": true,
      "chain_with": ["keyword to link with"]}}
  ],
  "next_actions": [
    {{"command": "exact shell command", "reasoning": "why",
      "priority": "high|medium|low", "confidence": 0.0 to 1.0,
      "category": "recon|enumerate|exploit|post_exploit|pivot|loot",
      "expected_outcome": "what this reveals",
      "alternatives": ["fallback 1", "fallback 2"]}}
  ],
  "new_hosts": ["ip", ...],
  "new_services": [["host", "port/service", "version"], ...],
  "new_credentials": [{{"username": "", "value": "", "type": ""}}],
  "phase": "recon|exploitation|post_exploitation|pivoting|complete",
  "done": false,
  "lesson": "what this output taught us"
}}"""

        raw = await self._call_llm(self._SYSTEM, prompt)
        data = self._robust_json(raw)
        analysis = BrainAnalysis()
        analysis.hypothesis = str(data.get("hypothesis", ""))
        analysis.findings = [
            self._as_finding(f) for f in data.get("findings", []) if isinstance(f, dict)
        ]
        analysis.next_actions = [
            self._as_decision(a, self.phase)
            for a in data.get("next_actions", [])
            if isinstance(a, dict)
        ]
        analysis.new_hosts = [str(h) for h in data.get("new_hosts", [])]
        analysis.new_services = [list(s) for s in data.get("new_services", [])]
        analysis.new_credentials = [dict(c) for c in data.get("new_credentials", [])]
        analysis.phase = str(data.get("phase", self.phase))
        analysis.done = bool(data.get("done", False))
        analysis.lesson = str(data.get("lesson", ""))
        return analysis

    async def _llm_decide(self) -> list[BrainDecision]:
        state = self.compress_state()
        prompt = f"""Choose the NEXT ACTION(s) for the ongoing penetration test.

CURRENT STATE:
{state}

Decide 1-5 actions that maximize information gain and progress toward gaining
access. Consider: intelligence still missing, services not yet enumerated,
credentials not yet tested, vulnerabilities not yet exploited, hosts not yet
scanned, pivoting opportunities. If a previous technique failed choose a
DIFFERENT technique.

Respond with ONLY this JSON schema:
{{
  "next_actions": [
    {{"command": "exact shell command", "reasoning": "why",
      "priority": "high|medium|low", "confidence": 0.0 to 1.0,
      "category": "recon|enumerate|exploit|post_exploit|pivot|loot",
      "expected_outcome": "what this reveals",
      "alternatives": ["fallback command"]}}
  ]
}}"""

        raw = await self._call_llm(self._SYSTEM, prompt)
        data = self._robust_json(raw)
        return [
            self._as_decision(a, self.phase)
            for a in data.get("next_actions", [])
            if isinstance(a, dict)
        ]

    async def _llm_alternatives(self, failed_command: str, output: str) -> list[str]:
        prompt = f"""A command FAILED (or produced no useful output) during the pentest.
Propose a completely different approach a senior pentester would try next.

FAILED COMMAND: {failed_command[:300]}
FAILED OUTPUT: {output[:1500]}
CURRENT STATE: {self.compress_state()}

Respond JSON:
{{"alternatives": [{{"command": "...", "reasoning": "..."}}]}}
Give exactly 3 alternatives. Do NOT repeat the failed technique."""

        raw = await self._call_llm(self._SYSTEM, prompt)
        data = self._robust_json(raw)
        alts = data.get("alternatives", [])
        if not alts:
            return []
        out = []
        for a in alts:
            if isinstance(a, dict):
                cmd = a.get("command", "")
                out.append(f"{cmd} # {a.get('reasoning', '')}" if a.get("reasoning") else cmd)
            elif isinstance(a, str):
                out.append(a)
        return out

    async def _llm_chain(self) -> list[dict]:
        placed = "\n".join(
            f"- [{f.severity}] {f.title} (target {f.target or self.target or 'unknown'}) "
            f"exploitable={f.exploitable}"
            for f in self.findings[-10:]
        )
        prompt = f"""Chain the discovered vulnerabilities into one attack path.

FINDINGS:
{placed}

CREDENTIALS: {self.credentials[:10]}
ACCESS: {self.access_levels}

Respond JSON:
{{"chain": [
  {{"step": "exact shell command", "goal": "what this achieves",
    "prerequisite": "finding/cred/access this step needs"}}
]}}
Chain up to 6 steps from current position to full compromise."""

        raw = await self._call_llm(self._SYSTEM, prompt)
        data = self._robust_json(raw)
        return [dict(s) for s in data.get("chain", []) if isinstance(s, dict)]
# ── Heuristic fallbacks (no LLM) ──────────────────────────────────────────
    def _heuristic_analyze(self, command: str, output: str, exit_code: int) -> BrainAnalysis:
        """No-LLM fallback: extract facts and suggest the next step."""
        analysis = BrainAnalysis()
        out = output or ""
        low = out.lower()

        if "CVE-" in out:
            for cve in re.findall(r"CVE-\d{4}-\d+", out):
                analysis.findings.append(
                    BrainFinding(
                        category="vulnerability", severity="high", title=f"Found {cve}",
                        evidence=out[:200], exploitable=True,
                    )
                )
        if "password" in low or "passwd" in low:
            analysis.findings.append(
                BrainFinding(
                    category="credential", severity="critical", title="Credential material in output",
                    evidence=out[:200], exploitable=True,
                )
            )
        if "uid=0" in low or "root@" in low or "nt authority" in low:
            analysis.findings.append(
                BrainFinding(
                    category="access", severity="critical", title="Root/admin access",
                    evidence=out[:200], exploitable=True,
                )
            )

        # Next step by phase (minimal, keeps the engagement moving)
        if not self.hosts:
            analysis.phase = "recon"
            analysis.next_actions.append(
                BrainDecision(
                    command=f"nmap -sn -T4 {self.target}", reasoning="Host discovery first",
                    category="recon", expected_outcome="Live hosts",
                )
            )
        elif not self.services_flat():
            analysis.phase = "enumerate"
            host = self.hosts[0]
            analysis.next_actions.append(
                BrainDecision(
                    command=f"nmap -sV -sC -p- {host} --open",
                    reasoning="Full port scan with version detection",
                    category="enumerate", expected_outcome="Open services",
                )
            )
        else:
            svc = self.services_flat()[0]
            name = svc.get("service", "http")
            version = svc.get("version", "")
            analysis.phase = "exploitation"
            cmd = f"searchsploit {name} {version}".rstrip() if version else f"searchsploit {name}"
            analysis.next_actions.append(
                BrainDecision(command=cmd, reasoning=f"research exploits for {name}", category="exploit")
            )

        analysis.lesson = f"Cycle {self.cycle}: ran {command[:80]}"
        return analysis

    def _heuristic_decide(self) -> list[BrainDecision]:
        decisions: list[BrainDecision] = []
        if not self.hosts:
            decisions.append(BrainDecision(command=f"nmap -sn -T4 {self.target}", reasoning="Discover live hosts", category="recon"))
        elif not self.services_flat():
            decisions.append(BrainDecision(command=f"nmap -sV -sC -p- {self.hosts[0]} --open", reasoning="Enumerate services on first host", category="enumerate"))
        else:
            for svc in self.services_flat()[:4]:
                host = svc.get("_host")
                port = svc.get("port")
                name = str(svc.get("service", "")).lower()
                if name == "http":
                    decisions.append(BrainDecision(command=f"curl -s -i http://{host}:{port}/ | head -50", reasoning="Fingerprint web app", category="enumerate", expected_outcome="Web server details"))
                elif name == "ssh":
                    decisions.append(BrainDecision(command=f"ssh -o ConnectTimeout=5 -o BatchMode=yes root@{host} id 2>&1 || echo auth-required", reasoning="Test auth state / shared keys", category="exploit"))
                elif name in ("https", "ssl"):
                    decisions.append(BrainDecision(command=f"curl -sk -i https://{host}:{port}/ | head -50", reasoning="Fingerprint HTTPS service", category="enumerate"))
                else:
                    decisions.append(BrainDecision(command=f"nc -vn {host} {port} 2>&1 <<< ''", reasoning=f"Banner grab {name}", category="enumerate"))
        return decisions[:5]

    def _heuristic_alternatives(self, failed_command: str, output: str) -> list[str]:
        """Rolling fallbacks: swap the tool/technique when one fails."""
        target = self.hosts[0] if self.hosts else self.target
        alternatives: list[str] = []
        fc = failed_command.lower()

        if "nmap" in fc:
            alternatives.append(f"sudo masscan -p1-10000 --rate 1000 {target} 2>/dev/null")
            alternatives.append(f"sudo rustscan -a {target} -- -sV")
        elif "gobuster" in fc or "dirb" in fc or "ffuf" in fc:
            alternatives.append(f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 50")
            alternatives.append(f"ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403")
        elif "hydra" in fc or "medusa" in fc:
            alternatives.append(f"crackmapexec ssh {target} -u root -p /usr/share/wordlists/rockyou.txt --continue-on-success")
            alternatives.append(f"sshpass -p toor ssh -o StrictHostKeyChecking=no root@{target} 2>/dev/null echo ok")
        elif "sqlmap" in fc:
            alternatives.append(f"curl -s '{target}' -d 'id=1%27' -i | grep -Ei 'sql|syntax|error'")
        elif "searchsploit" in fc:
            alternatives.append(f"nmap --script=vuln -T4 {target}")
        elif "curl" in fc and ("http" in fc or "https" in fc):
            alternatives.append(f"whatweb --color never {target}")

        if not alternatives:
            alternatives.append(f"nmap --script=vuln -T4 {target}")
            alternatives.append(f"searchsploit {self.target}")
        return alternatives[:3]

    def _heuristic_chain(self) -> list[dict]:
        """Simple but coherent vuln-to-access chain when no LLM."""
        chain: list[dict] = []
        if self.credentials:
            chain.append(
                {"step": "attempt login with discovered credentials", "goal": "authenticate",
                 "prerequisite": "credentials"}
            )
        for f in self.findings:
            if f.exploitable and not f.exploited:
                chain.append(
                    {"step": f"attack {f.title[:60]}", "goal": "exploit the weakest link",
                     "prerequisite": "current access"}
                )
            if len(chain) >= 4:
                break
        if not chain:
            chain.append(
                {"step": f"nmap -sV -sC -p- {self.target}", "goal": "discover something to attack",
                 "prerequisite": "none"}
            )
        return chain

    # ── Fact extraction helpers ─────────────────────────────────────────────
    def _extract_facts(self, command: str, output: str) -> None:
        """Greedily absorb facts from raw output into brain state."""
        out = output or ""
        ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", out)
        for ip in ips:
            if ip not in self.hosts:
                self.hosts.append(ip)
        matches = re.findall(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?", out)
        for port, _proto, name, ver in matches[:50]:
            self._record_service({"port": int(port), "service": name, "version": (ver or "").strip()})
        creds = re.findall(r"([\w.-]+)\s*:\s*([^\s:]{6,})(?:\s|$)", out)
        ignore = {"host", "user", "date", "login", "password", "usage", "http", "sample", "example"}
        for u, v in creds:
            if u.lower() not in ignore:
                self.credentials.append({"username": u, "value": v, "type": "found"})
        if re.search(r"uid=0|nt authority\s?\\system", out):
            host = self.hosts[0] if self.hosts else self.target
            self.access_levels[host] = "root/system"

    def _record_service(self, svc: dict) -> None:
        host = svc.pop("_host", None) or (self.hosts[0] if self.hosts else self.target)
        self.services.setdefault(host, [])
        if svc not in self.services[host]:
            self.services[host].append(svc)