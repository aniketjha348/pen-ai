"""AI Brain - Observes the environment, prepares context for LLM decision-making.

No hardcoded attack paths. No fixed rules. The LLM decides everything.
This module only:
1. Parses and summarizes current state
2. Generates context-rich prompts for the LLM
3. Provides dynamic, data-driven observations (not conclusions)
"""


class AttackSurface:
    """Analyze what we found and prepare context for the LLM to decide."""

    @staticmethod
    def get_attack_plan(services: list[dict], host: str = "?") -> list[dict]:
        """Given discovered services, prepare attack context for LLM.

        Instead of hardcoding attack paths, we describe what the service
        is and let the LLM decide what tools/techniques to use.
        """
        plan = []
        for svc in services:
            port = svc.get("port", 0)
            service = svc.get("service", "").lower()
            version = svc.get("version", "")

            plan.append({
                "target_port": port,
                "target_service": service,
                "target_version": version,
                "description": f"Service '{service}' on port {port}"
                              + (f" version {version}" if version else ""),
                "host": host,
            })

        return plan

    @staticmethod
    def get_post_exploit_plan(access_level: str) -> list[dict]:
        """Describe the access level and let LLM decide post-exploit actions.

        Returns observation context, not fixed commands.
        """
        return [{
            "access_level": access_level,
            "description": f"Current access level is '{access_level}'. "
                          "Determine appropriate post-exploitation actions "
                          "based on this access and the target environment.",
        }]

    @staticmethod
    def reason_about_findings(state: dict) -> str:
        """Generate observations about current state for the LLM to act on.

        Instead of prescribing actions, we observe and describe.
        """
        lines = []
        hosts = state.get("hosts", [])
        services = state.get("services", {})
        creds = state.get("credentials", [])
        access = state.get("access_map", {})
        failed = state.get("failed", [])
        commands_run = state.get("commands_run", [])

        if not hosts:
            return "No hosts discovered yet. Target needs reconnaissance."

        lines.append(f"Observed: {len(hosts)} host(s) discovered.")

        if services:
            total_svcs = sum(len(svcs) for svcs in services.values())
            lines.append(f"Observed: {total_svcs} service(s) open across hosts.")

            for host_ip, svcs in services.items():
                for svc in svcs:
                    port = svc.get("port", 0)
                    name = svc.get("service", "")
                    ver = svc.get("version", "")
                    lines.append(f"  - {host_ip}:{port} -> {name}"
                                + (f" ({ver})" if ver else ""))

        if creds:
            lines.append(f"Observed: {len(creds)} credential(s) found.")
            for c in creds:
                lines.append(f"  - [{c.get('type', '?')}] "
                            f"{str(c.get('value', ''))[:40]}")

        if access:
            for host_ip, level in access.items():
                lines.append(f"Observed: {host_ip} -> access level '{level}'")

        if failed:
            lines.append(f"Observed: {len(failed)} action(s) failed.")

        if commands_run:
            lines.append(f"Observed: {len(commands_run)} command(s) executed so far.")

        return "\n".join(lines)

    @staticmethod
    def generate_llm_prompt(state: dict, phase: str = "unknown") -> str:
        """Generate a rich context prompt for the LLM to decide next actions.

        This is the core of the 'no fixed rules' approach - we present
        the full state and let the LLM decide what makes sense.
        """
        observations = AttackSurface.reason_about_findings(state)

        prompt = f"""## Current Engagement State

Phase: {phase}

{observations}

## Your Task

Based on the above observations, decide the NEXT action(s) to take.
Consider:
- What information is still missing?
- What services need deeper enumeration?
- What attack vectors should be explored?
- Are there any credentials that could be leveraged?
- Is pivoting possible from current access?
- What would a real penetration tester do next?

Respond with 1-3 specific commands to execute, with brief reasoning for each.
Use the exact tool names and syntax appropriate for the target environment.
"""

        return prompt


class DecisionEngine:
    """Decide what to do next based on current state.

    With no LLM, falls back to simple state-based heuristics.
    With LLM, defers all decisions to the LLM.
    """

    def __init__(self, llm=None):
        self.llm = llm

    def decide_next(self, state: dict) -> list[str]:
        """Decide the next action(s) to take.

        If LLM is available, it decides. Otherwise, simple heuristics.
        """
        if self.llm:
            return self._llm_decide(state)
        return self._heuristic_decide(state)

    def _llm_decide(self, state: dict) -> list[str]:
        """Let the LLM decide what commands to run next."""
        # This would call the LLM in async context
        # For now, return empty - the autonomous_agent handles LLM calls
        return []

    def _heuristic_decide(self, state: dict) -> list[str]:
        """Simple fallback heuristics when no LLM is available.

        These are intentionally minimal - just enough to bootstrap.
        The LLM takes over once available.
        """
        commands = []
        hosts = state.get("hosts", [])
        services = state.get("services", {})
        failed = state.get("failed", [])
        commands_run = state.get("commands_run", [])

        # If no hosts, discover them
        if not hosts:
            target = state.get("target", "")
            if target:
                commands.append(f"nmap -sn {target}")
            return commands

        # If hosts exist but some lack service enumeration
        for host in hosts:
            if host not in services or not services[host]:
                commands.append(f"nmap -sV -sC -p- {host} --open")
                return commands

        # All hosts have services - present observation, let user/LLM decide
        return commands
