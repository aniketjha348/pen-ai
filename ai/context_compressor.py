"""Context Compressor - Compress engagement state for LLM token limits."""


class ContextCompressor:
    """Compress engagement context to fit LLM token limits.

    LLMs have limited context. When engagement gets long,
    we need to summarize instead of sending everything.
    """

    def __init__(self, max_tokens: int = 6000):
        self.max_tokens = max_tokens  # Leave room for system prompt + response

    def compress(self, state: dict) -> str:
        """Compress state into a concise summary."""
        lines = []

        # Target info (always include)
        lines.append(f"TARGET: {state.get('target', 'unknown')}")
        lines.append(f"CYCLE: {state.get('cycle', 0)}")
        lines.append(f"ACCESS: {state.get('access_map', {})}")

        # Hosts - just IP list
        hosts = state.get("known_hosts", [])
        if hosts:
            lines.append(f"HOSTS ({len(hosts)}): {', '.join(list(hosts)[:20])}")

        # Services - compact format
        services = state.get("known_services", {})
        if services:
            svc_lines = []
            for host, svcs in list(services.items())[:10]:
                svc_strs = [f"{s.get('port', '?')}/{s.get('service', '?')}" for s in svcs[:5]]
                svc_lines.append(f"  {host}: {', '.join(svc_strs)}")
            lines.append(f"SERVICES:")
            lines.extend(svc_lines)

        # Credentials - always include
        creds = state.get("credentials", [])
        if creds:
            lines.append(f"CREDENTIALS ({len(creds)}):")
            for cred in creds[:10]:
                val = str(cred.get("value", ""))[:40]
                lines.append(f"  [{cred.get('type', '?')}] {val}")

        # Failed attempts - don't retry
        failed = state.get("failed_attempts", [])
        if failed:
            lines.append(f"FAILED (don't retry): {', '.join(list(failed)[:15])}")

        # Tools installed
        tools = state.get("tools_installed", [])
        if tools:
            lines.append(f"TOOLS: {', '.join(tools[:20])}")

        # Pivoted networks
        pivots = state.get("pivoted_networks", [])
        if pivots:
            lines.append(f"PIVOTED NETS: {', '.join(pivots[:10])}")

        # Recent commands (last 10)
        commands = state.get("commands_run", [])
        if commands:
            lines.append(f"RECENT CMDS:")
            for cmd in commands[-10:]:
                lines.append(f"  $ {cmd[:80]}")

        return "\n".join(lines)

    def estimate_tokens(self, text: str) -> int:
        """Rough token estimate (1 token ≈ 4 chars)."""
        return len(text) // 4

    def fits_in_context(self, state: dict) -> bool:
        """Check if state fits in LLM context."""
        compressed = self.compress(state)
        return self.estimate_tokens(compressed) < self.max_tokens

    def get_context(self, state: dict, system_prompt: str = "") -> str:
        """Get context that fits in LLM window."""
        compressed = self.compress(state)

        # If still too long, truncate
        while self.estimate_tokens(compressed) > self.max_tokens and len(compressed) > 100:
            # Remove lines from the middle
            lines = compressed.split("\n")
            # Keep first 5 and last 5 lines
            if len(lines) > 10:
                compressed = "\n".join(lines[:5] + ["..."] + lines[-5:])

        return compressed
