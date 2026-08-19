"""Session Replay - Review and replay previous engagement sessions."""

import json
import os
from datetime import datetime
from typing import Optional


class SessionReplay:
    """Replay and review previous engagement sessions."""

    def __init__(self, sessions_dir: str = None):
        self.sessions_dir = sessions_dir or os.path.join(os.path.expanduser("~"), ".pen-ai", "sessions")
        os.makedirs(self.sessions_dir, exist_ok=True)

    def list_sessions(self) -> list[dict]:
        """List all saved sessions with metadata."""
        sessions = []
        if not os.path.exists(self.sessions_dir):
            return sessions

        for filename in os.listdir(self.sessions_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(self.sessions_dir, filename)
                try:
                    with open(filepath) as f:
                        data = json.load(f)
                    session_id = filename.replace(".json", "")
                    sessions.append({
                        "session_id": session_id,
                        "target": data.get("target", "unknown"),
                        "hosts": len(data.get("known_hosts", [])),
                        "services": sum(len(v) for v in data.get("known_services", {}).values()),
                        "credentials": len(data.get("credentials", [])),
                        "access_level": data.get("access_map", {}),
                        "commands_run": len(data.get("commands_run", [])),
                        "timestamp": data.get("timestamp", "unknown"),
                    })
                except Exception:
                    continue

        sessions.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return sessions

    def load_session(self, session_id: str) -> Optional[dict]:
        """Load a session by ID."""
        filepath = os.path.join(self.sessions_dir, f"{session_id}.json")
        if os.path.exists(filepath):
            with open(filepath) as f:
                return json.load(f)
        return None

    def get_session_summary(self, session_id: str) -> str:
        """Get a human-readable summary of a session."""
        data = self.load_session(session_id)
        if not data:
            return f"Session {session_id} not found."

        lines = []
        lines.append(f"\n  \033[1m📋 SESSION SUMMARY: {session_id}\033[0m")
        lines.append(f"  {'─'*50}")

        target = data.get("target", "unknown")
        hosts = data.get("known_hosts", [])
        services = data.get("known_services", {})
        credentials = data.get("credentials", [])
        access_map = data.get("access_map", {})
        pivoted = data.get("pivoted_networks", [])
        commands = data.get("commands_run", [])

        lines.append(f"  Target: {target}")
        lines.append(f"  Hosts: {len(hosts)}")
        lines.append(f"  Services: {sum(len(v) for v in services.values())}")
        lines.append(f"  Credentials: {len(credentials)}")
        lines.append(f"  Access: {access_map}")
        lines.append(f"  Networks: {len(pivoted)}")
        lines.append(f"  Commands: {len(commands)}")

        if hosts:
            lines.append(f"\n  \033[92mHOSTS:\033[0m")
            for h in hosts:
                svcs = services.get(h, [])
                access = access_map.get(h, "")
                access_str = f" [{access}]" if access else ""
                svc_str = ", ".join(f"{s.get('port', '?')}/{s.get('service', '?')}" for s in svcs)
                lines.append(f"    {h}{access_str}: {svc_str or 'no services'}")

        if credentials:
            lines.append(f"\n  \033[91mCREDENTIALS:\033[0m")
            for c in credentials:
                cred_type = c.get("type", "?") if isinstance(c, dict) else "?"
                value = str(c.get("value", "") if isinstance(c, dict) else "")[:40]
                lines.append(f"    [{cred_type}] {value}")

        lines.append(f"\n  {'─'*50}")
        return "\n".join(lines)

    def replay_commands(self, session_id: str) -> list[str]:
        """Get the list of commands from a session for replay."""
        data = self.load_session(session_id)
        if data:
            return data.get("commands_run", [])
        return []

    def compare_sessions(self, session_id1: str, session_id2: str) -> str:
        """Compare two sessions."""
        data1 = self.load_session(session_id1)
        data2 = self.load_session(session_id2)

        if not data1 or not data2:
            return "One or both sessions not found."

        lines = []
        lines.append(f"\n  \033[1m📊 SESSION COMPARISON\033[0m")
        lines.append(f"  {'─'*50}")
        lines.append(f"  {'Metric':<20} {'Session 1':<15} {'Session 2':<15}")
        lines.append(f"  {'─'*50}")

        metrics = [
            ("Target", data1.get("target", "?"), data2.get("target", "?")),
            ("Hosts", len(data1.get("known_hosts", [])), len(data2.get("known_hosts", []))),
            ("Services", sum(len(v) for v in data1.get("known_services", {}).values()),
                       sum(len(v) for v in data2.get("known_services", {}).values())),
            ("Credentials", len(data1.get("credentials", [])), len(data2.get("credentials", []))),
            ("Commands", len(data1.get("commands_run", [])), len(data2.get("commands_run", []))),
        ]

        for metric, val1, val2 in metrics:
            diff = ""
            if isinstance(val1, int) and isinstance(val2, int):
                if val2 > val1:
                    diff = f" (+{val2-val1})"
                elif val1 > val2:
                    diff = f" (-{val1-val2})"
            lines.append(f"  {metric:<20} {str(val1):<15} {str(val2):<15}{diff}")

        lines.append(f"  {'─'*50}")
        return "\n".join(lines)
