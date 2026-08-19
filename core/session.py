"""Session Persistence - Save engagement state, resume later."""

import json
import os
from datetime import datetime
from typing import Optional
from pathlib import Path


class SessionManager:
    """Save and resume engagement sessions."""

    def __init__(self, session_dir: str = None):
        if session_dir is None:
            session_dir = os.path.join(os.path.expanduser("~"), ".pen-ai", "sessions")
        self.session_dir = session_dir
        os.makedirs(session_dir, exist_ok=True)

    def save(self, state: dict, session_id: str = None) -> str:
        """Save engagement state to disk."""
        if session_id is None:
            session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        session_path = os.path.join(self.session_dir, f"{session_id}.json")
        state["saved_at"] = datetime.now().isoformat()
        state["session_id"] = session_id

        with open(session_path, "w") as f:
            json.dump(state, f, indent=2, default=str)

        return session_path

    def load(self, session_id: str) -> Optional[dict]:
        """Load a session from disk."""
        session_path = os.path.join(self.session_dir, f"{session_id}.json")
        if not os.path.exists(session_path):
            return None

        with open(session_path, "r") as f:
            return json.load(f)

    def list_sessions(self) -> list[dict]:
        """List all saved sessions."""
        sessions = []
        for filename in os.listdir(self.session_dir):
            if filename.endswith(".json"):
                session_id = filename.replace(".json", "")
                session_path = os.path.join(self.session_dir, filename)
                try:
                    with open(session_path, "r") as f:
                        state = json.load(f)
                    sessions.append({
                        "session_id": session_id,
                        "target": state.get("target", "unknown"),
                        "saved_at": state.get("saved_at", "unknown"),
                        "cycle": state.get("cycle", 0),
                        "hosts": len(state.get("known_hosts", [])),
                        "credentials": len(state.get("credentials", [])),
                    })
                except Exception:
                    pass
        return sorted(sessions, key=lambda x: x["saved_at"], reverse=True)

    def delete(self, session_id: str) -> bool:
        """Delete a session."""
        session_path = os.path.join(self.session_dir, f"{session_id}.json")
        if os.path.exists(session_path):
            os.remove(session_path)
            return True
        return False

    def auto_save(self, state: dict, session_id: str, interval_cycles: int = 5) -> bool:
        """Auto-save every N cycles."""
        cycle = state.get("cycle", 0)
        if cycle > 0 and cycle % interval_cycles == 0:
            self.save(state, session_id)
            return True
        return False
