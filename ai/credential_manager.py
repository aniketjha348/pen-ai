"""Credential Manager - Track, organize, and manage discovered credentials."""

import json
import os
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class Credential:
    """A discovered credential."""
    username: str = ""
    password: str = ""
    hash_value: str = ""
    hash_type: str = ""
    credential_type: str = "password"  # password, hash, key, token, ssh_key
    source: str = ""  # Where it was found
    target: str = ""  # Which host it belongs to
    service: str = ""  # Which service (ssh, smb, mysql, etc.)
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    cracked: bool = False
    verified: bool = False
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "password": self.password,
            "hash_value": self.hash_value,
            "hash_type": self.hash_type,
            "credential_type": self.credential_type,
            "source": self.source,
            "target": self.target,
            "service": self.service,
            "discovered_at": self.discovered_at,
            "cracked": self.cracked,
            "verified": self.verified,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Credential":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def __eq__(self, other):
        if not isinstance(other, Credential):
            return False
        return (self.username == other.username and
                self.target == other.target and
                self.service == other.service)

    def __hash__(self):
        return hash((self.username, self.target, self.service))


class CredentialManager:
    """Manage discovered credentials with deduplication and organization."""

    def __init__(self, storage_dir: str = None):
        self.credentials: list[Credential] = []
        self.storage_dir = storage_dir or os.path.join(os.path.expanduser("~"), ".pen-ai", "credentials")
        os.makedirs(self.storage_dir, exist_ok=True)

    def add(self, username: str = "", password: str = "", hash_value: str = "",
            hash_type: str = "", credential_type: str = "password",
            source: str = "", target: str = "", service: str = "",
            notes: str = "") -> Optional[Credential]:
        """Add a credential, avoiding duplicates."""
        cred = Credential(
            username=username,
            password=password,
            hash_value=hash_value,
            hash_type=hash_type,
            credential_type=credential_type,
            source=source,
            target=target,
            service=service,
            notes=notes,
        )

        # Check for duplicates
        for existing in self.credentials:
            if cred == existing:
                # Update if new info is better
                if password and not existing.password:
                    existing.password = password
                if hash_value and not existing.hash_value:
                    existing.hash_value = hash_value
                if source and not existing.source:
                    existing.source = source
                return None

        self.credentials.append(cred)
        return cred

    def add_from_output(self, output: str, target: str = "", service: str = "") -> list[Credential]:
        """Extract credentials from command output."""
        import re
        found = []

        # Password patterns
        pw_patterns = [
            (r"password[=:]\s*(\S+)", "password"),
            (r"PASSWORD[=:]\s*(\S+)", "password"),
            (r"passwd[=:]\s*(\S+)", "password"),
            (r"LOGIN:\s*(\S+)\s+PASSWORD:\s*(\S+)", "login_creds"),
        ]

        for pattern, cred_type in pw_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    username, password = match
                else:
                    username = ""
                    password = match

                if password and len(password) > 1:
                    cred = self.add(
                        username=username,
                        password=password,
                        credential_type="password",
                        source="output_parsing",
                        target=target,
                        service=service,
                    )
                    if cred:
                        found.append(cred)

        # Hash patterns
        hash_patterns = [
            (r"NTLM.*?:([a-f0-9]{32})", "ntlm"),
            (r"\$krb5tgs\$.*?\$", "kerberos_tgs"),
            (r"\$krb5asrep\$.*?\$", "kerberos_asrep"),
            (r"\$6\$[^\s]+", "sha512_crypt"),
            (r"\$5\$[^\s]+", "sha256_crypt"),
            (r"\$1\$[^\s]+", "md5_crypt"),
        ]

        for pattern, hash_type in hash_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in matches:
                cred = self.add(
                    hash_value=match if isinstance(match, str) else match[0],
                    hash_type=hash_type,
                    credential_type="hash",
                    source="output_parsing",
                    target=target,
                    service=service,
                )
                if cred:
                    found.append(cred)

        return found

    def get_by_target(self, target: str) -> list[Credential]:
        """Get credentials for a specific target."""
        return [c for c in self.credentials if c.target == target]

    def get_by_service(self, service: str) -> list[Credential]:
        """Get credentials for a specific service."""
        return [c for c in self.credentials if c.service.lower() == service.lower()]

    def get_by_type(self, cred_type: str) -> list[Credential]:
        """Get credentials by type."""
        return [c for c in self.credentials if c.credential_type == cred_type]

    def get_cracked(self) -> list[Credential]:
        """Get all cracked credentials."""
        return [c for c in self.credentials if c.cracked]

    def get_verified(self) -> list[Credential]:
        """Get all verified credentials."""
        return [c for c in self.credentials if c.verified]

    def mark_cracked(self, username: str, target: str, password: str):
        """Mark a credential as cracked."""
        for cred in self.credentials:
            if cred.username == username and cred.target == target:
                cred.cracked = True
                cred.password = password

    def mark_verified(self, username: str, target: str):
        """Mark a credential as verified."""
        for cred in self.credentials:
            if cred.username == username and cred.target == target:
                cred.verified = True

    def to_dict_list(self) -> list[dict]:
        """Convert all credentials to dict list."""
        return [c.to_dict() for c in self.credentials]

    def from_dict_list(self, data: list[dict]):
        """Load credentials from dict list."""
        self.credentials = [Credential.from_dict(d) for d in data]

    def save(self, filename: str = None):
        """Save credentials to file."""
        if not filename:
            filename = os.path.join(self.storage_dir, "credentials.json")
        with open(filename, "w") as f:
            json.dump(self.to_dict_list(), f, indent=2)

    def load(self, filename: str = None):
        """Load credentials from file."""
        if not filename:
            filename = os.path.join(self.storage_dir, "credentials.json")
        if os.path.exists(filename):
            with open(filename) as f:
                self.from_dict_list(json.load(f))

    def summary(self) -> str:
        """Generate a summary of all credentials."""
        if not self.credentials:
            return "No credentials discovered."

        lines = []
        lines.append(f"\n  \033[1m🔑 CREDENTIAL SUMMARY\033[0m")
        lines.append(f"  {'─'*40}")

        # By type
        by_type = {}
        for c in self.credentials:
            t = c.credential_type
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(c)

        for cred_type, creds in by_type.items():
            lines.append(f"\n  \033[96m{cred_type.upper()} ({len(creds)}):\033[0m")
            for c in creds[:10]:
                target_str = f" @ {c.target}" if c.target else ""
                service_str = f" ({c.service})" if c.service else ""
                if c.password:
                    lines.append(f"    {c.username}: {c.password[:30]}{target_str}{service_str}")
                elif c.hash_value:
                    lines.append(f"    {c.username}: {c.hash_value[:30]}...{target_str}{service_str}")
                else:
                    lines.append(f"    {c.username}{target_str}{service_str}")

        lines.append(f"\n  {'─'*40}")
        lines.append(f"  Total: {len(self.credentials)} | Cracked: {len(self.get_cracked())} | Verified: {len(self.get_verified())}")

        return "\n".join(lines)
