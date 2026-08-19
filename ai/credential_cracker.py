"""Auto Credential Cracker - Crack hashes found during engagement."""

import asyncio
import os
import tempfile
from typing import Optional


class CredentialCracker:
    """Auto-crack hashes found during penetration testing."""

    def __init__(self):
        self.cracked = []
        self.hash_file = os.path.join(tempfile.gettempdir(), "penai_hashes.txt")

    async def auto_crack(self, hashes: list[dict]) -> list[dict]:
        """Automatically crack any hashes found."""
        results = []

        for cred in hashes:
            hash_value = cred.get("value", "")
            cred_type = cred.get("type", "")

            if cred_type == "ntlm":
                result = await self.crack_ntlm(hash_value)
                if result:
                    results.append(result)
            elif cred_type == "kerberos" or cred_type == "asrep":
                result = await self.crack_kerberos(hash_value)
                if result:
                    results.append(result)
            elif cred_type == "password":
                # Already a plaintext password
                results.append({"hash": hash_value, "password": hash_value, "method": "plaintext"})
            elif cred_type == "login":
                # username:password format
                results.append({"hash": hash_value, "password": hash_value, "method": "login_creds"})

        self.cracked.extend(results)
        return results

    async def crack_ntlm(self, ntlm_hash: str) -> Optional[dict]:
        """Crack NTLM hash using john or hashcat."""
        # Write hash to file
        with open(self.hash_file, "w") as f:
            f.write(f"admin::{ntlm_hash}\n")

        # Try john first
        result = await self._run_john(self.hash_file)
        if result:
            return {"hash": ntlm_hash, "password": result, "method": "john_ntlm"}

        # Try hashcat
        result = await self._run_hashcat(ntlm_hash, mode="1000")  # NTLM mode
        if result:
            return {"hash": ntlm_hash, "password": result, "method": "hashcat_ntlm"}

        # Try common passwords
        result = await self._try_common_passwords(ntlm_hash)
        if result:
            return {"hash": ntlm_hash, "password": result, "method": "common_password"}

        return None

    async def crack_kerberos(self, kerberos_hash: str) -> Optional[dict]:
        """Crack Kerberos hash."""
        with open(self.hash_file, "w") as f:
            f.write(f"{kerberos_hash}\n")

        # Kerberos TGS = mode 13100 in hashcat
        result = await self._run_hashcat(kerberos_hash, mode="13100")
        if result:
            return {"hash": kerberos_hash, "password": result, "method": "hashcat_kerberos"}

        result = await self._run_john(self.hash_file, format="krb5tgs")
        if result:
            return {"hash": kerberos_hash, "password": result, "method": "john_kerberos"}

        return None

    async def _run_john(self, hash_file: str, format: str = "") -> Optional[str]:
        """Run john the ripper."""
        try:
            fmt = f"--format={format}" if format else ""
            cmd = f"john {fmt} --wordlist=/usr/share/wordlists/rockyou.txt {hash_file} 2>/dev/null"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)

            # Get cracked passwords
            show_cmd = f"john --show {hash_file} 2>/dev/null"
            proc2 = await asyncio.create_subprocess_shell(
                show_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc2.communicate(), timeout=30)
            output = stdout.decode("utf-8", errors="replace")

            for line in output.split("\n"):
                if ":" in line:
                    password = line.split(":")[1].strip()
                    if password:
                        return password

        except FileNotFoundError:
            pass
        except Exception:
            pass
        return None

    async def _run_hashcat(self, hash_value: str, mode: str = "1000") -> Optional[str]:
        """Run hashcat."""
        try:
            with open(self.hash_file, "w") as f:
                f.write(f"{hash_value}\n")

            cmd = f"hashcat -m {mode} {self.hash_file} /usr/share/wordlists/rockyou.txt --potfile-path=/tmp/penai_cracked.pot 2>/dev/null"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)

            # Check pot file
            if os.path.exists("/tmp/penai_cracked.pot"):
                with open("/tmp/penai_cracked.pot", "r") as f:
                    for line in f:
                        if hash_value.lower() in line.lower():
                            password = line.split(":")[-1].strip()
                            return password

        except FileNotFoundError:
            pass
        except Exception:
            pass
        return None

    async def _try_common_passwords(self, ntlm_hash: str) -> Optional[str]:
        """Try common passwords without hashcat/john."""
        common_passwords = [
            "password", "Password1", "password1", "123456", "admin",
            "Admin123", "P@ssw0rd", "Welcome1", "Passw0rd!", "letmein",
            "qwerty", "abc123", "monkey", "master", "dragon",
            "login", "princess", "solo", "passw0rd", "shadow",
            "Trustno1", "iloveyou", "sunshine", "charlie", "donald",
            "changeme", "default", "root", "toor", "password123",
        ]

        # Write all to temp file and check with hashcat
        if os.path.exists("/tmp/penai_common.txt"):
            os.remove("/tmp/penai_common.txt")

        with open("/tmp/penai_common.txt", "w") as f:
            f.write("\n".join(common_passwords))

        return await self._run_hashcat(ntlm_hash, mode="1000")

    def get_cracked(self) -> list[dict]:
        """Get all cracked credentials."""
        return self.cracked.copy()
