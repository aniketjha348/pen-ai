"""Safe shell command construction for PEN-AI tool integrations."""

import shlex

ROCKYOU = "/usr/share/wordlists/rockyou.txt"

DEFAULT_PASSWORD_LIST = [
    "password", "123456", "admin", "root", "test", "guest", "letmein",
    "welcome", "changeme", "Password1", "P@ssw0rd", "admin123", "root123",
    "toor", "12345", "12345678", "qwerty", "abc123", "monkey", "dragon",
]

SSH_OPTS = "-o StrictHostKeyChecking=no"


def q(value: str) -> str:
    """Quote a value so it is safe inside a single shell command line."""
    return shlex.quote(str(value))


def password_list(kwargs: dict) -> list[str]:
    """Return caller-supplied passwords or the built-in default list."""
    passwords = kwargs.get("passwords")
    if isinstance(passwords, (list, tuple)) and passwords:
        return list(passwords)
    return list(DEFAULT_PASSWORD_LIST)


def build_remote_cmd(
    local: str,
    target: str,
    username: str,
    password: str,
    port: int = 22,
    timeout: int = 5,
) -> str:
    """Build an sshpass ssh command with every interpolated value quoted."""
    return (
        "sshpass -p {pw} ssh {opts} -o ConnectTimeout={t} "
        "{user}@{target} -p {port} {cmd}"
    ).format(
        pw=q(password),
        opts=SSH_OPTS,
        t=int(timeout),
        user=q(username),
        target=q(target),
        port=int(port),
        cmd=q(local),
    )


def build_smb_client_cmd(
    operation: str,
    target: str,
    port: int,
    username: str = "",
    password: str = "",
    share: str = "IPC$",
    extra: str = "",
) -> str:
    """Build an smbclient command (operation='list' or 'connect')."""
    if operation == "list":
        auth = f" -U {q(username)}%{q(password)}" if username else " -N"
        return f"smbclient -L {q(target)} {auth} -p {int(port)} {extra}".strip()
    auth = f" -U {q(username)}%{q(password)}" if username else " -N"
    return f"smbclient //{q(target)}/{q(share)} {auth} -p {int(port)} {extra}".strip()
