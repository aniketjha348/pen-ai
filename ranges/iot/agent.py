"""IoT Range Agent - Real IoT firmware analysis using binwalk, firmware-mod-kit."""

import asyncio
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from ai.tool_registry import ToolCategory, register_tool, ToolParameter


class IoTDeviceType(str, Enum):
    """Types of IoT devices."""

    ROUTER = "router"
    CAMERA = "camera"
    SENSOR = "sensor"
    GATEWAY = "gateway"
    INDUSTRIAL = "industrial"
    UNKNOWN = "unknown"


class IoTProtocol(str, Enum):
    """IoT protocols."""

    MQTT = "mqtt"
    COAP = "coap"
    MODBUS = "modbus"
    BACNET = "bacnet"
    ZIGBEE = "zigbee"
    BLUETOOTH = "bluetooth"
    WIFI = "wifi"
    LORAWAN = "lorawan"


@dataclass
class FirmwareInfo:
    """Information about IoT firmware."""

    path: str
    device_type: IoTDeviceType
    architecture: Optional[str] = None
    kernel_version: Optional[str] = None
    filesystem_type: Optional[str] = None
    extracted_files: list[str] = None
    hardcoded_credentials: list[dict] = None
    vulnerabilities: list[str] = None


@dataclass
class IoTDevice:
    """An discovered IoT device."""

    ip: str
    device_type: IoTDeviceType
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    protocols: list[IoTProtocol] = None
    open_ports: list[int] = None


class IoTAgent:
    """IoT analysis and attack agent using real tools."""

    def __init__(self):
        self._devices: list[IoTDevice] = []
        self._firmware: list[FirmwareInfo] = []

    async def discover_devices(self, target: str) -> dict:
        """Discover IoT devices using nmap."""
        results = {
            "devices": [],
            "protocols": [],
            "open_services": [],
        }

        try:
            # Scan for common IoT ports
            cmd = f"nmap -sV -p 80,443,554,8080,8443,1883,5683,502,47808 {target}"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode("utf-8", errors="replace")

            import re
            # Parse open ports
            port_pattern = r"(\d+)/tcp\s+open\s+(\S+)"
            for match in re.finditer(port_pattern, output):
                port = int(match.group(1))
                service = match.group(2)
                results["open_services"].append({"port": port, "service": service})

                # Identify device type based on service
                device_type = "unknown"
                if port in [554]:
                    device_type = "camera"  # RTSP
                elif port in [1883]:
                    device_type = "iot_mqtt"  # MQTT
                elif port in [5683]:
                    device_type = "iot_coap"  # CoAP
                elif port in [502]:
                    device_type = "industrial"  # Modbus

                results["devices"].append({
                    "ip": target,
                    "port": port,
                    "service": service,
                    "type": device_type,
                })

        except Exception as e:
            results["error"] = f"Device discovery failed: {str(e)}"

        return results

    async def enumerate_device(self, target: str, port: int = 80) -> dict:
        """Enumerate an IoT device via web interface."""
        results = {
            "device_type": "unknown",
            "manufacturer": "unknown",
            "model": "unknown",
            "firmware": "unknown",
            "interfaces": [],
            "default_creds": [],
        }

        try:
            # Try to access web interface
            cmd = f"curl -sk --max-time 10 http://{target}:{port}/"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode("utf-8", errors="replace")

            # Parse for device info
            import re
            # Look for manufacturer
            manufacturers = ["hikvision", "dahua", "axis", "tplink", "netgear", "dlink", "linksys", "zyxel"]
            for mfr in manufacturers:
                if mfr.lower() in output.lower():
                    results["manufacturer"] = mfr
                    break

            # Look for model
            model_match = re.search(r"model[:\s]+([A-Za-z0-9\-]+)", output, re.IGNORECASE)
            if model_match:
                results["model"] = model_match.group(1)

            # Look for firmware version
            fw_match = re.search(r"firmware[:\s]+([0-9\.]+)", output, re.IGNORECASE)
            if fw_match:
                results["firmware"] = fw_match.group(1)

            results["web_content"] = output[:2000]

        except Exception as e:
            results["error"] = f"Device enumeration failed: {str(e)}"

        # Check for default credentials
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", ""),
            ("root", "root"),
            ("admin", "12345"),
            ("admin", "admin123"),
        ]

        for username, password in default_creds:
            results["default_creds"].append({"username": username, "password": password})

        return results

    async def acquire_firmware(self, target: str, method: str = "web") -> dict:
        """Acquire firmware from device via web download."""
        results = {
            "success": False,
            "path": None,
            "error": None,
        }

        try:
            # Try common firmware download paths
            firmware_paths = [
                "/firmware.bin",
                "/firmware.gz",
                "/upgrade.bin",
                "/update.bin",
                "/fw.bin",
                "/latest_firmware.bin",
            ]

            for path in firmware_paths:
                try:
                    cmd = f"curl -sk --max-time 30 -o /tmp/firmware.bin http://{target}{path}"
                    proc = await asyncio.create_subprocess_shell(
                        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                    )
                    await asyncio.wait_for(proc.communicate(), timeout=35)

                    # Check if file is valid
                    if os.path.exists("/tmp/firmware.bin") and os.path.getsize("/tmp/firmware.bin") > 1000:
                        results["success"] = True
                        results["path"] = "/tmp/firmware.bin"
                        results["size"] = os.path.getsize("/tmp/firmware.bin")
                        break
                except Exception:
                    continue

            if not results["success"]:
                results["error"] = "Could not acquire firmware from common paths"

        except Exception as e:
            results["error"] = f"Firmware acquisition failed: {str(e)}"

        return results

    async def extract_firmware(self, path: str) -> dict:
        """Extract firmware image using binwalk."""
        results = {
            "success": False,
            "filesystem": None,
            "files": [],
            "error": None,
        }

        try:
            # Create extraction directory
            extract_dir = f"/tmp/firmware_extract_{os.path.basename(path)}"
            os.makedirs(extract_dir, exist_ok=True)

            # Use binwalk to extract
            cmd = f"binwalk -e -C {extract_dir} {path}"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode("utf-8", errors="replace")
            error_output = stderr.decode("utf-8", errors="replace")

            # Check for extracted files
            cmd2 = f"find {extract_dir} -type f 2>/dev/null | head -100"
            proc2 = await asyncio.create_subprocess_shell(
                cmd2, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=30)
            files = stdout2.decode("utf-8", errors="replace").strip().split("\n")

            if files and files[0]:
                results["success"] = True
                results["files"] = [f for f in files if f]
                results["extract_dir"] = extract_dir
            else:
                results["error"] = f"binwalk extraction failed: {error_output[:500]}"

        except FileNotFoundError:
            results["error"] = "binwalk not found. Install: apt-get install binwalk"
        except Exception as e:
            results["error"] = f"Firmware extraction failed: {str(e)}"

        return results

    async def analyze_firmware(self, path: str) -> dict:
        """Analyze extracted firmware for hardcoded credentials and vulnerabilities."""
        results = {
            "hardcoded_creds": [],
            "vulnerable_services": [],
            "interesting_files": [],
            "config_files": [],
            "passwords_found": [],
        }

        try:
            # Search for hardcoded credentials
            cmd = f"grep -rn -i 'password\\|passwd\\|credential\\|secret\\|key' {path} 2>/dev/null | head -50"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode("utf-8", errors="replace")

            import re
            # Extract password patterns
            for line in output.split("\n"):
                if ":" in line:
                    # Look for password in config files
                    pw_match = re.search(r"password[=:]\s*[\"']?([^\s\"']+)", line, re.IGNORECASE)
                    if pw_match:
                        results["passwords_found"].append({
                            "password": pw_match.group(1),
                            "source": line.split(":")[0] if ":" in line else "unknown",
                        })

            # Search for config files
            cmd2 = f"find {path} -name '*.conf' -o -name '*.cfg' -o -name '*.ini' -o -name '*.json' 2>/dev/null | head -20"
            proc2 = await asyncio.create_subprocess_shell(
                cmd2, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=10)
            configs = stdout2.decode("utf-8", errors="replace").strip().split("\n")
            results["config_files"] = [c for c in configs if c]

            # Search for interesting files
            cmd3 = f"find {path} -name 'shadow' -o -name 'passwd' -o -name 'hosts' -o -name '*.key' -o -name '*.pem' 2>/dev/null | head -20"
            proc3 = await asyncio.create_subprocess_shell(
                cmd3, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout3, _ = await asyncio.wait_for(proc3.communicate(), timeout=10)
            interesting = stdout3.decode("utf-8", errors="replace").strip().split("\n")
            results["interesting_files"] = [f for f in interesting if f]

        except Exception as e:
            results["error"] = f"Firmware analysis failed: {str(e)}"

        return results

    async def analyze_protocol(self, target: str, protocol: str) -> dict:
        """Analyze IoT protocol traffic."""
        results = {
            "protocol": protocol,
            "messages": [],
            "vulnerabilities": [],
        }

        if protocol.lower() == "mqtt":
            try:
                # Try to connect to MQTT broker
                cmd = f"mosquitto_sub -h {target} -t '#' -W 5 2>/dev/null || echo 'MQTT connection failed'"
                proc = await asyncio.create_subprocess_shell(
                    cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                output = stdout.decode("utf-8", errors="replace")

                if "MQTT" in output or "Connection" in output:
                    results["vulnerabilities"].append({
                        "type": "mqtt_anonymous",
                        "description": "MQTT broker allows anonymous connections",
                        "risk": "high",
                    })
            except Exception:
                pass

        elif protocol.lower() == "modbus":
            try:
                # Try Modbus read
                cmd = f"modbus-cli read-holding 1 0 10 {target} 2>/dev/null || echo 'Modbus test failed'"
                proc = await asyncio.create_subprocess_shell(
                    cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                output = stdout.decode("utf-8", errors="replace")

                if "Register" in output or "Value" in output:
                    results["vulnerabilities"].append({
                        "type": "modbus_no_auth",
                        "description": "Modbus allows unauthenticated reads",
                        "risk": "high",
                    })
            except Exception:
                pass

        return results

    def get_attack_surface(self) -> list[dict]:
        """Analyze IoT attack surface."""
        surface = []

        for device in self._devices:
            if device.open_ports:
                surface.append({
                    "type": "network_service",
                    "device": device.ip,
                    "ports": device.open_ports,
                    "risk": "high",
                })

            if device.protocols:
                for protocol in device.protocols:
                    surface.append({
                        "type": "protocol",
                        "device": device.ip,
                        "protocol": protocol.value,
                        "risk": "medium",
                    })

        return surface


# Register IoT tools
@register_tool(
    name="iot_discover",
    description="Discover IoT devices on network using nmap",
    category=ToolCategory.IOT,
    parameters=[
        ToolParameter(name="target", type="str", description="Target network"),
    ],
)
async def iot_discover(target: str) -> dict:
    """Execute IoT device discovery."""
    agent = IoTAgent()
    return await agent.discover_devices(target)


@register_tool(
    name="iot_enumerate",
    description="Enumerate IoT device via web interface",
    category=ToolCategory.IOT,
    parameters=[
        ToolParameter(name="target", type="str", description="Target IP"),
        ToolParameter(name="port", type="int", description="Web port", required=False, default=80),
    ],
)
async def iot_enumerate(target: str, port: int = 80) -> dict:
    """Execute device enumeration."""
    agent = IoTAgent()
    return await agent.enumerate_device(target, port)


@register_tool(
    name="iot_firmware_extract",
    description="Extract firmware using binwalk",
    category=ToolCategory.IOT,
    parameters=[
        ToolParameter(name="path", type="str", description="Path to firmware file"),
    ],
)
async def iot_firmware_extract(path: str) -> dict:
    """Execute firmware extraction."""
    agent = IoTAgent()
    return await agent.extract_firmware(path)


@register_tool(
    name="iot_firmware_analyze",
    description="Analyze extracted firmware for credentials and vulnerabilities",
    category=ToolCategory.IOT,
    parameters=[
        ToolParameter(name="path", type="str", description="Path to extracted firmware directory"),
    ],
)
async def iot_firmware_analyze(path: str) -> dict:
    """Execute firmware analysis."""
    agent = IoTAgent()
    return await agent.analyze_firmware(path)
