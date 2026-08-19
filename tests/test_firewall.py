"""Tests for the CPENT firewall/filter analysis modules (recon.firewall_analysis)."""

import asyncio

import pytest

from recon.firewall_analysis import (
    FirewallAnalyzer,
    classify_port_states,
    classify_filter,
    detect_icmp_prohibited,
    build_controlled_scan,
)

# --- Sample nmap outputs ---------------------------------------------------

CISCO_STATELESS_RAW = """\
Nmap scan report for 10.10.20.5
Host is up.
Not shown: 990 filtered tcp ports (no-response)
PORT     STATE    SERVICE
22/tcp   filtered ssh
23/tcp   filtered telnet
21/tcp   open     ftp
80/tcp   filtered http
443/tcp  filtered https
3389/tcp filtered ms-wbt-server
(ICMP type=3 code=13 received for several probes)
"""

IPTABLES_PROHIBITED_RAW = """\
Nmap scan report for 10.10.20.10
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE  SERVICE
22/tcp   closed ssh
138/tcp  filtered netbios-ssn
(ICMP type 3 code 10 observed)
"""

FILTERED_AND_CLOSED_RAW = """\
Nmap scan report for 10.10.20.15
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE    SERVICE
80/tcp   closed   http
22/tcp   closed   ssh
443/tcp  filtered https
"""

SILENT_DROP_RAW = """\
Nmap scan report for 10.10.20.20
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE    SERVICE
22/tcp   filtered ssh
53/tcp   filtered domain
"""

FLAT_NETWORK_RAW = """\
Nmap scan report for 10.10.10.5
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
"""


# --- Pure parsing ----------------------------------------------------------

class TestPortParsing:
    def test_classify_port_states(self):
        probes = classify_port_states("22/tcp open ssh\n80/tcp closed http")
        assert len(probes) == 2
        assert probes[0].port == 22 and probes[0].state == "open"

    def test_detect_icmp_prohibited_code13(self):
        codes = detect_icmp_prohibited(CISCO_STATELESS_RAW)
        assert (3, 13) in codes

    def test_detect_icmp_prohibited_code10(self):
        codes = detect_icmp_prohibited(IPTABLES_PROHIBITED_RAW)
        assert (3, 10) in codes


# --- Classification --------------------------------------------------------

class TestFilterClassification:
    def test_cisco_router_acl_code13(self):
        report = classify_filter(
            classify_port_states(CISCO_STATELESS_RAW),
            detect_icmp_prohibited(CISCO_STATELESS_RAW),
        )
        assert report.mechanism == "router_acl"
        assert report.filter_present is True
        assert report.confidence >= 0.9
        assert report.finding is not None

    def test_iptables_host_deny_code10(self):
        report = classify_filter(
            classify_port_states(IPTABLES_PROHIBITED_RAW),
            detect_icmp_prohibited(IPTABLES_PROHIBITED_RAW),
        )
        assert report.mechanism == "iptables"

    def test_filter_software_filtered_and_closed(self):
        report = classify_filter(classify_port_states(FILTERED_AND_CLOSED_RAW), None)
        assert report.mechanism == "firewall_software"

    def test_silent_drop_firewall_device(self):
        report = classify_filter(classify_port_states(SILENT_DROP_RAW), None)
        assert report.mechanism == "firewall_device"

    def test_no_filter_flat_network(self):
        report = classify_filter(classify_port_states(FLAT_NETWORK_RAW), None)
        assert report.mechanism == "none"
        assert report.filter_present is False


# --- Command building ------------------------------------------------------

class TestCommandBuilding:
    def test_controlled_scan_flags(self):
        cmd = build_controlled_scan("10.10.20.5", "1-100")
        assert "-Pn" in cmd
        assert "-sS" in cmd
        assert "-T1" in cmd
        assert "--max-retries 1" in cmd
        assert "--scan-delay" in cmd

    def test_controlled_scan_source_port(self):
        cmd = build_controlled_scan("10.10.20.5", "1-100", source_port=20)
        assert "-g 20" in cmd


# --- Analyzer (offline raw mode, no nmap required) -------------------------

class TestFirewallAnalyzer:
    def test_detect_filter_offline_router_acl(self):
        result = asyncio.run(
            FirewallAnalyzer().detect_filter("10.10.20.5", raw=CISCO_STATELESS_RAW)
        )
        assert result["filter_present"] is True
        assert result["mechanism"] == "router_acl"

    def test_map_filter_rules(self):
        result = asyncio.run(
            FirewallAnalyzer().map_filter_rules("10.10.20.5", raw=CISCO_STATELESS_RAW)
        )
        assert 21 in result["ports_allowed_open"]      # ftp passes filter
        assert 22 in result["ports_filtered_blocked"]   # ssh dropped

    def test_source_port_bypass_reveals_new_port(self):
        baseline = FLAT_NETWORK_RAW.replace("80/tcp   open  http", "80/tcp   filtered http")
        bypass = FLAT_NETWORK_RAW  # 80 becomes visible when source port 20 used
        result = asyncio.run(
            FirewallAnalyzer().source_port_bypass(
                "10.10.20.5",
                source_port=20,
                baseline_raw=baseline,
                bypass_raw=bypass,
            )
        )
        assert result["bypass_successful"] is True
        assert 80 in result["newly_visible_via_sourceport"]
        assert 80 in result["newly_open_via_sourceport"]

    def test_source_port_bypass_no_change(self):
        result = asyncio.run(
            FirewallAnalyzer().source_port_bypass(
                "10.10.20.5",
                source_port=22,
                baseline_raw=FLAT_NETWORK_RAW,
                bypass_raw=FLAT_NETWORK_RAW,
            )
        )
        assert result["bypass_successful"] is False
