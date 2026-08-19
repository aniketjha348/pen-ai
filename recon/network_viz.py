"""Network Visualization - ASCII network maps for terminal output."""


class NetworkVisualizer:
    """Generate ASCII network visualizations."""

    @staticmethod
    def visualize(hosts: list, services: dict, access_map: dict, pivoted: list) -> str:
        """Generate an ASCII network map."""
        lines = []
        lines.append("\n  \033[1m🗺️  NETWORK MAP\033[0m")
        lines.append("  " + "─" * 50)

        if not hosts:
            lines.append("  No hosts discovered yet.")
            return "\n".join(lines)

        # Group hosts by network
        networks = {}
        for host in hosts:
            parts = host.split(".")
            if len(parts) == 4:
                network = ".".join(parts[:3]) + ".0/24"
                if network not in networks:
                    networks[network] = []
                networks[network].append(host)
            else:
                if "unknown" not in networks:
                    networks["unknown"] = []
                networks["unknown"].append(host)

        for network, net_hosts in networks.items():
            lines.append(f"\n  \033[96m[{network}]\033[0m")

            for i, host in enumerate(net_hosts):
                is_last = i == len(net_hosts) - 1
                prefix = "└── " if is_last else "├── "
                access = access_map.get(host, "")
                access_str = f" \033[91m[{access}]\033[0m" if access else ""

                lines.append(f"  {prefix}\033[92m{host}\033[0m{access_str}")

                # Show services
                svcs = services.get(host, [])
                if svcs:
                    svc_prefix = "    " if is_last else "│   "
                    svc_strs = []
                    for svc in svcs:
                        port = svc.get("port", "?")
                        name = svc.get("service", "?")
                        ver = svc.get("version", "")
                        svc_strs.append(f"{port}/{name}" + (f" ({ver})" if ver else ""))

                    # Show services in groups of 3
                    for j in range(0, len(svc_strs), 3):
                        chunk = svc_strs[j:j+3]
                        lines.append(f"  {svc_prefix}\033[90m{' | '.join(chunk)}\033[0m")

        # Show pivoted networks
        if pivoted:
            lines.append(f"\n  \033[95m[PIVOTED NETWORKS]\033[0m")
            for net in pivoted:
                lines.append(f"  ├── \033[93m{net}\033[0m \033[90m(discovered)\033[0m")

        lines.append("\n  " + "─" * 50)
        return "\n".join(lines)

    @staticmethod
    def visualize_compact(hosts: list, services: dict, access_map: dict) -> str:
        """Generate a compact network visualization."""
        if not hosts:
            return "  No hosts"

        lines = []
        lines.append("\n  \033[1m📊 HOSTS:\033[0m")

        for host in hosts:
            access = access_map.get(host, "")
            access_str = f" \033[91m[{access}]\033[0m" if access else ""
            svcs = services.get(host, [])

            if svcs:
                svc_count = len(svcs)
                ports = [str(s.get("port", "?")) for s in svcs[:5]]
                more = f" +{svc_count-5} more" if svc_count > 5 else ""
                lines.append(f"  \033[92m→ {host}\033[0m{access_str} \033[90m({svc_count} services: {', '.join(ports)}{more})\033[0m")
            else:
                lines.append(f"  \033[92m→ {host}\033[0m{access_str} \033[90m(no services)\033[0m")

        return "\n".join(lines)

    @staticmethod
    def visualize_services_table(services: dict) -> str:
        """Generate a table of all discovered services."""
        if not services:
            return "  No services discovered"

        lines = []
        lines.append("\n  \033[1m📋 SERVICES TABLE:\033[0m")
        lines.append("  " + "─" * 60)
        lines.append(f"  {'HOST':<16} {'PORT':<8} {'SERVICE':<15} {'VERSION':<20}")
        lines.append("  " + "─" * 60)

        for host, svcs in services.items():
            for svc in svcs:
                port = svc.get("port", "?")
                name = svc.get("service", "?")
                ver = svc.get("version", "")[:18]
                lines.append(f"  {host:<16} {port:<8} {name:<15} {ver:<20}")

        lines.append("  " + "─" * 60)
        return "\n".join(lines)
