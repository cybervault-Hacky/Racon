"""Network module.

Performs connectivity checks (ICMP ping), traceroute, TCP banner grabbing,
simple service detection and an optional Nmap-based authorized port scan.

Ping/traceroute rely on OS binaries (``ping``/``traceroute``) and are wrapped
so failures degrade gracefully. Nmap is optional and only runs when the binary
is present and enabled.
"""

from __future__ import annotations

import platform
import socket
import subprocess
from typing import Any

from modules.base import BaseModule, Finding, ModuleResult
from core import utils

def _extract_rtt(output: str) -> float | None:
    """Best-effort parse of an average RTT from ping output."""
    import re

    match = re.search(r"(\d+\.?\d*)\s*ms", output)
    if match:
        try:
            return round(float(match.group(1)), 2)
        except ValueError:
            return None
    return None


#: Common service guesses keyed by port number (defensive inventory only).
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "SMTP Submission", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    27017: "MongoDB",
}


class NetworkModule(BaseModule):
    """Network-level scanning for a resolved target IP."""

    name = "Network"
    key = "network"

    def __init__(self, config: Any, http: Any, context: dict[str, Any]) -> None:
        super().__init__(config, http, context)
        ips = context.get("ips") or utils.resolve_hostname(self.target)
        self.primary_ip = ips[0] if ips else self.target

    def execute(self, result: ModuleResult) -> None:
        data: dict[str, Any] = {
            "ip": self.primary_ip,
            "ping": None,
            "traceroute": [],
            "banners": [],
            "services": [],
        }

        data["ping"] = self._ping(self.primary_ip)
        data["traceroute"] = self._traceroute(self.target)

        # Banner grabbing + service detection on common ports.
        ports = self._parse_ports(self.config.port_range)
        for port, service in self._probe_ports(self.primary_ip, ports):
            data["services"].append({"port": port, "service": service})
            banner = self._grab_banner(self.primary_ip, port)
            if banner:
                data["banners"].append({"port": port, "banner": banner})

        # Optional Nmap scan.
        nmap_result = self._run_nmap(self.primary_ip, ports)
        if nmap_result is not None:
            data["nmap"] = nmap_result

        result.data["network"] = data

        if data["ping"] and data["ping"].get("success"):
            result.findings.append(Finding(
                title="Host Responds to ICMP",
                severity="info",
                description=f"Ping to {self.primary_ip} succeeded (avg {data['ping'].get('rtt')} ms).",
                evidence=str(data["ping"]),
            ))
        else:
            result.findings.append(Finding(
                title="ICMP Unreachable / Filtered",
                severity="info",
                description="The host did not respond to ICMP echo requests.",
                recommendation="ICMP may be filtered; TCP checks are more reliable.",
            ))

        open_ports = [s["port"] for s in data["services"]]
        if open_ports:
            result.findings.append(Finding(
                title="Open TCP Ports Detected",
                severity="info",
                description=f"{len(open_ports)} TCP service(s) responded on the target.",
                evidence=", ".join(str(p) for p in open_ports),
                recommendation="Verify each open port is required and access-controlled.",
            ))
        for entry in data["banners"]:
            result.findings.append(Finding(
                title=f"Banner on Port {entry['port']}",
                severity="info",
                description="A service banner was retrieved on an open port.",
                evidence=entry["banner"][:200],
                recommendation="Disable unnecessary service banners where possible.",
            ))

        result.status = "success"

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _parse_ports(range_spec: str) -> list[int]:
        ports: list[int] = []
        for part in str(range_spec).split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start, _, end = part.partition("-")
                try:
                    for p in range(int(start), int(end) + 1):
                        ports.append(p)
                except ValueError:
                    continue
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    continue
        # Deduplicate, keep order.
        return list(dict.fromkeys(ports))

    @staticmethod
    def _ping(ip: str) -> dict:
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", "2000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "2", ip]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=8,
                check=False,
            )
            output = proc.stdout or proc.stderr
            success = proc.returncode == 0
            rtt = None
            if success:
                rtt = _extract_rtt(output)
            return {"success": success, "rtt": rtt, "output": output.strip()[:300]}
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return {"success": False, "rtt": None, "output": "ping unavailable"}

    @staticmethod
    def _traceroute(host: str) -> list[dict]:
        system = platform.system().lower()
        if system == "windows":
            return []  # tracert output parsing is platform-specific.
        try:
            proc = subprocess.run(
                ["traceroute", "-m", "10", "-w", "1", host],
                capture_output=True, text=True, timeout=20, check=False,
            )
            hops: list[dict] = []
            for line in (proc.stdout or "").splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                hops.append({"hop": stripped[:120]})
            return hops[:30]
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return []

    def _probe_ports(self, ip: str, ports: list[int]) -> list[tuple[int, str]]:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        found: list[tuple[int, str]] = []

        def probe(port: int) -> tuple[int, str] | None:
            try:
                with socket.create_connection((ip, port), timeout=3):
                    service = COMMON_SERVICES.get(port, "unknown")
                    return port, service
            except (OSError, socket.timeout):
                return None

        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = [pool.submit(probe, p) for p in ports]
            for future in as_completed(futures):
                res = future.result()
                if res:
                    found.append(res)
        return sorted(found, key=lambda x: x[0])

    @staticmethod
    def _grab_banner(ip: str, port: int) -> str | None:
        try:
            with socket.create_connection((ip, port), timeout=4) as sock:
                sock.settimeout(4)
                sock.sendall(b"\r\n")
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(1024)
                if data:
                    try:
                        return data.decode("utf-8", errors="replace").strip()
                    except Exception:  # noqa: BLE001
                        return data.hex()[:100]
        except (OSError, socket.timeout):
            return None
        return None

    def _run_nmap(self, ip: str, ports: list[int]) -> dict | None:
        if not self.config.nmap_enabled:
            self.log_info("Nmap disabled by configuration")
            return None
        ports_str = self._parse_ports(self.config.port_range)
        if not ports_str:
            ports_str = ports
        port_arg = ",".join(str(p) for p in ports_str)
        cmd = [
            self.config.nmap_binary, "-sV", "-sS",
            "-T", self.config.scan_speed, "-p", port_arg, ip,
        ]
        try:
            import nmap
        except ImportError:
            self.log_warn("python-nmap not installed; skipping Nmap scan")
            return None
        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=ip, arguments=f"-sV -T {self.config.scan_speed} -p {port_arg}")
        except Exception as exc:  # noqa: BLE001
            self.log_warn("Nmap scan failed: %s", exc)
            return {"error": str(exc)}

        results = {}
        for host in scanner.all_hosts():
            results[host] = scanner[host].all_protocols()
        return {"command": cmd, "results": results} if results else {"note": "no open ports"}
