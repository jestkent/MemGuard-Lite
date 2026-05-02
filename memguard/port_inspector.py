"""Network port inspection module.

Collects listening ports and active network connections,
scoring them for security risk and linking to processes.
"""

from __future__ import annotations

import concurrent.futures
import logging
import socket
from typing import TypedDict

import psutil

logger = logging.getLogger(__name__)

# Common insecure ports and protocols
_INSECURE_PORTS: dict[int, str] = {
    21: "FTP (unencrypted file transfer)",
    23: "Telnet (unencrypted remote shell)",
    80: "HTTP (unencrypted web)",
    143: "IMAP (unencrypted email)",
    110: "POP3 (unencrypted email)",
    25: "SMTP (unencrypted email)",
    53: "DNS (can be exploited)",
}

_EXPOSED_PORTS: dict[int, str] = {
    3306: "MySQL (database)",
    5432: "PostgreSQL (database)",
    6379: "Redis (cache, no auth by default)",
    27017: "MongoDB (database)",
    9200: "Elasticsearch (search engine)",
    8080: "HTTP Alt (often development)",
    8000: "HTTP Alt (often development)",
    8888: "HTTP Alt (often Jupyter/dev)",
}

_EPHEMERAL_PORT_MIN: int = 49152


class PortRecord(TypedDict):
    """Network port record with security scoring."""

    port: int
    protocol: str
    state: str
    local_addr: str
    remote_addr: str
    pid: int | None
    process_name: str
    risk_level: str
    risk_score: int
    triggered_rules: list[str]


def _assess_port_risk(port: int, state: str, local_addr: str = "") -> tuple[str, int, list[str]]:
    """Score a port for security risk.

    Returns:
        (risk_level, risk_score, triggered_rules)
    """
    score = 0
    rules: list[str] = []

    if port in _INSECURE_PORTS:
        score += 30
        rules.append(f"Insecure protocol: {_INSECURE_PORTS[port]}")
    elif port in _EXPOSED_PORTS:
        score += 20
        rules.append(f"Exposed service: {_EXPOSED_PORTS[port]}")

    if port in {4444, 5555, 6666, 7777, 8888, 9999}:
        score += 15
        rules.append("Common backdoor/exploit port")

    if state in {"LISTEN", "LISTENING"}:
        score += 5
        rules.append("Port listening for incoming connections")

    if port >= _EPHEMERAL_PORT_MIN and port not in _EXPOSED_PORTS and port not in {4444, 5555, 6666, 7777, 8888, 9999}:
        score += 5
        rules.append("Ephemeral port range (>= 49152)")

    if local_addr.startswith("127.0.0.1"):
        score -= 10
        rules.append("Localhost only (reduced risk)")

    if score >= 35:
        risk_level = "HIGH"
    elif score >= 20:
        risk_level = "MEDIUM"
    elif score >= 10:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    return risk_level, max(0, score), rules


def collect_listening_ports() -> list[PortRecord]:
    """Collect all listening ports and active connections.
    
    Returns:
        List of PortRecord dicts sorted by risk score descending.
    """
    ports: list[PortRecord] = []
    port_to_pid: dict[int, int] = {}
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(psutil.net_connections, "inet")
            try:
                connections = future.result(timeout=8)
            except concurrent.futures.TimeoutError:
                logger.warning("net_connections timed out - skipping port scan")
                return ports
    except (psutil.AccessDenied, OSError):
        logger.warning("Could not enumerate network connections (may require admin)")
        return ports
    
    # Build a map of ports to PIDs
    for conn in connections:
        if conn.laddr and conn.laddr.port and conn.pid:
            port_to_pid[conn.laddr.port] = conn.pid
    
    # Collect unique listening ports
    seen_ports: set[tuple[int, str]] = set()
    
    for conn in connections:
        if not conn.laddr or not conn.laddr.port:
            continue
        
        port = conn.laddr.port
        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        state = str(conn.status).upper() if conn.status else "UNKNOWN"
        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        pid = conn.pid
        
        port_key = (port, protocol)
        if port_key in seen_ports:
            continue
        seen_ports.add(port_key)
        
        # Get process name
        process_name = "N/A"
        if pid:
            try:
                proc = psutil.Process(pid)
                process_name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = f"PID {pid} (unknown)"
        
        risk_level, risk_score, triggered_rules = _assess_port_risk(port, state, local_addr)
        
        ports.append(
            {
                "port": port,
                "protocol": protocol,
                "state": state,
                "local_addr": local_addr,
                "remote_addr": remote_addr,
                "pid": pid,
                "process_name": process_name,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "triggered_rules": triggered_rules,
            }
        )
    
    # Sort by risk score descending, then by port number
    ports.sort(key=lambda p: (p["risk_score"], p["port"]), reverse=True)
    logger.info("Collected %d unique listening ports", len(ports))
    return ports
