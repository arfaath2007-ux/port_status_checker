#!/usr/bin/env python3
"""
Port Status Checker
-------------------
A Python utility that checks whether a specific TCP port on a target host
is OPEN, CLOSED, or FILTERED (timed out).

Networking Concepts:
- TCP Handshake: A connection attempt sends a SYN packet.
  - If a service is listening: The host replies with SYN-ACK -> Port is OPEN.
  - If no service is listening (and no stealth firewall): The host sends RST -> Port is CLOSED.
  - If a firewall drops packets or host is unreachable: No response -> Port is FILTERED / TIMED OUT.
"""

import sys
import socket
import argparse
import time
from typing import Tuple, Optional


COMMON_PORTS = {
    20: "FTP (Data)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP (Submission)",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP Alt / Dev Server",
    8080: "HTTP Proxy / Dev Server",
    8443: "HTTPS Alt",
    27017: "MongoDB",
}


def get_service_name(port: int) -> str:
    """Retrieve known service name for a given port."""
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except (OSError, socket.error):
        return "Unknown Service"


def check_port(host: str, port: int, timeout: float = 2.0) -> Tuple[str, str, Optional[float]]:
    """
    Checks the status of a specific TCP port on a host.

    Returns:
        (status, explanation, elapsed_time_ms)
        status: "OPEN", "CLOSED", "FILTERED", or "ERROR"
    """
    # 1. Resolve host to ensure it exists
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        return "ERROR", f"Could not resolve host '{host}': {e}", None

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    t0 = time.perf_counter()
    try:
        sock.connect((ip, port))
        t1 = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000
        return "OPEN", "Connection accepted (SYN-ACK received). A service is actively listening on this port.", elapsed_ms

    except ConnectionRefusedError:
        t1 = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000
        return "CLOSED", "Connection actively refused (RST received). Target machine is online, but no service is listening.", elapsed_ms

    except (TimeoutError, socket.timeout):
        t1 = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000
        return "FILTERED", f"Connection timed out after {timeout:.1f}s. Packets were likely dropped by a firewall or stealth mode.", elapsed_ms

    except OSError as e:
        t1 = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000
        # Common Winsock & POSIX errors
        err = getattr(e, "winerror", getattr(e, "errno", None))
        if err in (10061, 111):
            return "CLOSED", "Connection refused. Target host is up, but no service is listening.", elapsed_ms
        elif err in (10060, 110):
            return "FILTERED", f"Connection timed out after {timeout:.1f}s.", elapsed_ms
        elif err in (10051, 101):
            return "ERROR", "Network is unreachable.", elapsed_ms
        elif err in (10065, 113):
            return "ERROR", "Host is unreachable.", elapsed_ms
        else:
            return "CLOSED", f"Could not connect: {e}", elapsed_ms

    except Exception as e:
        return "ERROR", f"An unexpected error occurred: {e}", None

    finally:
        sock.close()


def prompt_user_input() -> Tuple[str, int, float]:
    """Interactively prompts user for target host, port, and timeout."""
    print("=" * 60)
    print("           PORT STATUS CHECKER (Interactive Mode)")
    print("=" * 60)

    # Host input
    host_input = input("Enter target host/IP [Default: 127.0.0.1]: ").strip()
    host = host_input if host_input else "127.0.0.1"

    # Port input with validation
    while True:
        port_input = input("Enter port number (1-65535): ").strip()
        if not port_input:
            print("Port number is required.")
            continue
        try:
            port = int(port_input)
            if 1 <= port <= 65535:
                break
            else:
                print("Port must be between 1 and 65535.")
        except ValueError:
            print("Invalid input! Please enter an integer port number.")

    # Timeout input
    timeout_input = input("Enter timeout in seconds [Default: 2.0]: ").strip()
    if timeout_input:
        try:
            timeout = float(timeout_input)
            if timeout <= 0:
                timeout = 2.0
        except ValueError:
            timeout = 2.0
    else:
        timeout = 2.0

    return host, port, timeout


def display_results(host: str, port: int, status: str, explanation: str, elapsed_ms: Optional[float]):
    """Pretty prints the scan result."""
    service = get_service_name(port)

    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror:
        resolved_ip = "Unknown"

    print("\n" + "-" * 60)
    print("                   PORT SCAN RESULTS")
    print("-" * 60)
    print(f"Target Host    : {host} ({resolved_ip})")
    print(f"Target Port    : {port} ({service})")

    if status == "OPEN":
        status_label = "[+] OPEN"
    elif status == "CLOSED":
        status_label = "[-] CLOSED"
    elif status == "FILTERED":
        status_label = "[?] FILTERED (TIMED OUT)"
    else:
        status_label = "[!] ERROR"

    print(f"Port Status    : {status_label}")
    if elapsed_ms is not None:
        print(f"Response Time  : {elapsed_ms:.2f} ms")
    print(f"Details        : {explanation}")
    print("-" * 60)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Check whether a specific TCP port on a target system is open or closed."
    )
    parser.add_argument(
        "-H", "--host",
        type=str,
        default=None,
        help="Target hostname or IP address (e.g. 127.0.0.1, scanme.nmap.org). Default: 127.0.0.1",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        help="Port number to check (1-65535)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=2.0,
        help="Connection timeout in seconds (default: 2.0)",
    )

    args = parser.parse_args()

    # If port is not provided via CLI arguments, switch to interactive mode
    if args.port is None:
        host, port, timeout = prompt_user_input()
    else:
        host = args.host if args.host else "127.0.0.1"
        port = args.port
        timeout = args.timeout

        if not (1 <= port <= 65535):
            print(f"Error: Port {port} is out of valid range (1-65535).", file=sys.stderr)
            sys.exit(1)

    print(f"\n[*] Probing {host}:{port} with timeout {timeout:.1f}s...")
    status, explanation, elapsed_ms = check_port(host, port, timeout)
    display_results(host, port, status, explanation, elapsed_ms)


if __name__ == "__main__":
    main()
