# Port Status Checker

A lightweight, zero-dependency Python tool to check whether a specific TCP port on a system is **OPEN**, **CLOSED**, or **FILTERED (TIMED OUT)**.

---

## 🌐 How Networking & Port Status Works

When computers communicate over TCP/IP:
- **Port**: A logical number (from `1` to `65535`) identifying a specific service/application running on a computer (e.g., port 80 for web servers, port 22 for SSH).
- **TCP Three-Way Handshake**:
  1. **SYN**: The client sends a synchronize packet to request a connection.
  2. **SYN-ACK / RST**:
     - **OPEN**: If a service is actively listening, it replies with `SYN-ACK`. The connection succeeds.
     - **CLOSED**: If the target host is up but no service is listening on that port, it sends an `RST` (Reset) packet, immediately terminating the connection.
     - **FILTERED / TIMEOUT**: If a firewall (or security group) silently drops the packet, or the host is unreachable, no response arrives and the request times out.

---

## 🚀 Usage

### 1. Interactive Mode
Run the script without arguments. It will guide you with prompts:
```bash
py port_checker.py
```
**Example prompt**:
```text
Enter target host/IP [Default: 127.0.0.1]: 127.0.0.1
Enter port number (1-65535): 8080
Enter timeout in seconds [Default: 2.0]: 2
```

### 2. Command-Line Arguments Mode
You can specify the host, port, and timeout directly via flags:
```bash
# Check port 80 on a local service
py port_checker.py -p 80

# Check port 443 on a remote host
py port_checker.py -H google.com -p 443

# Check port 22 with a custom 1.5s timeout
py port_checker.py -H scanme.nmap.org -p 22 -t 1.5
```

---

## 🧪 Running Tests

Run the included automated unit tests:
```bash
py test_port_checker.py
```
