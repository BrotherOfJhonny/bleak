"""RadioRecon V7 — Smart Adapter Manager.

Detects all BT interfaces, classifies capabilities, and allocates
the best adapter for each task automatically.

Adapter hierarchy:
  ESP32-S3 (NimBLE): BLE spam, MAC cloning, beacon, HID injection, scan
  ESP32-C3 (NimBLE): BLE spam, scan, sniff (less RAM than S3)
  HCI (BlueZ):       Discovery (bleak), GATT enum, vuln scan, Classic BT

Task allocation logic:
  - BLE Spam → ESP32 (any) — HCI cannot do this reliably
  - BLE Scan → ESP32-C3 preferred (leaves S3 free for attacks)
  - Discovery → HCI (bleak works best with BlueZ)
  - GATT Enum → HCI (bleak connects via BlueZ)
  - Exploits → HCI for BLE, ESP32-S3 for HID injection
  - Sniffer → HCI (btmon) + ESP32-C3 (parallel scan)
  - MAC Clone → ESP32-S3 only (needs PSRAM for address table)
"""
from __future__ import annotations
import asyncio
import logging
import subprocess
import time
import threading
import re
import os
import glob
import json

logger = logging.getLogger("radiorecon.ble_mgr")

_ble_lock = threading.Lock()


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


# ═══════════════════════════════════════════════════════════
# ADAPTER TYPES & CAPABILITIES
# ═══════════════════════════════════════════════════════════

CAPABILITIES = {
    "esp32_s3": {
        "ble_spam": True, "ble_scan": True, "ble_sniff": True,
        "mac_clone": True, "hid_inject": True, "beacon": True,
        "custom_adv": True, "karma": True,
        "gatt_enum": False, "classic_bt": False,
        "discovery_bleak": False, "vuln_scan": False,
        "priority": 2, "label": "ESP32-S3 (NimBLE)",
        "note": "Heavy tasks: HID inject, MAC clone, large payload attacks",
    },
    "esp32_c3": {
        "ble_spam": True, "ble_scan": True, "ble_sniff": True,
        "mac_clone": False, "hid_inject": False, "beacon": True,
        "custom_adv": True, "karma": True,
        "gatt_enum": False, "classic_bt": False,
        "discovery_bleak": False, "vuln_scan": False,
        "priority": 1, "label": "ESP32-C3 (NimBLE)",
        "note": "Primary BLE adapter: spam, scan, karma, beacon",
    },
    "hci_usb": {
        "ble_spam": False, "ble_scan": False, "ble_sniff": True,
        "mac_clone": False, "hid_inject": False, "beacon": False,
        "custom_adv": False, "karma": False,
        "gatt_enum": True, "classic_bt": True,
        "discovery_bleak": True, "vuln_scan": True,
        "priority": 3, "label": "HCI USB (BlueZ)",
        "note": "BlueZ only: discovery, GATT enum, vuln scan, Classic BT",
    },
}

# Task → required capability mapping
TASK_CAPABILITY = {
    "ble_spam": "ble_spam",       # → ESP32-C3 (priority 1)
    "ble_scan": "ble_scan",       # → ESP32-C3 (priority 1)
    "karma": "karma",             # → ESP32-C3 (priority 1)
    "beacon": "beacon",           # → ESP32-C3 (priority 1)
    "custom_adv": "custom_adv",   # → ESP32-C3 (priority 1)
    "hid_inject": "hid_inject",   # → ESP32-S3 only (priority 2)
    "mac_clone": "mac_clone",     # → ESP32-S3 only (priority 2)
    "discovery": "discovery_bleak",  # → hci0 (priority 3)
    "gatt_enum": "gatt_enum",       # → hci0 (priority 3)
    "vuln_scan": "vuln_scan",       # → hci0 (priority 3)
    "classic_bt": "classic_bt",     # → hci0 (priority 3)
    "sniffer": "ble_sniff",         # → hci0 btmon (priority 3)
}


# ═══════════════════════════════════════════════════════════
# ADAPTER DETECTION
# ═══════════════════════════════════════════════════════════

def _identify_esp32(port: str) -> dict:
    """Identify ESP32 type from port name (non-blocking).
    Full probe happens only on explicit connect via /api/esp32/connect.
    """
    # Classify by port name — fast, no serial I/O
    if "ttyACM" in port:
        etype = "esp32_c3"  # C3 uses native USB CDC → ttyACM
    else:
        etype = "esp32_s3"  # S3 with FTDI → ttyUSB

    return {
        "port": port, "type": etype,
        "firmware": "not probed (use Connect to identify)",
        "connected": False, "allocated_to": None,
        "capabilities": CAPABILITIES[etype],
        "label": CAPABILITIES[etype]["label"],
    }


def detect_adapters() -> dict:
    """Detect all Bluetooth adapters with capabilities classification."""
    result = {"hci": [], "esp32": [], "total": 0, "best_for": {}}

    # ── HCI adapters ──
    try:
        r = subprocess.run(["hciconfig", "-a"], capture_output=True, text=True, timeout=5)
        for m in re.finditer(
            r"(hci\d+):\s+Type:\s+(\S+)\s+Bus:\s+(\S+).*?BD Address:\s+([0-9A-F:]{17})(.*?)(?=hci\d+:|$)",
            r.stdout, re.DOTALL | re.IGNORECASE
        ):
            name, bus, mac, info = m.group(1), m.group(3), m.group(4), m.group(5)
            result["hci"].append({
                "name": name, "bus": bus, "mac": mac,
                "up": "UP RUNNING" in info,
                "type": "hci_usb",
                "capabilities": CAPABILITIES["hci_usb"],
                "label": f"{name} ({bus} {mac[:8]}..)",
                "allocated_to": None,
            })
    except Exception:
        try:
            iface = active_hci()
            r = subprocess.run(["hciconfig", iface], capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                result["hci"].append({
                    "name": iface, "bus": "USB", "mac": "?", "up": "UP" in r.stdout,
                    "type": "hci_usb", "capabilities": CAPABILITIES["hci_usb"],
                    "label": iface + " (USB)", "allocated_to": None,
                })
        except Exception:
            pass

    # ── ESP32 serial ports ──
    # Detect JTAG ports to exclude/warn about
    _jtag_ports = set()
    try:
        import serial.tools.list_ports as _slp
        for _sp in _slp.comports():
            if _sp.vid == 0x303A and _sp.pid == 0x1001:
                _jtag_ports.add(_sp.device)
    except Exception:
        pass

    for pattern in ["/dev/ttyUSB*", "/dev/ttyACM*"]:
        for port in sorted(glob.glob(pattern)):
            if port in _jtag_ports:
                # JTAG debug port — show warning but skip for BLE operations
                result["esp32"].append({
                    "port": port, "type": "jtag_debug", "firmware": "JTAG (not serial)",
                    "connected": False, "allocated_to": None,
                    "jtag_warning": True,
                    "capabilities": {k: False for k in CAPABILITIES["esp32_c3"]},
                    "label": f"⚠ JTAG Debug ({port}) — não usar para BLE",
                })
                continue
            info = _identify_esp32(port)
            if info:
                result["esp32"].append(info)
            else:
                etype = "esp32_c3" if "ttyACM" in port else "esp32_s3"
                result["esp32"].append({
                    "port": port, "type": etype, "firmware": "not probed",
                    "connected": False, "allocated_to": None,
                    "capabilities": CAPABILITIES[etype],
                    "label": CAPABILITIES[etype]["label"] + f" ({port})",
                })

    result["total"] = len(result["hci"]) + len(result["esp32"])

    # ── Best adapter for each task ──
    all_adapters = []
    for h in result["hci"]:
        all_adapters.append({"id": h["name"], "type": h["type"], "caps": h.get("capabilities", {})})
    for e in result["esp32"]:
        all_adapters.append({"id": e["port"], "type": e.get("type", ""), "caps": e.get("capabilities", {})})

    for task, cap in TASK_CAPABILITY.items():
        best = None
        best_priority = 999
        for a in all_adapters:
            if a["caps"].get(cap):
                p = a["caps"].get("priority", 99)
                if p < best_priority:
                    best = a["id"]
                    best_priority = p
        result["best_for"][task] = best

    return result


def get_best_adapter(task: str) -> str | None:
    """Get the best adapter for a specific task."""
    adapters = detect_adapters()
    return adapters["best_for"].get(task)


def get_available_adapter(exclude: str = None) -> str | None:
    """Get first available HCI adapter."""
    adapters = detect_adapters()
    for a in adapters["hci"]:
        if a["name"] != exclude:
            return a["name"]
    if adapters["hci"]:
        return adapters["hci"][0]["name"]
    return None


def get_esp32_for_task(task: str) -> str | None:
    """Get the best ESP32 port for a task."""
    adapters = detect_adapters()
    cap_needed = TASK_CAPABILITY.get(task, "")

    # Sort ESP32s by priority (S3 first for heavy tasks, C3 for light)
    candidates = []
    for e in adapters["esp32"]:
        if e.get("capabilities", {}).get(cap_needed):
            p = e.get("capabilities", {}).get("priority", 99)
            candidates.append((p, e["port"]))

    candidates.sort()
    return candidates[0][1] if candidates else None


def ensure_adapter_up(adapter: str = None) -> bool:
    try:
        adapter = adapter or active_hci()
        subprocess.run(["hciconfig", adapter, "up"], capture_output=True, timeout=3)
        return True
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════
# BLE OPERATIONS (unchanged from V6)
# ═══════════════════════════════════════════════════════════

def _run_ble_async(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        loop.close()


def reset_adapter(adapter: str = None) -> bool:
    try:
        adapter = adapter or active_hci()
        subprocess.run(["bluetoothctl", "scan", "off"],
                       capture_output=True, timeout=3, input=b"\n")
        time.sleep(0.2)
        subprocess.run(["hciconfig", adapter, "down"], capture_output=True, timeout=3)
        time.sleep(0.3)
        subprocess.run(["hciconfig", adapter, "up"], capture_output=True, timeout=3)
        time.sleep(0.5)
        return True
    except Exception as e:
        logger.warning("Adapter reset failed: %s", e)
        return False


def remove_device_cache(mac: str):
    try:
        subprocess.run(["bluetoothctl", "remove", mac],
                       capture_output=True, timeout=3, input=b"yes\n")
    except Exception:
        pass


def prepare_and_run(mac: str, async_fn, **kwargs) -> dict:
    """Run a BLE exploit function safely.
    
    IMPORTANT: does NOT reset adapter (hciconfig down/up) — that kills
    ALL active BLE connections and causes 'Device disconnected' errors.
    Only stops any active scan to free the adapter for connection.
    """
    acquired = _ble_lock.acquire(timeout=10)
    if not acquired:
        return {"status": "BUSY", "evidence": "Another BLE operation in progress.", "mac": mac}
    try:
        # Stop scan (non-destructive) — does NOT kill existing connections
        try:
            subprocess.run(["bluetoothctl", "scan", "off"], capture_output=True, timeout=3)
        except Exception:
            pass
        time.sleep(0.3)
        # Check adapter is up without resetting
        try:
            r = subprocess.run(["hciconfig", active_hci()], capture_output=True, text=True, timeout=3)
            if "DOWN" in r.stdout:
                subprocess.run(["hciconfig", active_hci(), "up"], capture_output=True, timeout=5)
                time.sleep(1)
        except Exception:
            pass
        return _run_ble_async(async_fn(mac, **kwargs))
    except Exception as e:
        return {"status": "ERROR", "evidence": f"BLE operation failed: {e}", "mac": mac}
    finally:
        _ble_lock.release()


def run_passive_ble(async_fn, mac: str, **kwargs) -> dict:
    acquired = _ble_lock.acquire(timeout=10)
    if not acquired:
        return {"status": "BUSY", "evidence": "BLE busy.", "mac": mac}
    try:
        return _run_ble_async(async_fn(mac, **kwargs))
    except Exception as e:
        return {"status": "ERROR", "evidence": str(e), "mac": mac}
    finally:
        _ble_lock.release()
