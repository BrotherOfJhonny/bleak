"""RadioRecon Opus V1 — BLE GATT Enumeration."""
from __future__ import annotations
import asyncio, logging
logger = logging.getLogger("radiorecon.enum")

KNOWN_SERVICES = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "00001812-0000-1000-8000-00805f9b34fb": "HID",
    "0000fee0-0000-1000-8000-00805f9b34fb": "Mi Band Service",
    "0000fee1-0000-1000-8000-00805f9b34fb": "Mi Band Auth",
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": "Nordic UART",
    "0000fe59-0000-1000-8000-00805f9b34fb": "Nordic DFU",
    # Google Fast Pair (UUID 0xFE2C) — GATT provider: Google LLC
    "0000fe2c-0000-1000-8000-00805f9b34fb": "Fast Pair Service",
}
KNOWN_CHARS = {
    "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
    "00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Rev",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer",
    "00002a37-0000-1000-8000-00805f9b34fb": "Heart Rate Meas",
    # Google Fast Pair characteristics (within 0xFE2C service)
    "fe2c1233-8366-4814-8eb0-01de32100bea": "FP Key-Based Pairing",
    "fe2c1234-8366-4814-8eb0-01de32100bea": "FP Passkey",
    "fe2c1235-8366-4814-8eb0-01de32100bea": "FP Account Key",
    "fe2c1236-8366-4814-8eb0-01de32100bea": "FP Additional Data",
}
UUID_CATALOG = {**KNOWN_SERVICES, **KNOWN_CHARS}

def resolve_uuid(uuid):
    u = uuid.lower()
    if u in UUID_CATALOG: return UUID_CATALOG[u]
    if len(uuid) == 4:
        full = f"0000{u}-0000-1000-8000-00805f9b34fb"
        if full in UUID_CATALOG: return UUID_CATALOG[full]
    return "Unknown"

async def enumerate_device(mac, timeout=30):
    from bleak import BleakClient, BleakScanner
    import subprocess as _esp
    result = {"mac": mac, "services": [], "error": None, "chars_count": 0, "readable_count": 0}

    # For random MACs (locally administered bit set) — verify device is in range first
    try:
        first_byte = int(mac.split(":")[0], 16)
        is_random_mac = bool(first_byte & 0x02)
    except Exception:
        is_random_mac = False

    # Short passive scan to check if device is in range
    # Note: we use a 1.5s scan only — not 3s (too slow for multiple devices)
    try:
        async def _quick_check():
            devices = await BleakScanner.discover(timeout=1.5, return_adv=False)
            macs = [str(d.address).upper() for d in devices]
            return mac.upper() in macs
        in_range = await asyncio.wait_for(_quick_check(), timeout=2.5)
        if not in_range:
            # Device not seen in scan — may be connected/paired, try anyway
            pass
    except Exception:
        pass

    try:
        for _attempt in range(1, 4):
            try:
                async with BleakClient(mac, timeout=timeout) as client:
                    if not client.is_connected:
                        result["error"] = "Failed to connect"
                        continue
                    # Give BlueZ time to complete service discovery
                    await asyncio.sleep(2)

                    for svc in client.services:
                        svc_info = {"uuid": str(svc.uuid),
                                    "description": resolve_uuid(str(svc.uuid)),
                                    "handle": svc.handle, "characteristics": []}
                        for ch in svc.characteristics:
                            result["chars_count"] += 1
                            ci = {"uuid": str(ch.uuid),
                                  "description": resolve_uuid(str(ch.uuid)),
                                  "handle": ch.handle,
                                  "properties": list(ch.properties),
                                  "value": None, "value_hex": None}
                            if "read" in ch.properties:
                                try:
                                    val = await client.read_gatt_char(ch.handle)
                                    ci["value_hex"] = val.hex()
                                    try: ci["value"] = val.decode("utf-8", errors="replace")
                                    except: ci["value"] = val.hex()
                                    result["readable_count"] += 1
                                except Exception as re:
                                    ci["value"] = "Error: " + str(re)[:60]
                            svc_info["characteristics"].append(ci)
                        result["services"].append(svc_info)

                    if result["services"]:
                        break  # success — don't retry

            except Exception as _ae:
                if _attempt < 3:
                    await asyncio.sleep(2)
                else:
                    result["error"] = str(_ae)

    except Exception as e:
        result["error"] = str(e)
    return result

async def enumerate_multiple(macs, timeout=15):
    results = []
    for mac in macs:
        r = await enumerate_device(mac, timeout)
        results.append(r)
    return results

def compute_exposure_score(enum_result):
    if enum_result.get("error"): return 0
    score = 0
    services = enum_result.get("services", [])
    score += min(len(services) * 5, 30)
    writable = 0
    for svc in services:
        for ch in svc.get("characteristics", []):
            props = ch.get("properties", [])
            if "write" in props or "write-without-response" in props: writable += 1
    score += min(writable * 8, 30)
    for svc in services:
        u = svc.get("uuid","").lower()
        if "1530" in u or "fe59" in u: score += 20
    return min(score, 100)
