"""RadioRecon Opus V1 — Vulnerability Checks.

The catalog intentionally contains more checks than the local scanner can prove
from passive discovery/GATT enumeration alone. Only checks with real local
evidence should emit VULNERABLE findings.
"""
from __future__ import annotations

CHECKS_CATALOG = {
    "AV-001": {"name": "Static Key Reuse", "severity": "HIGH", "category": "anti-replay", "description": "Device uses static encryption keys that don't rotate between sessions.", "cve": None},
    "AV-002": {"name": "No Replay Protection", "severity": "HIGH", "category": "anti-replay", "description": "BLE commands can be replayed without rejection.", "cve": None},
    "AV-003": {"name": "Predictable Sequence Numbers", "severity": "MEDIUM", "category": "anti-replay", "description": "Sequence numbers follow predictable patterns.", "cve": None},
    "AV-004": {"name": "Weak Nonce Generation", "severity": "HIGH", "category": "anti-replay", "description": "Nonces are generated with insufficient entropy.", "cve": None},
    "AV-005": {"name": "Missing Freshness Tokens", "severity": "MEDIUM", "category": "anti-replay", "description": "Authentication lacks freshness/challenge-response.", "cve": None},
    "AV-006": {"name": "Rolling Code Sync Vulnerability", "severity": "HIGH", "category": "anti-replay", "description": "Rolling code can be desynchronized allowing replay.", "cve": None},
    "AV-007": {"name": "Counter Overflow Handling", "severity": "MEDIUM", "category": "anti-replay", "description": "Counter overflow not handled, allowing reset attacks.", "cve": None},
    "AV-008": {"name": "Timestamp Validation Missing", "severity": "MEDIUM", "category": "anti-replay", "description": "No timestamp validation on BLE commands.", "cve": None},
    "AV-009": {"name": "Session Token Reuse", "severity": "HIGH", "category": "anti-replay", "description": "Session tokens can be reused across sessions.", "cve": None},
    "AV-010": {"name": "Challenge-Response Bypass", "severity": "CRITICAL", "category": "anti-replay", "description": "Challenge-response authentication can be bypassed.", "cve": None},
    "AV-011": {"name": "IV Reuse in Encryption", "severity": "HIGH", "category": "anti-replay", "description": "Initialization vectors are reused in encryption.", "cve": None},
    "AV-012": {"name": "Weak MAC Algorithm", "severity": "MEDIUM", "category": "anti-replay", "description": "Message authentication uses weak algorithm.", "cve": None},
    "BLE-001": {"name": "Pairing Mode: Just Works", "severity": "HIGH", "category": "ble-surface", "description": "Device uses Just Works pairing (no MITM protection).", "cve": None},
    "BLE-002": {"name": "No Encryption on Characteristics", "severity": "HIGH", "category": "ble-surface", "description": "Sensitive characteristics lack encryption requirement.", "cve": None},
    "BLE-003": {"name": "Writable Characteristics Exposed", "severity": "MEDIUM", "category": "ble-surface", "description": "Writable characteristics exposed without authentication.", "cve": None},
    "BLE-004": {"name": "Default/Weak Auth Key", "severity": "CRITICAL", "category": "ble-surface", "description": "Device uses default or weak authentication key.", "cve": None},
    "BLE-005": {"name": "Excessive GATT Exposure", "severity": "MEDIUM", "category": "ble-surface", "description": "Device exposes more GATT services than necessary.", "cve": None},
    "BLE-006": {"name": "No Bonding Required", "severity": "MEDIUM", "category": "ble-surface", "description": "Device allows connections without bonding.", "cve": None},
    "BLE-007": {"name": "Advertising Data Leakage", "severity": "LOW", "category": "ble-surface", "description": "Advertising packets leak sensitive information.", "cve": None},
    "BLE-008": {"name": "MAC Address Not Randomized", "severity": "LOW", "category": "ble-surface", "description": "Device uses static public MAC address (trackable).", "cve": None},
    "BLE-009": {"name": "Legacy Pairing Support", "severity": "MEDIUM", "category": "ble-surface", "description": "Device supports legacy (insecure) pairing.", "cve": None},
    "BLE-010": {"name": "No Secure Connections", "severity": "HIGH", "category": "ble-surface", "description": "BLE Secure Connections (LE SC) not enforced.", "cve": None},
    "BLE-011": {"name": "OOB Data Not Used", "severity": "LOW", "category": "ble-surface", "description": "Out-of-Band pairing data not utilized.", "cve": None},
    "BLE-012": {"name": "DFU Service Exposed", "severity": "CRITICAL", "category": "ble-surface", "description": "Device Firmware Update service accessible without auth.", "cve": None},
    "BLE-013": {"name": "Debug Service Active", "severity": "HIGH", "category": "ble-surface", "description": "Debug/diagnostic services left active in production.", "cve": None},
    "BLE-014": {"name": "No Connection Parameter Limits", "severity": "LOW", "category": "ble-surface", "description": "No limits on connection parameter update requests.", "cve": None},
    "BLE-015": {"name": "Firmware Version Disclosure", "severity": "LOW", "category": "ble-surface", "description": "Firmware version exposed in GATT.", "cve": None},
    "BLE-016": {"name": "Serial Number Exposure", "severity": "LOW", "category": "ble-surface", "description": "Device serial number readable without authentication.", "cve": None},
    "BLE-017": {"name": "Unprotected Notify/Indicate", "severity": "MEDIUM", "category": "ble-surface", "description": "Notification/indication on sensitive chars without encryption.", "cve": None},
    "CB-BBN-001": {"name": "BlueBorne — Linux RCE", "severity": "CRITICAL", "category": "classic-bt", "description": "Linux kernel RCE via Bluetooth L2CAP.", "cve": "CVE-2017-1000251"},
    "CB-BBN-002": {"name": "BlueBorne — Android RCE", "severity": "CRITICAL", "category": "classic-bt", "description": "Android Bluetooth stack RCE.", "cve": "CVE-2017-0785"},
    "CB-BBN-003": {"name": "BlueBorne — Info Leak", "severity": "HIGH", "category": "classic-bt", "description": "Bluetooth stack information leak.", "cve": "CVE-2017-0781"},
    "CB-BIA-001": {"name": "BIAS — Role Switch", "severity": "HIGH", "category": "classic-bt", "description": "Bluetooth Impersonation Attack on Secure Simple Pairing.", "cve": "CVE-2020-10135"},
    "CB-BIA-002": {"name": "BIAS — Legacy Auth Bypass", "severity": "HIGH", "category": "classic-bt", "description": "Legacy authentication bypass via role switch.", "cve": None},
    "CB-DOS-001": {"name": "SweynTooth — Truncated L2CAP", "severity": "HIGH", "category": "dos", "description": "Truncated L2CAP causing DoS on BLE SoCs.", "cve": "CVE-2019-19195"},
    "CB-DOS-002": {"name": "Magic Keyboard DoS", "severity": "MEDIUM", "category": "dos", "description": "Apple Magic Keyboard Bluetooth DoS.", "cve": None},
    "CB-KNB-001": {"name": "KNOB — Entropy Downgrade", "severity": "HIGH", "category": "classic-bt", "description": "Key Negotiation of Bluetooth — entropy reduction to 1 byte.", "cve": "CVE-2019-9506"},
    "CB-MIT-001": {"name": "MITM — Pairing Vulnerable", "severity": "HIGH", "category": "mitm", "description": "Pairing method susceptible to MITM interception.", "cve": None},
    "CB-MIT-002": {"name": "Address Spoofing Possible", "severity": "HIGH", "category": "mitm", "description": "Device does not validate source address authenticity.", "cve": None},
    "CB-PAR-001": {"name": "Passkey Entry Brute-Force", "severity": "MEDIUM", "category": "pairing", "description": "6-digit passkey can be brute-forced.", "cve": None},
    "CB-PAR-002": {"name": "No LESC Support", "severity": "MEDIUM", "category": "pairing", "description": "LE Secure Connections not supported.", "cve": None},
    "CB-PLT-001": {"name": "iOS BLE Type Confusion", "severity": "HIGH", "category": "platform", "description": "iOS Bluetooth type confusion vulnerability.", "cve": "CVE-2023-45866"},
    "CB-PLT-002": {"name": "Windows BT Driver RCE", "severity": "CRITICAL", "category": "platform", "description": "Windows Bluetooth driver remote code execution.", "cve": "CVE-2023-24871"},
    "CB-RCE-001": {"name": "BLE Stack Buffer Overflow", "severity": "CRITICAL", "category": "rce", "description": "Buffer overflow in BLE stack implementation.", "cve": None},
    "CB-RCE-002": {"name": "GATT Write Overflow", "severity": "CRITICAL", "category": "rce", "description": "Oversized GATT write causes buffer overflow.", "cve": None},
    "DS-HOM-001": {"name": "Smart Lock — Replay Unlock", "severity": "CRITICAL", "category": "smart-home", "description": "Smart lock unlock command can be replayed.", "cve": None},
    "DS-HOM-002": {"name": "Smart Lock — Static Key", "severity": "CRITICAL", "category": "smart-home", "description": "Smart lock uses static encryption key.", "cve": None},
    "DS-HOM-003": {"name": "Smart Bulb — No Auth", "severity": "MEDIUM", "category": "smart-home", "description": "Smart bulb controllable without authentication.", "cve": None},
    "DS-HOM-004": {"name": "Thermostat — Unencrypted", "severity": "MEDIUM", "category": "smart-home", "description": "Smart thermostat communicates without encryption.", "cve": None},
    "DS-HOM-005": {"name": "Hub — Default Credentials", "severity": "HIGH", "category": "smart-home", "description": "Smart home hub uses default BLE credentials.", "cve": None},
    "DS-IOT-001": {"name": "Industrial Sensor — No Auth", "severity": "HIGH", "category": "iot", "description": "Industrial BLE sensor lacks authentication.", "cve": None},
    "DS-IOT-002": {"name": "IoT Gateway — Firmware Leak", "severity": "MEDIUM", "category": "iot", "description": "IoT gateway exposes firmware via BLE DFU.", "cve": None},
    "DS-BLB-001": {"name": "Smart Bulb — Open GATT Control", "severity": "MEDIUM", "category": "smart-bulb", "description": "Smart bulb color/brightness controllable via open GATT.", "cve": None},
    "DS-BLB-002": {"name": "Smart Bulb — No Encryption", "severity": "MEDIUM", "category": "smart-bulb", "description": "Smart bulb commands transmitted without encryption.", "cve": None},
    "DS-BLB-003": {"name": "Smart Bulb — Replay Control", "severity": "HIGH", "category": "smart-bulb", "description": "Smart bulb commands can be replayed from captured traffic.", "cve": None},
    "DS-BLB-004": {"name": "Smart Bulb — Firmware Update Open", "severity": "HIGH", "category": "smart-bulb", "description": "Smart bulb accepts firmware updates without signature verification.", "cve": None},
}

VULN_PROFILES = {
    "pentest-basico": ["BLE-001","BLE-002","BLE-003","BLE-004","BLE-005","BLE-006","BLE-007","BLE-008","BLE-009","BLE-010","BLE-012","BLE-013","CB-MIT-001","CB-PAR-001","CB-PAR-002"],
    "smartwatch": ["BLE-001","BLE-002","BLE-003","BLE-004","BLE-007","BLE-008","BLE-017","AV-001","AV-002","AV-005","AV-009","CB-MIT-001"],
    "veicular": ["AV-001","AV-002","AV-003","AV-006","AV-010","BLE-001","BLE-002","BLE-004","BLE-010","BLE-012","CB-MIT-001","CB-MIT-002","DS-HOM-001","DS-HOM-002"],
    "smart-bulb": ["BLE-001","BLE-002","BLE-003","BLE-006","DS-HOM-003","DS-BLB-001","DS-BLB-002","DS-BLB-003","DS-BLB-004"],
    "iot-completo": list(CHECKS_CATALOG.keys()),
}

CHECK_CAPABILITIES = {
    "BLE-001": {"mode": "active", "implemented": True, "evidence": "BLE connection without user confirmation"},
    "BLE-002": {"mode": "active", "implemented": True, "evidence": "Readable GATT characteristics from unauthenticated enumeration"},
    "BLE-003": {"mode": "active", "implemented": True, "evidence": "Writable GATT characteristics from unauthenticated enumeration"},
    "BLE-005": {"mode": "active", "implemented": True, "evidence": "Service/characteristic count from GATT enumeration"},
    "BLE-006": {"mode": "active", "implemented": True, "evidence": "GATT enumeration completed before bonding"},
    "BLE-007": {"mode": "passive", "implemented": True, "evidence": "Advertising manufacturer/service data"},
    "BLE-008": {"mode": "passive", "implemented": True, "evidence": "Public/static BLE address type"},
    "BLE-012": {"mode": "active", "implemented": True, "evidence": "DFU service UUID exposed in GATT"},
    "BLE-013": {"mode": "active", "implemented": True, "evidence": "Debug/diagnostic service UUID or name exposed in GATT"},
    "BLE-015": {"mode": "active", "implemented": True, "evidence": "Firmware revision characteristic readable"},
    "BLE-016": {"mode": "active", "implemented": True, "evidence": "Serial number characteristic readable"},
    "BLE-017": {"mode": "active", "implemented": True, "evidence": "Notify/indicate characteristic exposed during unauthenticated enumeration"},
}

for _cid, _check in CHECKS_CATALOG.items():
    _cap = CHECK_CAPABILITIES.get(_cid, {"mode": "manual", "implemented": False,
                                         "evidence": "Requires external PoC, packet capture, or product-specific protocol knowledge"})
    _check.setdefault("test_mode", _cap["mode"])
    _check.setdefault("implemented", _cap["implemented"])
    _check.setdefault("evidence_required", _cap["evidence"])


def run_vuln_checks(devices, selected_checks, fingerprints, enum_results=None, progress_cb=None):
    results = []
    total = len(selected_checks) * max(len(devices), 1)
    done = 0
    enum_by_mac = {_norm_mac(e.get("mac")): e for e in (enum_results or [])}
    for check_id in selected_checks:
        check = CHECKS_CATALOG.get(check_id)
        if not check: continue
        for dev in (devices or [{"mac": "N/A", "name": "No devices"}]):
            mac = dev.get("mac", dev.get("address", "N/A"))
            fp = fingerprints.get(mac, {})
            finding = _evaluate_check(check_id, check, dev, fp, enum_by_mac.get(_norm_mac(mac), {}))
            if finding: results.append(finding)
            done += 1
            if progress_cb: progress_cb(done, total, check_id)
    return results

def _norm_mac(mac):
    return str(mac or "").strip().upper()


def _services(dev, fingerprint, enum_result):
    out = []
    for src in (dev.get("services", []), fingerprint.get("services", [])):
        out.extend(str(s) for s in (src or []))
    for svc in enum_result.get("services", []) or []:
        if isinstance(svc, dict):
            out.append(str(svc.get("uuid", "")))
        else:
            out.append(str(svc))
    return [s for s in out if s]


def _chars(enum_result):
    out = []
    for svc in enum_result.get("services", []) or []:
        if not isinstance(svc, dict):
            continue
        for ch in svc.get("characteristics", []) or []:
            if isinstance(ch, dict):
                item = dict(ch)
                item.setdefault("service_uuid", svc.get("uuid", ""))
                out.append(item)
    return out


def _props(ch):
    props = ch.get("properties", [])
    if isinstance(props, str):
        return [p.strip().lower() for p in props.replace(",", " ").split()]
    return [str(p).lower() for p in (props or [])]


def _uuid_has(value, needles):
    value_l = str(value or "").lower()
    return any(n in value_l for n in needles)


def _read_value(ch):
    return ch.get("value_text") or ch.get("value") or ch.get("value_hex") or ch.get("hex") or ""


def _evaluate_check(check_id, check, dev, fingerprint, enum_result=None):
    enum_result = enum_result or {}
    mac = dev.get("mac", dev.get("address", "N/A"))
    name = dev.get("name", "Unknown")
    severity = check["severity"]
    connectable = dev.get("connectable", True)
    triggered = False
    evidence = ""
    evidence_items = []
    services = _services(dev, fingerprint, enum_result)
    chars = _chars(enum_result)
    enum_ok = bool(enum_result.get("services")) and not enum_result.get("error")

    if check_id == "BLE-001":
        pairing = str(fingerprint.get("pairing_method") or dev.get("pairing_method") or "").lower()
        if "just" in pairing and "works" in pairing:
            triggered, evidence = True, "Pairing method explicitly identified as Just Works."
        elif enum_ok and connectable:
            triggered, evidence = True, "Unauthenticated GATT enumeration completed; device allowed connection without prior bond."
    elif check_id == "BLE-002":
        readable = [ch for ch in chars if "read" in _props(ch) and _read_value(ch)]
        if readable:
            evidence_items = [str(ch.get("uuid")) for ch in readable[:6]]
            triggered, evidence = True, "{} readable characteristic(s) exposed without pairing/encryption: {}".format(
                len(readable), ", ".join(evidence_items))
    elif check_id == "BLE-003":
        writable = [ch for ch in chars if "write" in _props(ch) or "write-without-response" in _props(ch)]
        if writable:
            evidence_items = [str(ch.get("uuid")) for ch in writable[:6]]
            triggered, evidence = True, "{} writable characteristic(s) exposed during unauthenticated enumeration: {}".format(
                len(writable), ", ".join(evidence_items))
    elif check_id == "BLE-005":
        svc_count = len(services)
        char_count = len(chars) or int(enum_result.get("chars_count") or 0)
        if svc_count >= 8 or char_count >= 24:
            triggered, evidence = True, "Large GATT surface exposed: {} service(s), {} characteristic(s).".format(
                svc_count, char_count)
    elif check_id == "BLE-006":
        if enum_ok and (chars or services):
            triggered, evidence = True, "Services were enumerated before bonding; no bond was required for discovery."
    elif check_id == "BLE-007":
        adv_data = dev.get("metadata", {}).get("manufacturer_data")
        service_data = dev.get("metadata", {}).get("service_data")
        if adv_data or service_data:
            triggered, evidence = True, "Advertising exposes data fields: manufacturer={} service={}.".format(
                bool(adv_data), bool(service_data))
    elif check_id == "BLE-008":
        if mac != "N/A" and str(dev.get("address_type", "public")).lower() == "public":
            triggered, evidence = True, f"Static MAC: {mac} — device is trackable."
    elif check_id == "BLE-009":
        if fingerprint.get("legacy_pairing") is True or dev.get("legacy_pairing") is True:
            triggered, evidence = True, "Legacy pairing support explicitly identified by fingerprint data."
    elif check_id == "BLE-010":
        if fingerprint.get("secure_pairing") is False and fingerprint.get("secure_pairing_observed") is True:
            triggered, evidence = True, "Fingerprint observed pairing without LE Secure Connections."
    elif check_id == "BLE-012":
        for svc in services:
            if any(d in str(svc).lower() for d in ["1530", "fe59", "8e400001"]):
                triggered, evidence = True, f"DFU service: {svc}"
                break
    elif check_id == "BLE-013":
        debug_terms = ["debug", "diagnostic", "diag", "uart", "shell", "console", "nordic uart"]
        matches = [s for s in services if _uuid_has(s, ["6e400001", "ffe0", "fff0"]) or
                   any(t in str(s).lower() for t in debug_terms)]
        matches.extend(str(ch.get("uuid")) for ch in chars
                       if any(t in str(ch.get("description", "")).lower() for t in debug_terms))
        if matches:
            triggered, evidence = True, "Debug/diagnostic surface exposed: {}".format(", ".join(matches[:6]))
    elif check_id == "BLE-015":
        matches = [ch for ch in chars if _uuid_has(ch.get("uuid"), ["2a26", "2a28"])]
        readable = [ch for ch in matches if "read" in _props(ch)]
        if readable:
            vals = ["{}={}".format(ch.get("uuid"), _read_value(ch)) for ch in readable[:4]]
            triggered, evidence = True, "Firmware/software revision readable: {}".format(", ".join(vals))
    elif check_id == "BLE-016":
        readable = [ch for ch in chars if _uuid_has(ch.get("uuid"), ["2a25"]) and "read" in _props(ch)]
        if readable:
            vals = ["{}={}".format(ch.get("uuid"), _read_value(ch)) for ch in readable[:4]]
            triggered, evidence = True, "Serial number readable: {}".format(", ".join(vals))
    elif check_id == "BLE-017":
        notifying = [ch for ch in chars if "notify" in _props(ch) or "indicate" in _props(ch)]
        if notifying:
            ids = [str(ch.get("uuid")) for ch in notifying[:6]]
            triggered, evidence = True, "{} notify/indicate characteristic(s) exposed before bonding: {}".format(
                len(notifying), ", ".join(ids))

    if triggered:
        return {"check_id": check_id, "name": check["name"], "severity": severity,
                "category": check["category"], "description": check["description"],
                "cve": check.get("cve"), "mac": mac, "device_name": name,
                "evidence": evidence, "status": "VULNERABLE",
                "confidence": "confirmed", "test_mode": check.get("test_mode", "unknown")}
    return None
