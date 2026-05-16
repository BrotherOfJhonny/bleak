"""RadioRecon Opus V2 — OBD2 ELM327 Connection Module.

Connects to ELM327 Bluetooth OBD2 adapters for vehicle diagnostics.
Supports PID reading like Torque Pro.
"""
from __future__ import annotations
import socket, time, logging, threading

logger = logging.getLogger("radiorecon.obd2")

# Standard OBD-II PIDs
STANDARD_PIDS = {
    "010C": {"name": "RPM", "unit": "rpm", "formula": "((A*256)+B)/4", "min": 0, "max": 16383},
    "010D": {"name": "Velocidade", "unit": "km/h", "formula": "A", "min": 0, "max": 255},
    "0105": {"name": "Temp. Refrigerante", "unit": "°C", "formula": "A-40", "min": -40, "max": 215},
    "010F": {"name": "Temp. Ar Admissão", "unit": "°C", "formula": "A-40", "min": -40, "max": 215},
    "0111": {"name": "Posição Acelerador", "unit": "%", "formula": "(A*100)/255", "min": 0, "max": 100},
    "012F": {"name": "Nível Combustível", "unit": "%", "formula": "(A*100)/255", "min": 0, "max": 100},
    "0104": {"name": "Carga Motor", "unit": "%", "formula": "(A*100)/255", "min": 0, "max": 100},
    "010B": {"name": "Pressão MAP", "unit": "kPa", "formula": "A", "min": 0, "max": 255},
    "010E": {"name": "Avanço Ignição", "unit": "°", "formula": "(A/2)-64", "min": -64, "max": 63.5},
    "0110": {"name": "Fluxo MAF", "unit": "g/s", "formula": "((A*256)+B)/100", "min": 0, "max": 655.35},
    "0142": {"name": "Tensão Bateria", "unit": "V", "formula": "((A*256)+B)/1000", "min": 0, "max": 65.535},
    "015C": {"name": "Temp. Óleo Motor", "unit": "°C", "formula": "A-40", "min": -40, "max": 210},
    "015E": {"name": "Consumo Comb.", "unit": "L/h", "formula": "((A*256)+B)/20", "min": 0, "max": 3276.75},
    "0146": {"name": "Temp. Ambiente", "unit": "°C", "formula": "A-40", "min": -40, "max": 215},
    "0121": {"name": "Dist. c/ MIL", "unit": "km", "formula": "(A*256)+B", "min": 0, "max": 65535},
    "011F": {"name": "Tempo Motor", "unit": "seg", "formula": "(A*256)+B", "min": 0, "max": 65535},
    "0103": {"name": "Status Sist. Comb.", "unit": "", "formula": "A", "min": 0, "max": 255},
}

# EV-specific PIDs (non-standard, manufacturer-dependent)
EV_PIDS = {
    "2101": {"name": "SOC Bateria HV", "unit": "%", "description": "State of Charge da bateria de alta tensão"},
    "2102": {"name": "Tensão Bateria HV", "unit": "V", "description": "Tensão da bateria de alta tensão"},
    "2103": {"name": "Corrente Bateria HV", "unit": "A", "description": "Corrente da bateria de alta tensão"},
    "2104": {"name": "Temp. Bateria HV", "unit": "°C", "description": "Temperatura da bateria de alta tensão"},
    "2105": {"name": "Potência Motor EV", "unit": "kW", "description": "Potência instantânea do motor elétrico"},
}

# Brazil/LATAM vehicle profiles
VEHICLE_PROFILES_LATAM = {
    "fiat": {
        "name": "Fiat", "country": "Itália/Brasil", "popular_models": ["Strada", "Argo", "Mobi", "Toro", "Pulse", "Fastback"],
        "obd_protocol": "ISO 15765-4 (CAN)", "ble_services": ["Fiat Connect", "Uconnect BLE"],
        "pids": ["010C", "010D", "0105", "010F", "0111", "012F", "0104", "0142"],
        "known_vulns": ["AV-001", "BLE-001", "CB-MIT-001"],
        "attack_surface": ["Uconnect IVI", "Remote Start", "Lock/Unlock BLE"],
        "risk_level": "MEDIUM", "ref": "UNECE WP.29 R155",
    },
    "chevrolet": {
        "name": "Chevrolet/GM", "country": "EUA/Brasil", "popular_models": ["Onix", "Tracker", "S10", "Montana", "Spin"],
        "obd_protocol": "ISO 15765-4 (CAN)", "ble_services": ["myChevrolet BLE", "OnStar"],
        "pids": ["010C", "010D", "0105", "010F", "0111", "012F", "0104", "0142", "015C"],
        "known_vulns": ["AV-001", "AV-002", "BLE-001", "CB-MIT-001"],
        "attack_surface": ["myChevrolet App", "OnStar Remote", "Key Fob Relay"],
        "risk_level": "HIGH", "ref": "UNECE WP.29 R155",
    },
    "volkswagen": {
        "name": "Volkswagen", "country": "Alemanha/Brasil", "popular_models": ["Polo", "T-Cross", "Nivus", "Virtus", "Taos", "Amarok"],
        "obd_protocol": "ISO 15765-4 (CAN)", "ble_services": ["We Connect", "VW Connect BLE"],
        "pids": ["010C", "010D", "0105", "010F", "0111", "012F", "0104", "0142", "015C", "015E"],
        "known_vulns": ["AV-001", "AV-006", "BLE-001", "CB-MIT-002"],
        "attack_surface": ["We Connect App", "IVI Discover", "Digital Key"],
        "risk_level": "HIGH", "ref": "UNECE WP.29 R155",
    },
    "toyota": {
        "name": "Toyota", "country": "Japão/Brasil", "popular_models": ["Corolla Cross", "Hilux", "Yaris", "SW4", "RAV4"],
        "obd_protocol": "ISO 15765-4 (CAN)", "ble_services": ["Toyota Connected", "Smart Key BLE"],
        "pids": ["010C", "010D", "0105", "010F", "0111", "012F", "0104"],
        "known_vulns": ["AV-001", "BLE-001"],
        "attack_surface": ["Smart Key Relay", "Connected Services"],
        "risk_level": "MEDIUM", "ref": "ISO/SAE 21434",
    },
    "hyundai": {
        "name": "Hyundai", "country": "Coreia/Brasil", "popular_models": ["HB20", "Creta", "Tucson", "Santa Fe", "IONIQ 5"],
        "obd_protocol": "ISO 15765-4 (CAN)", "ble_services": ["Bluelink BLE", "Digital Key 2.0"],
        "pids": ["010C", "010D", "0105", "010F", "0111", "012F", "0104", "0142"],
        "known_vulns": ["AV-001", "AV-002", "CB-MIT-001", "BLE-001"],
        "attack_surface": ["Bluelink App", "Digital Key BLE", "Remote Start", "OTA Updates"],
        "risk_level": "HIGH", "ref": "UNECE WP.29 R155",
    },
    "byd": {
        "name": "BYD", "country": "China/Brasil", "popular_models": ["Dolphin", "Yuan Plus", "Seal", "Song Plus", "Han"],
        "obd_protocol": "ISO 15765-4 (CAN)", "ble_services": ["BYD Connect BLE", "NFC Key"],
        "pids": ["010C", "010D", "0105", "0142"],
        "ev_pids": ["2101", "2102", "2103", "2104", "2105"],
        "known_vulns": ["AV-001", "AV-002", "BLE-001", "BLE-004", "CB-MIT-001"],
        "attack_surface": ["BYD App BLE", "NFC Key Relay", "Battery BMS BLE", "OTA Firmware", "Charging CCS/CHAdeMO"],
        "risk_level": "CRITICAL",
        "ev_risks": ["Battery BMS manipulation via CAN", "Charging session hijack", "SOC falsification",
                     "Thermal management bypass", "Regen braking parameter modification"],
        "ref": "UNECE WP.29 R155 / GB/T",
    },
    "gwm": {
        "name": "GWM/Haval", "country": "China/Brasil", "popular_models": ["Haval H6", "Jolion", "ORA 03"],
        "obd_protocol": "ISO 15765-4 (CAN)", "ble_services": ["GWM Connect BLE"],
        "pids": ["010C", "010D", "0105", "0142"],
        "ev_pids": ["2101", "2102", "2104"],
        "known_vulns": ["AV-001", "BLE-001", "BLE-004", "CB-MIT-001"],
        "attack_surface": ["GWM App BLE", "OTA Updates", "Battery BMS"],
        "risk_level": "HIGH",
        "ev_risks": ["BMS data exposure via CAN", "OTA update interception"],
        "ref": "UNECE WP.29 R155",
    },
    "renault": {
        "name": "Renault", "country": "França/Brasil", "popular_models": ["Kwid", "Duster", "Oroch", "Captur"],
        "obd_protocol": "ISO 15765-4 (CAN)", "ble_services": ["MY Renault BLE"],
        "pids": ["010C", "010D", "0105", "010F", "0111", "012F"],
        "known_vulns": ["AV-001", "BLE-001"],
        "attack_surface": ["MY Renault App", "Keyless Entry"],
        "risk_level": "MEDIUM", "ref": "UNECE WP.29 R155",
    },
    "jeep": {
        "name": "Jeep (Stellantis)", "country": "EUA/Brasil", "popular_models": ["Compass", "Renegade", "Commander"],
        "obd_protocol": "ISO 15765-4 (CAN)", "ble_services": ["Uconnect BLE"],
        "pids": ["010C", "010D", "0105", "010F", "0111", "012F", "0104", "0142"],
        "known_vulns": ["AV-001", "AV-006", "BLE-001", "CB-MIT-001"],
        "attack_surface": ["Uconnect IVI", "Remote Start", "Keyless Entry"],
        "risk_level": "HIGH", "ref": "UNECE WP.29 R155",
    },
    "tesla": {
        "name": "Tesla", "country": "EUA", "popular_models": ["Model 3", "Model Y"],
        "obd_protocol": "Proprietário (CAN via OBD adapter)", "ble_services": ["Phone Key BLE", "Summon BLE"],
        "pids": ["010D"],
        "ev_pids": ["2101", "2102", "2103", "2104", "2105"],
        "known_vulns": ["AV-002", "AV-010", "BLE-001", "CB-MIT-001"],
        "attack_surface": ["Phone Key Relay Attack", "BLE Relay via Flipper/Proxmark", "Summon BLE Hijack",
                           "CAN injection via OBD", "Sentry Mode bypass"],
        "risk_level": "CRITICAL",
        "ev_risks": ["Phone Key relay (demonstrated by NCC Group)", "CAN injection via diagnostic port",
                     "Battery SOC falsification", "Autopilot parameter manipulation"],
        "ref": "UNECE WP.29 R155",
    },
}


class ELM327Connection:
    """Bluetooth or serial connection to ELM327 OBD2 adapter."""

    def __init__(self, mac_or_port: str, connection_type: str = "bluetooth"):
        self.address = mac_or_port
        self.connection_type = connection_type
        self._socket = None
        self._connected = False
        self.elm_version = ""
        self.protocol = ""
        self.vin = ""
        self.error = None

    def connect(self) -> bool:
        try:
            if self.connection_type == "bluetooth":
                self._socket = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
                self._socket.settimeout(10)
                self._socket.connect((self.address, 1))  # RFCOMM channel 1
            elif self.connection_type == "tcp":
                host, port = self.address.split(":")
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(10)
                self._socket.connect((host, int(port)))
            else:
                import serial
                self._socket = serial.Serial(self.address, 38400, timeout=5)

            self._connected = True
            # Initialize ELM327
            self._send("ATZ")  # Reset
            time.sleep(1)
            self.elm_version = self._send("ATI")  # Version
            self._send("ATE0")  # Echo off
            self._send("ATL0")  # Linefeed off
            self._send("ATS0")  # Spaces off
            self._send("ATH0")  # Headers off
            self._send("ATSP0")  # Auto protocol
            self.protocol = self._send("ATDPN")  # Get protocol number
            # Try to read VIN
            vin_resp = self._send("0902")
            if vin_resp and "NO DATA" not in vin_resp:
                self.vin = self._parse_vin(vin_resp)
            return True
        except Exception as e:
            self.error = str(e)
            self._connected = False
            logger.error("ELM327 connect error: %s", e)
            return False

    def _send(self, cmd: str) -> str:
        if not self._connected:
            return ""
        try:
            if hasattr(self._socket, 'send'):
                self._socket.send((cmd + "\r").encode())
                time.sleep(0.3)
                data = b""
                while True:
                    try:
                        chunk = self._socket.recv(1024)
                        if not chunk:
                            break
                        data += chunk
                        if b">" in data:
                            break
                    except socket.timeout:
                        break
                return data.decode(errors="replace").replace(">", "").strip()
            else:
                self._socket.write((cmd + "\r").encode())
                time.sleep(0.3)
                return self._socket.read_all().decode(errors="replace").strip()
        except Exception as e:
            return f"ERROR:{e}"

    def read_pid(self, pid: str) -> dict:
        """Read a single OBD-II PID and return parsed value."""
        if not self._connected:
            return {"pid": pid, "error": "Not connected", "raw": ""}
        raw = self._send(pid)
        if "NO DATA" in raw or "ERROR" in raw or "UNABLE" in raw:
            return {"pid": pid, "raw": raw, "value": None, "error": raw}
        info = STANDARD_PIDS.get(pid, {})
        parsed = self._parse_pid(pid, raw)
        return {
            "pid": pid,
            "name": info.get("name", pid),
            "raw": raw,
            "value": parsed,
            "unit": info.get("unit", ""),
        }

    def read_multiple_pids(self, pids: list) -> list:
        return [self.read_pid(p) for p in pids]

    def read_dtc(self) -> list:
        """Read Diagnostic Trouble Codes."""
        raw = self._send("03")
        if "NO DATA" in raw:
            return []
        return [{"raw": raw, "codes": self._parse_dtc(raw)}]

    def close(self):
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
        self._connected = False

    def _parse_pid(self, pid, raw):
        try:
            clean = raw.replace(" ", "").replace("\r", "").replace("\n", "")
            # Remove echoed command
            if clean.startswith("41"):
                hex_data = clean[4:]  # Skip mode+pid response
            else:
                hex_data = clean
            if len(hex_data) >= 2:
                a = int(hex_data[0:2], 16)
                b = int(hex_data[2:4], 16) if len(hex_data) >= 4 else 0
                if pid == "010C":
                    return ((a * 256) + b) / 4
                elif pid in ("010D", "010B", "0146"):
                    return a
                elif pid in ("0105", "010F", "015C"):
                    return a - 40
                elif pid in ("0111", "012F", "0104"):
                    return round((a * 100) / 255, 1)
                elif pid == "010E":
                    return (a / 2) - 64
                elif pid in ("0110", "015E"):
                    return ((a * 256) + b) / 100
                elif pid == "0142":
                    return ((a * 256) + b) / 1000
                return a
        except:
            pass
        return None

    def _parse_vin(self, raw):
        try:
            clean = raw.replace(" ", "").replace("\r\n", "")
            # Extract ASCII from VIN response
            hex_part = clean.split("490201")[-1] if "490201" in clean else clean
            vin = bytes.fromhex(hex_part).decode("ascii", errors="replace")
            return vin[:17]
        except:
            return ""

    def _parse_dtc(self, raw):
        codes = []
        try:
            clean = raw.replace(" ", "")
            if clean.startswith("43"):
                clean = clean[2:]
            for i in range(0, len(clean), 4):
                if i + 4 <= len(clean):
                    code_hex = clean[i:i+4]
                    if code_hex != "0000":
                        prefix = {"0": "P0", "1": "P1", "2": "P2", "3": "P3",
                                  "4": "C0", "5": "C1", "6": "C2", "7": "C3",
                                  "8": "B0", "9": "B1", "A": "B2", "B": "B3",
                                  "C": "U0", "D": "U1", "E": "U2", "F": "U3"}
                        first = code_hex[0].upper()
                        codes.append(prefix.get(first, "P") + code_hex[1:])
        except:
            pass
        return codes


# Global connection
_elm_connection: ELM327Connection | None = None
_live_pids: dict = {}
_live_thread: threading.Thread | None = None
_live_running = False


def elm_connect(address: str, conn_type: str = "bluetooth") -> dict:
    global _elm_connection
    _elm_connection = ELM327Connection(address, conn_type)
    if _elm_connection.connect():
        return {
            "connected": True,
            "elm_version": _elm_connection.elm_version,
            "protocol": _elm_connection.protocol,
            "vin": _elm_connection.vin,
        }
    return {"connected": False, "error": _elm_connection.error}


def elm_read_pids(pids: list) -> list:
    if not _elm_connection or not _elm_connection._connected:
        return [{"pid": p, "error": "Not connected"} for p in pids]
    return _elm_connection.read_multiple_pids(pids)


def elm_start_live(pids: list, interval: float = 1.0):
    global _live_running, _live_thread, _live_pids
    if _live_running:
        return
    _live_running = True
    _live_pids = {}

    def _loop():
        while _live_running and _elm_connection and _elm_connection._connected:
            for pid in pids:
                if not _live_running:
                    break
                result = _elm_connection.read_pid(pid)
                _live_pids[pid] = result
            time.sleep(interval)

    _live_thread = threading.Thread(target=_loop, daemon=True)
    _live_thread.start()


def elm_stop_live():
    global _live_running
    _live_running = False


def elm_get_live() -> dict:
    return dict(_live_pids)


def elm_disconnect():
    global _elm_connection, _live_running
    _live_running = False
    if _elm_connection:
        _elm_connection.close()
        _elm_connection = None


def get_vehicle_profiles() -> dict:
    return VEHICLE_PROFILES_LATAM


def get_standard_pids() -> dict:
    return STANDARD_PIDS


def get_ev_pids() -> dict:
    return EV_PIDS


# ═══ PerfektBlue Automotive BT Assessment ═══
AUTOMOTIVE_BT_CHECKS = [
    {"id": "AUTO-BT-001", "name": "AVRCP Service Discovery", 
     "desc": "Check if vehicle infotainment exposes AVRCP (Audio/Video Remote Control Profile)",
     "cmd": "sdptool browse {mac} | grep -i avrcp",
     "severity": "INFO", "cve": "CVE-2024-45434"},
    {"id": "AUTO-BT-002", "name": "L2CAP Ping Flood Resilience",
     "desc": "Test L2CAP connection handling under load (PerfektBlue prerequisite)",
     "cmd": "l2ping -c 20 -f {mac}",
     "severity": "MEDIUM", "cve": "CVE-2024-45431"},
    {"id": "AUTO-BT-003", "name": "RFCOMM Channel Enumeration",
     "desc": "Enumerate RFCOMM channels for potential PerfektBlue attack surface",
     "cmd": "sdptool browse {mac} | grep -i rfcomm",
     "severity": "INFO", "cve": "CVE-2024-45433"},
    {"id": "AUTO-BT-004", "name": "Bluetooth Pairing Mode Detection",
     "desc": "Check if vehicle BT is in discoverable/pairable mode",
     "cmd": "hcitool scan | grep {mac}",
     "severity": "HIGH", "cve": None},
    {"id": "AUTO-BT-005", "name": "BT Classic Service Count",
     "desc": "Enumerate all exposed Classic BT services",
     "cmd": "sdptool browse {mac}",
     "severity": "INFO", "cve": None},
]
