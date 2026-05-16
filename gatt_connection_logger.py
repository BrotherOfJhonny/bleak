"""
gatt_connection_logger.py
=========================
Módulo de log de conexões no GATT server falso.

Inspirado na arquitetura do BtleJuice (DigitalSecurity/btlejuice):
- BtleJuice usa um "proxy" que fica entre o periférico real e o central (app)
- Captura o MAC do central que conectou
- Permite hooking (interceptar e modificar GATT operations)
- Permite forced sync (reenviar dados ao central conectado)

Nossa implementação Python (sem Node.js):
- GATT server BlueZ D-Bus loga cada conexão com MAC do central
- MAC do central (Zepp Life) é capturado quando conecta
- Com esse MAC, podemos forçar sincronismo enviando notificações
- Implementa hook system: before_write, after_read, on_connect, on_disconnect

Fluxo BtleJuice adaptado:
  1. GATT server falso anuncia com MAC clonado da Mi Band
  2. Zepp Life conecta → capturamos seu MAC
  3. Injetamos dados → Zepp Life recebe como se viessem da Mi Band real
  4. Logged: timestamp, central MAC, operations (read/write/notify)
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


# ─── Connection Log Entry ─────────────────────────────────────────────────────

@dataclass
class GATTConnectionEvent:
    event_type: str          # connect, disconnect, read, write, notify
    timestamp: float = field(default_factory=time.time)
    central_mac: str = ""    # MAC of the central (smartphone/Zepp Life)
    characteristic_uuid: str = ""
    data_hex: str = ""
    data_decoded: str = ""
    direction: str = ""      # "central→peripheral" or "peripheral→central"

    def to_dict(self) -> Dict:
        return {
            "event": self.event_type,
            "time": time.strftime("%H:%M:%S", time.localtime(self.timestamp)),
            "central_mac": self.central_mac,
            "char_uuid": self.characteristic_uuid,
            "data_hex": self.data_hex,
            "data_decoded": self.data_decoded,
            "direction": self.direction,
        }


# ─── GATT Connection Logger ───────────────────────────────────────────────────

class GATTConnectionLogger:
    """
    Logs all GATT connections and operations on the fake GATT server.
    Implements the BtleJuice-inspired tracking approach.
    """

    def __init__(self, session_id: str, target_mac: str):
        self.session_id = session_id
        self.target_mac = target_mac
        self.events: List[GATTConnectionEvent] = []
        self.connected_centrals: Dict[str, float] = {}  # mac → connect_time
        self.hooks: Dict[str, List[Callable]] = {
            "on_connect": [],
            "on_disconnect": [],
            "before_write": [],
            "after_read": [],
            "on_notify": [],
        }
        self._lock = threading.Lock()
        self._log_file: Optional[str] = None

        # State for forced sync
        self._pending_notifications: List[Dict] = []
        self._last_central_mac: str = ""

    def set_log_file(self, path: str):
        self._log_file = path

    def _append_event(self, ev: GATTConnectionEvent):
        with self._lock:
            self.events.append(ev)
            if len(self.events) > 1000:
                self.events = self.events[-1000:]
            if self._log_file:
                try:
                    with open(self._log_file, "a") as f:
                        f.write(json.dumps(ev.to_dict()) + "\n")
                except Exception:
                    pass

    def register_hook(self, event_type: str, callback: Callable):
        """Register a hook to intercept GATT events (BtleJuice-style hooking)."""
        if event_type in self.hooks:
            self.hooks[event_type].append(callback)

    def _fire_hooks(self, event_type: str, *args, **kwargs) -> Optional[Any]:
        """Fire all registered hooks for an event type."""
        result = None
        for hook in self.hooks.get(event_type, []):
            try:
                r = hook(*args, **kwargs)
                if r is not None:
                    result = r
            except Exception:
                pass
        return result

    def log_connect(self, central_mac: str) -> bool:
        """
        Log a new central connection.
        Returns True if this is a new central (not seen before).
        """
        is_new = central_mac not in self.connected_centrals
        self.connected_centrals[central_mac] = time.time()
        self._last_central_mac = central_mac

        ev = GATTConnectionEvent(
            event_type="connect",
            central_mac=central_mac,
            direction="central→peripheral",
        )
        self._append_event(ev)

        if is_new:
            print(f"[GATT LOG] ★ NOVO CENTRAL CONECTOU: {central_mac}")
            print(f"[GATT LOG]   Zepp Life MAC capturado → pode forçar sincronismo")

        self._fire_hooks("on_connect", central_mac=central_mac, is_new=is_new)
        return is_new

    def log_disconnect(self, central_mac: str):
        ev = GATTConnectionEvent(
            event_type="disconnect",
            central_mac=central_mac,
        )
        self._append_event(ev)
        if central_mac in self.connected_centrals:
            session_s = time.time() - self.connected_centrals[central_mac]
            print(f"[GATT LOG] DESCONEXÃO: {central_mac} (sessão: {session_s:.1f}s)")
        self._fire_hooks("on_disconnect", central_mac=central_mac)

    def log_write(self, central_mac: str, char_uuid: str,
                  data: bytes, modified_data: Optional[bytes] = None) -> bytes:
        """
        Log a WRITE operation from central.
        Fires before_write hooks which can modify the data (BtleJuice hooking).
        Returns the (potentially modified) data to forward.
        """
        hex_data = data.hex()
        try:
            decoded = data.decode("utf-8", errors="replace")
        except Exception:
            decoded = hex_data

        ev = GATTConnectionEvent(
            event_type="write",
            central_mac=central_mac,
            characteristic_uuid=char_uuid,
            data_hex=hex_data,
            data_decoded=decoded[:50],
            direction="central→peripheral",
        )
        self._append_event(ev)
        print(f"[GATT LOG] WRITE {char_uuid[:8]}: {hex_data[:30]}")

        # Allow hooks to modify the data before forwarding
        hook_result = self._fire_hooks(
            "before_write", central_mac=central_mac,
            char_uuid=char_uuid, data=data
        )
        return hook_result if isinstance(hook_result, bytes) else data

    def log_notify(self, char_uuid: str, data: bytes, central_mac: str = ""):
        """Log a NOTIFY sent to central."""
        ev = GATTConnectionEvent(
            event_type="notify",
            central_mac=central_mac or self._last_central_mac,
            characteristic_uuid=char_uuid,
            data_hex=data.hex(),
            direction="peripheral→central",
        )
        self._append_event(ev)
        print(f"[GATT LOG] NOTIFY {char_uuid[:8]}: {data.hex()[:20]}")
        self._fire_hooks("on_notify", char_uuid=char_uuid, data=data)

    def queue_forced_notification(self, char_uuid: str, data: bytes):
        """
        Queue a notification to be sent to the connected central.
        Used for forced sync (BtleJuice-style replay/injection).
        """
        self._pending_notifications.append({
            "char_uuid": char_uuid,
            "data": data,
            "queued_at": time.time(),
        })
        print(f"[GATT LOG] QUEUED NOTIFY {char_uuid[:8]}: {data.hex()[:20]}")

    def get_pending_notifications(self) -> List[Dict]:
        """Get and clear pending notifications queue."""
        with self._lock:
            pending = self._pending_notifications.copy()
            self._pending_notifications.clear()
        return pending

    @property
    def last_central_mac(self) -> str:
        return self._last_central_mac

    @property
    def active_connections(self) -> List[str]:
        return list(self.connected_centrals.keys())

    def get_summary(self) -> Dict:
        unique_centrals = list(set(e.central_mac for e in self.events if e.central_mac))
        writes = [e for e in self.events if e.event_type == "write"]
        notifs = [e for e in self.events if e.event_type == "notify"]
        return {
            "session_id": self.session_id,
            "target_mac": self.target_mac,
            "total_events": len(self.events),
            "unique_centrals": unique_centrals,
            "writes": len(writes),
            "notifications_sent": len(notifs),
            "last_central_mac": self._last_central_mac,
            "active_connections": self.active_connections,
            "recent_events": [e.to_dict() for e in self.events[-20:]],
        }

    def force_sync_miband(self, hr: int = 72, steps: int = 5000,
                          notification: str = "") -> List[Dict]:
        """
        Force sync Mi Band data to connected Zepp Life.
        Queues HR notification, steps, and optional alert.
        """
        import struct
        queued = []

        # HR measurement: [flags=0x00, bpm_uint8]
        hr_data = bytes([0x00, hr & 0xFF])
        self.queue_forced_notification(
            "00002a37-0000-1000-8000-00805f9b34fb", hr_data
        )
        queued.append({"char": "HR_Measurement", "data": hr_data.hex()})
        print(f"[SYNC] HR queued: {hr} BPM → Zepp Life")

        # Steps: [steps_lo, steps_hi, 0, 0]
        steps_data = struct.pack("<H", min(steps, 65535)) + bytes([0, 0])
        self.queue_forced_notification(
            "0000ff06-0000-1000-8000-00805f9b34fb", steps_data
        )
        queued.append({"char": "Steps", "data": steps_data.hex()})
        print(f"[SYNC] Steps queued: {steps} → Zepp Life")

        # Optional notification/alert
        if notification:
            notif_data = bytes([0x01]) + notification.encode("utf-8")[:19]
            self.queue_forced_notification(
                "0000ff03-0000-1000-8000-00805f9b34fb", notif_data
            )
            queued.append({"char": "Alert", "data": notif_data.hex()})
            print(f"[SYNC] Alert queued: {repr(notification[:20])} → Zepp Life")

        return queued


# ─── Singleton registry ───────────────────────────────────────────────────────

_loggers: Dict[str, GATTConnectionLogger] = {}

def get_logger(session_id: str) -> Optional[GATTConnectionLogger]:
    return _loggers.get(session_id)

def create_logger(session_id: str, target_mac: str) -> GATTConnectionLogger:
    logger = GATTConnectionLogger(session_id, target_mac)
    _loggers[session_id] = logger
    return logger

def list_loggers() -> List[Dict]:
    return [logger.get_summary() for logger in _loggers.values()]
