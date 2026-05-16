"""RadioRecon — ESP32 Serial Bridge.

Communicates with ESP32-S3 running RadioRecon firmware via USB serial.
AT command protocol for BLE spam, scan, beacon, HID injection.

Commands sent to ESP32:
  AT+VERSION           → firmware version
  AT+STATUS            → current status
  AT+BLESPAM=type,dur  → start BLE spam (apple/android/samsung/windows/all)
  AT+BLESTOP           → stop spam
  AT+BLESCAN=seconds   → scan for BLE devices
  AT+BLEADV=hexdata    → send custom advertisement
"""
from __future__ import annotations
import threading
import time
import logging
import re
from datetime import datetime

logger = logging.getLogger("radiorecon.esp32")


class ESP32Bridge:
    def __init__(self, port: str = "/dev/ttyUSB0", baud: int = 115200):
        self.port = port
        self.baud = baud
        self._serial = None
        self._connected = False
        self._lock = threading.Lock()
        self._log: list[dict] = []
        self._firmware: str = ""
        self._spam_status = {"running": False, "packets": 0, "type": ""}
        self._scan_results: list[dict] = []
        self._reader_thread = None
        self._reader_running = False

    @property
    def connected(self):
        try:
            import os
            return bool(self._connected and self._serial and self._serial.is_open and os.path.exists(self.port))
        except Exception:
            return False

    def connect(self, port: str = None, quick: bool = False) -> dict:
        if port:
            self.port = port
        try:
            import serial
            self._serial = serial.Serial(self.port, self.baud, timeout=1)
            time.sleep(1.0 if quick else 1.5)  # C3 needs at least 1s
            self._connected = True

            # Read boot message — firmware v5.0 sends "OK:BLEAK-S3 v5.0 [ESP32-S3]" on boot
            boot_msg = ""
            deadline = time.time() + 2.0
            while time.time() < deadline:
                if self._serial.in_waiting:
                    boot_msg += self._serial.read_all().decode(errors="replace")
                    if "OK:BLEAK" in boot_msg or "OK:RadioRecon" in boot_msg:
                        break
                time.sleep(0.1)

            # Always send AT+VERSION to get current state. Some USB-UART boards
            # reset on open, so allow one delayed retry before declaring failure.
            resp = self.send_command("AT+VERSION")
            if not resp.get("success") and not ("OK:BLEAK" in resp.get("response", "") or "OK:RadioRecon" in resp.get("response", "")):
                time.sleep(0.7)
                resp = self.send_command("AT+VERSION", timeout=4.0)
            raw_resp = resp.get("response", "")

            # Accept either AT+VERSION response OR boot message
            # Always take first line only — firmware may send multiline (INFO:HID=... etc)
            if "OK:BLEAK" in raw_resp or "OK:RadioRecon" in raw_resp:
                firmware = raw_resp.strip().split("\n")[0].strip()
            elif "OK:BLEAK" in boot_msg or "OK:RadioRecon" in boot_msg:
                firmware = boot_msg.strip().split("\n")[0].strip()
                resp["success"] = True
            else:
                firmware = (raw_resp.strip() or boot_msg.strip()).split("\n")[0].strip()

            if resp.get("success") or "OK:" in raw_resp or "OK:BLEAK" in boot_msg:
                self._firmware = firmware  # cache for _firmware_has_android_fix
                self._log_entry("Connected: " + firmware, "ok")
                # Flush remaining serial bytes (INFO: lines, etc.) before starting reader
                time.sleep(0.1)
                if self._serial and self._serial.in_waiting:
                    self._serial.read_all()  # discard trailing firmware lines
                self._start_reader()
                return {"success": True, "port": self.port, "firmware": firmware,
                        "response": firmware}
            else:
                self._connected = False
                try: self._serial.close()
                except: pass
                self._serial = None
                return {"success": False, "error": "No response on " + self.port}
        except Exception as e:
            self._connected = False
            return {"success": False, "error": str(e)}

    def disconnect(self):
        self._reader_running = False
        if self._serial and self._serial.is_open:
            try:
                self._serial.close()
            except Exception:
                pass
        self._connected = False
        self._log_entry("Disconnected", "info")

    def send_command(self, cmd: str, timeout: float = 3.0) -> dict:
        """Send AT command and wait for response.

        Timeout is extended automatically for long-running commands:
          AT+SPAM, AT+KARMA → 5s (NimBLE setup takes time)
          AT+SCAN, AT+FPSCAN → scan_duration + 2s (handled by caller)
          others → timeout param (default 3s)
        """
        if not self.connected:
            self._connected = False
            return {"command": cmd, "response": "NOT_CONNECTED", "success": False}

        # Auto-extend timeout for commands that take longer to acknowledge
        cmd_upper = cmd.upper()
        if cmd_upper.startswith("AT+SPAM=") or cmd_upper.startswith("AT+KARMA="):
            timeout = max(timeout, 5.0)
        elif cmd_upper.startswith("AT+HID"):
            timeout = max(timeout, 8.0)

        with self._lock:
            try:
                self._serial.reset_input_buffer()
                self._serial.write((cmd + "\r\n").encode())
                time.sleep(0.2)
                resp = ""
                end = time.time() + timeout
                while time.time() < end:
                    if self._serial.in_waiting:
                        chunk = self._serial.read(self._serial.in_waiting).decode(errors="replace")
                        resp += chunk
                        # Stop when we see a complete response line
                        if any(tok in resp for tok in ["OK:", "ERR:", "SPAM:DONE", "SCAN:DONE"]):
                            # Read any remaining bytes
                            time.sleep(0.05)
                            if self._serial.in_waiting:
                                resp += self._serial.read(self._serial.in_waiting).decode(errors="replace")
                            break
                    time.sleep(0.05)

                resp = resp.strip()
                lines = [ln.strip() for ln in resp.split("\n") if ln.strip()]
                ack_lines = [ln for ln in lines if ln.startswith(("OK:", "ERR:"))]
                # Prefer the command acknowledgement over async telemetry.
                # During spam the firmware may emit SPAM:PKT before/around OK:SPAM.
                resp_first = (ack_lines[0] if ack_lines else (lines[0] if lines else ""))
                self._log_entry("TX:" + cmd + " | RX:" + resp_first[:80], "cmd")
                success = ("OK:" in resp or "DEV:" in resp or "FP:" in resp or
                           "RAW:" in resp or "ENUM:" in resp)
                if cmd_upper.startswith("AT+SPAM=") and ("SPAM:PKT:" in resp or "SPAM:DONE:" in resp):
                    success = True
                if cmd_upper == "AT+STOP" and "SPAM:DONE:" in resp:
                    success = True
                return {"command": cmd, "response": resp_first,
                        "raw_response": resp, "success": success}
            except Exception as e:
                return {"command": cmd, "response": f"ERROR: {e}", "success": False}

    # ── BLE Spam via ESP32 ──────────────────────────────────

    def _drain_async(self, quiet_for: float = 0.25, timeout: float = 1.5) -> str:
        """Drain pending async firmware lines without treating them as command replies."""
        if not self._serial:
            return ""
        data = ""
        end = time.time() + timeout
        quiet_end = time.time() + quiet_for
        while time.time() < end:
            try:
                waiting = self._serial.in_waiting
            except Exception:
                break
            if waiting:
                chunk = self._serial.read(waiting).decode(errors="replace")
                data += chunk
                quiet_end = time.time() + quiet_for
                for line in chunk.strip().split("\n"):
                    line = line.strip()
                    if line.startswith("SPAM:PKT:"):
                        try:
                            self._spam_status["packets"] = int(line.split(":")[2])
                        except Exception:
                            pass
                    elif line.startswith("SPAM:DONE:"):
                        try:
                            self._spam_status["packets"] = int(line.split(":")[2])
                        except Exception:
                            pass
                        self._spam_status["running"] = False
            elif time.time() >= quiet_end:
                break
            time.sleep(0.05)
        return data.strip()

    def start_spam(self, spam_type: str = "all", duration: int = 30) -> dict:
        # Always flush + stop previous spam before starting new one
        # Prevents "No response" when ESP32 is still processing previous AT+SPAM
        if self._serial:
            try:
                self._serial.reset_input_buffer()
                self._serial.reset_output_buffer()
            except Exception:
                pass
        # Send stop first (idempotent — OK if nothing running)
        stop_resp = self.send_command("AT+STOP", timeout=3.0)
        time.sleep(0.3)
        self._drain_async(quiet_for=0.25, timeout=1.5)
        # Now send spam command with extended timeout
        resp = self.send_command("AT+SPAM={},{}".format(spam_type, duration), timeout=6.0)
        if resp["success"]:
            self._spam_status = {"running": True, "packets": 0, "type": spam_type,
                                 "started": datetime.now().isoformat(), "started_ts": time.time(),
                                 "duration": duration}
        return resp

    def stop_spam(self) -> dict:
        resp = self.send_command("AT+STOP")
        self._spam_status["running"] = False
        return resp

    def get_spam_status(self) -> dict:
        if self._spam_status.get("running"):
            self._drain_async(quiet_for=0.05, timeout=0.15)
            started_ts = float(self._spam_status.get("started_ts") or 0)
            duration = float(self._spam_status.get("duration") or 0)
            if started_ts and duration and time.time() >= started_ts + duration + 1.0:
                self._drain_async(quiet_for=0.15, timeout=0.8)
                self._spam_status["running"] = False
                self._spam_status["completed"] = datetime.now().isoformat()
        return dict(self._spam_status)

    # ── BLE Scan via ESP32 ──────────────────────────────────

    def start_karma(self, duration: int = 30) -> dict:
        """Start BLE Karma attack — impersonate nearby devices."""
        resp = self.send_command(f"AT+KARMA={duration}")
        return resp

    def stop_karma(self) -> dict:
        return self.send_command("AT+KARMASTOP")

    def ble_scan(self, seconds: int = 5) -> dict:
        self._scan_results = []
        resp = self.send_command(f"AT+SCAN={seconds}")
        for line in resp.get("response", "").split("\n"):
            line = line.strip()
            if line.startswith("DEV:"):
                parts = line[4:].split(":", 2)
                if len(parts) >= 3:
                    self._scan_results.append({
                        "mac": parts[0].upper(), "rssi": int(parts[1]) if parts[1].lstrip("-").isdigit() else -99,
                        "name": parts[2] if parts[2] and parts[2] != "?" else "Unknown", "source": "esp32",
                    })
        return {"devices": self._scan_results, "count": len(self._scan_results)}

    def fast_pair_scan(self, seconds: int = 8) -> dict:
        """Scan for Google Fast Pair devices via ESP32-C3 (0xFE2C / 0x00E0).

        The ESP32-C3 captures raw BLE advertisements that BlueZ/hci0 may filter
        out when a device is already paired. Returns a list of detected Fast Pair
        devices with model_id and pairing_state fields parsed from the payload.

        AT+FPSCAN=<seconds> — dedicated command added in firmware v4.2+.
        Falls back to AT+SCAN= with client-side filtering if firmware is older.
        """
        self._fp_results: list[dict] = []

        # Try dedicated Fast Pair scan command first (firmware v4.2+)
        resp = self.send_command(f"AT+FPSCAN={seconds}")
        if resp.get("success") and "FPSCAN" in resp.get("response", ""):
            for line in resp.get("response", "").split("\n"):
                line = line.strip()
                if line.startswith("FP:"):
                    # FP:<MAC>:<RSSI>:<model_id_hex>:<pairing_state>:<name>
                    parts = line[3:].split(":", 5)
                    if len(parts) >= 4:
                        self._fp_results.append({
                            "mac": parts[0].upper(),
                            "rssi": int(parts[1]) if parts[1].lstrip("-").isdigit() else -99,
                            "model_id": parts[2],
                            "pairing_state": parts[3],
                            "name": parts[4] if len(parts) > 4 else "Unknown",
                            "fast_pair": True,
                            "source": "esp32_fpscan",
                        })
            return {"devices": self._fp_results, "count": len(self._fp_results), "method": "dedicated"}

        # Fallback: raw scan + filter by manufacturer data 0x00E0 (Google)
        # or service UUID 0xFE2C present in payload bytes
        raw = self.send_command(f"AT+SCANRAW={seconds}")
        if not raw.get("success"):
            # Last resort: use regular scan and tag all results as candidates
            generic = self.ble_scan(seconds)
            return {"devices": generic["devices"], "count": generic["count"],
                    "method": "generic_fallback", "note": "Firmware v4.2+ required for Fast Pair filtering"}

        for line in raw.get("response", "").split("\n"):
            line = line.strip()
            if not line.startswith("RAW:"):
                continue
            # RAW:<MAC>:<RSSI>:<hex_payload>
            parts = line[4:].split(":", 3)
            if len(parts) < 4:
                continue
            mac, rssi_s, payload_hex = parts[0], parts[1], parts[3]
            payload = bytes.fromhex(payload_hex) if len(payload_hex) % 2 == 0 else b""
            is_fp = False
            model_id = ""
            pairing_state = "unknown"

            # Check for Fast Pair Service UUID 0xFE2C in 16-bit UUID list (AD type 0x02/0x03)
            i = 0
            while i < len(payload) - 1:
                length = payload[i]
                if i + length >= len(payload):
                    break
                ad_type = payload[i + 1]
                ad_data = payload[i + 2: i + 1 + length]
                if ad_type in (0x02, 0x03) and len(ad_data) >= 2:
                    for j in range(0, len(ad_data) - 1, 2):
                        uuid16 = (ad_data[j + 1] << 8) | ad_data[j]
                        if uuid16 == 0xFE2C:
                            is_fp = True
                # Check manufacturer data for Google (0x00E0) with Fast Pair model ID
                if ad_type == 0xFF and len(ad_data) >= 2:
                    company = (ad_data[1] << 8) | ad_data[0]
                    if company == 0x00E0 and len(ad_data) >= 5:
                        is_fp = True
                        model_id = ad_data[2:5].hex().upper()
                        pairing_state = "discoverable" if ad_data[2] & 0x40 else "paired_nearby"
                # Check Service Data for 0xFE2C (AD type 0x16)
                if ad_type == 0x16 and len(ad_data) >= 2:
                    uuid16 = (ad_data[1] << 8) | ad_data[0]
                    if uuid16 == 0xFE2C:
                        is_fp = True
                        if len(ad_data) >= 5:
                            model_id = ad_data[2:5].hex().upper()
                i += 1 + length

            if is_fp:
                self._fp_results.append({
                    "mac": mac.upper(),
                    "rssi": int(rssi_s) if rssi_s.lstrip("-").isdigit() else -99,
                    "model_id": model_id or "?",
                    "pairing_state": pairing_state,
                    "name": "Fast Pair Device",
                    "fast_pair": True,
                    "source": "esp32_raw",
                })

        return {"devices": self._fp_results, "count": len(self._fp_results), "method": "raw_filter"}

    # ── Custom Advertisement ────────────────────────────────

    def send_adv(self, hex_data: str) -> dict:
        return self.send_command(f"AT+BLEADV={hex_data}")

    # ── Status & Log ────────────────────────────────────────

    def get_status(self) -> dict:
        status = {"connected": self._connected, "port": self.port, "log": self._log[-20:]}
        if self._connected:
            resp = self.send_command("AT+STATUS")
            status["firmware_status"] = resp.get("response", "")
            status["spam"] = dict(self._spam_status)
        return status

    def get_log(self) -> list:
        return self._log[-50:]

    # ── Internal ────────────────────────────────────────────


    def set_mac_clone(self, mac: str = "RANDOM") -> dict:
        """Set static MAC for next advertisement cycles.
        mac = 'RANDOM' to disable, or 'XX:XX:XX:XX:XX:XX' to spoof.
        """
        return self.send_command(f"AT+MACCLONE={mac}")

    def set_tx_power(self, level: int = 9) -> dict:
        """Set TX power level 0 (min -12dBm) to 9 (max +9dBm)."""
        level = max(0, min(9, level))
        return self.send_command(f"AT+SETPOWER={level}")

    def set_rssi_filter(self, threshold: int = -99) -> dict:
        """Set RSSI scan filter. Only devices above threshold are reported."""
        return self.send_command(f"AT+RSSI={threshold}")

    def start_beacon(self, name: str, duration: int = 0) -> dict:
        """Broadcast a named beacon. duration=0 = until stop()."""
        return self.send_command(f"AT+BEACON={name},{duration}")

    def start_beacon_loop(self, name: str, interval_ms: int = 200) -> dict:
        """Continuous beacon with configurable interval. Runs until AT+STOP."""
        return self.send_command(f"AT+BEACONLOOP={name},{interval_ms}")

    def stop_beacon(self) -> dict:
        """Stop beacon broadcast."""
        return self.send_command("AT+BEACONSTOP")

    def ble_enum(self, target_mac: str = "", seconds: int = 8) -> dict:
        """Passive scan targeting a specific device or all devices."""
        resp = self.send_command(f"AT+BLEENUM={target_mac}")
        results = []
        for line in resp.get("response", "").split("\n"):
            line = line.strip()
            if line.startswith("ENUM:"):
                parts = line[5:].split(":", 5)
                if len(parts) >= 3:
                    results.append({
                        "mac": parts[0].upper(),
                        "rssi": int(parts[1]) if parts[1].lstrip("-").isdigit() else -99,
                        "name": parts[2] if len(parts) > 2 else "?",
                        "flags": parts[3] if len(parts) > 3 else "",
                        "uuid": parts[4] if len(parts) > 4 else "",
                    })
        return {"devices": results, "count": len(results)}

    def hid_inject(self, payload: str, mode: str = "ble") -> dict:
        """Inject HID keystrokes. S3 only.
        payload: DuckyScript-style, lines separated by |
        mode: 'ble' = BLE HID, 'usb' = USB HID (S3 USB-OTG)
        """
        if mode == "usb":
            return self.send_command(f"AT+HIDUSB={payload}")
        return self.send_command(f"AT+HID={payload}")

    def hid_stop(self) -> dict:
        """Stop HID injection. S3 only."""
        return self.send_command("AT+HIDSTOP")

    def hid_status(self) -> dict:
        """Get HID injection status. S3 only."""
        return self.send_command("AT+HIDSTATUS")

    def get_chip_type(self) -> str:
        """Detect if connected chip is C3 or S3."""
        resp = self.send_command("AT+VERSION")
        r = resp.get("response", "")
        if "S3" in r or "s3" in r:
            return "esp32_s3"
        if "C3" in r or "c3" in r:
            return "esp32_c3"
        return "esp32_unknown"

    def _log_entry(self, msg: str, level: str = "info"):
        self._log.append({"time": datetime.now().isoformat(), "msg": msg, "level": level})
        if len(self._log) > 200:
            self._log = self._log[-200:]

    def _start_reader(self):
        """Background thread to read async ESP32 responses (spam status, etc)."""
        if self._reader_thread and self._reader_thread.is_alive():
            return
        self._reader_running = True

        def _read():
            while self._reader_running and self._connected:
                try:
                    # Only drain unsolicited telemetry while an async operation is
                    # active. Otherwise status/version replies belong to send_command().
                    async_active = bool(self._spam_status.get("running"))
                    if async_active and self._serial and self._serial.in_waiting and not self._lock.locked():
                        with self._lock:
                            data = self._serial.read(self._serial.in_waiting).decode(errors="replace")
                        for line in data.strip().split("\n"):
                            line = line.strip()
                            if not line:
                                continue
                            # Only process structured events — silently discard everything else
                            # (status/version responses are handled by send_command, not here)
                            if line.startswith("SPAM:DONE:"):
                                try:
                                    count = int(line.split(":")[2])
                                    self._spam_status["running"] = False
                                    self._spam_status["packets"] = count
                                    self._spam_status["completed"] = datetime.now().isoformat()
                                    self._log_entry("Spam done: " + str(count) + " packets", "ok")
                                except Exception:
                                    pass
                            elif line.startswith('SPAM:PKT:'):
                                try:
                                    self._spam_status['packets'] = int(line.split(':')[2])
                                except Exception:
                                    pass
                            elif line.startswith(('OK:', 'INFO:', 'ERR:')):
                                # Firmware status — log only, never print to stdout
                                self._log_entry('fw: ' + line[:80], 'debug')
                            elif line.startswith("SPAM:PKT:"):
                                try:
                                    self._spam_status["packets"] = int(line.split(":")[2])
                                except Exception:
                                    pass
                            elif line.startswith("SCAN:") or line.startswith("DEV:") or line.startswith("FP:"):
                                self._log_entry("async: " + line[:80], "info")
                            # INFO:, OK:BLEAK, OK:RadioRecon etc → silently logged, not printed
                            elif line.startswith("INFO:") or line.startswith("OK:BLEAK") or line.startswith("OK:RadioRecon"):
                                self._log_entry("fw: " + line[:80], "debug")
                            # ERR: lines → log as warning
                            elif line.startswith("ERR:"):
                                self._log_entry("fw_err: " + line[:80], "warn")
                except Exception:
                    pass
                time.sleep(0.2)

        self._reader_thread = threading.Thread(target=_read, daemon=True)
        self._reader_thread.start()


# Global ESP32 instance
_esp32: ESP32Bridge | None = None


def get_esp32() -> ESP32Bridge:
    global _esp32
    if _esp32 is None:
        _esp32 = ESP32Bridge()
    return _esp32
