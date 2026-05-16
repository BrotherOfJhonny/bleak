"""BLEAK — Bluetooth Link Exploitation & Attack Knowledgebase — State models."""
from __future__ import annotations
import warnings; warnings.filterwarnings("ignore", category=DeprecationWarning)
from dataclasses import dataclass, field
from typing import Any

APP_VERSION = "V0.19"

@dataclass
class AppState:
    discovered_devices: list = field(default_factory=list)
    discovery_running: bool = False
    discovery_start_time: float = 0
    enum_results: list = field(default_factory=list)
    enum_running: bool = False
    vuln_results: list = field(default_factory=list)
    vuln_running: bool = False
    attack_results: list = field(default_factory=list)
    exploit_results: list = field(default_factory=list)
    evidence_results: dict = field(default_factory=dict)
    evidence_running: bool = False
    evidence_error: str | None = None
    mitm_active: bool = False
    esp32_connected: bool = False
    esp32_port: str | None = None
    _miband_live_data: dict = field(default_factory=dict)
    _mitm_traffic: dict = field(default_factory=lambda: {"packets": 0, "bytes": 0, "captures": []})
    progress: dict = field(default_factory=dict)
    fingerprints: dict = field(default_factory=dict)
    gatt_log_sessions: list = field(default_factory=list)
    capture_active: bool = False
    capture_file: str | None = None
    vehicle_results: dict = field(default_factory=dict)
    vehicle_running: bool = False
    vehicle_error: str | None = None
    vehicle_progress: dict = field(default_factory=dict)
    vehicle_connection: dict = field(default_factory=dict)
    tuya_results: list = field(default_factory=list)
    tuya_keys: dict = field(default_factory=dict)
    audio_evidence_archive: list = field(default_factory=list)
    report_files: list = field(default_factory=list)
    selected_targets: list = field(default_factory=list)
    smart_bulb_devices: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "discovered_devices": self.discovered_devices,
            "discovery_running": self.discovery_running,
            "enum_results": self.enum_results,
            "enum_running": self.enum_running,
            "vuln_results": self.vuln_results,
            "vuln_running": self.vuln_running,
            "attack_results": self.attack_results,
            "exploit_results": self.exploit_results,
            "mitm_active": self.mitm_active,
            "esp32_connected": self.esp32_connected,
            "esp32_port": self.esp32_port,
            "progress": self.progress,
            "total_devices": len(self.discovered_devices),
            "total_vulns": len(self.vuln_results),
            "total_enum": len(self.enum_results),
            "selected_targets": self.selected_targets,
            "vehicle_running": self.vehicle_running,
            "smart_bulb_devices": self.smart_bulb_devices,
            "audio_evidence_archive": self.audio_evidence_archive,
        }

STATE = AppState()
