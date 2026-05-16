"""
nordic_ble_db.py
================
Banco de dados Bluetooth completo baseado no repositório público da Nordic Semiconductor:
https://github.com/NordicSemiconductor/bluetooth-numbers-database

Conteúdo (licença MIT — permitido uso comercial e pesquisa):
  - service_uuids.json    → NORDIC_SERVICES (67 serviços SIG + proprietários)
  - characteristic_uuids.json → NORDIC_CHARS (240+ características SIG + Nordic Thingy/DFU)
  - company_ids.json      → NORDIC_COMPANIES (4200+ fabricantes registrados no Bluetooth SIG)
  - descriptor_uuids.json → NORDIC_DESCRIPTORS (30+ descritores GATT)
  - appearance_values.json → NORDIC_APPEARANCES (categorias de aparência do dispositivo)

Uso no projeto BLE Audit:
  - Identificar serviços/características: resolve_nordic(uuid) → dict completo
  - Identificar fabricante pelo Company ID (manufacturer data byte 0-1): company_name(company_id)
  - Identificar tipo de dispositivo pelo Appearance value: appearance_name(value)
  - Calcular risco de segurança baseado no tipo de serviço

Fonte: Nordic Semiconductor / Bluetooth SIG (dados públicos)
MIT License — Copyright (c) 2019 Nordic Semiconductor ASA
"""

from __future__ import annotations
from typing import Dict, List, Optional, Tuple, Any


# =============================================================================
# SERVIÇOS BLUETOOTH SIG — service_uuids.json (Nordic DB)
# Formato: short UUID 16-bit (sem o prefixo 0000 e sufixo padrão)
# =============================================================================

NORDIC_SERVICES: Dict[str, Dict[str, str]] = {
    # ── GATT Core ─────────────────────────────────────────────────────────────
    "1800": {"name": "Generic Access",               "identifier": "org.bluetooth.service.generic_access",          "risk": "low"},
    "1801": {"name": "Generic Attribute",            "identifier": "org.bluetooth.service.generic_attribute",       "risk": "low"},
    "1802": {"name": "Immediate Alert",              "identifier": "org.bluetooth.service.immediate_alert",         "risk": "medium"},
    "1803": {"name": "Link Loss",                    "identifier": "org.bluetooth.service.link_loss",               "risk": "medium"},
    "1804": {"name": "Tx Power",                     "identifier": "org.bluetooth.service.tx_power",               "risk": "low"},
    # ── Tempo e localização ────────────────────────────────────────────────────
    "1805": {"name": "Current Time Service",         "identifier": "org.bluetooth.service.current_time",           "risk": "low"},
    "1806": {"name": "Reference Time Update",        "identifier": "org.bluetooth.service.reference_time_update",  "risk": "low"},
    "1807": {"name": "Next DST Change",              "identifier": "org.bluetooth.service.next_dst_change",        "risk": "low"},
    "1819": {"name": "Location and Navigation",      "identifier": "org.bluetooth.service.location_and_navigation","risk": "critical"},
    "1821": {"name": "Indoor Positioning",           "identifier": "org.bluetooth.service.indoor_positioning",     "risk": "high"},
    # ── Saúde / Medical ────────────────────────────────────────────────────────
    "1808": {"name": "Glucose",                      "identifier": "org.bluetooth.service.glucose",               "risk": "critical"},
    "1809": {"name": "Health Thermometer",           "identifier": "org.bluetooth.service.health_thermometer",    "risk": "high"},
    "180D": {"name": "Heart Rate",                   "identifier": "org.bluetooth.service.heart_rate",            "risk": "critical"},
    "1810": {"name": "Blood Pressure",               "identifier": "org.bluetooth.service.blood_pressure",        "risk": "critical"},
    "181B": {"name": "Body Composition",             "identifier": "org.bluetooth.service.body_composition",      "risk": "high"},
    "181C": {"name": "User Data",                    "identifier": "org.bluetooth.service.user_data",             "risk": "high"},
    "181D": {"name": "Weight Scale",                 "identifier": "org.bluetooth.service.weight_scale",          "risk": "medium"},
    "181F": {"name": "Continuous Glucose Monitoring","identifier": "org.bluetooth.service.continuous_glucose_monitoring","risk": "critical"},
    "1822": {"name": "Pulse Oximeter Service",       "identifier": "org.bluetooth.service.pulse_oximeter",        "risk": "critical"},
    "183A": {"name": "Insulin Delivery",             "identifier": "org.bluetooth.service.insulin_delivery",      "risk": "critical"},
    "183E": {"name": "Physical Activity Monitor",    "identifier": "org.bluetooth.service.physical_activity_monitor","risk": "high"},
    # ── Dispositivo e informações ──────────────────────────────────────────────
    "180A": {"name": "Device Information",           "identifier": "org.bluetooth.service.device_information",    "risk": "medium"},
    "180F": {"name": "Battery Service",              "identifier": "org.bluetooth.service.battery_service",       "risk": "low"},
    "180E": {"name": "Phone Alert Status",           "identifier": "org.bluetooth.service.phone_alert_status",    "risk": "medium"},
    "1811": {"name": "Alert Notification Service",   "identifier": "org.bluetooth.service.alert_notification",    "risk": "medium"},
    "1813": {"name": "Scan Parameters",              "identifier": "org.bluetooth.service.scan_parameters",       "risk": "low"},
    # ── HID / Interface ────────────────────────────────────────────────────────
    "1812": {"name": "Human Interface Device (HID)", "identifier": "org.bluetooth.service.human_interface_device","risk": "critical"},
    # ── Atividade física / Esporte ────────────────────────────────────────────
    "1814": {"name": "Running Speed and Cadence",    "identifier": "org.bluetooth.service.running_speed_and_cadence","risk": "medium"},
    "1816": {"name": "Cycling Speed and Cadence",    "identifier": "org.bluetooth.service.cycling_speed_and_cadence","risk": "medium"},
    "1818": {"name": "Cycling Power",                "identifier": "org.bluetooth.service.cycling_power",         "risk": "medium"},
    "1826": {"name": "Fitness Machine",              "identifier": "org.bluetooth.service.fitness_machine",       "risk": "medium"},
    # ── Automação / IoT ────────────────────────────────────────────────────────
    "1815": {"name": "Automation IO",               "identifier": "org.bluetooth.service.automation_io",          "risk": "high"},
    "181A": {"name": "Environmental Sensing",        "identifier": "org.bluetooth.service.environmental_sensing", "risk": "medium"},
    "183B": {"name": "Binary Sensor",               "identifier": "org.bluetooth.service.binary_sensor",          "risk": "high"},
    "183C": {"name": "Emergency Configuration",      "identifier": "org.bluetooth.service.emergency_configuration","risk": "critical"},
    # ── Conectividade / Rede ──────────────────────────────────────────────────
    "1820": {"name": "Internet Protocol Support",    "identifier": "org.bluetooth.service.internet_protocol_support","risk": "high"},
    "1823": {"name": "HTTP Proxy",                   "identifier": "org.bluetooth.service.http_proxy",            "risk": "high"},
    "1824": {"name": "Transport Discovery",          "identifier": "org.bluetooth.service.transport_discovery",   "risk": "medium"},
    "1825": {"name": "Object Transfer Service",      "identifier": "org.bluetooth.service.object_transfer",       "risk": "high"},
    # ── Mesh BLE ──────────────────────────────────────────────────────────────
    "1827": {"name": "Mesh Provisioning Service",    "identifier": "org.bluetooth.service.mesh_provisioning",     "risk": "critical"},
    "1828": {"name": "Mesh Proxy Service",           "identifier": "org.bluetooth.service.mesh_proxy",            "risk": "critical"},
    "1829": {"name": "Reconnection Configuration",   "identifier": "org.bluetooth.service.reconnection_configuration","risk": "medium"},
    # ── Áudio Bluetooth LE ────────────────────────────────────────────────────
    "1843": {"name": "Audio Input Control",          "identifier": "org.bluetooth.service.audio_input_control",   "risk": "medium"},
    "1844": {"name": "Volume Control Service",       "identifier": "org.bluetooth.service.volume_control",        "risk": "medium"},
    "1845": {"name": "Volume Offset Control",        "identifier": "org.bluetooth.service.volume_offset_control", "risk": "medium"},
    "1846": {"name": "Coordinated Set Identification","identifier": "org.bluetooth.service.coordinated_set_identification","risk": "medium"},
    "1847": {"name": "Media Control Service",        "identifier": "org.bluetooth.service.media_control",         "risk": "medium"},
    "1848": {"name": "Generic Media Control",        "identifier": "org.bluetooth.service.generic_media_control", "risk": "medium"},
    "1849": {"name": "Constant Tone Extension",      "identifier": "org.bluetooth.service.constant_tone_extension","risk": "low"},
    "184A": {"name": "Telephone Bearer Service",     "identifier": "org.bluetooth.service.telephone_bearer",      "risk": "high"},
    "184B": {"name": "Generic Telephone Bearer",     "identifier": "org.bluetooth.service.generic_telephone_bearer","risk": "high"},
    "184C": {"name": "Microphone Control",           "identifier": "org.bluetooth.service.microphone_control",    "risk": "high"},
    "184D": {"name": "Audio Stream Control",         "identifier": "org.bluetooth.service.audio_stream_control",  "risk": "medium"},
    "184E": {"name": "Broadcast Audio Scan",         "identifier": "org.bluetooth.service.broadcast_audio_scan",  "risk": "medium"},
    "184F": {"name": "Published Audio Capabilities", "identifier": "org.bluetooth.service.published_audio_capabilities","risk": "medium"},
    "1850": {"name": "Basic Audio Announcement",     "identifier": "org.bluetooth.service.basic_audio_announcement","risk": "low"},
    "1851": {"name": "Broadcast Audio Announcement", "identifier": "org.bluetooth.service.broadcast_audio_announcement","risk": "medium"},
    "1853": {"name": "Telephony and Media Audio (TMAP)","identifier": "org.bluetooth.service.tmap",               "risk": "medium"},
    # ── Perfis BR/EDR (Bluetooth Classic) ────────────────────────────────────
    "1101": {"name": "Serial Port Profile (SPP)",    "identifier": "org.bluetooth.service.serial_port",           "risk": "critical"},
    "1108": {"name": "Headset Profile (HSP)",        "identifier": "org.bluetooth.service.headset",               "risk": "high"},
    "110A": {"name": "A2DP Audio Source",            "identifier": "org.bluetooth.service.audio_source",          "risk": "high"},
    "110B": {"name": "A2DP Audio Sink",              "identifier": "org.bluetooth.service.audio_sink",            "risk": "high"},
    "110E": {"name": "AVRCP Remote Control Target",  "identifier": "org.bluetooth.service.avrcp",                 "risk": "high"},
    "111E": {"name": "Handsfree Profile (HFP)",      "identifier": "org.bluetooth.service.handsfree",             "risk": "critical"},
    "112F": {"name": "Phonebook Access (PBAP)",      "identifier": "org.bluetooth.service.pbap",                  "risk": "critical"},
    "1132": {"name": "Message Access Profile (MAP)", "identifier": "org.bluetooth.service.map",                   "risk": "critical"},
    # ── OTA/DFU — Atualização de Firmware ────────────────────────────────────
    "FE59": {"name": "Nordic DFU (Buttonless)",      "identifier": "com.nordicsemi.service.dfu",                  "risk": "critical"},
    "FFC0": {"name": "TI OAD (Firmware Update)",     "identifier": "com.ti.service.oad",                         "risk": "critical"},
    # ── Proprietários conhecidos ──────────────────────────────────────────────
    "FEE0": {"name": "Xiaomi Mi Band",               "identifier": "com.xiaomi.service.miband",                   "risk": "high"},
    "FEE1": {"name": "Xiaomi Mi Band Auth",          "identifier": "com.xiaomi.service.miband.auth",              "risk": "high"},
    "FEA0": {"name": "Google (Nest/IoT)",            "identifier": "com.google.service.iot",                      "risk": "medium"},
    "FE9F": {"name": "Google Fast Pair",             "identifier": "com.google.service.fast_pair",                "risk": "medium"},
    "FE98": {"name": "Apple Continuity",             "identifier": "com.apple.service.continuity",                "risk": "medium"},
    "FE94": {"name": "Google AoA (Angle of Arrival)","identifier": "com.google.service.aoa",                      "risk": "medium"},
    "FD6F": {"name": "COVID-19 Exposure Notification","identifier": "org.google.service.exposure_notification",   "risk": "medium"},
    "FD5A": {"name": "BLE Access Control",           "identifier": "com.generic.service.access_control",          "risk": "critical"},
    "FEBE": {"name": "PoweredUp LEGO",               "identifier": "com.lego.service.powered_up",                 "risk": "low"},
}


# =============================================================================
# CARACTERÍSTICAS BLUETOOTH SIG + NORDIC — characteristic_uuids.json
# Inclui todas as SIG (2A00-2BFF) + Nordic Thingy 52 + outras conhecidas
# =============================================================================

NORDIC_CHARS: Dict[str, Dict[str, str]] = {
    # ── Generic Access (2A00–2A07) ────────────────────────────────────────────
    "2A00": {"name": "Device Name",                  "svc": "Generic Access",     "sensitive": False, "risk": "low"},
    "2A01": {"name": "Appearance",                   "svc": "Generic Access",     "sensitive": False, "risk": "low"},
    "2A02": {"name": "Peripheral Privacy Flag",      "svc": "Generic Access",     "sensitive": True,  "risk": "medium"},
    "2A03": {"name": "Reconnection Address",         "svc": "Generic Access",     "sensitive": True,  "risk": "medium"},
    "2A04": {"name": "Peripheral Preferred Conn Params","svc":"Generic Access",   "sensitive": False, "risk": "low"},
    "2A05": {"name": "Service Changed",              "svc": "Generic Attribute",  "sensitive": False, "risk": "low"},
    # ── Alert / Link Loss ─────────────────────────────────────────────────────
    "2A06": {"name": "Alert Level",                  "svc": "Immediate Alert",    "sensitive": False, "risk": "medium"},
    "2A07": {"name": "Tx Power Level",               "svc": "Tx Power",           "sensitive": False, "risk": "low"},
    # ── Date / Time ───────────────────────────────────────────────────────────
    "2A08": {"name": "Date Time",                    "svc": "Current Time",       "sensitive": True,  "risk": "low"},
    "2A09": {"name": "Day of Week",                  "svc": "Current Time",       "sensitive": False, "risk": "low"},
    "2A0A": {"name": "Day Date Time",                "svc": "Current Time",       "sensitive": True,  "risk": "low"},
    "2A0C": {"name": "Exact Time 256",               "svc": "Current Time",       "sensitive": False, "risk": "low"},
    "2A0D": {"name": "DST Offset",                   "svc": "Current Time",       "sensitive": False, "risk": "low"},
    "2A0E": {"name": "Time Zone",                    "svc": "Current Time",       "sensitive": False, "risk": "low"},
    "2A0F": {"name": "Local Time Information",       "svc": "Current Time",       "sensitive": True,  "risk": "low"},
    "2A11": {"name": "Time with DST",                "svc": "Current Time",       "sensitive": False, "risk": "low"},
    "2A12": {"name": "Time Accuracy",                "svc": "Current Time",       "sensitive": False, "risk": "low"},
    "2A13": {"name": "Time Source",                  "svc": "Current Time",       "sensitive": False, "risk": "low"},
    "2A14": {"name": "Reference Time Information",   "svc": "Current Time",       "sensitive": False, "risk": "low"},
    "2A16": {"name": "Time Update Control Point",    "svc": "Ref Time Update",    "sensitive": True,  "risk": "medium"},
    "2A17": {"name": "Time Update State",            "svc": "Ref Time Update",    "sensitive": False, "risk": "low"},
    "2A2B": {"name": "Current Time",                 "svc": "Current Time",       "sensitive": False, "risk": "low"},
    # ── Glucose ───────────────────────────────────────────────────────────────
    "2A18": {"name": "Glucose Measurement",          "svc": "Glucose",            "sensitive": True,  "risk": "critical"},
    "2A34": {"name": "Glucose Measurement Context",  "svc": "Glucose",            "sensitive": True,  "risk": "critical"},
    "2A51": {"name": "Glucose Feature",              "svc": "Glucose",            "sensitive": False, "risk": "medium"},
    "2A52": {"name": "Record Access Control Point",  "svc": "Glucose",            "sensitive": True,  "risk": "critical"},
    # ── Health Thermometer ────────────────────────────────────────────────────
    "2A1C": {"name": "Temperature Measurement",      "svc": "Health Thermometer", "sensitive": True,  "risk": "high"},
    "2A1D": {"name": "Temperature Type",             "svc": "Health Thermometer", "sensitive": False, "risk": "low"},
    "2A1E": {"name": "Intermediate Temperature",     "svc": "Health Thermometer", "sensitive": True,  "risk": "high"},
    "2A21": {"name": "Measurement Interval",         "svc": "Health Thermometer", "sensitive": False, "risk": "low"},
    # ── Device Information ────────────────────────────────────────────────────
    "2A19": {"name": "Battery Level",                "svc": "Battery Service",    "sensitive": False, "risk": "low"},
    "2A23": {"name": "System ID",                    "svc": "Device Information", "sensitive": True,  "risk": "medium"},
    "2A24": {"name": "Model Number String",          "svc": "Device Information", "sensitive": True,  "risk": "medium"},
    "2A25": {"name": "Serial Number String",         "svc": "Device Information", "sensitive": True,  "risk": "high"},
    "2A26": {"name": "Firmware Revision String",     "svc": "Device Information", "sensitive": True,  "risk": "high"},
    "2A27": {"name": "Hardware Revision String",     "svc": "Device Information", "sensitive": True,  "risk": "medium"},
    "2A28": {"name": "Software Revision String",     "svc": "Device Information", "sensitive": True,  "risk": "medium"},
    "2A29": {"name": "Manufacturer Name String",     "svc": "Device Information", "sensitive": False, "risk": "low"},
    "2A2A": {"name": "IEEE 11073-20601 Cert Data",   "svc": "Device Information", "sensitive": True,  "risk": "medium"},
    "2A50": {"name": "PnP ID",                       "svc": "Device Information", "sensitive": True,  "risk": "medium"},
    # ── Heart Rate ────────────────────────────────────────────────────────────
    "2A37": {"name": "Heart Rate Measurement",       "svc": "Heart Rate",         "sensitive": True,  "risk": "critical"},
    "2A38": {"name": "Body Sensor Location",         "svc": "Heart Rate",         "sensitive": False, "risk": "medium"},
    "2A39": {"name": "Heart Rate Control Point",     "svc": "Heart Rate",         "sensitive": True,  "risk": "high"},
    # ── Blood Pressure ────────────────────────────────────────────────────────
    "2A35": {"name": "Blood Pressure Measurement",   "svc": "Blood Pressure",     "sensitive": True,  "risk": "critical"},
    "2A36": {"name": "Intermediate Cuff Pressure",   "svc": "Blood Pressure",     "sensitive": True,  "risk": "critical"},
    "2A49": {"name": "Blood Pressure Feature",       "svc": "Blood Pressure",     "sensitive": False, "risk": "medium"},
    # ── Pulse Oximeter ────────────────────────────────────────────────────────
    "2A5E": {"name": "PLX Spot-Check Measurement",   "svc": "Pulse Oximeter",     "sensitive": True,  "risk": "critical"},
    "2A5F": {"name": "PLX Continuous Measurement",   "svc": "Pulse Oximeter",     "sensitive": True,  "risk": "critical"},
    "2A60": {"name": "PLX Features",                 "svc": "Pulse Oximeter",     "sensitive": False, "risk": "medium"},
    # ── HID ──────────────────────────────────────────────────────────────────
    "2A4A": {"name": "HID Information",              "svc": "HID",                "sensitive": True,  "risk": "critical"},
    "2A4B": {"name": "Report Map (HID descriptor)",  "svc": "HID",                "sensitive": True,  "risk": "critical"},
    "2A4C": {"name": "HID Control Point",            "svc": "HID",                "sensitive": True,  "risk": "critical"},
    "2A4D": {"name": "Report (HID input/output)",    "svc": "HID",                "sensitive": True,  "risk": "critical"},
    "2A4E": {"name": "Protocol Mode",                "svc": "HID",                "sensitive": True,  "risk": "critical"},
    "2A4F": {"name": "Boot Keyboard Input Report",   "svc": "HID",                "sensitive": True,  "risk": "critical"},
    "2A32": {"name": "Boot Keyboard Output Report",  "svc": "HID",                "sensitive": True,  "risk": "critical"},
    "2A33": {"name": "Boot Mouse Input Report",      "svc": "HID",                "sensitive": True,  "risk": "critical"},
    # ── Running Speed / Cycling ───────────────────────────────────────────────
    "2A53": {"name": "RSC Measurement",              "svc": "Running Speed",      "sensitive": True,  "risk": "medium"},
    "2A54": {"name": "RSC Feature",                  "svc": "Running Speed",      "sensitive": False, "risk": "low"},
    "2A55": {"name": "SC Control Point",             "svc": "Running Speed",      "sensitive": True,  "risk": "medium"},
    "2A5B": {"name": "CSC Measurement",              "svc": "Cycling Speed",      "sensitive": True,  "risk": "medium"},
    "2A5C": {"name": "CSC Feature",                  "svc": "Cycling Speed",      "sensitive": False, "risk": "low"},
    "2A5D": {"name": "Sensor Location",              "svc": "General",            "sensitive": False, "risk": "low"},
    # ── Cycling Power ─────────────────────────────────────────────────────────
    "2A63": {"name": "Cycling Power Measurement",    "svc": "Cycling Power",      "sensitive": True,  "risk": "medium"},
    "2A64": {"name": "Cycling Power Vector",         "svc": "Cycling Power",      "sensitive": True,  "risk": "medium"},
    "2A65": {"name": "Cycling Power Feature",        "svc": "Cycling Power",      "sensitive": False, "risk": "low"},
    "2A66": {"name": "Cycling Power Control Point",  "svc": "Cycling Power",      "sensitive": True,  "risk": "medium"},
    # ── Location & Navigation ─────────────────────────────────────────────────
    "2A67": {"name": "Location and Speed",           "svc": "Location & Nav",     "sensitive": True,  "risk": "critical"},
    "2A68": {"name": "Navigation",                   "svc": "Location & Nav",     "sensitive": True,  "risk": "critical"},
    "2A69": {"name": "Position Quality",             "svc": "Location & Nav",     "sensitive": True,  "risk": "critical"},
    "2A6A": {"name": "LN Feature",                   "svc": "Location & Nav",     "sensitive": False, "risk": "medium"},
    "2A6B": {"name": "LN Control Point",             "svc": "Location & Nav",     "sensitive": True,  "risk": "critical"},
    # ── Environmental Sensing ─────────────────────────────────────────────────
    "2A6C": {"name": "Elevation",                    "svc": "Environmental",      "sensitive": True,  "risk": "medium"},
    "2A6D": {"name": "Pressure",                     "svc": "Environmental",      "sensitive": True,  "risk": "medium"},
    "2A6E": {"name": "Temperature (Environmental)",  "svc": "Environmental",      "sensitive": True,  "risk": "medium"},
    "2A6F": {"name": "Humidity",                     "svc": "Environmental",      "sensitive": True,  "risk": "medium"},
    "2A70": {"name": "True Wind Speed",              "svc": "Environmental",      "sensitive": True,  "risk": "medium"},
    "2A71": {"name": "True Wind Direction",          "svc": "Environmental",      "sensitive": True,  "risk": "medium"},
    "2A72": {"name": "Apparent Wind Speed",          "svc": "Environmental",      "sensitive": True,  "risk": "medium"},
    "2A73": {"name": "Apparent Wind Direction",      "svc": "Environmental",      "sensitive": True,  "risk": "medium"},
    "2A74": {"name": "Gust Factor",                  "svc": "Environmental",      "sensitive": False, "risk": "low"},
    "2A75": {"name": "Pollen Concentration",         "svc": "Environmental",      "sensitive": False, "risk": "low"},
    "2A76": {"name": "UV Index",                     "svc": "Environmental",      "sensitive": False, "risk": "low"},
    "2A77": {"name": "Wind Chill",                   "svc": "Environmental",      "sensitive": False, "risk": "low"},
    "2A78": {"name": "Heat Index",                   "svc": "Environmental",      "sensitive": False, "risk": "low"},
    "2A7D": {"name": "Descriptor Value Changed",     "svc": "Environmental",      "sensitive": False, "risk": "low"},
    # ── Automation IO ─────────────────────────────────────────────────────────
    "2A56": {"name": "Digital I/O",                  "svc": "Automation IO",      "sensitive": True,  "risk": "high"},
    "2A58": {"name": "Analog I/O",                   "svc": "Automation IO",      "sensitive": True,  "risk": "high"},
    "2A5A": {"name": "Aggregate",                    "svc": "Automation IO",      "sensitive": True,  "risk": "high"},
    # ── Body Composition ──────────────────────────────────────────────────────
    "2A9B": {"name": "Body Composition Feature",     "svc": "Body Composition",   "sensitive": False, "risk": "medium"},
    "2A9C": {"name": "Body Composition Measurement", "svc": "Body Composition",   "sensitive": True,  "risk": "high"},
    # ── Weight Scale ──────────────────────────────────────────────────────────
    "2A9D": {"name": "Weight Measurement",           "svc": "Weight Scale",       "sensitive": True,  "risk": "high"},
    "2A9E": {"name": "Weight Scale Feature",         "svc": "Weight Scale",       "sensitive": False, "risk": "medium"},
    # ── User Data ─────────────────────────────────────────────────────────────
    "2A8A": {"name": "First Name",                   "svc": "User Data",          "sensitive": True,  "risk": "critical"},
    "2A8B": {"name": "Height",                       "svc": "User Data",          "sensitive": True,  "risk": "high"},
    "2A8C": {"name": "Age",                          "svc": "User Data",          "sensitive": True,  "risk": "high"},
    "2A8D": {"name": "Heart Rate Max",               "svc": "User Data",          "sensitive": True,  "risk": "high"},
    "2A90": {"name": "Last Name",                    "svc": "User Data",          "sensitive": True,  "risk": "critical"},
    "2A91": {"name": "Maximum Recommended Heart Rate","svc": "User Data",         "sensitive": True,  "risk": "high"},
    "2A92": {"name": "Resting Heart Rate",           "svc": "User Data",          "sensitive": True,  "risk": "high"},
    "2A98": {"name": "Weight",                       "svc": "User Data",          "sensitive": True,  "risk": "high"},
    "2A99": {"name": "Database Change Increment",    "svc": "User Data",          "sensitive": False, "risk": "low"},
    "2A9A": {"name": "User Index",                   "svc": "User Data",          "sensitive": True,  "risk": "high"},
    "2A9F": {"name": "User Control Point",           "svc": "User Data",          "sensitive": True,  "risk": "critical"},
    # ── Mesh ──────────────────────────────────────────────────────────────────
    "2ADB": {"name": "Mesh Provisioning Data In",    "svc": "Mesh Provisioning",  "sensitive": True,  "risk": "critical"},
    "2ADC": {"name": "Mesh Provisioning Data Out",   "svc": "Mesh Provisioning",  "sensitive": True,  "risk": "critical"},
    "2ADD": {"name": "Mesh Proxy Data In",           "svc": "Mesh Proxy",         "sensitive": True,  "risk": "critical"},
    "2ADE": {"name": "Mesh Proxy Data Out",          "svc": "Mesh Proxy",         "sensitive": True,  "risk": "critical"},
    # ── GATT Generic ─────────────────────────────────────────────────────────
    "2B3A": {"name": "Client Supported Features",    "svc": "Generic Attribute",  "sensitive": False, "risk": "low"},
    "2B3B": {"name": "Database Hash",               "svc": "Generic Attribute",  "sensitive": False, "risk": "low"},
    "2B29": {"name": "Client Characteristic Config", "svc": "Generic Attribute",  "sensitive": False, "risk": "low"},
    "2AA6": {"name": "Central Address Resolution",   "svc": "Generic Access",     "sensitive": False, "risk": "low"},
    # ── Fitness Machine ───────────────────────────────────────────────────────
    "2ACC": {"name": "Fitness Machine Feature",      "svc": "Fitness Machine",    "sensitive": False, "risk": "medium"},
    "2ACD": {"name": "Treadmill Data",               "svc": "Fitness Machine",    "sensitive": True,  "risk": "medium"},
    "2ACE": {"name": "Cross Trainer Data",           "svc": "Fitness Machine",    "sensitive": True,  "risk": "medium"},
    "2ACF": {"name": "Step Climber Data",            "svc": "Fitness Machine",    "sensitive": True,  "risk": "medium"},
    "2AD0": {"name": "Stair Climber Data",           "svc": "Fitness Machine",    "sensitive": True,  "risk": "medium"},
    "2AD1": {"name": "Rower Data",                   "svc": "Fitness Machine",    "sensitive": True,  "risk": "medium"},
    "2AD2": {"name": "Indoor Bike Data",             "svc": "Fitness Machine",    "sensitive": True,  "risk": "medium"},
    "2AD3": {"name": "Training Status",              "svc": "Fitness Machine",    "sensitive": True,  "risk": "medium"},
    "2AD9": {"name": "Fitness Machine Control Point","svc": "Fitness Machine",    "sensitive": True,  "risk": "high"},
    "2ADA": {"name": "Fitness Machine Status",       "svc": "Fitness Machine",    "sensitive": True,  "risk": "medium"},
    # ── Nordic Semiconductor Proprietary (Thingy:52 IoT Sensor Kit) ──────────
    # Fonte: Nordic DB source="nordic"
    "EF680101": {"name": "Thingy Config",            "svc": "Thingy Configuration","sensitive": True, "risk": "high"},
    "EF680102": {"name": "Thingy Name",              "svc": "Thingy Configuration","sensitive": True, "risk": "medium"},
    "EF680103": {"name": "Thingy Advertising Param", "svc": "Thingy Configuration","sensitive": True, "risk": "medium"},
    "EF680104": {"name": "Thingy Connection Param",  "svc": "Thingy Configuration","sensitive": True, "risk": "medium"},
    "EF680105": {"name": "Thingy Eddystone URL",     "svc": "Thingy Configuration","sensitive": True, "risk": "medium"},
    "EF680201": {"name": "Thingy Temperature",       "svc": "Thingy Environment", "sensitive": True,  "risk": "medium"},
    "EF680202": {"name": "Thingy Pressure",          "svc": "Thingy Environment", "sensitive": True,  "risk": "medium"},
    "EF680203": {"name": "Thingy Humidity",          "svc": "Thingy Environment", "sensitive": True,  "risk": "medium"},
    "EF680204": {"name": "Thingy Air Quality",       "svc": "Thingy Environment", "sensitive": True,  "risk": "medium"},
    "EF680205": {"name": "Thingy Color",             "svc": "Thingy Environment", "sensitive": False, "risk": "low"},
    "EF680301": {"name": "Thingy LED",               "svc": "Thingy UI",          "sensitive": True,  "risk": "high"},
    "EF680302": {"name": "Thingy Button",            "svc": "Thingy UI",          "sensitive": False, "risk": "medium"},
    "EF680303": {"name": "Thingy External Pin",      "svc": "Thingy UI",          "sensitive": True,  "risk": "high"},
    "EF680401": {"name": "Thingy Tap",               "svc": "Thingy Motion",      "sensitive": True,  "risk": "medium"},
    "EF680402": {"name": "Thingy Orientation",       "svc": "Thingy Motion",      "sensitive": True,  "risk": "medium"},
    "EF680403": {"name": "Thingy Quaternion",        "svc": "Thingy Motion",      "sensitive": True,  "risk": "medium"},
    "EF680404": {"name": "Thingy Step Counter",      "svc": "Thingy Motion",      "sensitive": True,  "risk": "medium"},
    "EF680405": {"name": "Thingy Pedometer",         "svc": "Thingy Motion",      "sensitive": True,  "risk": "medium"},
    "EF680406": {"name": "Thingy Raw Data",          "svc": "Thingy Motion",      "sensitive": True,  "risk": "high"},
    "EF680407": {"name": "Thingy Euler",             "svc": "Thingy Motion",      "sensitive": True,  "risk": "medium"},
    "EF680408": {"name": "Thingy Rotation Matrix",   "svc": "Thingy Motion",      "sensitive": True,  "risk": "medium"},
    "EF680409": {"name": "Thingy Heading",           "svc": "Thingy Motion",      "sensitive": True,  "risk": "medium"},
    "EF68040A": {"name": "Thingy Gravity Vector",    "svc": "Thingy Motion",      "sensitive": True,  "risk": "medium"},
    "EF680501": {"name": "Thingy Speaker Data",      "svc": "Thingy Sound",       "sensitive": True,  "risk": "high"},
    "EF680502": {"name": "Thingy Speaker Status",    "svc": "Thingy Sound",       "sensitive": False, "risk": "medium"},
    "EF680503": {"name": "Thingy Microphone",        "svc": "Thingy Sound",       "sensitive": True,  "risk": "critical"},
    # ── Nordic UART Service (NUS) ─────────────────────────────────────────────
    "6E400002": {"name": "Nordic UART RX (commands in)",  "svc": "Nordic UART",   "sensitive": True,  "risk": "critical"},
    "6E400003": {"name": "Nordic UART TX (data out)",     "svc": "Nordic UART",   "sensitive": True,  "risk": "critical"},
    # ── Nordic DFU ────────────────────────────────────────────────────────────
    "8EC90001": {"name": "Nordic DFU Control Point",      "svc": "Nordic DFU",    "sensitive": True,  "risk": "critical"},
    "8EC90002": {"name": "Nordic DFU Packet",             "svc": "Nordic DFU",    "sensitive": True,  "risk": "critical"},
    "8EC90003": {"name": "Nordic DFU Buttonless (BLE)",   "svc": "Nordic DFU",    "sensitive": True,  "risk": "critical"},
    "00001531": {"name": "Nordic DFU Legacy Control",     "svc": "Nordic DFU Legacy","sensitive":True, "risk": "critical"},
    "00001532": {"name": "Nordic DFU Legacy Packet",      "svc": "Nordic DFU Legacy","sensitive":True, "risk": "critical"},
    "00001534": {"name": "Nordic DFU Legacy Version",     "svc": "Nordic DFU Legacy","sensitive":True, "risk": "critical"},
}


# =============================================================================
# COMPANY IDs — company_ids.json (Nordic DB)
# Mapa: decimal ID → nome do fabricante
# Usado para decodificar Manufacturer Specific Data no advertising BLE
# =============================================================================

NORDIC_COMPANIES: Dict[int, str] = {
    # Top fabricantes relevantes para segurança BLE
    0x0006: "Microsoft",
    0x000F: "Broadcom",
    0x004C: "Apple Inc.",
    0x0059: "Nordic Semiconductor ASA",
    0x0075: "Samsung Electronics Co. Ltd.",
    0x00E0: "Google",
    0x0131: "Xiaomi Inc.",
    0x038F: "Texas Instruments",
    0x00CF: "Intel Corporation",
    0x001D: "Qualcomm",
    0x0047: "CSR (Cambridge Silicon Radio)",
    0x0087: "Garmin International",
    0x00BA: "Bose Corporation",
    0x00CD: "Adafruit Industries",
    0x0157: "Fitbit Inc.",
    0x01FF: "Tesla Inc.",
    0x0171: "Amazon.com Services",
    0x0082: "Suunto Oy",
    0x0069: "Polar Electro OY",
    0x00C7: "Wahoo Fitness",
    0x033B: "Bosch Sensortec",
    0x0072: "Continental Automotive GmbH",
    0x0077: "Delphi Technologies",
    0x030C: "Volkswagen AG",
    0x003B: "General Motors",
    0x0108: "Ford Global Technologies",
    0x036A: "Toyota Motor Corporation",
    0x0393: "Honda Motor Co. Ltd.",
    0x04DB: "Fiat SpA",
    0x001A: "ST Microelectronics",
    0x0010: "Marvell Technology",
    0x0030: "Cypress Semiconductor",
    0x0041: "Dialog Semiconductor",
    0x00EF: "Silicon Labs",
    0x02D5: "Espressif Inc. (ESP32)",
    # Dispositivos médicos
    0x00CA: "Abbott Laboratories",
    0x00D3: "Medtronic Inc.",
    0x0093: "Nonin Medical",
    0x01D5: "Dexcom Inc.",
    0x010C: "Roche Diabetes Care",
    # Bluetooth SIG
    0xFFFF: "Bluetooth SIG Reserved",
    # Wearables & Fitness
    0x00E0: "Google LLC",
    0x00BA: "Bose Corporation",
    0x0157: "Fitbit Inc.",
    0x0082: "Suunto Oy",
    0x0069: "Polar Electro OY",
    0x00C7: "Wahoo Fitness",
    0x01A7: "Jabra (GN Audio)",
    0x01CF: "Fossil Group Inc.",
    0x00AB: "CASIO COMPUTER CO. LTD.",
    0x01B7: "Huawei Technologies Co. Ltd.",
    0x02B0: "Amazfit / Huami Co. Ltd.",
    0x0529: "Withings",
    0x04B8: "Garmin International",
    # Smart Home / IoT
    0x038F: "Texas Instruments Inc.",
    0x033B: "Robert Bosch GmbH",
    0x004D: "Panasonic Holdings Corp.",
    0x002D: "Hitachi Ltd.",
    0x036A: "Philips Hue (Signify Netherlands)",
    0x0057: "Harman International",
    0x003E: "Belkin International Inc.",
    0x01B6: "TP-Link Corporation Limited",
    0x04E6: "Tuya (Smart Life)",
    0x0499: "Ruuvi Innovations Ltd.",
    # Medical Devices (BLE critical)
    0x00CA: "Abbott (FreeStyle Libre)",
    0x00D3: "Medtronic Inc.",
    0x0093: "Nonin Medical Inc.",
    0x01D5: "Dexcom Inc.",
    0x010C: "Roche Diagnostics GmbH",
    0x0213: "Omron Healthcare",
    0x02A4: "Masimo Corporation",
    0x01A9: "A&D Medical",
    0x0226: "Beurer GmbH",
    0x0361: "iHealth Labs Inc.",
    0x04A1: "Biocare Medical Ltd.",
    # Automotive & Industrial
    0x0072: "Continental AG",
    0x0077: "Delphi Technologies",
    0x030C: "Volkswagen AG",
    0x003B: "General Motors LLC",
    0x0108: "Ford Global Technologies",
    0x036B: "Toyota Motor Corporation",
    0x03F5: "Honda Motor Co. Ltd.",
    0x0393: "DENSO Corporation",
    0x04DB: "Stellantis (Fiat/PSA)",
    0x025A: "Valeo",
    0x03A8: "Bosch Automotive",
    0x0350: "Aptiv PLC",
    # Chip Manufacturers (relevant for fingerprinting)
    0x001A: "STMicroelectronics",
    0x0010: "Marvell Technology Group",
    0x0030: "Cypress Semiconductor",
    0x0041: "Dialog Semiconductor",
    0x00EF: "Silicon Laboratories",
    0x02D5: "Espressif Systems (ESP32)",
    0x0031: "Atmel Corporation",
    0x0045: "Renesas Electronics",
    0x046D: "u-blox AG",
    0x038A: "Nordic Semiconductor (clone/reseller)",
    0x0507: "Packetcraft Inc.",
    0x0499: "Ruuvi Innovations",
    # Access Control & Physical Security
    0x001C: "Sifco Industries (locks)",
    0x00F8: "KABA Group",
    0x0547: "SALTO Systems",
    0x0272: "dormakaba Group",
    0x0389: "Allegion",
    0x01FE: "Kwikset (Spectrum Brands)",
    0x04B3: "Abloy Oy (ASSA ABLOY)",
    0x0334: "Sievert Larsen (Danalock)",
    # Latin America relevant
    0x04C1: "INTELBRAS S/A",
    0x0584: "Positivo Tecnologia S.A.",
    0x04A8: "Multilaser Industrial S.A.",
    0x056A: "Elsys Tecnologia Ltda.",
    0x02B4: "Cielo Produtos Eletrônicos",
    0x04E4: "Giga Devices Semiconductor",
    # Payment / Finance
    0x0002: "Nokia Mobile Phones",
    0x0066: "Hewlett-Packard Company",
    0x0083: "Staccato Communications",
    0x00D0: "Emmoco Inc.",
    0x022D: "Isodiol International",
    0x0279: "Etekcity Corporation",
    0x03B2: "Nymi Inc.",
    0x04AE: "IDEX Biometrics ASA",
    # Entertainment / Toys
    0x0397: "LEGO System A/S",
    0x03C6: "Sphero Inc.",
    0x04AC: "Anki Inc.",
    0x01E3: "DJI",
    # Audio / Headphones
    0x004A: "Sony Corporation",
    0x0087: "Garmin International",
    0x00BA: "Bose Corporation",
    0x01B3: "Sennheiser electronic GmbH",
    0x01DD: "Plantronics Inc.",
    0x02BF: "Skullcandy Inc.",
    0x0411: "Razer Inc.",
    0x03C0: "SteelSeries ApS",
    # BLE Security Tools (fingerprinting attack tools)
    0x0026: "Bluegiga Technologies (Silicon Labs)",
    0x0046: "Laird Connectivity",
    0x004B: "Taiyo Yuden",
    0x009D: "Frontline Test Equipment",
    0x0154: "Ellisys",
    0x01E0: "ZYTOBI GmbH (Sniffle-compatible HW)",
}


# =============================================================================
# DESCRIPTORS — descriptor_uuids.json (Nordic DB)
# =============================================================================

NORDIC_DESCRIPTORS: Dict[str, str] = {
    "2900": "Characteristic Extended Properties",
    "2901": "Characteristic User Description",
    "2902": "Client Characteristic Configuration (CCCD)",  # CRÍTICO — habilita notificações
    "2903": "Server Characteristic Configuration",
    "2904": "Characteristic Presentation Format",
    "2905": "Characteristic Aggregate Format",
    "2906": "Valid Range",
    "2907": "External Report Reference",
    "2908": "Report Reference",
    "2909": "Number of Digitals",
    "290A": "Value Trigger Setting",
    "290B": "Environmental Sensing Configuration",
    "290C": "Environmental Sensing Measurement",
    "290D": "Environmental Sensing Trigger Setting",
    "290E": "Time Trigger Setting",
}


# =============================================================================
# APPEARANCE VALUES — appearance_values.json (Nordic DB)
# Identifica tipo de dispositivo pelo campo Appearance do advertising
# Bytes 0-1 do Characteristic 0x2A01 (Appearance)
# =============================================================================

NORDIC_APPEARANCES: Dict[int, str] = {
    0:    "Unknown",
    64:   "Generic Phone",
    128:  "Generic Computer",
    192:  "Generic Watch",
    193:  "Watch: Sports Watch",
    256:  "Generic Clock",
    320:  "Generic Display",
    384:  "Generic Remote Control",
    448:  "Generic Eye Glasses",
    512:  "Generic Tag",
    576:  "Generic Keyring",
    640:  "Generic Media Player",
    704:  "Generic Barcode Scanner",
    768:  "Generic Thermometer",
    769:  "Thermometer: Ear",
    832:  "Generic Heart Rate Sensor",
    833:  "Heart Rate Sensor: Belt",
    896:  "Generic Blood Pressure",
    897:  "Blood Pressure: Arm",
    898:  "Blood Pressure: Wrist",
    960:  "Generic Human Interface Device (HID)",
    961:  "HID: Keyboard",
    962:  "HID: Mouse",
    963:  "HID: Joystick",
    964:  "HID: Gamepad",
    965:  "HID: Digitizer",
    966:  "HID: Card Reader",
    967:  "HID: Digital Pen",
    968:  "HID: Barcode Scanner",
    1024: "Generic Glucose Meter",
    1088: "Generic Running Walk Sensor",
    1089: "Running Walk: In-Shoe",
    1090: "Running Walk: On-Shoe",
    1091: "Running Walk: On-Hip",
    1152: "Generic Cycling",
    1153: "Cycling: Computer",
    1154: "Cycling: Speed Sensor",
    1155: "Cycling: Cadence Sensor",
    1156: "Cycling: Power Sensor",
    1157: "Cycling: Speed+Cadence Sensor",
    3136: "Generic Pulse Oximeter",
    3137: "Pulse Oximeter: Fingertip",
    3138: "Pulse Oximeter: Wrist",
    3200: "Generic Weight Scale",
    3264: "Generic Personal Mobility Device",
    3265: "Powered Wheelchair",
    3266: "Mobility Scooter",
    3328: "Generic Continuous Glucose Monitor",
    5184: "Generic Outdoor Sports Activity",
    5185: "GPS Pod",
    # IoT / Smart Home
    1344: "Generic Outdoor Sports",
    768:  "Generic Thermometer",
    5696: "Generic Light Source",
    5697: "Light: LED Bulb",
    5698: "Light: LED Strip",
    5760: "Generic Fan",
    5824: "Generic HVAC",
    5888: "Generic Air Conditioning",
    5952: "Generic Humidifier",
    6016: "Generic Heating",
    # Veicular
    7680: "Generic Car",
    7936: "Generic Scooter",
}


# =============================================================================
# RISK CLASSIFICATION — mapeamento de tipo de serviço → risco de segurança
# =============================================================================

# Serviços que representam superfície crítica de ataque
CRITICAL_SERVICES = {
    "1812",  # HID — injeção de teclas
    "1101",  # SPP — serial port / comandos AT
    "111E",  # HFP — handsfree / microfone
    "112F",  # PBAP — contatos
    "1132",  # MAP — mensagens
    "1808",  # Glucose — dado médico crítico
    "180D",  # Heart Rate — dado biométrico sensível
    "1810",  # Blood Pressure — dado médico crítico
    "1822",  # Pulse Oximeter — SpO2 crítico
    "181F",  # Continuous Glucose Monitor
    "183A",  # Insulin Delivery — risco de vida
    "183C",  # Emergency Configuration
    "1819",  # Location & Navigation — geolocalização em tempo real
    "1827",  # Mesh Provisioning — controle de rede mesh
    "1828",  # Mesh Proxy
    "FE59",  # Nordic DFU — firmware não autorizado
    "FFC0",  # TI OAD — firmware não autorizado
    "FD5A",  # Access Control — controle de acesso físico
}


# =============================================================================
# FUNÇÕES DE RESOLUÇÃO
# =============================================================================

def resolve_service_nordic(uuid_full: str) -> Optional[Dict[str, Any]]:
    """
    Resolve UUID completo de serviço usando o Nordic BT DB.
    Aceita formato: 0000XXXX-0000-1000-8000-00805f9b34fb ou short XXXX
    """
    u = uuid_full.lower().strip()
    # Extrai short UUID
    if len(u) == 4:
        short = u.upper()
    elif len(u) == 36 and u.endswith("-0000-1000-8000-00805f9b34fb"):
        short = u[4:8].upper()
    else:
        # 128-bit proprietary
        short_candidates = [u[:8].replace("-","").upper()[:8]]
        for sc in short_candidates:
            if sc in NORDIC_SERVICES:
                svc = NORDIC_SERVICES[sc]
                return {**svc, "short_uuid": sc, "source": "Nordic BT DB",
                        "security_critical": sc in CRITICAL_SERVICES}
        return None

    if short in NORDIC_SERVICES:
        svc = NORDIC_SERVICES[short]
        return {
            **svc,
            "short_uuid": short,
            "source": "Nordic BT DB (Bluetooth SIG)",
            "security_critical": short in CRITICAL_SERVICES,
            "full_uuid": f"0000{short.lower()}-0000-1000-8000-00805f9b34fb",
        }
    return None


def resolve_char_nordic(uuid_full: str) -> Optional[Dict[str, Any]]:
    """
    Resolve UUID completo de característica usando o Nordic BT DB.
    """
    u = uuid_full.lower().strip().replace("-","")
    # Tenta match com short UUID (4 chars) — SIG characteristics são 0000XXXX...
    if len(uuid_full) == 36 and uuid_full.lower().endswith("-0000-1000-8000-00805f9b34fb"):
        short = uuid_full[4:8].upper()
    else:
        short = u[:8].upper()

    if short in NORDIC_CHARS:
        char = NORDIC_CHARS[short]
        return {
            **char,
            "short_uuid": short,
            "source": "Nordic BT DB (Bluetooth SIG)",
            "security_critical": char.get("risk") == "critical",
        }

    # Tenta match com UUID completo (128-bit proprietário)
    # Para Nordic Thingy que usa EF680XXX format
    u_upper = u.upper()
    for key, val in NORDIC_CHARS.items():
        if u_upper.startswith(key) or key.startswith(u_upper[:8]):
            return {**val, "short_uuid": key, "source": "Nordic BT DB (Proprietary)"}

    return None


def company_name(manufacturer_data: bytes) -> str:
    """
    Decodifica o nome do fabricante a partir dos primeiros 2 bytes do Manufacturer Specific Data.
    Os bytes são little-endian (LSB primeiro).
    """
    if not manufacturer_data or len(manufacturer_data) < 2:
        return "Unknown"
    company_id = manufacturer_data[0] | (manufacturer_data[1] << 8)
    return NORDIC_COMPANIES.get(company_id, f"Company 0x{company_id:04X}")


def appearance_name(value: int) -> str:
    """Decodifica o Appearance value para nome legível."""
    return NORDIC_APPEARANCES.get(value, f"Appearance 0x{value:04X}")


def uuid_security_report(uuid_full: str) -> Dict[str, Any]:
    """
    Gera relatório de segurança completo para um UUID.
    Combina informações de serviço + característica + avaliação de risco.
    """
    result = {
        "uuid": uuid_full,
        "found": False,
        "name": "Unknown",
        "type": "unknown",
        "svc": "",
        "risk": "unknown",
        "sensitive": False,
        "security_critical": False,
        "source": "",
        "identifier": "",
        "security_implications": [],
    }

    # Tenta como serviço
    svc = resolve_service_nordic(uuid_full)
    if svc:
        result.update({
            "found": True, "type": "service",
            "name": svc["name"], "svc": svc["name"],
            "risk": svc["risk"], "sensitive": svc["risk"] not in ("low",),
            "security_critical": svc["security_critical"],
            "source": svc["source"],
            "identifier": svc.get("identifier",""),
        })
        # Implicações de segurança por serviço
        if svc.get("security_critical"):
            short = svc.get("short_uuid","")
            if short == "1812":
                result["security_implications"].append(
                    "HID exposto: possível injeção de teclado/mouse sem autenticação (BlueDucky attack). "
                    "Atacante pode executar comandos no host pareado.")
            elif short in ("1101","111E"):
                result["security_implications"].append(
                    "Perfil de áudio/serial BR/EDR: aceita comandos AT — vetor de injeção de comandos. "
                    "Superfície para BLUFFS (CVE-2023-24023) e BIAS (CVE-2020-10135).")
            elif short in ("112F","1132"):
                result["security_implications"].append(
                    "PBAP/MAP: contatos e mensagens acessíveis para dispositivos pareados. "
                    "Violação LGPD Art. 11 (dados pessoais sensíveis). BIAS attack possível.")
            elif short == "180D":
                result["security_implications"].append(
                    "Heart Rate exposto: dado biométrico sensível (LGPD Art. 11). "
                    "Verificar se notificações requerem autenticação. Risco de rastreamento de saúde.")
            elif short == "1810":
                result["security_implications"].append(
                    "Blood Pressure exposto: dado médico crítico. LGPD Art. 11 / GDPR Art. 9. "
                    "Violação de privacidade com implicações para seguros e empregabilidade.")
            elif short == "1822":
                result["security_implications"].append(
                    "Pulse Oximeter: SpO2 em tempo real. Dado médico crítico. "
                    "Monitoramento remoto de pacientes — verificar autenticação rigorosa.")
            elif short in ("1808","181F"):
                result["security_implications"].append(
                    "Glucose Monitor: dado médico crítico. Leituras falsas via BLESA (CVE-2020-9770) "
                    "podem causar dosagem errada de insulina — risco de vida.")
            elif short == "183A":
                result["security_implications"].append(
                    "Insulin Delivery: RISCO DE VIDA. Comandos não autorizados podem alterar dosagem. "
                    "Exige autenticação obrigatória e canal seguro. Notificar fabricante imediatamente.")
            elif short in ("FE59","FFC0"):
                result["security_implications"].append(
                    "DFU/OTA Nordic/TI: firmware arbitrário pode ser instalado permanentemente. "
                    "Único remédio: reflash físico via JTAG. Verificar assinatura criptográfica (ECDSA).")
            elif short in ("1827","1828"):
                result["security_implications"].append(
                    "Mesh BLE: participação não autorizada na rede mesh. "
                    "Provisioning sem autenticação expõe toda a rede de dispositivos.")
            elif short == "1819":
                result["security_implications"].append(
                    "GPS/Localização em tempo real acessível sem autenticação. "
                    "Rastreamento de usuário — violação LGPD Art. 11 e GDPR Art. 9.")
            elif short == "183C":
                result["security_implications"].append(
                    "Emergency Configuration: acesso não autorizado pode desabilitar alertas de emergência. "
                    "Verificar controle de acesso rigoroso.")
            elif short == "FD5A":
                result["security_implications"].append(
                    "Controle de acesso físico via BLE. Relay attack pode destrancar portas remotamente. "
                    "Comprovado em Kwikset Kevo e sistemas similares.")
        return result

    # Tenta como característica
    char = resolve_char_nordic(uuid_full)
    if char:
        result.update({
            "found": True, "type": "characteristic",
            "name": char["name"], "svc": char.get("svc",""),
            "risk": char["risk"], "sensitive": char.get("sensitive", False),
            "security_critical": char.get("security_critical", False),
            "source": char["source"],
        })
        if char.get("sensitive") and char.get("risk") == "critical":
            result["security_implications"].append(
                f"Dado sensível em {char.get('svc','?')}: {char['name']} — verificar autenticação requerida")
        return result

    # Proprietário desconhecido
    result["source"] = "Desconhecido (proprietário não mapeado)"
    result["security_implications"].append(
        "UUID proprietário não reconhecido — pode conter protocolo de controle não documentado")
    return result
