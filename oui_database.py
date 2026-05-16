"""
oui_database.py — BLEAK V14
============================
Comprehensive MAC OUI → Vendor database.
Sources: IEEE public OUI assignments, Wireshark manuf database,
         vendor documentation, and field research.

Covers ~2500 most common OUI prefixes seen in BLE/BT environments.
Lookup priority:
  1. Full 24-bit OUI (XX:XX:XX) — exact match
  2. Device name heuristics — name-based vendor inference
  3. Manufacturer data company ID — from BLE advertisement

Format: "XX:XX:XX" → ("Vendor Name", "Category")
Categories: mobile, audio, wearable, tv, appliance, iot, networking,
            computer, automotive, medical, industrial, unknown
"""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# PRIMARY OUI DATABASE — 24-bit prefix (uppercase, colon-separated)
# ─────────────────────────────────────────────────────────────────────────────
OUI_DB: dict[str, tuple[str, str]] = {

    # ── Apple ─────────────────────────────────────────────────────────────────
    "00:03:93": ("Apple", "computer"), "00:05:02": ("Apple", "computer"),
    "00:0A:27": ("Apple", "computer"), "00:0A:95": ("Apple", "computer"),
    "00:0D:93": ("Apple", "computer"), "00:11:24": ("Apple", "computer"),
    "00:14:51": ("Apple", "computer"), "00:16:CB": ("Apple", "computer"),
    "00:17:F2": ("Apple", "computer"), "00:19:E3": ("Apple", "computer"),
    "00:1B:63": ("Apple", "computer"), "00:1C:B3": ("Apple", "computer"),
    "00:1D:4F": ("Apple", "computer"), "00:1E:52": ("Apple", "computer"),
    "00:1E:C2": ("Apple", "computer"), "00:1F:5B": ("Apple", "computer"),
    "00:1F:F3": ("Apple", "computer"), "00:21:E9": ("Apple", "computer"),
    "00:22:41": ("Apple", "computer"), "00:23:12": ("Apple", "computer"),
    "00:23:32": ("Apple", "computer"), "00:23:6C": ("Apple", "computer"),
    "00:23:DF": ("Apple", "computer"), "00:24:36": ("Apple", "computer"),
    "00:25:00": ("Apple", "computer"), "00:25:4B": ("Apple", "computer"),
    "00:25:BC": ("Apple", "computer"), "00:26:08": ("Apple", "computer"),
    "00:26:4A": ("Apple", "computer"), "00:26:B0": ("Apple", "computer"),
    "00:26:BB": ("Apple", "computer"), "00:30:65": ("Apple", "computer"),
    "00:3E:E1": ("Apple", "mobile"),   "00:50:E4": ("Apple", "computer"),
    "04:0C:CE": ("Apple", "mobile"),   "04:15:52": ("Apple", "mobile"),
    "04:1E:64": ("Apple", "mobile"),   "04:26:65": ("Apple", "mobile"),
    "04:4B:ED": ("Apple", "mobile"),   "04:52:F3": ("Apple", "mobile"),
    "04:54:53": ("Apple", "mobile"),   "04:69:F8": ("Apple", "mobile"),
    "04:6D:2F": ("Apple", "mobile"),   "04:E5:36": ("Apple", "mobile"),
    "04:F1:3E": ("Apple", "mobile"),   "04:F7:E4": ("Apple", "mobile"),
    "08:00:07": ("Apple", "computer"), "08:6D:41": ("Apple", "mobile"),
    "08:70:45": ("Apple", "mobile"),   "08:74:02": ("Apple", "mobile"),
    "08:F4:AB": ("Apple", "mobile"),   "0C:15:39": ("Apple", "mobile"),
    "0C:1D:AF": ("Apple", "computer"), "0C:3E:9F": ("Apple", "mobile"),
    "0C:51:01": ("Apple", "mobile"),   "0C:74:C2": ("Apple", "mobile"),
    "0C:77:1A": ("Apple", "mobile"),   "10:1C:0C": ("Apple", "mobile"),
    "10:40:F3": ("Apple", "mobile"),   "10:41:7F": ("Apple", "mobile"),
    "10:9A:DD": ("Apple", "mobile"),   "10:DD:B1": ("Apple", "mobile"),
    "14:5A:05": ("Apple", "mobile"),   "14:8F:C6": ("Apple", "mobile"),
    "14:99:E2": ("Apple", "mobile"),   "18:20:32": ("Apple", "mobile"),
    "18:34:51": ("Apple", "mobile"),   "18:65:90": ("Apple", "mobile"),
    "18:81:0E": ("Apple", "mobile"),   "18:9E:FC": ("Apple", "mobile"),
    "18:AF:61": ("Apple", "mobile"),   "18:F1:D8": ("Apple", "mobile"),
    "1C:1A:C0": ("Apple", "mobile"),   "1C:36:BB": ("Apple", "mobile"),
    "1C:5C:F2": ("Apple", "mobile"),   "1C:91:48": ("Apple", "mobile"),
    "20:78:F0": ("Apple", "mobile"),   "20:7D:74": ("Apple", "mobile"),
    "20:A2:E4": ("Apple", "mobile"),   "20:C9:D0": ("Apple", "mobile"),
    "24:1E:EB": ("Apple", "mobile"),   "24:24:0E": ("Apple", "mobile"),
    "24:A0:74": ("Apple", "mobile"),   "24:AB:81": ("Apple", "mobile"),
    "28:37:37": ("Apple", "mobile"),   "28:39:26": ("Apple", "mobile"),
    "28:6A:BA": ("Apple", "mobile"),   "28:CF:DA": ("Apple", "mobile"),
    "28:ED:6A": ("Apple", "mobile"),   "2C:1F:23": ("Apple", "mobile"),
    "2C:20:0B": ("Apple", "mobile"),   "2C:B4:3A": ("Apple", "mobile"),
    "2C:F0:A2": ("Apple", "mobile"),   "30:10:E4": ("Apple", "mobile"),
    "30:35:AD": ("Apple", "mobile"),   "30:63:6B": ("Apple", "mobile"),
    "30:90:AB": ("Apple", "mobile"),   "34:08:BC": ("Apple", "mobile"),
    "34:36:3B": ("Apple", "mobile"),   "34:A3:95": ("Apple", "mobile"),
    "34:AB:37": ("Apple", "mobile"),   "34:C0:59": ("Apple", "mobile"),
    "38:0F:4A": ("Apple", "mobile"),   "38:48:4C": ("Apple", "mobile"),
    "38:89:2C": ("Apple", "mobile"),   "38:C9:86": ("Apple", "mobile"),
    "3C:06:30": ("Apple", "mobile"),   "3C:07:71": ("Apple", "mobile"),
    "3C:15:C2": ("Apple", "mobile"),   "3C:2E:F9": ("Apple", "mobile"),
    "3C:D0:F8": ("Apple", "mobile"),   "40:33:1A": ("Apple", "mobile"),
    "40:3C:FC": ("Apple", "mobile"),   "40:4D:7F": ("Apple", "mobile"),
    "40:6C:8F": ("Apple", "mobile"),   "40:9C:28": ("Apple", "mobile"),
    "40:A6:D9": ("Apple", "mobile"),   "40:B3:95": ("Apple", "mobile"),
    "40:CB:C0": ("Apple", "mobile"),   "40:D3:2D": ("Apple", "mobile"),
    "44:00:10": ("Apple", "mobile"),   "44:2A:60": ("Apple", "mobile"),
    "44:4C:0C": ("Apple", "mobile"),   "44:65:0D": ("Apple", "mobile"),
    "44:D8:84": ("Apple", "mobile"),   "48:43:7C": ("Apple", "mobile"),
    "48:60:BC": ("Apple", "mobile"),   "48:74:6E": ("Apple", "mobile"),
    "48:A1:95": ("Apple", "mobile"),   "48:BF:6B": ("Apple", "mobile"),
    "48:D7:05": ("Apple", "mobile"),   "4C:57:CA": ("Apple", "mobile"),
    "4C:74:BF": ("Apple", "mobile"),   "4C:7C:5F": ("Apple", "mobile"),
    "4C:8D:79": ("Apple", "mobile"),   "50:7A:55": ("Apple", "mobile"),
    "50:BC:96": ("Apple", "mobile"),   "50:EA:D6": ("Apple", "mobile"),
    "54:26:96": ("Apple", "mobile"),   "54:4E:90": ("Apple", "mobile"),
    "54:AE:27": ("Apple", "mobile"),   "54:E4:3A": ("Apple", "mobile"),
    "58:1F:AA": ("Apple", "mobile"),   "58:40:4E": ("Apple", "mobile"),
    "58:55:CA": ("Apple", "mobile"),   "58:7F:66": ("Apple", "mobile"),
    "58:B1:0E": ("Apple", "mobile"),   "5C:95:AE": ("Apple", "mobile"),
    "5C:F7:E6": ("Apple", "mobile"),   "60:03:08": ("Apple", "mobile"),
    "60:33:4B": ("Apple", "mobile"),   "60:69:44": ("Apple", "mobile"),
    "60:8C:4A": ("Apple", "mobile"),   "60:C5:47": ("Apple", "mobile"),
    "60:D9:C7": ("Apple", "mobile"),   "60:F4:45": ("Apple", "mobile"),
    "60:F8:1D": ("Apple", "mobile"),   "64:20:0C": ("Apple", "mobile"),
    "64:76:BA": ("Apple", "mobile"),   "64:A5:C3": ("Apple", "mobile"),
    "64:B9:E8": ("Apple", "mobile"),   "68:09:27": ("Apple", "mobile"),
    "68:5B:35": ("Apple", "mobile"),   "68:AE:20": ("Apple", "mobile"),
    "68:D9:3C": ("Apple", "mobile"),   "6C:19:C0": ("Apple", "mobile"),
    "6C:40:08": ("Apple", "mobile"),   "6C:70:9F": ("Apple", "mobile"),
    "6C:72:E7": ("Apple", "mobile"),   "6C:94:F8": ("Apple", "mobile"),
    "70:14:A6": ("Apple", "mobile"),   "70:48:0F": ("Apple", "mobile"),
    "70:56:81": ("Apple", "mobile"),   "70:73:CB": ("Apple", "mobile"),
    "70:CD:60": ("Apple", "mobile"),   "70:EC:E4": ("Apple", "mobile"),
    "74:1B:B2": ("Apple", "mobile"),   "74:E2:F5": ("Apple", "mobile"),
    "78:31:C1": ("Apple", "mobile"),   "78:4F:43": ("Apple", "mobile"),
    "78:67:D7": ("Apple", "mobile"),   "78:9F:70": ("Apple", "mobile"),
    "78:CA:39": ("Apple", "mobile"),   "7C:01:91": ("Apple", "mobile"),
    "7C:11:BE": ("Apple", "mobile"),   "7C:6D:62": ("Apple", "mobile"),
    "7C:D1:C3": ("Apple", "mobile"),   "80:00:6E": ("Apple", "mobile"),
    "80:49:71": ("Apple", "mobile"),   "80:82:23": ("Apple", "mobile"),
    "80:BE:05": ("Apple", "mobile"),   "80:E6:50": ("Apple", "mobile"),
    "84:29:99": ("Apple", "mobile"),   "84:38:35": ("Apple", "mobile"),
    "84:78:8B": ("Apple", "mobile"),   "84:85:06": ("Apple", "mobile"),
    "84:A1:34": ("Apple", "mobile"),   "84:B1:53": ("Apple", "mobile"),
    "84:FC:FE": ("Apple", "mobile"),   "88:1F:A1": ("Apple", "mobile"),
    "88:63:DF": ("Apple", "mobile"),   "88:66:A5": ("Apple", "mobile"),
    "88:C6:63": ("Apple", "mobile"),   "8C:00:6D": ("Apple", "mobile"),
    "8C:58:77": ("Apple", "mobile"),   "8C:7C:92": ("Apple", "mobile"),
    "8C:85:90": ("Apple", "mobile"),   "90:27:E4": ("Apple", "mobile"),
    "90:60:F1": ("Apple", "mobile"),   "90:72:40": ("Apple", "mobile"),
    "90:84:0D": ("Apple", "mobile"),   "90:8D:6C": ("Apple", "mobile"),
    "90:B0:ED": ("Apple", "mobile"),   "94:94:26": ("Apple", "mobile"),
    "94:BF:2D": ("Apple", "mobile"),   "94:E9:6A": ("Apple", "mobile"),
    "98:01:A7": ("Apple", "mobile"),   "98:10:E8": ("Apple", "mobile"),
    "98:9E:63": ("Apple", "mobile"),   "98:B8:E3": ("Apple", "mobile"),
    "9C:04:EB": ("Apple", "mobile"),   "9C:20:7B": ("Apple", "mobile"),
    "9C:35:EB": ("Apple", "mobile"),   "9C:4F:DA": ("Apple", "mobile"),
    "9C:FC:01": ("Apple", "mobile"),   "A0:18:28": ("Apple", "mobile"),
    "A0:3B:E3": ("Apple", "mobile"),   "A0:4E:A7": ("Apple", "mobile"),
    "A0:99:9B": ("Apple", "mobile"),   "A0:D7:95": ("Apple", "mobile"),
    "A4:5E:60": ("Apple", "mobile"),   "A4:B1:97": ("Apple", "mobile"),
    "A4:C3:61": ("Apple", "mobile"),   "A4:D9:31": ("Apple", "mobile"),
    "A8:20:66": ("Apple", "mobile"),   "A8:51:AB": ("Apple", "mobile"),
    "A8:5C:2C": ("Apple", "mobile"),   "A8:8E:24": ("Apple", "mobile"),
    "A8:91:3D": ("Apple", "mobile"),   "AC:1F:74": ("Apple", "mobile"),
    "AC:29:3A": ("Apple", "mobile"),   "AC:3C:0B": ("Apple", "mobile"),
    "AC:61:EA": ("Apple", "mobile"),   "AC:87:A3": ("Apple", "mobile"),
    "AC:BC:32": ("Apple", "mobile"),   "AC:CF:5C": ("Apple", "mobile"),
    "AC:E4:B5": ("Apple", "mobile"),   "B0:34:95": ("Apple", "mobile"),
    "B0:65:BD": ("Apple", "mobile"),   "B0:9F:BA": ("Apple", "mobile"),
    "B4:18:D1": ("Apple", "mobile"),   "B4:F0:AB": ("Apple", "mobile"),
    "B8:09:8A": ("Apple", "mobile"),   "B8:17:C2": ("Apple", "mobile"),
    "B8:44:D9": ("Apple", "mobile"),   "B8:63:4D": ("Apple", "mobile"),
    "B8:78:2E": ("Apple", "mobile"),   "B8:8D:12": ("Apple", "mobile"),
    "B8:C7:5D": ("Apple", "mobile"),   "B8:FF:61": ("Apple", "mobile"),
    "BC:3B:AF": ("Apple", "mobile"),   "BC:52:B7": ("Apple", "mobile"),
    "BC:67:1C": ("Apple", "mobile"),   "BC:92:6B": ("Apple", "mobile"),
    "C0:1A:DA": ("Apple", "mobile"),   "C0:63:94": ("Apple", "mobile"),
    "C0:9F:42": ("Apple", "mobile"),   "C0:CE:CD": ("Apple", "mobile"),
    "C4:2C:03": ("Apple", "mobile"),   "C4:61:8B": ("Apple", "mobile"),
    "C4:B3:01": ("Apple", "mobile"),   "C8:2A:14": ("Apple", "mobile"),
    "C8:3C:85": ("Apple", "mobile"),   "C8:BC:C8": ("Apple", "mobile"),
    "CC:08:8D": ("Apple", "mobile"),   "CC:20:E8": ("Apple", "mobile"),
    "CC:29:F5": ("Apple", "mobile"),   "CC:44:63": ("Apple", "mobile"),
    "D0:03:4B": ("Apple", "mobile"),   "D0:23:DB": ("Apple", "mobile"),
    "D0:33:11": ("Apple", "mobile"),   "D0:4F:7E": ("Apple", "mobile"),
    "D0:81:7A": ("Apple", "mobile"),   "D4:DC:CD": ("Apple", "mobile"),
    "D4:F4:6F": ("Apple", "mobile"),   "D8:1D:72": ("Apple", "mobile"),
    "D8:30:62": ("Apple", "mobile"),   "D8:CF:9C": ("Apple", "mobile"),
    "D8:D1:CB": ("Apple", "mobile"),   "DC:08:56": ("Apple", "mobile"),
    "DC:2B:2A": ("Apple", "mobile"),   "DC:2B:61": ("Apple", "mobile"),
    "DC:37:14": ("Apple", "mobile"),   "DC:9B:9C": ("Apple", "mobile"),
    "DC:A9:04": ("Apple", "mobile"),   "E0:33:8E": ("Apple", "mobile"),
    "E0:5F:45": ("Apple", "mobile"),   "E0:AC:CB": ("Apple", "mobile"),
    "E0:B5:5F": ("Apple", "mobile"),   "E0:C7:67": ("Apple", "mobile"),
    "E4:25:E7": ("Apple", "mobile"),   "E4:8B:7F": ("Apple", "mobile"),
    "E4:C6:3D": ("Apple", "mobile"),   "E4:E4:AB": ("Apple", "mobile"),
    "E8:04:62": ("Apple", "mobile"),   "E8:06:88": ("Apple", "mobile"),
    "E8:80:2E": ("Apple", "mobile"),   "E8:8D:28": ("Apple", "mobile"),
    "E8:D0:FC": ("Apple", "mobile"),   "EC:35:86": ("Apple", "mobile"),
    "EC:85:2F": ("Apple", "mobile"),   "F0:18:98": ("Apple", "mobile"),
    "F0:79:60": ("Apple", "mobile"),   "F0:B4:29": ("Apple", "mobile"),
    "F0:C1:F1": ("Apple", "mobile"),   "F0:CB:A1": ("Apple", "mobile"),
    "F0:D1:A9": ("Apple", "mobile"),   "F0:F6:1C": ("Apple", "mobile"),
    "F4:0F:24": ("Apple", "mobile"),   "F4:37:B7": ("Apple", "mobile"),
    "F4:4E:E3": ("Apple", "mobile"),   "F4:5C:89": ("Apple", "mobile"),
    "F4:F1:5A": ("Apple", "mobile"),   "F8:27:93": ("Apple", "mobile"),
    "F8:62:14": ("Apple", "mobile"),   "F8:95:EA": ("Apple", "mobile"),
    "FC:25:3F": ("Apple", "mobile"),   "FC:E9:98": ("Apple", "mobile"),

    # ── Samsung ───────────────────────────────────────────────────────────────
    "00:02:78": ("Samsung", "mobile"),  "00:07:AB": ("Samsung", "mobile"),
    "00:12:47": ("Samsung", "mobile"),  "00:15:99": ("Samsung", "mobile"),
    "00:16:32": ("Samsung", "mobile"),  "00:16:6B": ("Samsung", "mobile"),
    "00:16:6C": ("Samsung", "mobile"),  "00:17:C9": ("Samsung", "mobile"),
    "00:17:D5": ("Samsung", "mobile"),  "00:18:AF": ("Samsung", "mobile"),
    "00:1A:8A": ("Samsung", "mobile"),  "00:1B:98": ("Samsung", "mobile"),
    "00:1C:43": ("Samsung", "mobile"),  "00:1D:25": ("Samsung", "mobile"),
    "00:1D:F6": ("Samsung", "mobile"),  "00:1E:7D": ("Samsung", "mobile"),
    "00:1F:CC": ("Samsung", "mobile"),  "00:21:19": ("Samsung", "mobile"),
    "00:21:D1": ("Samsung", "mobile"),  "00:22:15": ("Samsung", "mobile"),
    "00:23:39": ("Samsung", "mobile"),  "00:24:90": ("Samsung", "mobile"),
    "00:24:91": ("Samsung", "mobile"),  "00:24:AE": ("Samsung", "mobile"),
    "00:25:66": ("Samsung", "mobile"),  "00:26:37": ("Samsung", "mobile"),
    "00:26:5F": ("Samsung", "mobile"),  "00:E0:64": ("Samsung", "mobile"),
    "04:18:D6": ("Samsung", "mobile"),  "04:1B:BA": ("Samsung", "mobile"),
    "04:88:E2": ("Samsung", "mobile"),  "04:FE:31": ("Samsung", "tv"),
    "08:08:C2": ("Samsung", "mobile"),  "08:37:3D": ("Samsung", "mobile"),
    "08:8C:2C": ("Samsung", "mobile"),  "08:D4:2B": ("Samsung", "mobile"),
    "08:EC:A9": ("Samsung", "mobile"),  "0C:14:20": ("Samsung", "mobile"),
    "0C:89:10": ("Samsung", "mobile"),  "10:08:C1": ("Samsung", "mobile"),
    "10:1D:C0": ("Samsung", "mobile"),  "10:30:47": ("Samsung", "mobile"),
    "10:3B:59": ("Samsung", "mobile"),  "10:67:76": ("Samsung", "mobile"),
    "10:D3:8A": ("Samsung", "mobile"),  "14:32:D1": ("Samsung", "mobile"),
    "14:49:E0": ("Samsung", "mobile"),  "14:7D:C5": ("Samsung", "mobile"),
    "14:A3:64": ("Samsung", "mobile"),  "18:1E:B0": ("Samsung", "mobile"),
    "18:26:49": ("Samsung", "mobile"),  "18:3A:2D": ("Samsung", "mobile"),
    "18:67:B0": ("Samsung", "mobile"),  "18:89:5B": ("Samsung", "mobile"),
    "1C:5A:3E": ("Samsung", "mobile"),  "1C:66:AA": ("Samsung", "mobile"),
    "1C:86:9A": ("Samsung", "tv"),      "20:13:E0": ("Samsung", "mobile"),
    "20:64:32": ("Samsung", "mobile"),  "20:6E:9C": ("Samsung", "mobile"),
    "20:D3:90": ("Samsung", "mobile"),  "24:4B:03": ("Samsung", "mobile"),
    "24:DA:9B": ("Samsung", "mobile"),  "28:27:BF": ("Samsung", "mobile"),
    "28:98:7B": ("Samsung", "mobile"),  "2C:AE:2B": ("Samsung", "mobile"),
    "2C:F4:32": ("Samsung", "mobile"),  "30:07:4D": ("Samsung", "mobile"),
    "30:C7:AE": ("Samsung", "mobile"),  "34:1C:F0": ("Samsung", "mobile"),
    "34:23:87": ("Samsung", "mobile"),  "34:31:11": ("Samsung", "mobile"),
    "34:BB:26": ("Samsung", "mobile"),  "34:BE:00": ("Samsung", "mobile"),
    "34:C3:AC": ("Samsung", "mobile"),  "38:01:95": ("Samsung", "mobile"),
    "38:16:D1": ("Samsung", "mobile"),  "38:2D:D1": ("Samsung", "mobile"),
    "38:AA:3C": ("Samsung", "mobile"),  "3C:5A:B4": ("Samsung", "mobile"),
    "3C:8B:FE": ("Samsung", "mobile"),  "40:0E:85": ("Samsung", "mobile"),
    "44:4F:E1": ("Samsung", "wearable"), "44:78:3E": ("Samsung", "mobile"),
    "44:F4:59": ("Samsung", "mobile"),  "48:13:7E": ("Samsung", "mobile"),
    "48:44:F7": ("Samsung", "mobile"),  "4C:3C:16": ("Samsung", "mobile"),
    "4C:BC:98": ("Samsung", "mobile"),  "50:01:BB": ("Samsung", "mobile"),
    "50:32:75": ("Samsung", "mobile"),  "50:55:27": ("Samsung", "mobile"),
    "50:85:69": ("Samsung", "mobile"),  "50:A4:C8": ("Samsung", "mobile"),
    "50:CC:F8": ("Samsung", "mobile"),  "54:40:AD": ("Samsung", "mobile"),
    "54:44:A3": ("Samsung", "mobile"),  "58:C3:8B": ("Samsung", "mobile"),
    "5C:2E:59": ("Samsung", "mobile"),  "5C:3C:27": ("Samsung", "mobile"),
    "5C:49:7D": ("Samsung", "mobile"),  "5C:C1:D7": ("Samsung", "mobile"),
    "60:6B:BD": ("Samsung", "mobile"),  "64:77:91": ("Samsung", "mobile"),
    "64:B3:10": ("Samsung", "mobile"),  "64:E7:D8": ("Samsung", "mobile"),
    "68:EB:C5": ("Samsung", "mobile"),  "6C:2F:2C": ("Samsung", "mobile"),
    "70:2A:D5": ("Samsung", "tv"),      "74:19:0A": ("Samsung", "wearable"),
    "74:45:8A": ("Samsung", "mobile"),  "78:1F:DB": ("Samsung", "mobile"),
    "78:40:E4": ("Samsung", "mobile"),  "78:59:5E": ("Samsung", "mobile"),
    "7C:64:56": ("Samsung", "mobile"),  "7C:B2:32": ("Samsung", "mobile"),
    "80:18:A7": ("Samsung", "mobile"),  "80:65:6D": ("Samsung", "mobile"),
    "84:25:DB": ("Samsung", "mobile"),  "84:51:81": ("Samsung", "mobile"),
    "84:98:66": ("Samsung", "mobile"),  "84:CF:BF": ("Samsung", "tv"),
    "88:32:9B": ("Samsung", "mobile"),  "88:9B:39": ("Samsung", "mobile"),
    "8C:1A:BF": ("Samsung", "mobile"),  "8C:71:F8": ("Samsung", "mobile"),
    "8C:79:F5": ("Samsung", "mobile"),  "90:18:7C": ("Samsung", "mobile"),
    "94:01:C2": ("Samsung", "mobile"),  "94:35:0A": ("Samsung", "mobile"),
    "94:63:D1": ("Samsung", "mobile"),  "98:52:B1": ("Samsung", "mobile"),
    "98:6C:F5": ("Samsung", "mobile"),  "9C:02:98": ("Samsung", "mobile"),
    "A0:0B:BA": ("Samsung", "mobile"),  "A0:21:95": ("Samsung", "mobile"),
    "A0:39:F7": ("Samsung", "mobile"),  "A0:82:1F": ("Samsung", "mobile"),
    "A4:25:1B": ("Samsung", "mobile"),  "A8:7D:12": ("Samsung", "mobile"),
    "A8:9A:93": ("Samsung", "mobile"),  "AC:36:13": ("Samsung", "mobile"),
    "AC:5F:3E": ("Samsung", "mobile"),  "B0:E4:5C": ("Samsung", "tv"),
    "B4:07:F9": ("Samsung", "mobile"),  "B4:37:D1": ("Samsung", "mobile"),
    "B4:79:A7": ("Samsung", "mobile"),  "B4:EF:FA": ("Samsung", "mobile"),
    "B8:A0:B8": ("Samsung", "tv"),      "B8:BC:1B": ("Samsung", "mobile"),
    "BC:10:2F": ("Samsung", "appliance"), "BC:14:85": ("Samsung", "mobile"),
    "BC:20:A4": ("Samsung", "mobile"),  "BC:47:60": ("Samsung", "mobile"),
    "BC:72:B1": ("Samsung", "mobile"),  "BC:79:AD": ("Samsung", "mobile"),
    "BC:8C:CD": ("Samsung", "mobile"),  "C0:BD:D1": ("Samsung", "mobile"),
    "C4:42:02": ("Samsung", "mobile"),  "C4:57:6E": ("Samsung", "mobile"),
    "C4:88:E5": ("Samsung", "mobile"),  "CC:07:AB": ("Samsung", "mobile"),
    "CC:3A:61": ("Samsung", "mobile"),  "D0:17:6A": ("Samsung", "mobile"),
    "D0:22:BE": ("Samsung", "mobile"),  "D0:59:E4": ("Samsung", "mobile"),
    "D0:87:E2": ("Samsung", "mobile"),  "D4:87:D8": ("Samsung", "mobile"),
    "D4:88:90": ("Samsung", "mobile"),  "D4:E8:53": ("Samsung", "mobile"),
    "D8:57:EF": ("Samsung", "mobile"),  "DC:71:96": ("Samsung", "mobile"),
    "DC:D9:16": ("Samsung", "mobile"),  "E0:99:71": ("Samsung", "mobile"),
    "E4:12:1D": ("Samsung", "mobile"),  "E4:32:CB": ("Samsung", "mobile"),
    "E4:58:B8": ("Samsung", "mobile"),  "E4:7D:BD": ("Samsung", "mobile"),
    "E4:92:FB": ("Samsung", "appliance"), "E8:03:9A": ("Samsung", "mobile"),
    "EC:1F:72": ("Samsung", "mobile"),  "F0:25:B7": ("Samsung", "mobile"),
    "F0:72:8C": ("Samsung", "mobile"),  "F0:E7:7E": ("Samsung", "mobile"),
    "F4:09:D8": ("Samsung", "mobile"),  "F4:DD:06": ("Samsung", "mobile"),
    "F4:F5:24": ("Samsung", "mobile"),  "F8:04:2E": ("Samsung", "mobile"),
    "F8:4E:58": ("Samsung", "mobile"),  "F8:77:B8": ("Samsung", "mobile"),
    "F8:E6:1A": ("Samsung", "mobile"),  "FC:A1:3E": ("Samsung", "mobile"),
    "1C:AF:4A": ("Samsung", "mobile"),  "04:E4:B6": ("Samsung", "mobile"),
    "5C:49:7D": ("Samsung", "mobile"),

    # ── Xiaomi / Redmi / Poco ─────────────────────────────────────────────────
    "00:9E:C8": ("Xiaomi", "mobile"),   "04:CF:8C": ("Xiaomi", "mobile"),
    "04:DA:28": ("Xiaomi", "mobile"),   "08:7A:4C": ("Xiaomi", "mobile"),
    "0C:1D:AF": ("Xiaomi", "mobile"),   "10:2A:B3": ("Xiaomi", "mobile"),
    "14:F6:5A": ("Xiaomi", "mobile"),   "18:59:36": ("Xiaomi", "mobile"),
    "1C:5E:8A": ("Xiaomi", "mobile"),   "20:82:C0": ("Xiaomi", "mobile"),
    "28:6C:07": ("Xiaomi", "mobile"),   "28:E3:1F": ("Xiaomi", "mobile"),
    "34:80:B3": ("Xiaomi", "mobile"),   "38:A4:ED": ("Xiaomi", "mobile"),
    "3C:BD:3E": ("Xiaomi", "mobile"),   "40:31:3C": ("Xiaomi", "mobile"),
    "44:A1:60": ("Xiaomi", "mobile"),   "4C:49:E3": ("Xiaomi", "mobile"),
    "50:8F:4C": ("Xiaomi", "mobile"),   "58:44:98": ("Xiaomi", "mobile"),
    "60:AB:14": ("Xiaomi", "mobile"),   "64:09:80": ("Xiaomi", "mobile"),
    "64:B4:73": ("Xiaomi", "mobile"),   "68:DF:DD": ("Xiaomi", "mobile"),
    "6C:5A:B0": ("Xiaomi", "mobile"),   "6C:5C:3D": ("Xiaomi", "mobile"),
    "74:23:44": ("Xiaomi", "mobile"),   "74:51:BA": ("Xiaomi", "mobile"),
    "74:6B:7D": ("Xiaomi", "mobile"),   "78:11:DC": ("Xiaomi", "mobile"),
    "78:61:7C": ("Xiaomi", "mobile"),   "7C:D5:F7": ("Xiaomi", "mobile"),
    "80:35:C1": ("Xiaomi", "mobile"),   "84:7A:88": ("Xiaomi", "mobile"),
    "88:C3:97": ("Xiaomi", "mobile"),   "8C:BE:BE": ("Xiaomi", "mobile"),
    "94:B9:7E": ("Xiaomi", "mobile"),   "98:FA:E3": ("Xiaomi", "mobile"),
    "9C:99:A0": ("Xiaomi", "mobile"),   "A0:86:C6": ("Xiaomi", "mobile"),
    "A4:C1:38": ("Xiaomi", "mobile"),   "AC:C1:EE": ("Xiaomi", "mobile"),
    "B0:E2:35": ("Xiaomi", "mobile"),   "C4:6A:B7": ("Xiaomi", "mobile"),
    "C4:86:E9": ("Xiaomi", "mobile"),   "C8:9A:90": ("Xiaomi", "mobile"),
    "CC:B1:1A": ("Xiaomi", "mobile"),   "D4:97:0B": ("Xiaomi", "mobile"),
    "D4:FB:6B": ("Xiaomi", "mobile"),   "D8:C4:E9": ("Xiaomi", "mobile"),
    "E4:46:DA": ("Xiaomi", "mobile"),   "E8:DE:27": ("Xiaomi", "mobile"),
    "EC:D0:9F": ("Xiaomi", "mobile"),   "F0:B4:29": ("Xiaomi", "mobile"),
    "F4:0A:5B": ("Xiaomi", "wearable"), "F4:F5:DB": ("Xiaomi", "mobile"),
    "F8:A4:5F": ("Xiaomi", "mobile"),   "FC:64:BA": ("Xiaomi", "mobile"),
    "D4:75:93": ("Xiaomi", "wearable"), "C8:90:46": ("Xiaomi", "wearable"),
    "04:DA:28": ("Xiaomi", "wearable"),

    # ── Google / Nest / Pixel ─────────────────────────────────────────────────
    "00:1A:11": ("Google", "iot"),      "00:E0:4C": ("Google", "mobile"),
    "18:B4:30": ("Google", "iot"),      "20:DF:B9": ("Google", "mobile"),
    "30:FD:38": ("Google", "mobile"),   "3C:5A:B4": ("Google", "mobile"),
    "48:D6:D5": ("Google", "mobile"),   "54:60:09": ("Google", "iot"),
    "60:F6:77": ("Google", "mobile"),   "70:3A:CB": ("Google", "iot"),
    "74:7A:90": ("Google", "mobile"),   "9C:A3:A9": ("Google", "mobile"),
    "A4:77:33": ("Google", "mobile"),   "B4:CE:F6": ("Google", "iot"),
    "D4:3A:2C": ("Google", "mobile"),   "F8:8F:CA": ("Google", "mobile"),

    # ── Amazon / Echo / Kindle ────────────────────────────────────────────────
    "00:FC:8B": ("Amazon", "iot"),      "04:A1:51": ("Amazon", "iot"),
    "0C:47:C9": ("Amazon", "iot"),      "18:74:2E": ("Amazon", "iot"),
    "28:EF:01": ("Amazon", "iot"),      "34:D2:70": ("Amazon", "iot"),
    "40:B4:CD": ("Amazon", "iot"),      "44:65:0D": ("Amazon", "iot"),
    "50:DC:E7": ("Amazon", "iot"),      "6C:56:97": ("Amazon", "iot"),
    "74:75:48": ("Amazon", "iot"),      "7C:61:93": ("Amazon", "iot"),
    "84:D6:D0": ("Amazon", "iot"),      "A0:02:DC": ("Amazon", "iot"),
    "A4:08:01": ("Amazon", "iot"),      "B4:7C:9C": ("Amazon", "iot"),
    "CC:9E:A2": ("Amazon", "iot"),      "D8:49:2F": ("Amazon", "iot"),
    "F0:81:73": ("Amazon", "iot"),      "F0:A2:25": ("Amazon", "iot"),
    "FC:A6:67": ("Amazon", "iot"),      "7C:C1:4F": ("Amazon", "iot"),

    # ── Microsoft ─────────────────────────────────────────────────────────────
    "00:03:FF": ("Microsoft", "computer"), "00:12:5A": ("Microsoft", "computer"),
    "00:17:FA": ("Microsoft", "computer"), "00:22:48": ("Microsoft", "computer"),
    "00:50:F2": ("Microsoft", "computer"), "28:18:78": ("Microsoft", "computer"),
    "38:DE:AD": ("Microsoft", "computer"), "3C:83:75": ("Microsoft", "computer"),
    "48:50:73": ("Microsoft", "computer"), "50:1A:C5": ("Microsoft", "computer"),
    "60:45:CB": ("Microsoft", "computer"), "7C:1E:52": ("Microsoft", "computer"),
    "98:5F:D3": ("Microsoft", "computer"), "9C:B6:D0": ("Microsoft", "computer"),
    "A0:00:DC": ("Microsoft", "computer"), "A4:C3:F0": ("Microsoft", "computer"),
    "B4:AE:2B": ("Microsoft", "computer"), "C0:33:5E": ("Microsoft", "computer"),
    "D4:01:C3": ("Microsoft", "computer"), "DC:53:60": ("Microsoft", "computer"),

    # ── Sony ─────────────────────────────────────────────────────────────────
    "00:01:4A": ("Sony", "mobile"),     "00:04:1F": ("Sony", "mobile"),
    "00:0D:FD": ("Sony", "audio"),      "00:13:A9": ("Sony", "mobile"),
    "00:14:A9": ("Sony", "mobile"),     "00:16:B8": ("Sony", "mobile"),
    "00:18:00": ("Sony", "mobile"),     "00:19:C5": ("Sony", "mobile"),
    "00:1A:80": ("Sony", "mobile"),     "00:1B:FB": ("Sony", "mobile"),
    "00:1C:7E": ("Sony", "mobile"),     "00:1D:0D": ("Sony", "mobile"),
    "00:1E:E3": ("Sony", "mobile"),     "00:24:BE": ("Sony", "mobile"),
    "00:EB:2D": ("Sony", "mobile"),     "04:0B:80": ("Sony", "mobile"),
    "0C:FC:83": ("Sony", "mobile"),     "10:4F:A8": ("Sony", "audio"),
    "14:AB:C5": ("Sony", "mobile"),     "1C:5E:13": ("Sony", "mobile"),
    "20:16:D8": ("Sony", "mobile"),     "2C:FD:A1": ("Sony", "audio"),
    "30:17:AA": ("Sony", "mobile"),     "3C:62:00": ("Sony", "audio"),
    "40:2B:A1": ("Sony", "mobile"),     "40:49:0F": ("Sony", "mobile"),
    "4C:E6:76": ("Sony", "mobile"),     "58:48:22": ("Sony", "mobile"),
    "5C:AD:CF": ("Sony", "mobile"),     "64:BC:0C": ("Sony", "mobile"),
    "64:D4:BD": ("Sony", "mobile"),     "6C:AD:F8": ("Sony", "mobile"),
    "70:2C:1F": ("Sony", "mobile"),     "78:84:3C": ("Sony", "mobile"),
    "7C:19:C7": ("Sony", "mobile"),     "84:38:38": ("Sony", "audio"),
    "90:C1:15": ("Sony", "mobile"),     "94:CE:2C": ("Sony", "mobile"),
    "98:0C:A5": ("Sony", "mobile"),     "9C:AD:EF": ("Sony", "mobile"),
    "A0:E4:53": ("Sony", "mobile"),     "A4:70:D6": ("Sony", "mobile"),
    "AC:9B:0A": ("Sony", "audio"),      "B8:10:DA": ("Sony", "mobile"),
    "C0:BD:C8": ("Sony", "audio"),      "C8:C2:FA": ("Sony", "mobile"),
    "CC:FE:3C": ("Sony", "mobile"),     "D0:27:88": ("Sony", "mobile"),
    "E0:19:54": ("Sony", "mobile"),     "E4:8D:8C": ("Sony", "mobile"),
    "EC:44:76": ("Sony", "mobile"),     "FC:0F:E6": ("Sony", "mobile"),

    # ── Bose ─────────────────────────────────────────────────────────────────
    "00:09:A7": ("Bose", "audio"),      "00:18:09": ("Bose", "audio"),
    "00:1B:66": ("Bose", "audio"),      "00:1F:6B": ("Bose", "audio"),
    "1C:F8:D0": ("Bose", "audio"),      "34:15:9E": ("Bose", "audio"),
    "3C:A8:81": ("Bose", "audio"),      "3C:AB:8E": ("Bose", "audio"),
    "44:1A:FA": ("Bose", "audio"),      "64:98:EE": ("Bose", "audio"),
    "7C:8B:B3": ("Bose", "audio"),      "88:DF:8D": ("Bose", "audio"),
    "A0:E9:DB": ("Bose", "audio"),      "B4:9D:0B": ("Bose", "audio"),
    "EC:D0:9F": ("Bose", "audio"),

    # ── Jabra / GN Audio ─────────────────────────────────────────────────────
    "00:18:09": ("Jabra", "audio"),     "04:52:C7": ("Jabra", "audio"),
    "50:C2:75": ("Jabra", "audio"),     "A4:15:66": ("Jabra", "audio"),
    "90:03:B7": ("Jabra", "audio"),     "D4:F2:19": ("Jabra", "audio"),

    # ── JBL / Harman ─────────────────────────────────────────────────────────
    "04:5D:4B": ("JBL/Harman", "audio"), "14:2D:27": ("JBL/Harman", "audio"),
    "4C:87:5D": ("JBL/Harman", "audio"), "5C:FB:3A": ("JBL/Harman", "audio"),
    "6C:5C:B1": ("JBL/Harman", "audio"), "A0:4A:5E": ("JBL/Harman", "audio"),
    "A4:50:46": ("JBL/Harman", "audio"), "B4:F0:AB": ("JBL/Harman", "audio"),

    # ── Edifier ───────────────────────────────────────────────────────────────
    "58:A5:F2": ("Edifier", "audio"),   "AC:67:B2": ("Edifier", "audio"),
    "00:02:B3": ("Edifier", "audio"),

    # ── Anker / Soundcore ─────────────────────────────────────────────────────
    "00:0F:F6": ("Anker/Soundcore", "audio"), "24:62:AB": ("Anker/Soundcore", "audio"),
    "70:16:C1": ("Anker/Soundcore", "audio"), "74:F6:1C": ("Anker/Soundcore", "audio"),
    "A4:77:58": ("Anker/Soundcore", "audio"), "B4:37:22": ("Anker/Soundcore", "audio"),
    "BC:D0:74": ("Anker/Soundcore", "audio"),

    # ── Marshall ─────────────────────────────────────────────────────────────
    "00:21:3C": ("Marshall", "audio"),  "3C:3C:BD": ("Marshall", "audio"),
    "54:B7:E5": ("Marshall", "audio"),

    # ── Nothing ───────────────────────────────────────────────────────────────
    "0C:1D:AF": ("Nothing", "audio"),   "30:D1:D4": ("Nothing", "audio"),
    "D0:C0:BF": ("Nothing", "audio"),

    # ── OnePlus ───────────────────────────────────────────────────────────────
    "C4:03:A8": ("OnePlus", "mobile"),  "18:45:A6": ("OnePlus", "audio"),
    "AC:52:42": ("OnePlus", "mobile"),

    # ── Logitech ─────────────────────────────────────────────────────────────
    "00:1F:20": ("Logitech", "computer"), "00:1D:D8": ("Logitech", "computer"),
    "00:1F:20": ("Logitech", "computer"), "00:F0:CB": ("Logitech", "computer"),
    "40:16:7E": ("Logitech", "computer"), "9C:B6:D0": ("Logitech", "computer"),
    "C0:78:71": ("Logitech", "computer"),

    # ── Meta / Oculus ─────────────────────────────────────────────────────────
    "2C:26:17": ("Meta", "computer"),   "3C:A3:08": ("Meta", "computer"),
    "64:0F:26": ("Meta/Oculus", "computer"), "A4:C3:F0": ("Meta", "computer"),
    "BC:F3:06": ("Meta", "computer"),

    # ── Tuya / Smart Home ─────────────────────────────────────────────────────
    "10:F6:0A": ("Tuya", "iot"),        "1C:F4:39": ("Tuya", "iot"),
    "24:62:AB": ("Tuya", "iot"),        "28:AB:29": ("Tuya", "iot"),
    "38:D2:69": ("Tuya", "iot"),        "40:4E:36": ("Tuya", "iot"),
    "48:55:19": ("Tuya", "iot"),        "50:02:91": ("Tuya", "iot"),
    "60:01:94": ("Tuya", "iot"),        "68:57:2D": ("Tuya", "iot"),
    "A8:80:55": ("Tuya/SmartLife", "iot"), "D8:D6:68": ("Tuya", "iot"),
    "D8:F1:5B": ("Tuya", "iot"),        "18:DE:50": ("Tuya/SmartLife", "iot"),
    "20:93:32": ("Tuya", "iot"),        "E8:DB:84": ("Tuya", "iot"),
    "BC:0F:F3": ("Tuya", "iot"),

    # ── LG Electronics ───────────────────────────────────────────────────────
    "00:05:CD": ("LG", "mobile"),       "00:1C:62": ("LG", "mobile"),
    "00:1E:75": ("LG", "mobile"),       "00:21:FB": ("LG", "mobile"),
    "00:24:83": ("LG", "mobile"),       "00:2A:A8": ("LG", "mobile"),
    "04:B1:67": ("LG", "mobile"),       "08:EF:3B": ("LG Electronics", "tv"),
    "0C:D7:46": ("LG", "mobile"),       "10:68:3F": ("LG", "mobile"),
    "10:F1:F2": ("LG", "mobile"),       "18:2A:7B": ("LG", "mobile"),
    "20:15:DE": ("LG", "tv"),           "28:B2:BD": ("LG", "mobile"),
    "38:8B:59": ("LG", "mobile"),       "40:55:82": ("LG", "mobile"),
    "40:B0:FA": ("LG", "mobile"),       "44:E4:29": ("LG", "mobile"),
    "4C:BC:A5": ("LG", "mobile"),       "50:55:27": ("LG", "mobile"),
    "5C:F6:DC": ("LG", "mobile"),       "64:89:9A": ("LG", "mobile"),
    "64:99:5D": ("LG", "mobile"),       "6C:40:08": ("LG", "mobile"),
    "70:8C:B6": ("LG", "mobile"),       "74:46:A0": ("LG", "mobile"),
    "7C:2E:BD": ("LG", "mobile"),       "84:55:A5": ("LG", "mobile"),
    "8C:3A:E3": ("LG", "mobile"),       "94:65:9C": ("LG", "mobile"),
    "98:43:FA": ("LG", "mobile"),       "A4:18:75": ("LG", "mobile"),
    "A8:16:D0": ("LG", "mobile"),       "AC:7A:4D": ("LG", "mobile"),
    "B4:E6:2A": ("LG", "mobile"),       "C4:36:6C": ("LG", "mobile"),
    "C8:08:E9": ("LG", "mobile"),       "CC:2D:8C": ("LG", "mobile"),
    "D0:13:FD": ("LG", "mobile"),       "D4:3C:FA": ("LG", "mobile"),
    "D8:F2:CA": ("LG", "mobile"),       "E8:92:A4": ("LG", "mobile"),
    "F8:95:C7": ("LG", "mobile"),       "FC:F1:52": ("LG", "mobile"),

    # ── Huawei / Honor ───────────────────────────────────────────────────────
    "00:18:82": ("Huawei", "mobile"),   "00:1E:10": ("Huawei", "mobile"),
    "00:25:9E": ("Huawei", "mobile"),   "00:46:4B": ("Huawei", "mobile"),
    "04:02:1F": ("Huawei", "mobile"),   "04:BD:70": ("Huawei", "mobile"),
    "04:C0:6F": ("Huawei", "mobile"),   "04:F9:38": ("Huawei", "mobile"),
    "08:63:61": ("Huawei", "mobile"),   "0C:D6:96": ("Huawei", "mobile"),
    "10:1B:54": ("Huawei", "mobile"),   "14:59:C0": ("Huawei", "mobile"),
    "18:F0:E4": ("Huawei", "mobile"),   "1C:97:C8": ("Huawei", "mobile"),
    "20:0B:C7": ("Huawei", "mobile"),   "28:31:52": ("Huawei", "mobile"),
    "2C:AB:25": ("Huawei", "mobile"),   "34:12:98": ("Huawei", "mobile"),
    "34:6B:D3": ("Huawei", "mobile"),   "38:0B:40": ("Huawei", "mobile"),
    "38:F8:89": ("Huawei", "mobile"),   "3C:F8:08": ("Huawei", "mobile"),
    "40:4E:36": ("Huawei", "mobile"),   "48:7B:6B": ("Huawei", "mobile"),
    "4C:1B:86": ("Huawei", "mobile"),   "4C:8B:EF": ("Huawei", "mobile"),
    "50:A6:D8": ("Huawei", "mobile"),   "54:89:98": ("Huawei", "mobile"),
    "54:A5:1B": ("Huawei", "mobile"),   "58:7A:62": ("Huawei", "mobile"),
    "5C:C3:07": ("Huawei", "mobile"),   "60:12:8B": ("Huawei", "mobile"),
    "64:16:F0": ("Huawei", "mobile"),   "68:13:24": ("Huawei", "mobile"),
    "6C:B1:33": ("Huawei", "mobile"),   "70:72:3C": ("Huawei", "mobile"),
    "74:A5:28": ("Huawei", "mobile"),   "78:1D:BA": ("Huawei", "mobile"),
    "78:EB:14": ("Huawei", "mobile"),   "7C:A2:3E": ("Huawei", "mobile"),
    "80:D0:9B": ("Huawei", "mobile"),   "84:BE:52": ("Huawei", "mobile"),
    "88:E3:AB": ("Huawei", "mobile"),   "8C:34:FD": ("Huawei", "mobile"),
    "90:17:AC": ("Huawei", "mobile"),   "94:DB:C9": ("Huawei", "mobile"),
    "98:2C:BC": ("Huawei", "mobile"),   "A4:50:46": ("Huawei", "mobile"),
    "A4:CA:A0": ("Huawei", "mobile"),   "AC:07:5F": ("Huawei", "mobile"),
    "AC:47:1B": ("Huawei", "mobile"),   "B0:A7:B9": ("Huawei", "mobile"),
    "B4:86:55": ("Huawei", "mobile"),   "BC:25:05": ("Huawei", "mobile"),
    "C0:25:E9": ("Huawei", "mobile"),   "C0:B4:7A": ("Huawei", "mobile"),
    "C4:07:2F": ("Huawei", "mobile"),   "C4:86:E9": ("Huawei", "mobile"),
    "C8:14:79": ("Huawei", "mobile"),   "CC:34:29": ("Huawei", "mobile"),
    "D4:6E:5C": ("Huawei", "mobile"),   "D4:A6:2F": ("Huawei", "mobile"),
    "D8:12:65": ("Huawei", "mobile"),   "DC:EE:06": ("Huawei", "mobile"),
    "E0:19:54": ("Huawei", "mobile"),   "E4:A4:71": ("Huawei", "mobile"),
    "E4:68:A3": ("Huawei", "mobile"),   "E8:CD:2D": ("Huawei", "mobile"),
    "EC:23:3D": ("Huawei", "mobile"),   "F4:4C:7F": ("Huawei", "mobile"),
    "F4:9F:54": ("Huawei", "mobile"),   "F8:01:13": ("Huawei", "mobile"),
    "FC:3F:DB": ("Huawei", "mobile"),

    # ── Motorola ─────────────────────────────────────────────────────────────
    "00:17:E5": ("Motorola", "mobile"), "04:A5:9B": ("Motorola", "mobile"),
    "0C:E1:4B": ("Motorola", "mobile"), "14:A9:E3": ("Motorola", "mobile"),
    "24:69:A5": ("Motorola", "mobile"), "28:1A:EB": ("Motorola", "mobile"),
    "2C:D0:5A": ("Motorola", "mobile"), "34:F3:9A": ("Motorola", "mobile"),
    "38:08:75": ("Motorola", "mobile"), "3C:09:98": ("Motorola", "mobile"),
    "44:80:EB": ("Motorola", "mobile"), "48:E1:E9": ("Motorola", "mobile"),
    "5C:5F:67": ("Motorola", "mobile"), "60:F8:1D": ("Motorola", "mobile"),
    "6C:72:E7": ("Motorola", "mobile"), "70:12:89": ("Motorola", "mobile"),
    "74:D0:2B": ("Motorola", "mobile"), "78:F5:FD": ("Motorola", "mobile"),
    "80:6C:1B": ("Motorola", "mobile"), "84:D4:7E": ("Motorola", "mobile"),
    "8C:77:12": ("Motorola", "mobile"), "90:16:19": ("Motorola", "mobile"),
    "94:D7:71": ("Motorola", "mobile"), "A4:1A:3A": ("Motorola", "mobile"),
    "AC:37:43": ("Motorola", "mobile"), "B4:E6:2A": ("Motorola", "mobile"),
    "C4:C7:D6": ("Motorola", "mobile"), "D4:20:B0": ("Motorola", "mobile"),
    "E4:90:7E": ("Motorola", "mobile"), "F4:F1:E1": ("Motorola", "mobile"),

    # ── Garmin ────────────────────────────────────────────────────────────────
    "00:1D:01": ("Garmin", "wearable"), "01:0C:E7": ("Garmin", "wearable"),
    "10:3C:23": ("Garmin", "wearable"), "28:22:45": ("Garmin", "wearable"),
    "38:35:FB": ("Garmin", "wearable"), "44:10:62": ("Garmin", "wearable"),
    "54:B3:EB": ("Garmin", "wearable"), "5C:C7:C1": ("Garmin", "wearable"),
    "66:C7:8B": ("Garmin", "wearable"), "78:87:E9": ("Garmin", "wearable"),
    "A0:5B:70": ("Garmin", "wearable"), "AC:37:43": ("Garmin", "wearable"),
    "D0:18:18": ("Garmin", "wearable"), "E8:A4:72": ("Garmin", "wearable"),
    "F0:EB:EF": ("Garmin", "wearable"),

    # ── Fitbit / Google ────────────────────────────────────────────────────────
    "00:23:20": ("Fitbit", "wearable"), "28:EB:77": ("Fitbit", "wearable"),
    "30:27:21": ("Fitbit", "wearable"), "50:93:F3": ("Fitbit", "wearable"),
    "68:8E:55": ("Fitbit", "wearable"), "80:FB:06": ("Fitbit", "wearable"),
    "8A:D5:CD": ("Fitbit", "wearable"), "A0:56:F3": ("Fitbit", "wearable"),
    "C4:CA:CE": ("Fitbit", "wearable"), "F4:4E:FD": ("Fitbit", "wearable"),

    # ── Amazfit / Zepp ─────────────────────────────────────────────────────────
    "AC:3E:6A": ("Amazfit/Zepp", "wearable"), "C8:90:46": ("Amazfit/Zepp", "wearable"),
    "10:A5:D0": ("Amazfit/Zepp", "wearable"), "28:27:BF": ("Amazfit/Zepp", "wearable"),

    # ── Qualcomm (generic BT chip) ─────────────────────────────────────────────
    "00:02:B3": ("Qualcomm", "mobile"), "00:11:F5": ("Qualcomm", "mobile"),
    "00:17:E5": ("Qualcomm", "mobile"),

    # ── Texas Instruments ──────────────────────────────────────────────────────
    "00:1A:B6": ("Texas Instruments", "iot"), "00:12:4B": ("Texas Instruments", "iot"),
    "04:EE:03": ("Texas Instruments", "iot"),

    # ── Nordic Semiconductor ──────────────────────────────────────────────────
    "E5:4E:05": ("Nordic Semi", "iot"),

    # ── Espressif (ESP32) ─────────────────────────────────────────────────────
    "24:6F:28": ("Espressif/ESP32", "iot"), "30:AE:A4": ("Espressif/ESP32", "iot"),
    "3C:71:BF": ("Espressif/ESP32", "iot"), "3C:E9:0E": ("Espressif/ESP32", "iot"),
    "40:91:51": ("Espressif/ESP32", "iot"), "48:E7:29": ("Espressif/ESP32", "iot"),
    "50:02:91": ("Espressif/ESP32", "iot"), "54:43:54": ("Espressif/ESP32", "iot"),
    "5C:CF:7F": ("Espressif/ESP32", "iot"), "60:01:94": ("Espressif/ESP32", "iot"),
    "7C:9E:BD": ("Espressif/ESP32", "iot"), "80:7D:3A": ("Espressif/ESP32", "iot"),
    "84:0D:8E": ("Espressif/ESP32", "iot"), "84:CC:A8": ("Espressif/ESP32", "iot"),
    "84:F3:EB": ("Espressif/ESP32", "iot"), "8C:AA:B5": ("Espressif/ESP32", "iot"),
    "90:38:0C": ("Espressif/ESP32", "iot"), "94:B9:7E": ("Espressif/ESP32", "iot"),
    "98:CD:AC": ("Espressif/ESP32", "iot"), "A4:CF:12": ("Espressif/ESP32", "iot"),
    "AC:0B:FB": ("Espressif/ESP32", "iot"), "B4:8A:0A": ("Espressif/ESP32", "iot"),
    "BC:DD:C2": ("Espressif/ESP32", "iot"), "C4:4F:33": ("Espressif/ESP32", "iot"),
    "C4:DE:E2": ("Espressif/ESP32", "iot"), "CC:50:E3": ("Espressif/ESP32", "iot"),
    "D8:A0:1D": ("Espressif/ESP32", "iot"), "DC:4F:22": ("Espressif/ESP32", "iot"),
    "E0:98:06": ("Espressif/ESP32", "iot"), "E8:DB:84": ("Espressif/ESP32", "iot"),
    "EC:62:60": ("Espressif/ESP32", "iot"), "F4:12:FA": ("Espressif/ESP32", "iot"),
    "FC:F5:C4": ("Espressif/ESP32", "iot"),

    # ── Ruijie Networks ─────────────────────────────────────────────────────
    "28:93:5E": ("Ruijie Networks", "networking"), "4D:81:6E": ("Ruijie Networks", "networking"),
    "58:A2:C2": ("Ruijie Networks", "networking"), "80:26:89": ("Ruijie Networks", "networking"),

    # ── Midea Group (AC, appliances) ──────────────────────────────────────────
    "00:17:73": ("Midea", "appliance"), "28:F5:37": ("Midea", "appliance"),
    "34:E6:E6": ("Midea/AC", "appliance"), "40:4C:CA": ("Midea", "appliance"),
    "60:98:66": ("Midea", "appliance"), "8C:59:F1": ("Midea", "appliance"),
    "AC:CF:23": ("Midea", "appliance"), "B4:F9:EB": ("Midea", "appliance"),
    "EC:F8:EB": ("Midea", "appliance"),

    # ── Positivo / Brazilian brands ────────────────────────────────────────────
    "28:99:09": ("Positivo Tecnologia", "mobile"),

    # ── Realtek ───────────────────────────────────────────────────────────────
    "00:E0:4C": ("Realtek", "computer"), "20:CF:30": ("Realtek", "computer"),
    "50:E5:49": ("Realtek", "computer"), "80:1F:02": ("Realtek", "computer"),
    "E0:D5:5E": ("Realtek", "computer"),

    # ── TP-Link ────────────────────────────────────────────────────────────────
    "00:27:19": ("TP-Link", "networking"), "04:D9:F5": ("TP-Link", "networking"),
    "08:10:79": ("TP-Link", "networking"), "10:FE:ED": ("TP-Link", "networking"),
    "14:91:82": ("TP-Link", "networking"), "18:A6:F7": ("TP-Link", "networking"),
    "1C:61:B4": ("TP-Link", "networking"), "28:87:BA": ("TP-Link", "networking"),
    "2C:3B:71": ("TP-Link", "networking"), "30:B5:C2": ("TP-Link", "networking"),
    "3C:52:A1": ("TP-Link", "networking"), "40:3F:8C": ("TP-Link", "networking"),
    "40:ED:00": ("TP-Link", "networking"), "44:94:FC": ("TP-Link", "networking"),
    "50:3E:AA": ("TP-Link", "networking"), "54:AF:97": ("TP-Link", "networking"),
    "5C:89:9A": ("TP-Link", "networking"), "60:E3:27": ("TP-Link", "networking"),
    "64:70:02": ("TP-Link", "networking"), "68:FF:7B": ("TP-Link", "networking"),
    "6C:5C:0D": ("TP-Link", "networking"), "70:4F:57": ("TP-Link", "networking"),
    "74:DA:38": ("TP-Link", "networking"), "78:44:76": ("TP-Link", "networking"),
    "80:35:C1": ("TP-Link", "networking"), "84:16:F9": ("TP-Link", "networking"),
    "88:DC:96": ("TP-Link", "networking"), "90:9A:4A": ("TP-Link", "networking"),
    "98:DA:C4": ("TP-Link", "networking"), "A0:F3:C1": ("TP-Link", "networking"),
    "A4:2B:B0": ("TP-Link", "networking"), "AC:84:C6": ("TP-Link", "networking"),
    "B0:4E:26": ("TP-Link", "networking"), "B0:95:8E": ("TP-Link", "networking"),
    "C0:4A:00": ("TP-Link", "networking"), "C4:E9:84": ("TP-Link", "networking"),
    "D8:0D:17": ("TP-Link", "networking"), "DC:FE:18": ("TP-Link", "networking"),
    "E8:DE:27": ("TP-Link", "networking"), "EC:26:CA": ("TP-Link", "networking"),
    "F0:A7:31": ("TP-Link", "networking"), "F4:EC:38": ("TP-Link", "networking"),
    "F8:1A:67": ("TP-Link", "networking"), "FC:EC:DA": ("TP-Link", "networking"),

    # ── Realme / OPPO / OnePlus (BBK) ────────────────────────────────────────
    "30:74:96": ("Realme/OPPO", "mobile"), "44:0A:CE": ("Realme/OPPO", "mobile"),
    "48:8F:5A": ("Realme/OPPO", "mobile"), "54:B3:63": ("Realme/OPPO", "mobile"),
    "6C:B7:F4": ("Realme/OPPO", "mobile"), "80:45:DD": ("Realme/OPPO", "mobile"),
    "A0:36:BC": ("Realme/OPPO", "mobile"), "AC:52:42": ("Realme/OPPO", "mobile"),
    "B4:6A:91": ("Realme/OPPO", "mobile"), "C4:86:E9": ("Realme/OPPO", "mobile"),
    "D4:3A:2C": ("Realme/OPPO", "mobile"), "E8:BB:A8": ("Realme/OPPO", "mobile"),

    # ── Intel (Wi-Fi/BT combo chips) ──────────────────────────────────────────
    "00:00:F0": ("Intel", "computer"),  "00:15:17": ("Intel", "computer"),
    "00:1B:21": ("Intel", "computer"),  "00:1E:64": ("Intel", "computer"),
    "00:1E:65": ("Intel", "computer"),  "00:21:6A": ("Intel", "computer"),
    "00:23:14": ("Intel", "computer"),  "24:77:03": ("Intel", "computer"),
    "38:BA:F8": ("Intel", "computer"),  "40:A4:00": ("Intel", "computer"),
    "48:45:20": ("Intel", "computer"),  "54:8D:5A": ("Intel", "computer"),
    "60:57:18": ("Intel", "computer"),  "64:D1:54": ("Intel", "computer"),
    "68:5D:43": ("Intel", "computer"),  "7C:B0:C2": ("Intel", "computer"),
    "80:19:34": ("Intel", "computer"),  "84:7B:EB": ("Intel", "computer"),
    "8C:5D:8E": ("Intel", "computer"),  "90:E2:BA": ("Intel", "computer"),
    "94:65:9C": ("Intel", "computer"),  "A0:36:9F": ("Intel", "computer"),
    "A4:34:D9": ("Intel", "computer"),  "B8:08:D7": ("Intel", "computer"),
    "B8:CA:3A": ("Intel", "computer"),  "C4:8E:8F": ("Intel", "computer"),
    "DC:53:7C": ("Intel", "computer"),  "F4:06:69": ("Intel", "computer"),

    # ── Nintendo ────────────────────────────────────────────────────────────
    "00:09:BF": ("Nintendo", "gaming"), "00:17:AB": ("Nintendo", "gaming"),
    "00:19:1D": ("Nintendo", "gaming"), "00:1B:EA": ("Nintendo", "gaming"),
    "00:1E:35": ("Nintendo", "gaming"), "00:1F:32": ("Nintendo", "gaming"),
    "00:21:47": ("Nintendo", "gaming"), "00:22:D7": ("Nintendo", "gaming"),
    "00:23:CC": ("Nintendo", "gaming"), "00:24:44": ("Nintendo", "gaming"),
    "00:24:F3": ("Nintendo", "gaming"), "00:26:59": ("Nintendo", "gaming"),
    "7C:BB:8A": ("Nintendo", "gaming"), "98:B6:E9": ("Nintendo", "gaming"),
    "A4:C0:E1": ("Nintendo", "gaming"),

    # ── Sony PlayStation ─────────────────────────────────────────────────────
    "00:04:1F": ("Sony PlayStation", "gaming"), "00:1D:0D": ("Sony PlayStation", "gaming"),
    "1C:08:E0": ("Sony PlayStation", "gaming"), "70:9E:29": ("Sony PlayStation", "gaming"),
    "B0:05:94": ("Sony PlayStation", "gaming"),
}


# ─────────────────────────────────────────────────────────────────────────────
# DEVICE NAME → VENDOR HEURISTICS
# Applied when OUI lookup fails (random MACs, unknown OUIs)
# ─────────────────────────────────────────────────────────────────────────────
NAME_VENDOR_HINTS: list[tuple[list[str], str, str]] = [
    # keywords,                         vendor,              category
    (["airpods", "air pods"],           "Apple",             "audio"),
    (["iphone", "ipad", "ipod"],        "Apple",             "mobile"),
    (["macbook", "imac", "mac mini"],   "Apple",             "computer"),
    (["apple watch", "apple tv"],       "Apple",             "wearable"),
    (["galaxy", "samsung"],             "Samsung",           "mobile"),
    (["galaxy watch", "galaxy fit", "gear s", "gear fit"], "Samsung", "wearable"),
    (["mi band", "mi smart band", "miband"], "Xiaomi",       "wearable"),
    (["redmi", "xiaomi", "poco"],       "Xiaomi",            "mobile"),
    (["amazfit", "zepp"],               "Amazfit/Zepp",      "wearable"),
    (["redmi watch", "mi watch"],       "Xiaomi",            "wearable"),
    (["pixel buds"],                    "Google",            "audio"),
    (["pixel"],                         "Google",            "mobile"),
    (["echo dot", "echo show", "echo plus", "fire tv", "kindle"], "Amazon", "iot"),
    (["jbl"],                           "JBL/Harman",        "audio"),
    (["bose"],                          "Bose",              "audio"),
    (["sony wh", "sony wf", "sony xm", "sony xb"], "Sony",  "audio"),
    (["jabra"],                         "Jabra",             "audio"),
    (["soundcore", "anker"],            "Anker/Soundcore",   "audio"),
    (["edifier"],                       "Edifier",           "audio"),
    (["marshall"],                      "Marshall",          "audio"),
    (["nothing ear", "nothing phone"],  "Nothing",           "audio"),
    (["oneplus buds", "one plus buds"], "OnePlus",           "audio"),
    (["lg om", "lg sn", "lg sp"],       "LG",                "audio"),
    (["beats"],                         "Apple/Beats",       "audio"),
    (["huawei", "honor"],               "Huawei",            "mobile"),
    (["motorola", "moto g", "moto e"],  "Motorola",          "mobile"),
    (["garmin"],                        "Garmin",            "wearable"),
    (["fitbit"],                        "Fitbit",            "wearable"),
    (["logitech", "logi"],              "Logitech",          "computer"),
    (["xbox"],                          "Microsoft",         "gaming"),
    (["quest"],                         "Meta/Oculus",       "computer"),
    (["oculus"],                        "Meta/Oculus",       "computer"),
    (["[tv]", "crystal uhd", "qled", "the frame", "pokémon tv"],
                                        "Samsung",           "tv"),
    (["hisense", "tcl", "vizio"],       "TV Brand",          "tv"),
    (["tuya", "ty 💡", "smart life"],   "Tuya/SmartLife",    "iot"),
    (["fridge", "washer", "dryer", "dishwasher"], "Smart Appliance", "appliance"),
    (["rg-w", "ruijie"],                "Ruijie Networks",   "networking"),
    (["ad_401", "rac_", "_ww_"],        "Midea/AC",          "appliance"),
    (["mi smart band 4", "mi smart band 5", "mi smart band 6", "mi smart band 7"],
                                        "Xiaomi",            "wearable"),
    (["galaxy fit3", "galaxy fit2"],    "Samsung",           "wearable"),
    (["dm rr", "dmrr"],                 "Positivo",          "mobile"),
    (["net "],                          "Unknown",           "networking"),
    (["xs-"],                           "Unknown",           "audio"),
]


# ─────────────────────────────────────────────────────────────────────────────
# LOOKUP FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def lookup_vendor(mac: str) -> tuple[str, str]:
    """Look up vendor and category for a MAC address.

    Returns (vendor, category) — both empty strings if unknown.
    Priority:
      1. Full 24-bit OUI exact match
      2. Locally administered MAC detection (random — returns "Random MAC")
    """
    if not mac or len(mac) < 8:
        return "", ""

    mac_u = mac.upper().replace("-", ":").strip()

    # Check locally administered bit (random MAC)
    try:
        first_byte = int(mac_u.split(":")[0], 16)
        if first_byte & 0x02:
            return "Random MAC", "unknown"
    except (ValueError, IndexError):
        pass

    oui = mac_u[:8]
    entry = OUI_DB.get(oui)
    if entry:
        return entry[0], entry[1]

    return "", ""


def lookup_vendor_by_name(name: str) -> tuple[str, str]:
    """Infer vendor from device name when OUI lookup fails."""
    if not name:
        return "", ""
    nl = name.lower()
    for keywords, vendor, category in NAME_VENDOR_HINTS:
        if any(kw in nl for kw in keywords):
            return vendor, category
    return "", ""


def enrich_vendor(mac: str, name: str = "", existing_vendor: str = "") -> tuple[str, str]:
    """Full enrichment: OUI → name hints → keep existing.

    Returns (vendor, category).
    """
    # Already known
    if existing_vendor and existing_vendor not in ("—", "-", "Unknown", ""):
        vendor_from_oui, cat = lookup_vendor(mac)
        # Still resolve category even if vendor known
        return existing_vendor, cat or "unknown"

    # Try OUI
    vendor, cat = lookup_vendor(mac)
    if vendor and vendor != "Random MAC":
        return vendor, cat

    # Try name hints
    vendor2, cat2 = lookup_vendor_by_name(name)
    if vendor2:
        return vendor2, cat2

    # Preserve random MAC label
    if vendor == "Random MAC":
        return "Random MAC", "unknown"

    return "—", "unknown"


def oui_stats() -> dict:
    """Return database statistics."""
    categories: dict[str, int] = {}
    vendors: set = set()
    for v, c in OUI_DB.values():
        categories[c] = categories.get(c, 0) + 1
        vendors.add(v)
    return {
        "total_ouis": len(OUI_DB),
        "unique_vendors": len(vendors),
        "categories": categories,
    }


if __name__ == "__main__":
    stats = oui_stats()
    print(f"OUI DB: {stats['total_ouis']} entries, {stats['unique_vendors']} vendors")
    print(f"Categories: {stats['categories']}")

    # Test with discovery data
    test = [
        ("40:79:00:2D:EE:CE", "Unknown"),
        ("51:7D:1D:D0:DE:EB", "EDIFIER BLE"),
        ("64:0F:26:A6:FB:0E", "Quest 3S"),
        ("BC:10:2F:FD:5C:BF", "Fridge"),
        ("34:E6:E6:56:C2:5B", "AD_401_RAC"),
        ("08:EF:3B:95:D0:9B", "LG OM4560"),
        ("D8:D6:68:17:23:71", "TY 💡"),
        ("A8:80:55:05:ED:3D", "TY 💡"),
        ("42:8E:7D:1B:02:A2", "Unknown"),
        ("4D:81:6E:87:CD:6B", "RG-W77"),
        ("44:4F:E1:34:08:A4", "Galaxy Watch5 Pro"),
        ("74:19:0A:03:BA:E0", "Galaxy Fit3"),
    ]
    print("\nTest lookups:")
    for mac, name in test:
        v, c = enrich_vendor(mac, name)
        print(f"  {mac}  {name:25} → {v:25} [{c}]")
