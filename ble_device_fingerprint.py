"""RadioRecon Opus V1 — BLE Device Fingerprinting."""
from __future__ import annotations
try:
    from oui_database import enrich_vendor, lookup_vendor_by_name
    _OUI_DB_AVAILABLE = True
except ImportError:
    _OUI_DB_AVAILABLE = False

DOMAIN_CLASSIFIERS = {
    # Order matters — more specific first
    "appliance": ["fridge", "washer", "dryer", "dishwasher", "oven", "microwave",
                   "air conditioner", "ac ", "hvac", "refrigerator", "freezer",
                   "robot vacuum", "roomba", "purifier"],
    "tv_display": ["[tv]", " tv ", "television", "smart tv", "roku", "fire tv",
                    "chromecast", "webos", "tizen", "apple tv", "shield",
                    "[monitor]", "display", "projector", "soundbar",
                    "series (", "crystal uhd", "frame ", "pokémon", "pokemon"],
    "wearable": ["band", "watch", "fit", "garmin", "polar", "amazfit", "mi band",
                 "mi smart band", "fitbit", "galaxy watch", "redmi watch"],
    "iot_home": ["tuya", "bulb", "plug", "lock", "switch", "sensor", "thermostat",
                 "hub", "zigbee", "shelly", "yeelight", "lifx", "hue", "lamp",
                 "light", "led", "smart bulb", "smartbulb", "wiz", "tapo",
                 "govee", "nanoleaf", "tradfri", "easyway", "smartbt", "iplug", "melk", "lantern", "magic light", "rgb bar", "led strip", "led bar"],
    "vehicle": ["bmw", "mercedes", "tesla", "vw", "kia", "hyundai", "ford",
                "toyota", "obd", "car", "elm327"],
    "medical": ["health", "blood", "pressure", "glucose", "pulse", "oximeter", "medical"],
    "audio": ["buds", "airpods", "headphone", "speaker", "bose", "sony wh",
              "jbl", "beats", "edifier", "earbuds", "earphone"],
    "peripheral": ["keyboard", "mouse", "gamepad", "controller", "remote",
                   "tile", "airtag", "tag", "tracker"],
    "networking": ["ap_", "router", "extender", "mesh", "rg-", "wifi", "access point"],
    "smartphone": ["iphone", "pixel", "galaxy s", "galaxy a", "galaxy z",
                   "oneplus", "phone", "poco", "redmi note", "oppo", "vivo",
                   "huawei p", "huawei mate", "honor"],
}

SMART_BULB_SIGNATURES = {
    "tuya": {"names": ["tuya", "ty", "smart bulb", "smartbulb"], "service_uuids": ["0000a001", "0000a002"]},
    "yeelight": {"names": ["yeelight", "yeelink"], "service_uuids": ["0000fee7"]},
    "govee": {"names": ["govee", "ihoment", "H6"], "service_uuids": []},
    "lifx": {"names": ["lifx"], "service_uuids": []},
    "wiz": {"names": ["wiz"], "service_uuids": []},
    "generic": {"names": ["bulb", "lamp", "light", "led"], "service_uuids": []},
}

COMPANY_IDS = {
    0x004C: "Apple, Inc.", 0x0006: "Microsoft", 0x000D: "Texas Instruments",
    0x000F: "Broadcom", 0x0059: "Nordic Semiconductor", 0x00E0: "Google",
    0x0075: "Samsung", 0x0157: "Xiaomi", 0x02FF: "Espressif", 0x0822: "Tuya Global",
    0x0000: "Ericsson", 0x0001: "Nokia", 0x0002: "Intel", 0x0003: "IBM",
    0x000A: "Cambridge Silicon Radio", 0x001D: "Qualcomm", 0x0060: "Sony",
    0x00C4: "LG Electronics", 0x00E0: "Google", 0x0131: "Bose", 0x018F: "Meta",
    0x02E5: "Huawei", 0x03F0: "Amazon", 0x0499: "Roku",
}

SERVICE_HINTS = {
    "00001812": ("peripheral", "", "HID device"),
    "0000180d": ("wearable", "", "Heart Rate sensor"),
    "00001816": ("wearable", "", "Cycling sensor"),
    "0000181a": ("iot_home", "", "Environmental sensor"),
    "0000181c": ("medical", "", "User data device"),
    "0000180f": ("general_ble", "", "Battery device"),
    "0000fe2c": ("audio", "Google", "Fast Pair device"),
    "0000fdf7": ("iot_home", "Samsung/SmartThings", "SmartThings device"),
    "0000fe95": ("iot_home", "Xiaomi", "Xiaomi BLE device"),
    "0000fee0": ("wearable", "Xiaomi", "Xiaomi wearable"),
    "0000fee1": ("wearable", "Xiaomi", "Xiaomi wearable"),
    "0000fee7": ("iot_home", "Yeelight/Xiaomi", "Yeelight device"),
}

def classify_domain(name: str, services: list = None) -> str:
    name_lower = (name or "").lower()
    for domain, keywords in DOMAIN_CLASSIFIERS.items():
        if any(kw in name_lower for kw in keywords):
            return domain
    if services:
        svc_str = " ".join(str(s).lower() for s in services)
        if "180d" in svc_str or "1816" in svc_str: return "wearable"
        if "1812" in svc_str: return "peripheral"
        if "fee0" in svc_str or "fee1" in svc_str: return "wearable"
    return "general_ble"

def is_smart_bulb(name: str, services: list = None) -> dict | None:
    name_lower = (name or "").lower()
    svc_str = " ".join(str(s).lower() for s in (services or []))
    for brand, sig in SMART_BULB_SIGNATURES.items():
        if any(n in name_lower for n in sig["names"]):
            return {"brand": brand, "match": "name"}
        for uuid in sig.get("service_uuids", []):
            if uuid in svc_str:
                return {"brand": brand, "match": "service_uuid"}
    return None

# ── BLE Name Database (21k entries from real-world BLE scans) ────────
_BLE_NAME_DB = {}
_BLE_NAME_DB_LOADED = False

def _load_ble_name_db():
    global _BLE_NAME_DB, _BLE_NAME_DB_LOADED
    if _BLE_NAME_DB_LOADED:
        return
    import json, os
    db_path = os.path.join(os.path.dirname(__file__), "ble_name_db.json")
    if os.path.exists(db_path):
        try:
            with open(db_path, encoding="utf-8") as f:
                _BLE_NAME_DB = json.load(f)
        except Exception:
            pass
    _BLE_NAME_DB_LOADED = True


def fingerprint_device(device_data: dict) -> dict:
    name = device_data.get("name", "") or ""
    mac = device_data.get("mac", device_data.get("address", ""))
    services = device_data.get("services", [])
    mfr_data = device_data.get("metadata", {}).get("manufacturer_data", {})
    rssi = device_data.get("rssi", -100)

    # ── Name DB lookup (highest priority enrichment) ─────────────
    _load_ble_name_db()
    db_entry = _BLE_NAME_DB.get(name) or _BLE_NAME_DB.get(name.strip())
    db_domain = db_entry["domain"] if db_entry else None
    db_brand  = db_entry["brand"]  if db_entry else None
    db_count  = db_entry["count"]  if db_entry else 0

    fp = {
        "mac": mac, "name": name,
        "domain": db_domain or classify_domain(name, services),
        "db_count": db_count,  # how many times seen globally
        "services": services, "os": "", "vendor": "", "model_guess": "",
        "secure_pairing": False, "address_type": device_data.get("address_type", "public"),
        "connectable": device_data.get("connectable", True),
        "rssi": rssi,
        "is_smart_bulb": False, "bulb_brand": None,
    }
    # Apply DB-sourced brand/domain
    if db_brand and not fp.get("vendor"):
        fp["vendor"] = db_brand
    if db_domain and db_domain not in ("general_ble", None):
        fp["domain"] = db_domain
        # Special case: led_light domain
        if db_domain == "led_light":
            fp["is_smart_bulb"] = True
            fp["bulb_brand"] = db_brand or "Generic BLE Light"

    bulb = is_smart_bulb(name, services)
    if bulb:
        fp["is_smart_bulb"] = True
        fp["bulb_brand"] = bulb["brand"]
        if not db_domain:
            fp["domain"] = "led_light"

    # ── OS Detection via manufacturer_data company IDs ──
    if mfr_data:
        for cid in mfr_data:
            cid_int = int(cid) if isinstance(cid, str) else cid
            if cid_int in COMPANY_IDS:
                fp["vendor"] = COMPANY_IDS[cid_int]
            # Apple (0x004C) — iPhones, iPads, Macs, AirPods, Apple Watch
            if cid_int == 0x004C:
                fp["os"] = "iOS/macOS"
                fp["vendor"] = "Apple"
            # Google (0x00E0) — Pixel, Android, Chromecast
            elif cid_int == 0x00E0:
                fp["os"] = "Android"
                fp["vendor"] = "Google"
            # Microsoft (0x0006) — Windows, Xbox, Surface
            elif cid_int == 0x0006:
                fp["os"] = "Windows"
                fp["vendor"] = "Microsoft"
            # Samsung (0x0075) — Galaxy phones, TVs, wearables
            elif cid_int == 0x0075:
                fp["os"] = "Android/Samsung"
                fp["vendor"] = "Samsung"

    # ── OS Detection via device name patterns ──
    nl = name.lower()
    if not fp["os"]:
        if any(k in nl for k in ["iphone", "ipad", "macbook", "airpods", "apple watch", "homepod"]):
            fp["os"] = "iOS/macOS"
            fp["vendor"] = fp["vendor"] or "Apple"
        elif any(k in nl for k in ["galaxy", "samsung", "sm-"]):
            fp["os"] = "Android/Samsung"
            fp["vendor"] = fp["vendor"] or "Samsung"
        elif any(k in nl for k in ["pixel", "nexus", "chromecast"]):
            fp["os"] = "Android"
            fp["vendor"] = fp["vendor"] or "Google"
        elif any(k in nl for k in ["surface", "xbox", "windows"]):
            fp["os"] = "Windows"
            fp["vendor"] = fp["vendor"] or "Microsoft"
        elif any(k in nl for k in ["oneplus", "oppo", "redmi", "poco", "realme", "vivo", "huawei", "honor"]):
            fp["os"] = "Android"
        elif any(k in nl for k in ["[tv]", "webos", "tizen", "roku", "fire tv", "shield"]):
            fp["os"] = "Smart TV"
            fp["domain"] = "iot_home"
        elif any(k in nl for k in ["[monitor]", "display", "lg ultragear"]):
            fp["os"] = "Monitor"
            fp["domain"] = "iot_home"

    # ── OS Detection via BLE address type ──
    addr_type = device_data.get("address_type", "public")
    if not fp["os"] and "random" in str(addr_type).lower():
        # Random addresses are commonly used by iOS, macOS, Windows 10+
        # Less by Android (which uses public more often)
        # Not enough info alone, but helps as hint
        pass

    # ── OS Detection via advertised services ──
    svc_lower = " ".join(services).lower()
    if not fp["os"]:
        if "d0611e78" in svc_lower or "7905f431" in svc_lower:
            fp["os"] = "iOS/macOS"  # Apple Continuity
        elif "0000fe2c" in svc_lower:
            fp["os"] = "Android"  # Google Nearby

    for svc_prefix, (dom, vendor, model) in SERVICE_HINTS.items():
        if svc_prefix in svc_lower:
            if fp["domain"] == "general_ble" and dom:
                fp["domain"] = dom
            if vendor and not fp["vendor"]:
                fp["vendor"] = vendor
            if model and not fp["model_guess"]:
                fp["model_guess"] = model

    # ── OUI (MAC prefix) detection — full OUI database ──
    if _OUI_DB_AVAILABLE and mac:
        oui_vendor, oui_cat = enrich_vendor(mac, name or "", fp["vendor"])
        if oui_vendor and oui_vendor not in ("—", "Random MAC", ""):
            fp["vendor"] = fp["vendor"] or oui_vendor
            # Update domain from OUI category if not already set
            cat_domain = {
                "audio": "audio", "wearable": "wearable", "tv": "tv_display",
                "appliance": "appliance", "networking": "networking",
                "gaming": "gaming", "iot": "iot_home", "mobile": "general_ble",
            }
            if oui_cat in cat_domain and fp["domain"] == "general_ble":
                fp["domain"] = cat_domain[oui_cat]
        elif oui_vendor == "Random MAC":
            fp["vendor"] = fp["vendor"] or "Random MAC"
        # Name-based vendor fallback when OUI unknown
        if not fp["vendor"] or fp["vendor"] in ("—", ""):
            name_v, name_c = lookup_vendor_by_name(name or "")
            if name_v:
                fp["vendor"] = name_v
                if name_c in {"audio", "wearable", "tv", "appliance", "iot_home"}:
                    fp["domain"] = {"audio": "audio", "wearable": "wearable",
                                    "tv": "tv_display", "appliance": "appliance",
                                    "iot": "iot_home"}.get(name_c, fp["domain"])
    else:
        # Fallback minimal OUI map (no oui_database.py)
        mac_prefix = mac[:8].upper() if mac else ""
        _mini = {
            "D4:75:93": "Xiaomi", "F4:0A:5B": "Xiaomi", "04:DA:28": "Xiaomi",
            "D8:D6:68": "Tuya",   "7C:64:56": "Samsung","54:44:A3": "Samsung",
            "70:2A:D5": "Samsung","1C:86:9A": "Samsung","00:E0:4C": "Realtek",
            "58:A5:F2": "Edifier","64:0F:26": "Meta",   "BC:10:2F": "Samsung",
        }
        if mac_prefix in _mini:
            fp["vendor"] = fp["vendor"] or _mini[mac_prefix]

    # Samsung domain refinement
    if fp.get("vendor") == "Samsung":
        if any(k in nl for k in ["tv", "[tv]", "series (", "crystal", "qled", "frame", "pokémon"]):
            fp["os"] = "Tizen (Smart TV)"; fp["domain"] = "tv_display"
        elif any(k in nl for k in ["monitor", "[monitor]", "display"]):
            fp["os"] = "Monitor"; fp["domain"] = "tv_display"
        elif any(k in nl for k in ["fridge", "refrigerator", "washer", "dryer"]):
            fp["os"] = "SmartThings"; fp["domain"] = "appliance"
        elif any(k in nl for k in ["galaxy watch", "galaxy fit", "gear s", "gear fit"]):
            fp["domain"] = "wearable"
        elif not fp["os"]:
            fp["os"] = "Android/Samsung"

    # ── Model-specific detection ──
    if "redmi buds" in nl:
        fp["vendor"] = "Xiaomi"
        fp["domain"] = "audio"
        fp["os"] = fp["os"] or "Android"
        fp["model_guess"] = name
    elif "redmi" in nl or "poco" in nl or "xiaomi" in nl:
        fp["vendor"] = fp["vendor"] or "Xiaomi"
    if "mi band 3" in nl or "mi smart band 3" in nl:
        fp["model_guess"] = "Mi Band 3"; fp["vendor"] = "Xiaomi"
    elif "mi band 4" in nl or "mi smart band 4" in nl:
        fp["model_guess"] = "Mi Band 4"; fp["vendor"] = "Xiaomi"
    elif "redmi watch" in nl or "amazfit" in nl:
        fp["vendor"] = fp["vendor"] or "Xiaomi/Zepp"
    elif "echo" in nl or "fire" in nl:
        fp["vendor"] = fp["vendor"] or "Amazon"; fp["os"] = fp["os"] or "Fire OS"
    elif "jbl" in nl or "bose" in nl or "sony" in nl:
        fp["domain"] = "audio"

    return fp

def estimate_distance(rssi: int, tx_power: int = -59) -> float:
    if rssi == 0: return -1.0
    ratio = rssi / tx_power
    if ratio < 1.0: return ratio ** 10
    return 0.89976 * (ratio ** 7.7095) + 0.111
