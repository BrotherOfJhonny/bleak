# BLEAK API Reference

Base URL: `http://<host>:8080`

All POST endpoints accept JSON (`Content-Type: application/json`).  
Long-running operations return `job_id` immediately — poll for results.

## Polling pattern

```bash
# Start operation → get job_id
POST /api/audio/whisperpair-flow  →  {"job_id": "wp_...", "status": "running"}

# Poll until status == "done"
GET /api/audio/whisperpair-status/<job_id>  →  {"status": "done", "verdict": "VULNERABLE", ...}
```

---

## System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | System status, HCI/ESP32 availability |
| GET | `/api/adapters` | List BT adapters (hci + ESP32) |
| GET | `/api/system/capabilities` | Tool availability (bettercap, blueducky…) |
| POST | `/api/esp32/test` | Test ESP32 serial connectivity |
| POST | `/api/esp32/fix-permissions` | chmod 666 on serial ports |
| POST | `/api/disclaimer/accept` | Accept legal disclaimer |

## Discovery

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/discovery/start` | `{"timeout": 30}` | Start BLE scan |
| GET | `/api/discovery/results` | — | Get discovered devices |
| POST | `/api/discovery/stop` | — | Stop active scan |
| POST | `/api/discovery/clear` | — | Clear device list |

## Enumeration

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/enum/start` | `{"macs": ["AA:BB:..."]}` | GATT enum (async) |
| GET | `/api/enum/results` | — | Enum results |

## Vulnerability Scan

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/vuln/scan` | `{"macs": [...]}` | Run vuln checks |
| GET | `/api/vuln/results` | — | Check results |

## Audio Exploits

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/audio/whisperpair-flow` | `{"mac": "..."}` | Full WhisperPair exploit |
| GET | `/api/audio/whisperpair-status/<id>` | — | Poll job status |
| POST | `/api/audio/fast-pair-scan` | `{"seconds": 8}` | Fast Pair device scan |
| POST | `/api/audio/bluespy-check` | `{"mac": "..."}` | BlueSpy check |
| POST | `/api/audio/race-check` | `{"mac": "..."}` | RACE/Airoha check |
| POST | `/api/audio/record` | `{"mac":"...","duration":20,"mode":"a2dp"}` | Record audio |
| POST | `/api/audio/record-stop/<id>` | — | Stop recording |

## BLE Spam

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/spam/start` | `{"type":"apple","duration":30}` | Start BLE spam |
| POST | `/api/spam/stop` | — | Stop spam |
| GET | `/api/spam/status` | — | Spam status + packet count |
| POST | `/api/spam/external-scan` | `{"duration":10}` | Detect Flipper/M5 spammers |

**Spam types:** `apple`, `apple_action`, `android`, `android_random`, `samsung`, `samsung_buds`, `samsung_watch`, `windows`, `kitchen`, `lovespouse`, `all`

## Smart Bulb

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/smartbulb/discover` | — | Find BLE bulbs |
| POST | `/api/smartbulb/color` | `{"mac":"...","r":255,"g":0,"b":0}` | Set RGB color |
| POST | `/api/smartbulb/power` | `{"mac":"...","on":true}` | Power on/off |
| POST | `/api/smartbulb/effect` | `{"mac":"...","effect":4}` | Set effect |

## Smartwatch

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/smartwatch/read` | `{"mac":"...","auth_key":"hex"}` | Read watch data |
| GET | `/api/smartwatch/profiles` | — | List supported models |

## Reports

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/reports/generate` | `{"type":"technical","selected_macs":[...]}` | Generate report |
| GET | `/api/reports/list` | — | List saved reports |

---

## Response formats

### Device object
```json
{
  "mac": "AA:BB:CC:DD:EE:FF",
  "name": "Redmi Buds 5 Pro",
  "rssi": -44,
  "domain": "audio",
  "vendor": "Xiaomi",
  "is_smart_bulb": false,
  "is_random_mac": false,
  "rotation_count": 1,
  "db_count": 12345
}
```

### Job status
```json
{
  "job_id": "wp_AA_BB_CC_1715123456",
  "status": "done",
  "verdict": "VULNERABLE",
  "details": "Device localizado via discovery_cache | KBP→1236 | VULNERÁVEL",
  "steps": ["scan", "preflight", "gatt_connect", "kbp_write", "verify_response"],
  "post_exploit_connected": true,
  "mac": "AA:BB:CC:DD:EE:FF"
}
```
