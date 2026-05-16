# BLEAK — Android BLE Scanner

Versão mobile nativa portada para Android. Usa **somente o Bluetooth nativo do aparelho** — sem ESP32.

![bleak](imagens/apk_bleak.jpg)

## Funcionalidades

### 📡 Discovery
- Scan BLE geral + fingerprinting (iOS, Android, Windows, Headphones)
- Detecção de MAC aleatório, ordenação por RSSI

### ⚡ Fast Pair Tab  
- Scan filtrando UUID `0xFE2C` + Google `0x00E0`
- Detecta devices Fast Pair mesmo quando pareados
- Extrai Model ID + lookup offline de modelo

### 🔍 GATT Analyzer
- Enumeração completa de serviços/características
- **CVE-2025-36911 (WhisperPair)**: write no KBP char fora do pairing mode
- **CVE-2025-20700 (RACE/Airoha)**: detecta service `0xAE00`
- Input manual de MAC

### 📋 Log
- Log completo com timestamps

## Módulos de Vulnerabilidade

| Módulo | CVE | Técnica |
|---|---|---|
| WhisperPair | CVE-2025-36911 | Write no FP KBP char sem autenticação |
| RACE Detection | CVE-2025-20700/01/02 | Detecção service 0xAE00 |
| HID Check | CVE-2023-45866 | Keyboard injection surface |
| BLESA | CVE-2020-9770 | Reconnection spoofing (iOS) |

## Stack

- Kotlin 1.9 + Android BLE API nativa
- minSdk 26 (Android 8.0) | targetSdk 34
- ViewBinding + LiveData + Coroutines
- Material Design 3 (dark theme)

## ⚠️ Disclaimer

Para uso exclusivo em testes de segurança autorizados.
