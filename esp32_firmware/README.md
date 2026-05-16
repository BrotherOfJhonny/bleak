# BLEAK ESP32 Firmware v5.1

## Dois firmwares separados — C3 e S3

### bleak_esp32_c3_v5.ino — ESP32-C3
Chip: ESP32-C3 | Port: /dev/ttyACM0 ou /dev/ttyACM1 (USB CDC nativo)
Capabilities: BLE Spam, Karma, Scan (FP/Raw/General), Beacon, BeaconLoop,
              Custom ADV, MAC Clone (random), TX Power, RSSI Filter, BLE Enum

### bleak_esp32_s3_v5.ino — ESP32-S3
Chip: ESP32-S3 | Port: /dev/ttyUSB1 (via FT232 adapter)
Capabilities: Tudo do C3 MAIS:
  - HID Injection via BLE (AT+HID=)
  - HID Injection via USB-OTG (AT+HIDUSB=) — requer compilação com USB stack
  - Dual core — spam no Core 0, serial no Core 1
  - MAC Clone aprimorado

---

## Flash — Arduino IDE

### Requisitos
- Arduino IDE 2.x
- Board: "esp32" by Espressif >= 3.x
- Library: NimBLE-Arduino >= 1.4.0 (instalar via Library Manager)

### Configurações para ESP32-C3
```
Board: "ESP32C3 Dev Module"
Upload Speed: 921600
USB CDC On Boot: Enabled   ← obrigatório para /dev/ttyACM*
Flash Size: 4MB
Partition Scheme: Default 4MB
```

### Configurações para ESP32-S3 (via FT232)
```
Board: "ESP32S3 Dev Module"
Upload Speed: 921600
USB CDC On Boot: Disabled  ← S3 usa FT232, não CDC nativo
USB Mode: Hardware CDC and OTG
Flash Size: 4MB (or 8MB if your board has it)
Partition Scheme: Default 4MB
Port: /dev/ttyUSB1 (FT232)
```

### ESP32-S3 com USB HID (AT+HIDUSB)
Para habilitar USB HID no S3, configure:
```
USB CDC On Boot: Disabled
USB DFU On Boot: Disabled
USB Firmware MSC On Boot: Disabled
USB Mode: USB-OTG
```
E conecte o cabo USB-OTG ao conector USB DATA do S3 (não o UART/FT232).

---

## Flash via linha de comando

### C3
```bash
pip install esptool
# Apagar flash
esptool.py --chip esp32c3 --port /dev/ttyACM0 erase_flash
# Flash (após compilar no Arduino IDE — Export Compiled Binary)
esptool.py --chip esp32c3 --port /dev/ttyACM0 --baud 921600 \
  write_flash -z 0x0 bleak_esp32_c3_v5.ino.bin
```

### S3
```bash
esptool.py --chip esp32s3 --port /dev/ttyUSB1 erase_flash
esptool.py --chip esp32s3 --port /dev/ttyUSB1 --baud 921600 \
  write_flash -z 0x0 bleak_esp32_s3_v5.ino.bin
```

---

## Teste rápido após flash

```bash
# C3
minicom -D /dev/ttyACM1 -b 115200
# S3
minicom -D /dev/ttyUSB1 -b 115200

# Deve responder:
> AT+VERSION
OK:BLEAK-C3 v5.1 [ESP32-C3]
> AT+STATUS
OK:idle,pkts=0,karma=0,heap=287000,chip=ESP32-C3,power=9,rssi_filter=-99
```

---

## Referência de comandos v5.1

### Comuns (C3 e S3)
| Comando | Descrição | Resposta |
|---|---|---|
| AT+VERSION | Versão do firmware | OK:BLEAK-C3/S3 v5.1 [...] |
| AT+STATUS | Status atual | OK:idle/spam/beacon/karma,pkts=N,... |
| AT+HELP | Lista de comandos | OK:CMDS:... |
| AT+SPAM=type,dur | Iniciar spam BLE | OK:SPAM:type:dur |
| AT+STOP | Parar tudo | OK:STOP:pkts=N |
| AT+KARMA=dur | Ataque karma | OK:KARMA:dur |
| AT+KARMASTOP | Parar karma | OK:KARMASTOP:N |
| AT+SCAN=sec | Scan BLE geral | DEV:MAC:RSSI:nome (por device) |
| AT+FPSCAN=sec | Scan Fast Pair | FP:MAC:RSSI:modelID:state:nome |
| AT+SCANRAW=sec | Scan raw hex | RAW:MAC:RSSI:0:hexPayload |
| AT+BLEENUM=MAC | Enumerar device | ENUM:MAC:RSSI:nome:flags:uuid |
| AT+ADV=hex | ADV customizado | OK:ADV:N |
| AT+BEACON=nome,dur | Beacon (dur=0=forever) | OK:BEACON:nome:dur |
| AT+BEACONSTOP | Parar beacon | OK:BEACONSTOP |
| AT+BEACONLOOP=nome,ms | Beacon contínuo | OK:BEACONLOOP:nome:ms |
| AT+MACCLONE=XX:XX:XX:XX:XX:XX | Spoof MAC | OK:MACCLONE:mac |
| AT+MACCLONE=RANDOM | MAC aleatório (padrão) | OK:MACCLONE:RANDOM |
| AT+SETPOWER=0-9 | TX power (-12 a +9 dBm) | OK:SETPOWER:N |
| AT+RSSI=threshold | Filtro RSSI para scans | OK:RSSI:N |

### Exclusivos S3
| Comando | Descrição | Resposta |
|---|---|---|
| AT+HID=payload | Injetar via BLE HID | OK:HID:BLE:N |
| AT+HIDUSB=payload | Injetar via USB HID | OK:HIDUSB:N |
| AT+HIDSTOP | Parar HID | OK:HIDSTOP |
| AT+HIDSTATUS | Status HID | OK:HIDSTATUS:idle/running |

### Tipos de SPAM
| Tipo | Alvo | Descrição |
|---|---|---|
| apple | iOS/macOS | AirPods popup, continuity |
| apple_crash | iOS 17 | Random model IDs — lockup |
| apple_action | iOS | Action modal dialogs |
| android | Android | Google Fast Pair com Model IDs conhecidos, connectable ADV, service UUID e scan response |
| android_random | Android | Fast Pair com Model IDs aleatórios para teste regressivo; Android recente pode ignorar |
| samsung | Galaxy | Alterna Google Fast Pair Samsung e Samsung EasySetup |
| samsung_buds | Galaxy | Galaxy Buds pairing popup via Fast Pair + EasySetup |
| samsung_watch | Galaxy | Galaxy Watch pairing popup via Fast Pair + EasySetup |
| windows | Windows | Swift Pair popup |
| lovespouse | Adults | Adult toy disruption |
| kitchen / all | Todos | Rotação de todos os tipos |

### Sintaxe HID payload
Linhas separadas por `|`:
```
STRING texto a digitar|ENTER|DELAY 500|GUI r|STRING calc|ENTER
```
Teclas: STRING, ENTER, TAB, SPACE, ESC, UP, DOWN, LEFT, RIGHT,
        BACKSPACE, DELETE, GUI key, CTRL key, ALT key, DELAY ms,
        CTRL ALT DELETE

### Resposta em tempo real (durante spam)
```
SPAM:PKT:10     ← a cada 10 packets
SPAM:PKT:20
SPAM:DONE:47    ← ao terminar
```

---

## Alocação automática BLEAK

| Tarefa | Adapter preferido |
|---|---|
| BLE Discovery / GATT | hci0 |
| Fast Pair Scan | ESP32-C3 |
| BLE Spam (todos os tipos) | ESP32-C3 |
| Karma | ESP32-C3 |
| Beacon / Custom ADV | ESP32-C3 |
| HID Injection (BLE) | ESP32-S3 |
| HID Injection (USB) | ESP32-S3 (USB-OTG) |
| MAC Clone | ESP32-S3 |
| Sniffer passivo | ESP32-C3 (FPSCAN) |

---

## Notas importantes

1. **Porta JTAG** — `ID 303a:1001` = JTAG debug. NÃO é porta serial.
2. **Android/Samsung spam** — exige firmware v5.1+. A v5.0 usava Model IDs aleatórios como padrão e enviava payloads Samsung com tamanho incorreto, o que fazia Android 11+ e Android recente ignorarem os anúncios.
3. **Pré-condições no telefone** — tela ligada/desbloqueada, Bluetooth ativo, Nearby/Dispositivos por perto ativo, ESP32 a menos de 1 metro. Android recente pode suprimir popups repetidos por cache/anti-spam.
   O BLEAK V16 detecta e exclui automaticamente estas portas.

2. **Permissões** — após conectar: `sudo chmod 666 /dev/ttyUSB1 /dev/ttyACM1`
   Ou adicione ao grupo: `sudo usermod -aG dialout kali`

3. **screen/minicom aberto** — fecha antes de usar o BLEAK.
   O BLEAK V16 detecta conflito e exibe mensagem de erro.

4. **NimBLE-Arduino** — library obrigatória. Versão recomendada: >= 1.4.0
   Install: Arduino IDE → Library Manager → "NimBLE-Arduino"
