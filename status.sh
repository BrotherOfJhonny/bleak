#!/usr/bin/env bash
SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo ""; echo "═══ ⚡ BLEAK V0.18 — Status ═══"; echo ""
echo "── Adapter ──"
HCI_IFACE=$(hciconfig 2>/dev/null | awk -F: '/^hci[0-9]+:/{print $1; exit}')
[[ -n "$HCI_IFACE" ]] && hciconfig "$HCI_IFACE" 2>/dev/null | head -3 || echo "  ✗ adaptador HCI indisponível"
echo ""; echo "── Ferramentas Nativas ──"
for t in hcitool hciconfig l2ping sdptool rfcomm bluetoothctl hcidump bettercap pactl parecord pw-record paplay; do
    p=$(which "$t" 2>/dev/null || echo ""); [[ -n "$p" ]] && echo "  ✓ $t" || echo "  ✗ $t"
done
echo ""; echo "── Ferramentas Externas ──"
for n in AppleJuice BlueDucky Bluetooth-LE-Spam BlueToolkit BluetoothDucky blendr; do
    [[ -d "$SD/tools/$n" ]] && echo "  ✓ $n" || echo "  ✗ $n"
done
echo ""; echo "── ESP32 ──"
ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null | while read p; do echo "  🔌 $p"; done
[[ -f "$SD/esp32_firmware/radiorecon_esp32.ino" ]] && echo "  ✓ Firmware disponível" || echo "  ✗ Firmware não encontrado"
echo ""; echo "── Python ──"
"$SD/.venv/bin/python" -c "
import sys; print(f'  Python {sys.version.split()[0]}')
for m,n in [('flask','Flask'),('bleak','bleak'),('Crypto','pycryptodome'),('serial','pyserial'),('bluetooth','PyBluez'),('rich','rich')]:
    try: __import__(m); print(f'  ✓ {n}')
    except: print(f'  ✗ {n}')
" 2>/dev/null || echo "  ✗ venv não encontrado"
echo ""; echo "═══ Iniciar: sudo ./run_web_lan.sh ═══"
