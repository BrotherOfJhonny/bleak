#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# BLEAK V0.18 — Instalador Completo
# ═══════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"
LOG_FILE="$SCRIPT_DIR/install.log"
SUDO="sudo"; [[ $EUID -eq 0 ]] && SUDO=""
CUR_USER="${SUDO_USER:-$USER}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
step()  { echo -e "\n${CYAN}═══ $1${NC}"; }
ok()    { echo -e "  ${GREEN}✓${NC} $1"; }
warn()  { echo -e "  ${YELLOW}△${NC} $1"; }
fail()  { echo -e "  ${RED}✗${NC} $1"; }
info()  { echo -e "  ${CYAN}→${NC} $1"; }

exec > >(tee -a "$LOG_FILE") 2>&1

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║            BLEAK V0.18 — Instalador Completo         ║"
echo "║          BLE/Bluetooth Security Assessment Platform       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "User: $CUR_USER | $(date)"

# ══════════════════════════════════════════════════════════
# 1. APT — system dependencies
# ══════════════════════════════════════════════════════════
step "1/11 — Dependências de sistema (apt)"
$SUDO apt-get update -qq 2>/dev/null || warn "apt update falhou"

for pkg in python3 python3-pip python3-venv python3-dev \
           bluetooth bluez bluez-tools libbluetooth-dev \
           pulseaudio-utils pipewire pipewire-pulse wireplumber alsa-utils \
           rfkill build-essential libglib2.0-dev libdbus-1-dev \
           git net-tools python3-gi python3-dbus \
           libpcap-dev libev-dev libnl-3-dev libnl-genl-3-dev libnl-route-3-dev \
           cmake screen tmux; do
    if dpkg -s "$pkg" &>/dev/null; then
        ok "$pkg"
    else
        $SUDO apt-get install -y -qq "$pkg" 2>/dev/null && ok "$pkg ✓" || warn "$pkg falhou"
    fi
done

# ══════════════════════════════════════════════════════════
# 2. PYTHON VENV + PIP
# ══════════════════════════════════════════════════════════
step "2/11 — Python venv + pip"
[[ ! -d "$SCRIPT_DIR/.venv" ]] && python3 -m venv "$SCRIPT_DIR/.venv" && ok "venv criado" || ok "venv existe"
source "$SCRIPT_DIR/.venv/bin/activate"
pip install --break-system-packages --upgrade pip setuptools wheel click -q 2>/dev/null
pip install --break-system-packages -q flask">=3.0" flask-cors">=4.0" bleak">=0.21" pycryptodome">=3.19" \
    rich">=13.0" pyserial">=3.5" pyyaml">=6.0" 2>/dev/null || warn "Algumas deps falharam"
ok "Deps pip base instaladas"

# Expor PyGObject do sistema ao venv
SYSTEM_SITE=$(python3 -c "import site; print(site.getsitepackages()[0])" 2>/dev/null || echo "")
VENV_SITE=$("$SCRIPT_DIR/.venv/bin/python" -c "import site; print(site.getsitepackages()[0])" 2>/dev/null || echo "")
if [[ -n "$SYSTEM_SITE" && -n "$VENV_SITE" && "$SYSTEM_SITE" != "$VENV_SITE" ]]; then
    echo "$SYSTEM_SITE" > "$VENV_SITE/system_packages.pth"
    ok "PyGObject exposto ao venv"
fi

# ══════════════════════════════════════════════════════════
# 3. PYBLUEZ (raw HCI socket — essencial para BLE spam)
# ══════════════════════════════════════════════════════════
step "3/11 — PyBluez (raw HCI — BLE Spam engine)"
if "$SCRIPT_DIR/.venv/bin/python" -c "import bluetooth" 2>/dev/null; then
    ok "PyBluez já instalado"
else
    info "Instalando PyBluez do GitHub (versão corrigida)..."
    pip install --break-system-packages -q git+https://github.com/pybluez/pybluez.git#egg=pybluez 2>/dev/null && ok "PyBluez instalado" || {
        warn "PyBluez via git falhou. Tentando pip..."
        pip install --break-system-packages -q pybluez 2>/dev/null && ok "PyBluez (pip)" || {
            warn "PyBluez falhou — BLE spam via AppleJuice pode não funcionar"
            info "Tente: sudo apt install python3-bluez libbluetooth-dev && pip install pybluez"
        }
    }
fi

# ══════════════════════════════════════════════════════════
# 4. FERRAMENTAS BT NATIVAS
# ══════════════════════════════════════════════════════════
step "4/11 — Ferramentas Bluetooth nativas"
for tool in hcitool hciconfig hcidump l2ping sdptool rfcomm bluetoothctl; do
    command -v "$tool" &>/dev/null && ok "$tool" || fail "$tool — sudo apt install bluez bluez-tools"
done

# ══════════════════════════════════════════════════════════
# 5. BETTERCAP
# ══════════════════════════════════════════════════════════
step "5/11 — bettercap"
if command -v bettercap &>/dev/null; then
    ok "bettercap: $(which bettercap)"
else
    $SUDO apt-get install -y -qq bettercap 2>/dev/null && ok "bettercap instalado" || warn "bettercap: instale manualmente"
fi

# ══════════════════════════════════════════════════════════
# 6. APPLEJUICE (BLE Spam — comprovado funcional em Linux)
# ══════════════════════════════════════════════════════════
step "6/11 — AppleJuice (BLE Spam — funcional via PyBluez)"
mkdir -p "$TOOLS_DIR"
AJ_DIR="$TOOLS_DIR/AppleJuice"

if [[ -d "$AJ_DIR/.git" ]]; then
    ok "AppleJuice existe"
    cd "$AJ_DIR" && git pull --quiet 2>/dev/null || true; cd "$SCRIPT_DIR"
elif [[ -f "$AJ_DIR/app.py" || -f "$AJ_DIR/utils/bluetooth_utils.py" || -f "$AJ_DIR/bluetooth_utils.py" ]]; then
    ok "AppleJuice presente em $AJ_DIR"
else
    info "Clonando AppleJuice..."
    if [[ -d "$AJ_DIR" && -n "$(ls -A "$AJ_DIR" 2>/dev/null)" ]]; then
        warn "AppleJuice dir existe mas não parece completo: $AJ_DIR"
    else
        rm -rf "$AJ_DIR"
        git clone --depth 1 https://github.com/ECTO-1A/AppleJuice.git "$AJ_DIR" 2>/dev/null && ok "AppleJuice clonado" || warn "AppleJuice não baixado — recurso opcional; usando fallback se já existir"
    fi
fi
# bluetooth_utils.py lives in utils/ subfolder
if [[ -f "$AJ_DIR/utils/bluetooth_utils.py" ]]; then
    ok "utils/bluetooth_utils.py presente"
elif [[ -f "$AJ_DIR/bluetooth_utils.py" ]]; then
    ok "bluetooth_utils.py presente (raiz)"
else
    warn "bluetooth_utils.py não encontrado — verifique o clone"
fi

# ══════════════════════════════════════════════════════════
# 7. BLUEDUCKY (CVE-2023-45866 — HID Injection)
# ══════════════════════════════════════════════════════════
step "7/11 — BlueDucky (CVE-2023-45866)"
BLUEDUCKY_DIR="$TOOLS_DIR/BlueDucky"
if [[ -d "$BLUEDUCKY_DIR/.git" ]]; then
    ok "BlueDucky existe"
    cd "$BLUEDUCKY_DIR" && git pull --quiet 2>/dev/null || true; cd "$SCRIPT_DIR"
elif [[ -f "$BLUEDUCKY_DIR/BlueDucky.py" ]]; then
    ok "BlueDucky presente em $BLUEDUCKY_DIR"
else
    info "Clonando BlueDucky..."
    if [[ -d "$BLUEDUCKY_DIR" && -n "$(ls -A "$BLUEDUCKY_DIR" 2>/dev/null)" ]]; then
        warn "BlueDucky dir existe mas não parece completo: $BLUEDUCKY_DIR"
    else
        rm -rf "$BLUEDUCKY_DIR"
        git clone --depth 1 https://github.com/pentestfunctions/BlueDucky.git "$BLUEDUCKY_DIR" 2>/dev/null && ok "BlueDucky clonado" || warn "BlueDucky não baixado — HID injection externo fica indisponível"
    fi
fi
[[ -f "$BLUEDUCKY_DIR/requirements.txt" ]] && pip install --break-system-packages -q -r "$BLUEDUCKY_DIR/requirements.txt" 2>/dev/null || true

# ══════════════════════════════════════════════════════════
# 8. BLUETOOLKIT + EXTRAS
# ══════════════════════════════════════════════════════════
step "8/11 — BlueToolkit + ferramentas extras"

declare -A REPOS=(
    ["BlueToolkit"]="sgxgsx/BlueToolkit"
    ["Bluetooth-LE-Spam"]="simondankelmann/Bluetooth-LE-Spam"
    ["BluetoothDucky"]="Eason-zz/BluetoothDucky"
    ["blendr"]="dmtrKovalenko/blendr"
)

declare -A SENTINELS=(
    ["BlueToolkit"]="README.md"
    ["Bluetooth-LE-Spam"]="README.md"
    ["BluetoothDucky"]="BluetoothDucky.py"
    ["blendr"]="Cargo.toml"
)

for name in "${!REPOS[@]}"; do
    repo="${REPOS[$name]}"
    dir="$TOOLS_DIR/$name"
    if [[ -d "$dir/.git" ]]; then
        ok "$name existe"
        cd "$dir" && git pull --quiet 2>/dev/null || true; cd "$SCRIPT_DIR"
    elif [[ -f "$dir/${SENTINELS[$name]}" ]]; then
        ok "$name presente em $dir"
    else
        if [[ -d "$dir" && -n "$(ls -A "$dir" 2>/dev/null)" ]]; then
            warn "$name dir existe mas não parece completo: $dir"
        else
            rm -rf "$dir"
            git clone --depth 1 "https://github.com/$repo.git" "$dir" 2>/dev/null && ok "$name clonado" || warn "$name não baixado — recurso opcional"
        fi
    fi
done

[[ -f "$TOOLS_DIR/BlueToolkit/requirements.txt" ]] && pip install --break-system-packages -q -r "$TOOLS_DIR/BlueToolkit/requirements.txt" 2>/dev/null || true

# ══════════════════════════════════════════════════════════
# 9. PERMISSÕES BLUETOOTH
# ══════════════════════════════════════════════════════════
step "9/11 — Permissões Bluetooth"
groups "$CUR_USER" 2>/dev/null | grep -q bluetooth || $SUDO usermod -aG bluetooth "$CUR_USER" 2>/dev/null || true
$SUDO systemctl enable bluetooth 2>/dev/null || true
$SUDO systemctl start bluetooth 2>/dev/null && ok "bluetooth ativo" || warn "bluetooth service falhou"
$SUDO rfkill unblock bluetooth 2>/dev/null && ok "rfkill OK" || true

REAL_PYTHON=$(readlink -f "$SCRIPT_DIR/.venv/bin/python" 2>/dev/null || echo "$SCRIPT_DIR/.venv/bin/python")
$SUDO setcap 'cap_net_raw,cap_net_admin+eip' "$REAL_PYTHON" 2>/dev/null && ok "setcap python (BLE sem sudo)" || warn "setcap falhou — use sudo"

for tool in hcitool l2ping hcidump; do
    tp=$(which "$tool" 2>/dev/null || echo "")
    [[ -n "$tp" ]] && $SUDO setcap 'cap_net_raw,cap_net_admin+eip' "$tp" 2>/dev/null || true
done

HCI_IFACE=$(hciconfig 2>/dev/null | awk -F: '/^hci[0-9]+:/{print $1; exit}')
[[ -n "$HCI_IFACE" ]] && $SUDO hciconfig "$HCI_IFACE" up 2>/dev/null && ok "$HCI_IFACE UP" || warn "adaptador HCI indisponível"

# ══════════════════════════════════════════════════════════
# 10. ESP32 FIRMWARE
# ══════════════════════════════════════════════════════════
step "10/11 — ESP32 Firmware"
if [[ -f "$SCRIPT_DIR/esp32_firmware/radiorecon_esp32.ino" ]]; then
    ok "Firmware ESP32 disponível: $SCRIPT_DIR/esp32_firmware/"
    info "Para flashar: Arduino IDE → Board: ESP32S3 Dev Module → USB CDC On Boot: Enabled → Upload"
else
    warn "Firmware ESP32 não encontrado"
fi

# ══════════════════════════════════════════════════════════
# 11. SCRIPTS + CONFIG
# ══════════════════════════════════════════════════════════
step "11/11 — Scripts e configuração"
mkdir -p "$SCRIPT_DIR"/{reports,captures,logs}

# tools_config.json
cat > "$SCRIPT_DIR/tools_config.json" << CFGEOF
{
    "version": "V0.18",
    "installed": "$(date -Iseconds)",
    "paths": {
        "applejuice": "$TOOLS_DIR/AppleJuice/app.py",
        "blueducky": "$TOOLS_DIR/BlueDucky/BlueDucky.py",
        "ble_spam": "$TOOLS_DIR/Bluetooth-LE-Spam",
        "bluetoolkit": "$TOOLS_DIR/BlueToolkit",
        "bluetooth_ducky": "$TOOLS_DIR/BluetoothDucky",
        "blendr": "$TOOLS_DIR/blendr",
        "tools_dir": "$TOOLS_DIR"
    },
    "venv": "$SCRIPT_DIR/.venv",
    "python": "$REAL_PYTHON"
}
CFGEOF
ok "tools_config.json"

# run_web_lan.sh
cat > "$SCRIPT_DIR/run_web_lan.sh" << 'RUNEOF'
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$SCRIPT_DIR"
PORT="${1:-8080}"; IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "0.0.0.0")
echo ""; echo "╔═════════════════════════════════════════╗"
echo "║     ⚡ BLEAK — Bluetooth Link Exploitation & Attack Knowledgebase     ║"
echo "╚═════════════════════════════════════════╝"
echo "  🌐 http://${IP}:${PORT}"; echo ""
HCI_IFACE=$(hciconfig 2>/dev/null | awk -F: '/^hci[0-9]+:/{print $1; exit}')
[[ -n "$HCI_IFACE" ]] && hciconfig "$HCI_IFACE" up 2>/dev/null || echo "⚠ adaptador HCI indisponível"
exec "$SCRIPT_DIR/.venv/bin/python" -W ignore::DeprecationWarning \
    "$SCRIPT_DIR/web_server.py" --host 0.0.0.0 --port "$PORT" \
    2>&1 | tee -a "$SCRIPT_DIR/logs/radiorecon_$(date +%Y%m%d).log"
RUNEOF
chmod +x "$SCRIPT_DIR/run_web_lan.sh"; ok "run_web_lan.sh"

# run_web.sh
cat > "$SCRIPT_DIR/run_web.sh" << 'RUNEOF'
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$SCRIPT_DIR"
PORT="${1:-8080}"; echo "⚡ BLEAK → http://127.0.0.1:${PORT}"
HCI_IFACE=$(hciconfig 2>/dev/null | awk -F: '/^hci[0-9]+:/{print $1; exit}')
[[ -n "$HCI_IFACE" ]] && hciconfig "$HCI_IFACE" up 2>/dev/null || true
exec "$SCRIPT_DIR/.venv/bin/python" -W ignore::DeprecationWarning \
    "$SCRIPT_DIR/web_server.py" --host 127.0.0.1 --port "$PORT"
RUNEOF
chmod +x "$SCRIPT_DIR/run_web.sh"; ok "run_web.sh"

# update_tools.sh
cat > "$SCRIPT_DIR/update_tools.sh" << 'UPDEOF'
#!/usr/bin/env bash
echo "Atualizando ferramentas..."; SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for dir in "$SD/tools"/*/; do
    [[ -d "$dir/.git" ]] || continue; n=$(basename "$dir"); echo -n "  $n: "
    cd "$dir" && git pull --quiet 2>/dev/null && echo "✓" || echo "△"; cd "$SD"
done
source "$SD/.venv/bin/activate"
pip install --break-system-packages --upgrade flask bleak pycryptodome rich pyserial -q 2>/dev/null
pip install --break-system-packages --upgrade git+https://github.com/pybluez/pybluez.git#egg=pybluez -q 2>/dev/null
echo "✓ Atualizado!"
UPDEOF
chmod +x "$SCRIPT_DIR/update_tools.sh"; ok "update_tools.sh"

# status.sh
cat > "$SCRIPT_DIR/status.sh" << 'STEOF'
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
STEOF
chmod +x "$SCRIPT_DIR/status.sh"; ok "status.sh"

# Ownership
$SUDO chown -R "$CUR_USER":"$CUR_USER" "$TOOLS_DIR" "$SCRIPT_DIR/.venv" "$SCRIPT_DIR/reports" "$SCRIPT_DIR/captures" "$SCRIPT_DIR/logs" "$SCRIPT_DIR/__pycache__" 2>/dev/null || true

# PulseAudio/PipeWire runs in the real user's session. BLEAK executes privileged
# Bluetooth operations with sudo, then drops to this user for pactl/parecord.
if command -v systemctl &>/dev/null; then
    $SUDO -u "$CUR_USER" XDG_RUNTIME_DIR="/run/user/$(id -u "$CUR_USER")" systemctl --user start pipewire pipewire-pulse wireplumber 2>/dev/null || true
fi

# ══════════════════════════════════════════════════════════
# RESUMO
# ══════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║               Instalação Concluída!                       ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  $SCRIPT_DIR/"
echo "  ├── .venv/                    Python + PyBluez"
echo "  ├── tools/"
echo "  │   ├── AppleJuice/           BLE Spam (iOS/Android/Win)"
echo "  │   ├── BlueDucky/            CVE-2023-45866 HID Injection"
echo "  │   ├── Bluetooth-LE-Spam/    BLE Spam (Android app)"
echo "  │   ├── BlueToolkit/          43 BT Classic exploits"
echo "  │   ├── BluetoothDucky/       Alt. BlueDucky"
echo "  │   └── blendr/               BLE scanner"
echo "  ├── esp32_firmware/           Firmware ESP32-S3"
echo "  ├── reports/ captures/ logs/"
echo "  ├── run_web_lan.sh            Iniciar (LAN)"
echo "  ├── update_tools.sh           Atualizar ferramentas"
echo "  └── status.sh                 Verificar status"
echo ""
echo "  Comandos:"
echo "    sudo ./install.sh             Instalar tudo"
echo "    sudo ./run_web_lan.sh         Iniciar BLEAK"
echo "    ./status.sh                   Verificar status"
echo "    ./update_tools.sh             Atualizar ferramentas"
echo ""
IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "SEU_IP")
echo "  Acesso: http://${IP}:8080"
echo "  Log: $LOG_FILE"
echo ""

# ── 12/12 — Validate Flask routes ──────────────────────────────
step "12/12 — Validando rotas Flask"
python3 -c "
import sys; sys.path.insert(0,'.')
try:
    from web_server import app
    audio_routes = [r.rule for r in app.url_map.iter_rules() if 'audio' in r.rule]
    if audio_routes:
        print('  ✓ Audio routes registered: ' + str(len(audio_routes)))
        for r in audio_routes: print('    ' + r)
    else:
        print('  ✗ Audio routes NOT found!')
    total = sum(1 for _ in app.url_map.iter_rules())
    print(f'  ✓ Total routes: {total}')
except Exception as e:
    print(f'  ✗ Flask import error: {e}')
    print('  → Fix: pip install --break-system-packages --upgrade flask click')
" 2>/dev/null || warn "Validação de rotas falhou"

ok "Instalação completa!"
