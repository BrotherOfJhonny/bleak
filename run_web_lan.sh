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
