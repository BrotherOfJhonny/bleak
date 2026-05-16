#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$SCRIPT_DIR"
PORT="${1:-8080}"; echo "⚡ BLEAK → http://127.0.0.1:${PORT}"
HCI_IFACE=$(hciconfig 2>/dev/null | awk -F: '/^hci[0-9]+:/{print $1; exit}')
[[ -n "$HCI_IFACE" ]] && hciconfig "$HCI_IFACE" up 2>/dev/null || true
exec "$SCRIPT_DIR/.venv/bin/python" -W ignore::DeprecationWarning \
    "$SCRIPT_DIR/web_server.py" --host 127.0.0.1 --port "$PORT"
