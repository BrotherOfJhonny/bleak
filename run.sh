#!/bin/bash
# BLEAK V0.18 — Start Server
echo "⚡ BLEAK V0.18"

# Fix click/flask compatibility
pip install --break-system-packages --upgrade click flask -q 2>/dev/null

# Validate
python3 -c "from flask import Flask; print('✓ Flask OK')" 2>/dev/null || {
    echo "✗ Flask broken. Run: pip install --break-system-packages --upgrade flask click"
    exit 1
}

# Check audio routes
python3 -c "
import sys; sys.path.insert(0,'.')
from web_server import app
routes = [r.rule for r in app.url_map.iter_rules() if 'audio' in r.rule]
print(f'✓ {len(routes)} audio routes registered')
" 2>/dev/null

# Start
echo "Starting on port 8080..."
sudo python3 web_server.py --host 0.0.0.0
