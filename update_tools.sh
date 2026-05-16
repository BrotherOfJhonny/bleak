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
