#!/bin/bash
# 通用批量下载+扫描脚本: batch_scan.sh <batch_json>
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

BATCH_JSON="$1"
DL_DIR="/home/ubuntu/realworld_scan_redownload"
mkdir -p "$DL_DIR"

dl_scan() {
    local name="$1" repo="$2" lang="$3"
    local target="${DL_DIR}/${name}"
    echo "[$(date +%H:%M:%S)] === $name ($repo, $lang) ==="
    rm -rf "$target" "$target.tar.gz" 2>/dev/null
    local ok=0
    for branch in master main; do
        curl -sL --max-time 120 "https://ghfast.top/https://github.com/${repo}/archive/refs/heads/${branch}.tar.gz" -o "$target.tar.gz" 2>/dev/null
        if [ -s "$target.tar.gz" ] && tar tzf "$target.tar.gz" >/dev/null 2>&1; then ok=1; break; fi
    done
    if [ $ok -eq 0 ]; then echo "[$(date +%H:%M:%S)] DL FAILED: $name ($repo)"; return 1; fi
    mkdir -p "$target"
    tar xzf "$target.tar.gz" -C "$target" --strip-components=1
    rm -f "$target.tar.gz"
    find . -name __pycache__ -exec rm -rf {} + 2>/dev/null
    timeout 1800 python3 kunlun.py scan -t "$target" --yes -lan "$lang" --no-cache 2>&1 | tail -3
    rm -rf "$target"
    echo ""
}

python3 - "$BATCH_JSON" << 'PYEOF'
import json, sys, subprocess
with open(sys.argv[1]) as f:
    batch = json.load(f)
for b in batch:
    subprocess.run(["bash", "-c", f"true"])  # noop
    print(f"DLSCAN|{b['name']}|{b['repo']}|{b['lang']}", flush=True)
PYEOF

# 直接用jq风格的python读取（上面只是打印，实际用下面循环）
while IFS='|' read -r cmd name repo lang; do
    [ "$cmd" = "DLSCAN" ] || continue
    dl_scan "$name" "$repo" "$lang"
done < <(python3 -c "
import json
with open('$BATCH_JSON') as f: batch = json.load(f)
for b in batch: print('DLSCAN|%s|%s|%s' % (b['name'], b['repo'], b['lang']))
")

echo "[$(date +%H:%M:%S)] BATCH $BATCH_JSON DONE"
