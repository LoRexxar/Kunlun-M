#!/bin/bash
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DOWNLOAD_DIR=/home/ubuntu/realworld_scan_redownload
PROXY="https://ghfast.top"
FALLBACK="https://ghproxy.net"

# 全新项目，DB中不存在
PROJECTS="withspectrum/spectrum|v1.10.3|javascript
cozy/cozy-stack|v4.10.2|go
perkeep/perkeep|v0.14.0|go
micro/micro|v3.18.0|go
jesseduffield/lazygit|v0.43.1|go
cli/cli|v2.62.0|go
jesseduffield/horcrux|v0.2.0|go
dominictarr/hyperquest|master|javascript
kee-org/KeeWeb|develop|javascript
Foundry376/Fiks|main|javascript
marktext/marktext|v0.17.1|typescript
coder/code-server|v4.92.2|typescript
pelikhan/typst|v0.11.0|rust
boa-dev/boa|v0.19.0|rust
denoland/dnt|v0.38.0|typescript
nushell/nushell|0.92.0|rust
shadowsocks/shadowsocks-libev|v3.3.5|c
redis/hiredis|v1.2.0|c
woltapp/wire|v3.5.0|kotlin"

while IFS='|' read -r repo ref lang; do
    [ -z "$repo" ] && continue
    dir_name="$(echo $repo | tr '/' '-')"
    outdir="$DOWNLOAD_DIR/$dir_name"

    if [ -d "$outdir" ] && [ -n "$(ls -A $outdir 2>/dev/null)" ]; then
        echo "[$(date)] SKIP_DL $dir_name"
    else
        mkdir -p "$outdir"
        echo "[$(date)] DL $dir_name ($lang)"
        curl -sL --max-time 300 "$PROXY/https://github.com/$repo/archive/$ref.tar.gz" -o "/tmp/${dir_name}.tar.gz" 2>/dev/null
        if ! file "/tmp/${dir_name}.tar.gz" 2>/dev/null | grep -q gzip; then
            rm -f "/tmp/${dir_name}.tar.gz" 2>/dev/null
            curl -sL --max-time 300 "$FALLBACK/https://github.com/$repo/archive/$ref.tar.gz" -o "/tmp/${dir_name}.tar.gz" 2>/dev/null
        fi
        if ! file "/tmp/${dir_name}.tar.gz" 2>/dev/null | grep -q gzip; then
            echo "[$(date)] DL_FAIL $dir_name"
            rm -f "/tmp/${dir_name}.tar.gz" 2>/dev/null; rm -rf "$outdir"; continue
        fi
        tar xzf "/tmp/${dir_name}.tar.gz" -C "$outdir" --strip-components=1
        if [ $? -ne 0 ]; then
            echo "[$(date)] EXTRACT_FAIL $dir_name"
            rm -f "/tmp/${dir_name}.tar.gz" 2>/dev/null; rm -rf "$outdir"; continue
        fi
        rm -f "/tmp/${dir_name}.tar.gz"
        fcount=$(find "$outdir" -type f | wc -l)
        echo "[$(date)] DL_OK $dir_name ($fcount files)"
        if [ "$fcount" -gt 5000 ]; then
            echo "[$(date)] TOO_BIG $dir_name"; rm -rf "$outdir"; continue
        fi
    fi
done <<< "$PROJECTS"
echo "=== DOWNLOAD DONE ==="

cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
find . -name __pycache__ -exec rm -rf {}+ 2>/dev/null

count=0
fail=0
while IFS='|' read -r repo ref lang; do
    [ -z "$repo" ] && continue
    dir_name="$(echo $repo | tr '/' '-')"
    outdir="$DOWNLOAD_DIR/$dir_name"
    if [ ! -d "$outdir" ] || [ -z "$(ls -A $outdir 2>/dev/null)" ]; then
        echo "[$(date)] SCAN_SKIP $dir_name"; continue
    fi
    echo "[$(date)] === SCAN $dir_name ($lang) ==="
    timeout 1800 python3 kunlun.py scan -t "$outdir" --yes -lan "$lang" --no-cache 2>/tmp/new_b4_${dir_name}.log
    rc=$?
    echo "[$(date)] $dir_name done rc=$rc"
    if [ $rc -eq 0 ]; then count=$((count+1)); else fail=$((fail+1)); fi
    rm -rf "$outdir"
done <<< "$PROJECTS"
echo "ALL DONE: scanned=$count failed=$fail"
