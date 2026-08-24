#!/bin/bash
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DOWNLOAD_DIR=/home/ubuntu/realworld_scan_redownload
PROXY="https://ghfast.top"
FALLBACK="https://ghproxy.net"

PROJECTS="PrestaShop/PrestaShop|8.1.3|php
phacility/phabricator|stable|php
ampache/ampache|6.6.0|php
e107inc/e107|v2.3.2|php
mybb/mybb|mybb_1838|php
fusioncms/fusioncms|3.0|php
pyrocms/pyrocms|3.10.1|php
OctoberCMS/october|v3.7.0|php
getgrav/grav|1.7.45|php
bolt/core|v5.2.3|php
gatsbyjs/gatsby|v5.14.0|typescript
sveltejs/kit|1.30.4|typescript
remix-run/remix|v2.13.1|typescript
nuxt/nuxt|v3.13.2|typescript
rocket-lang/rocket|v0.5.0|rust
vapor/vapor|4.101.2|swift
pallets/jinja|3.1.4|python
getsentry/sentry|24.8.0|python
strapi/strapi|v4.25.1|javascript"

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
            echo "[$(date)] DL_FAIL $dir_name"; rm -f "/tmp/${dir_name}.tar.gz" 2>/dev/null; rm -rf "$outdir"; continue
        fi
        tar xzf "/tmp/${dir_name}.tar.gz" -C "$outdir" --strip-components=1 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "[$(date)] EXTRACT_FAIL $dir_name"; rm -f "/tmp/${dir_name}.tar.gz" 2>/dev/null; rm -rf "$outdir"; continue
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

count=0; fail=0
while IFS='|' read -r repo ref lang; do
    [ -z "$repo" ] && continue
    dir_name="$(echo $repo | tr '/' '-')"
    outdir="$DOWNLOAD_DIR/$dir_name"
    if [ ! -d "$outdir" ] || [ -z "$(ls -A $outdir 2>/dev/null)" ]; then
        echo "[$(date)] SCAN_SKIP $dir_name"; continue
    fi
    echo "[$(date)] === SCAN $dir_name ($lang) ==="
    timeout 1800 python3 kunlun.py scan -t "$outdir" --yes -lan "$lang" --no-cache 2>/tmp/new_b7_${dir_name}.log
    rc=$?
    echo "[$(date)] $dir_name done rc=$rc"
    if [ $rc -eq 0 ]; then count=$((count+1)); else fail=$((fail+1)); fi
    rm -rf "$outdir"
done <<< "$PROJECTS"
echo "ALL DONE: scanned=$count failed=$fail"
