#!/bin/bash
# batch6 剩余: moodle + pimcore (串行)
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DL_DIR="/home/ubuntu/realworld_scan_redownload"
mkdir -p "$DL_DIR"

dl() {
    local name="$1" repo="$2" branch="$3" target="${DL_DIR}/$1"
    rm -rf "$target" "$target.tar.gz" 2>/dev/null
    for proxy in ghfast.top ghproxy.net; do
        curl -sL --max-time 300 "https://${proxy}/https://github.com/${repo}/archive/refs/heads/${branch}.tar.gz" -o "$target.tar.gz" 2>/dev/null
        if [ -s "$target.tar.gz" ] && tar tzf "$target.tar.gz" >/dev/null 2>&1; then
            echo "[$(date +%H:%M:%S)] $name: DL ok via $proxy ($branch)"
            mkdir -p "$target" && tar xzf "$target.tar.gz" -C "$target" --strip-components=1 && rm -f "$target.tar.gz"
            return 0
        fi
    done
    echo "[$(date +%H:%M:%S)] $name: DL FAILED all mirrors"; return 1
}

dl_commit() {
    local name="$1" repo="$2" sha="$3" target="${DL_DIR}/$1"
    rm -rf "$target" "$target.tar.gz" 2>/dev/null
    for proxy in ghfast.top ghproxy.net; do
        curl -sL --max-time 300 "https://${proxy}/https://github.com/${repo}/archive/${sha}.tar.gz" -o "$target.tar.gz" 2>/dev/null
        if [ -s "$target.tar.gz" ] && tar tzf "$target.tar.gz" >/dev/null 2>&1; then
            echo "[$(date +%H:%M:%S)] $name: DL ok via $proxy (commit $sha)"
            mkdir -p "$target" && tar xzf "$target.tar.gz" -C "$target" --strip-components=1 && rm -f "$target.tar.gz"
            return 0
        fi
    done
    echo "[$(date +%H:%M:%S)] $name: DL FAILED all mirrors"; return 1
}

scan() {
    local name="$1" lang="$2" tmo="$3" target="${DL_DIR}/$1"
    echo "[$(date +%H:%M:%S)] === SCAN $name (timeout ${tmo}s) ==="
    timeout "$tmo" python3 kunlun.py scan -t "$target" --yes -lan "$lang" --no-cache 2>&1 | tail -5
    rm -rf "$target"
    echo ""
}

# 1. moodle (master)
dl moodle moodle/moodle master || dl moodle moodle/moodle main
[ -d "${DL_DIR}/moodle" ] && scan moodle php 7200

# 2. pimcore (commit sha)
dl_commit pimcore-pimcore-715848f pimcore/pimcore 715848f
[ -d "${DL_DIR}/pimcore-pimcore-715848f" ] && scan pimcore-pimcore-715848f php 7200

echo "[$(date +%H:%M:%S)] BATCH6-REMAINING DONE"
