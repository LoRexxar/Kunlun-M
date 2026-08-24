#!/bin/bash
# 第六批补扫: dolibarr-dev(超时,加长时间), moodle(超时,加长时间), craftcms(develop分支), pimcore(换镜像重试)
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DL_DIR="/home/ubuntu/realworld_scan_redownload"
mkdir -p "$DL_DIR"

dl() {  # dl <name> <repo> <branch>
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

scan() {  # scan <name> <lang> <timeout>
    local name="$1" lang="$2" tmo="$3" target="${DL_DIR}/$1"
    echo "[$(date +%H:%M:%S)] === SCAN $name (timeout ${tmo}s) ==="
    timeout "$tmo" python3 kunlun.py scan -t "$target" --yes -lan "$lang" --no-cache 2>&1 | tail -3
    rm -rf "$target"
    echo ""
}

# 1. dolibarr-dev: 30min超时 -> 90min
dl dolibarr-dev Dolibarr/dolibarr master || dl dolibarr-dev Dolibarr/dolibarr develop
[ -d "${DL_DIR}/dolibarr-dev" ] && scan dolibarr-dev php 5400

# 2. moodle: 30min超时 -> 90min (默认分支main? moodle主分支是master)
dl moodle moodle/moodle master || dl moodle moodle/moodle main
[ -d "${DL_DIR}/moodle" ] && scan moodle php 5400

# 3. craftcms: 默认分支develop
dl craftcms craftcms/cms develop && scan craftcms php 3600

# 4. pimcore: 重试
dl pimcore-pimcore-715848f pimcore/pimcore master || dl pimcore-pimcore-715848f pimcore/pimcore 11.x
[ -d "${DL_DIR}/pimcore-pimcore-715848f" ] && scan pimcore-pimcore-715848f php 5400

echo "[$(date +%H:%M:%S)] BATCH6-FIXUP DONE"
