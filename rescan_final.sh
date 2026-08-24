#!/bin/bash
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE
DL_DIR="/home/ubuntu/realworld_scan_redownload"
mkdir -p "$DL_DIR"
LOG="/tmp/rescan_final.log"
> "$LOG"

dl() {
    local name="$1" repo="$2" branch="$3" target="${DL_DIR}/$1"
    rm -rf "$target" "$target.tar.gz" 2>/dev/null
    for proxy in ghfast.top ghproxy.net; do
        curl -sL --max-time 180 "https://${proxy}/https://github.com/${repo}/archive/refs/heads/${branch}.tar.gz" -o "$target.tar.gz" 2>/dev/null
        if [ -s "$target.tar.gz" ] && tar tzf "$target.tar.gz" >/dev/null 2>&1; then
            mkdir -p "$target" && tar xzf "$target.tar.gz" -C "$target" --strip-components=1 && rm -f "$target.tar.gz"
            echo "[$(date +%H:%M:%S)] DL ok $name" >> "$LOG"
            return 0
        fi
    done
    rm -f "$target.tar.gz" 2>/dev/null
    echo "[$(date +%H:%M:%S)] DL FAIL $name" >> "$LOG"
    return 1
}
scan() {
    local name="$1" lang="$2" tmo="$3" target="${DL_DIR}/$1"
    echo "[$(date +%H:%M:%S)] SCAN $name ($lang, tmo=${tmo})" >> "$LOG"
    timeout "$tmo" python3 kunlun.py scan -t "$target" --yes -lan "$lang" --no-cache >> "$LOG" 2>&1
    local rc=$?
    rm -rf "$target"
    if [ $rc -eq 0 ]; then
        echo "[$(date +%H:%M:%S)] DONE $name" >> "$LOG"
    else
        echo "[$(date +%H:%M:%S)] TIMEOUT/ERR $name (rc=$rc)" >> "$LOG"
    fi
}
dl 42-ajax-server 42AGency/ajax-server main && scan 42-ajax-server javascript 1800
dl WordPress-wordpress-develop-855551c WordPress/wordpress-develop master && scan WordPress-wordpress-develop-855551c php 1800
dl dotnet-aspnetcore-af22eff dotnet/aspnetcore main && scan dotnet-aspnetcore-af22eff csharp 1800
dl fastapi-fastapi-866b7a3 fastapi/fastapi main && scan fastapi-fastapi-866b7a3 python 1800
dl feincms-feincms feincms/feincms main && scan feincms-feincms python 1800
dl mui-material-ui-bc3294d mui-org/material-ui master && scan mui-material-ui-bc3294d javascript 3600
dl paper-trail-gem-paper_trail-7834c67 paper-trail-gem/paper_trail main && scan paper-trail-gem-paper_trail-7834c67 ruby 1800
dl wooey-wooey wooey/wooey main && scan wooey-wooey python 1800
dl Kotlin-kotlinx.coroutines-d8d6f8f Kotlin/kotlinx.coroutines master && scan Kotlin-kotlinx.coroutines-d8d6f8f kotlin 1800
dl Kotlin-kotlinx.serialization-6956af2 Kotlin/kotlinx.serialization main && scan Kotlin-kotlinx.serialization-6956af2 kotlin 1800
dl chartjs-Chart.js-9c5cf9f chartjs/Chart.js master && scan chartjs-Chart.js-9c5cf9f javascript 1800
dl etcd-io-etcd-4c01784 etcd-io/etcd main && scan etcd-io-etcd-4c01784 go 1800
dl ggml-org-llama.cpp-7be099f ggerganov/llama.cpp master && scan ggml-org-llama.cpp-7be099f c 1800
dl pydantic-pydantic-c326748 pydantic/pydantic main && scan pydantic-pydantic-c326748 python 1800
echo "[$(date +%H:%M:%S)] FINAL RETRY DONE" >> "$LOG"
