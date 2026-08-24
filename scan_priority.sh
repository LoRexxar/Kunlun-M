#!/bin/bash
# 补扫漏网的高优先级项目（源码已删，从镜像重新拉取）
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DL_DIR="/home/ubuntu/realworld_scan_redownload"
mkdir -p "$DL_DIR"

dl_scan() {
    local name="$1" repo="$2" lang="$3"
    local target="${DL_DIR}/${name}"
    echo "[$(date +%H:%M:%S)] === $name ($repo) ==="
    rm -rf "$target" "$target.tar.gz" 2>/dev/null
    local url="https://ghfast.top/https://github.com/${repo}/archive/refs/heads/master.tar.gz"
    curl -sL "$url" -o "$target.tar.gz"
    if [ ! -s "$target.tar.gz" ]; then
        url="https://ghfast.top/https://github.com/${repo}/archive/refs/heads/main.tar.gz"
        curl -sL "$url" -o "$target.tar.gz"
    fi
    if [ ! -s "$target.tar.gz" ]; then echo "DL FAILED $name"; return 1; fi
    mkdir -p "$target"
    tar xzf "$target.tar.gz" -C "$target" --strip-components=1
    rm -f "$target.tar.gz"
    find . -name __pycache__ -exec rm -rf {} + 2>/dev/null
    python3 kunlun.py scan -t "$target" --yes -lan "$lang" --no-cache 2>&1 | tail -3
    rm -rf "$target"
    echo ""
}

# 最高优先级：simple-login/app (57 old findings)
dl_scan "simple-login-app" "simple-login/app" "python"

echo "PRIORITY DONE"
