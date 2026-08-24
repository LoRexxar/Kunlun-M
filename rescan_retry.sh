#!/bin/bash
# 重扫retry: 40个下载失败项目 - 用master/main分支
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DL_DIR="/home/ubuntu/realworld_scan_redownload"
mkdir -p "$DL_DIR"
LOG="/tmp/rescan_retry.log"
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
    local name="$1" lang="$2" target="${DL_DIR}/$1"
    echo "[$(date +%H:%M:%S)] SCAN $name ($lang)" >> "$LOG"
    timeout 1800 python3 kunlun.py scan -t "$target" --yes -lan "$lang" --no-cache >> "$LOG" 2>&1
    local rc=$?
    rm -rf "$target"
    if [ $rc -eq 0 ]; then
        echo "[$(date +%H:%M:%S)] DONE $name" >> "$LOG"
    else
        echo "[$(date +%H:%M:%S)] TIMEOUT/ERR $name (rc=$rc)" >> "$LOG"
    fi
    return 0
}

dl 42-ajax-server 42AGency/ajax-server master && scan 42-ajax-server javascript
dl Kotlin-kotlinx.coroutines-d8d6f8f Kotlin/kotlinx.coroutines master && scan Kotlin-kotlinx.coroutines-d8d6f8f kotlin
dl WordPress-wordpress-develop-855551c WordPress/wordpress-develop master && scan WordPress-wordpress-develop-855551c php
dl allen7d-mini-shop-server allen7d/mini-shop-server master && scan allen7d-mini-shop-server java
dl diesel-rs-diesel-e674999 diesel-rs/diesel master && scan diesel-rs-diesel-e674999 rust
dl discourse-discourse-6816473 discourse/discourse main && scan discourse-discourse-6816473 ruby
dl dotnet-aspnetcore-af22eff dotnet/aspnetcore main && scan dotnet-aspnetcore-af22eff csharp
dl elastic-elasticsearch-js-436cd88 elastic/elasticsearch-js main && scan elastic-elasticsearch-js-436cd88 javascript
dl etcd-io-etcd-0e35b4f etcd-io/etcd main && scan etcd-io-etcd-0e35b4f go
dl faker-ruby-faker-46130d9 faker-ruby/faker main && scan faker-ruby-faker-46130d9 ruby
dl fastapi-fastapi-866b7a3 fastapi/fastapi main && scan fastapi-fastapi-866b7a3 python
dl feincms-feincms feincms/feincms main && scan feincms-feincms python
dl ggml-org-llama ggerganov/llama master && scan ggml-org-llama c
dl ggml-org-llama.cpp-7be099f ggerganov/llama.cpp master && scan ggml-org-llama.cpp-7be099f c
dl gin-gonic-gin-75ccf94 gin-gonic/gin master && scan gin-gonic-gin-75ccf94 go
dl go-chi-chi-67be7d9 go-chi/chi master && scan go-chi-chi-67be7d9 go
dl jacob-bd-gemini-notebook-mcp-cli jacob-bd/gemini-notebook-mcp-cli main && scan jacob-bd-gemini-notebook-mcp-cli python
dl jellyfin-jellyfin-1fbd873 jellyfin/jellyfin master && scan jellyfin-jellyfin-1fbd873 csharp
dl koreader-koreader-041e20b koreader/koreader master && scan koreader-koreader-041e20b lua
dl lysine-dev-okio-72e7819 square/okio master && scan lysine-dev-okio-72e7819 kotlin
dl mui-material-ui-bc3294d mui-org/material-ui master && scan mui-material-ui-bc3294d javascript
dl paper-trail-gem-paper_trail-7834c67 paper-trail-gem/paper_trail main && scan paper-trail-gem-paper_trail-7834c67 ruby
dl pgadmin4 pgadmin-org/pgadmin4 master && scan pgadmin4 python
dl pyca-cryptography-cc45554 pyca/cryptography main && scan pyca-cryptography-cc45554 python
dl pydantic-pydantic-7cedbfb pydantic/pydantic main && scan pydantic-pydantic-7cedbfb python
dl rails-rails-9c50861 rails/rails main && scan rails-rails-9c50861 ruby
dl rayon-rs-rayon-48c40f3 rayon-rs/rayon master && scan rayon-rs-rayon-48c40f3 rust
dl rclone-rclone-e10e196 rclone/rclone master && scan rclone-rclone-e10e196 go
dl sanic-org-sanic sanic-org/sanic main && scan sanic-org-sanic python
dl serde-rs-serde-180bcba serde-rs/serde master && scan serde-rs-serde-180bcba rust
dl shish-shimmie2 shish/shimmie2 main && scan shish-shimmie2 php
dl symfony-symfony-fd9802a symfony/symfony master && scan symfony-symfony-fd9802a php
dl the-events-calendar the-events-calendar/the-events-calendar main && scan the-events-calendar php
dl tokio-rs-tokio-bb7ca75 tokio-rs/tokio master && scan tokio-rs-tokio-bb7ca75 rust
dl uber-go-zap-b4401e6 uber-go/zap master && scan uber-go-zap-b4401e6 go
dl vitest-dev-vitest-7e1d762 vitest-dev/vitest main && scan vitest-dev-vitest-7e1d762 javascript
dl vlucas-phpdotenv-a59a137 vlucas/phpdotenv master && scan vlucas-phpdotenv-a59a137 php
dl woocommerce woocommerce/woocommerce master && scan woocommerce php
dl wooey-wooey wooey/wooey main && scan wooey-wooey python
dl ytdl-org-youtube-dl-1807cff ytdl-org/youtube-dl master && scan ytdl-org-youtube-dl-1807cff python
echo "[$(date +%H:%M:%S)] RETRY ALL DONE" >> "$LOG"
