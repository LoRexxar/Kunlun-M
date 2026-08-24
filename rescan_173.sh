#!/bin/bash
# 重扫173个7月遗留项目 - 162个可扫 (去测试/子目录)
# 每批20个串行: 下载(ghfast.top) -> 扫描 -> 删源码
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DL_DIR="/home/ubuntu/realworld_scan_redownload"
mkdir -p "$DL_DIR"
LOG="/tmp/rescan_173.log"
> "$LOG"

dl() {
    local name="$1" repo="$2" ref="$3" target="${DL_DIR}/$1"
    rm -rf "$target" "$target.tar.gz" 2>/dev/null
    # 判断是commit sha还是分支名
    if echo "$ref" | grep -qE '^[0-9a-f]{7,40}$'; then
        local url="https://ghfast.top/https://github.com/${repo}/archive/${ref}.tar.gz"
    else
        local url="https://ghfast.top/https://github.com/${repo}/archive/refs/heads/${ref}.tar.gz"
    fi
    curl -sL --max-time 120 "$url" -o "$target.tar.gz" 2>/dev/null
    if [ -s "$target.tar.gz" ] && tar tzf "$target.tar.gz" >/dev/null 2>&1; then
        mkdir -p "$target" && tar xzf "$target.tar.gz" -C "$target" --strip-components=1 && rm -f "$target.tar.gz"
        echo "[$(date +%H:%M:%S)] DL ok $name" >> "$LOG"
        return 0
    fi
    # fallback to ghproxy
    if echo "$ref" | grep -qE '^[0-9a-f]{7,40}$'; then
        url="https://ghproxy.net/https://github.com/${repo}/archive/${ref}.tar.gz"
    else
        url="https://ghproxy.net/https://github.com/${repo}/archive/refs/heads/${ref}.tar.gz"
    fi
    curl -sL --max-time 120 "$url" -o "$target.tar.gz" 2>/dev/null
    if [ -s "$target.tar.gz" ] && tar tzf "$target.tar.gz" >/dev/null 2>&1; then
        mkdir -p "$target" && tar xzf "$target.tar.gz" -C "$target" --strip-components=1 && rm -f "$target.tar.gz"
        echo "[$(date +%H:%M:%S)] DL ok(fallback) $name" >> "$LOG"
        return 0
    fi
    rm -f "$target.tar.gz" 2>/dev/null
    echo "[$(date +%H:%M:%S)] DL FAIL $name" >> "$LOG"
    return 1
}

scan() {
    local name="$1" lang="$2" target="${DL_DIR}/$1"
    local tmo=1800
    echo "[$(date +%H:%M:%S)] SCAN $name ($lang)" >> "$LOG"
    timeout "$tmo" python3 kunlun.py scan -t "$target" --yes -lan "$lang" --no-cache >> "$LOG" 2>&1
    local rc=$?
    rm -rf "$target"
    if [ $rc -eq 0 ]; then
        echo "[$(date +%H:%M:%S)] DONE $name" >> "$LOG"
    else
        echo "[$(date +%H:%M:%S)] TIMEOUT/ERR $name (rc=$rc)" >> "$LOG"
    fi
    return 0
}

# ======== C: 40 projects ========

# Batch 1
dl 0xsteph-pentest-ai 0xsteph/pentest-ai master && scan 0xsteph-pentest-ai c
dl 42-ajax-server 42/ajax-server master && scan 42-ajax-server c
dl HangfireIO-Hangfire-e19be91 HangfireIO/Hangfire e19be91 && scan HangfireIO-Hangfire-e19be91 c
dl Homebrew-brew-824efa8 Homebrew/brew 824efa8 && scan Homebrew-brew-824efa8 c
dl Humanizr-Humanizer-3ebc38d Humanizr/Humanizer 3ebc38d && scan Humanizr-Humanizer-3ebc38d c
dl JetBrains-ideavim-c164c0f JetBrains/ideavim c164c0f && scan JetBrains-ideavim-c164c0f c
dl MassTransit-MassTransit-62ab339 MassTransit/MassTransit 62ab339 && scan MassTransit-MassTransit-62ab339 c
dl MassTransit-MassTransit-c5de78a MassTransit/MassTransit c5de78a && scan MassTransit-MassTransit-c5de78a c
dl Unitech-pm2-01d4f6d Unitech/pm2 01d4f6d && scan Unitech-pm2-01d4f6d c
dl abseil-abseil-cpp-4447c75 abseil/abseil-cpp 4447c75 && scan abseil-abseil-cpp-4447c75 c
dl amethyst-specs-01adaf6 amethyst/specs 01adaf6 && scan amethyst-specs-01adaf6 c
dl chef-chef-2f2e826 chef/chef 2f2e826 && scan chef-chef-2f2e826 c
dl curl-curl-1d6e08c curl/curl 1d6e08c && scan curl-curl-1d6e08c c
dl curl-curl-3f00a2f curl/curl 3f00a2f && scan curl-curl-3f00a2f c
dl discourse-discourse-6816473 discourse/discourse 6816473 && scan discourse-discourse-6816473 c
dl fluent-fluentd-a53c755 fluent/fluentd a53c755 && scan fluent-fluentd-a53c755 c
dl gabime-spdlog-8e56133 gabime/spdlog 8e56133 && scan gabime-spdlog-8e56133 c
dl ggml-org-llama ggml/org-llama master && scan ggml-org-llama c
dl ggml-org-llama.cpp-7be099f ggml/org-llama.cpp 7be099f && scan ggml-org-llama.cpp-7be099f c
dl google-flatbuffers-334ffbb google/flatbuffers 334ffbb && scan google-flatbuffers-334ffbb c

# Batch 2
dl google-leveldb-99b3c03 google/leveldb 99b3c03 && scan google-leveldb-99b3c03 c
dl httpie-cli-29de4ce httpie/cli 29de4ce && scan httpie-cli-29de4ce c
dl jacob-bd-gemini-notebook-mcp-cli jacob/bd-gemini-notebook-mcp-cli master && scan jacob-bd-gemini-notebook-mcp-cli c
dl kovidgoyal-kitty-f750dd4 kovidgoyal/kitty f750dd4 && scan kovidgoyal-kitty-f750dd4 c
dl leafo-lapis-0dda7b0 leafo/lapis 0dda7b0 && scan leafo-lapis-0dda7b0 c
dl libevent-libevent-4f12382 libevent/libevent 4f12382 && scan libevent-libevent-4f12382 c
dl libuv-libuv-6a276e3 libuv/libuv 6a276e3 && scan libuv-libuv-6a276e3 c
dl lysine-dev-okio-72e7819 lysine/dev-okio 72e7819 && scan lysine-dev-okio-72e7819 c
dl madler-zlib-925af44 madler/zlib 925af44 && scan madler-zlib-925af44 c
dl nlohmann-json-9cca280 nlohmann/json 9cca280 && scan nlohmann-json-9cca280 c
dl ocornut-imgui-dbb5eea ocornut/imgui dbb5eea && scan ocornut-imgui-dbb5eea c
dl pallets-jinja-2fc6e52 pallets/jinja 2fc6e52 && scan pallets-jinja-2fc6e52 c
dl pnggroup-libpng-cae4745 pnggroup/libpng cae4745 && scan pnggroup-libpng-cae4745 c
dl ramsey-uuid-45cc61f ramsey/uuid 45cc61f && scan ramsey-uuid-45cc61f c
dl redis-redis-74b289a redis/redis 74b289a && scan redis-redis-74b289a c
dl redis-redis-c9d29f6 redis/redis c9d29f6 && scan redis-redis-c9d29f6 c
dl sindresorhus-execa-7eb0642 sindresorhus/execa 7eb0642 && scan sindresorhus-execa-7eb0642 c
dl sqlite-sqlite-262de1b sqlite/sqlite 262de1b && scan sqlite-sqlite-262de1b c
dl ytdl-org-youtube-dl-1807cff ytdl/org-youtube-dl 1807cff && scan ytdl-org-youtube-dl-1807cff c
dl zccodere-study-imooc zccodere/study-imooc master && scan zccodere-study-imooc c
# ======== GO: 17 projects ========

# Batch 3
dl beego-beego-420e11e beego/beego 420e11e && scan beego-beego-420e11e go
dl etcd-io-etcd-0e35b4f etcd/io-etcd 0e35b4f && scan etcd-io-etcd-0e35b4f go
dl etcd-io-etcd-4c01784 etcd/io-etcd 4c01784 && scan etcd-io-etcd-4c01784 go
dl gin-gonic-gin-75ccf94 gin/gonic-gin 75ccf94 && scan gin-gonic-gin-75ccf94 go
dl go-chi-chi-67be7d9 go/chi-chi 67be7d9 && scan go-chi-chi-67be7d9 go
dl gohugoio-hugo-bfbee17 gohugoio/hugo bfbee17 && scan gohugoio-hugo-bfbee17 go
dl hashicorp-vagrant-720b68f hashicorp/vagrant 720b68f && scan hashicorp-vagrant-720b68f go
dl hyperium-hyper-c68d424 hyperium/hyper c68d424 && scan hyperium-hyper-c68d424 go
dl labstack-echo-88c379f labstack/echo 88c379f && scan labstack-echo-88c379f go
dl libarchive-libarchive-7ce4254 libarchive/libarchive 7ce4254 && scan libarchive-libarchive-7ce4254 go
dl prometheus-prometheus-3c2a2ff prometheus/prometheus 3c2a2ff && scan prometheus-prometheus-3c2a2ff go
dl prometheus-prometheus-4f774b1 prometheus/prometheus 4f774b1 && scan prometheus-prometheus-4f774b1 go
dl rclone-rclone-e10e196 rclone/rclone e10e196 && scan rclone-rclone-e10e196 go
dl spf13-cobra-e94f6d0 spf13/cobra e94f6d0 && scan spf13-cobra-e94f6d0 go
dl traefik-traefik-b00f640 traefik/traefik b00f640 && scan traefik-traefik-b00f640 go
dl uber-go-zap-b4401e6 uber/go-zap b4401e6 && scan uber-go-zap-b4401e6 go
dl valyala-fasthttp-66bc61e valyala/fasthttp 66bc61e && scan valyala-fasthttp-66bc61e go
# ======== RUST: 7 projects ========

# Batch 4
dl BurntSushi-ripgrep-744a802 BurntSushi/ripgrep 744a802 && scan BurntSushi-ripgrep-744a802 rust
dl diesel-rs-diesel-e674999 diesel/rs-diesel e674999 && scan diesel-rs-diesel-e674999 rust
dl rayon-rs-rayon-48c40f3 rayon/rs-rayon 48c40f3 && scan rayon-rs-rayon-48c40f3 rust
dl seanmonstar-warp-ce8114b seanmonstar/warp ce8114b && scan seanmonstar-warp-ce8114b rust
dl serde-rs-serde-180bcba serde/rs-serde 180bcba && scan serde-rs-serde-180bcba rust
dl sharkdp-bat-dab96bf sharkdp/bat dab96bf && scan sharkdp-bat-dab96bf rust
dl tokio-rs-tokio-bb7ca75 tokio/rs-tokio bb7ca75 && scan tokio-rs-tokio-bb7ca75 rust
# ======== JAVASCRIPT: 26 projects ========

# Batch 5
dl Leaflet-Leaflet-91900f7 Leaflet/Leaflet 91900f7 && scan Leaflet-Leaflet-91900f7 javascript
dl axios-axios-eb5756a axios/axios eb5756a && scan axios-axios-eb5756a javascript
dl chartjs-Chart chartjs/Chart master && scan chartjs-Chart javascript
dl chartjs-Chart.js-9c5cf9f chartjs/Chart.js 9c5cf9f && scan chartjs-Chart.js-9c5cf9f javascript
dl ckeditor-ckeditor5-5cae643 ckeditor/ckeditor5 5cae643 && scan ckeditor-ckeditor5-5cae643 javascript
dl denoland-deno-3da4eca denoland/deno 3da4eca && scan denoland-deno-3da4eca javascript
dl ghost TryGhost/Ghost main && scan ghost javascript
dl graphql-graphql-js-9c9504e graphql/graphql-js 9c9504e && scan graphql-graphql-js-9c9504e javascript
dl highlightjs-highlight highlightjs/highlight master && scan highlightjs-highlight javascript
dl highlightjs-highlight.js-15d3b62 highlightjs/highlight.js 15d3b62 && scan highlightjs-highlight.js-15d3b62 javascript
dl jquery-jquery-642abe6 jquery/jquery 642abe6 && scan jquery-jquery-642abe6 javascript
dl mermaid-js-mermaid-57f945e mermaid-js/mermaid 57f945e && scan mermaid-js-mermaid-57f945e javascript
dl microsoft-TypeScript-d48a5cf microsoft/TypeScript d48a5cf && scan microsoft-TypeScript-d48a5cf javascript
dl moleculerjs-moleculer-55c405a moleculerjs/moleculer 55c405a && scan moleculerjs-moleculer-55c405a javascript
dl moment-moment-80d585a moment/moment 80d585a && scan moment-moment-80d585a javascript
dl mui-material-ui-bc3294d mui/material-ui bc3294d && scan mui-material-ui-bc3294d javascript
dl nestjs-nest-98ada9f nestjs/nest 98ada9f && scan nestjs-nest-98ada9f javascript
dl nestjs-nest-c808922 nestjs/nest c808922 && scan nestjs-nest-c808922 javascript
dl postcss-postcss-18f430a postcss/postcss 18f430a && scan postcss-postcss-18f430a javascript
dl react-react-7aa5dda react/react 7aa5dda && scan react-react-7aa5dda javascript

# Batch 6
dl stenciljs-core-86a36b4 stenciljs/core 86a36b4 && scan stenciljs-core-86a36b4 javascript
dl tailwindlabs-tailwindcss-6069a81 tailwindlabs/tailwindcss 6069a81 && scan tailwindlabs-tailwindcss-6069a81 javascript
dl trpc-trpc-218585c trpc/trpc 218585c && scan trpc-trpc-218585c javascript
dl vitejs-vite-814120f vitejs/vite 814120f && scan vitejs-vite-814120f javascript
dl vitest-dev-vitest-7e1d762 vitest/dev-vitest 7e1d762 && scan vitest-dev-vitest-7e1d762 javascript
dl webpack-webpack-2c66e9d webpack/webpack 2c66e9d && scan webpack-webpack-2c66e9d javascript
# ======== PYTHON: 34 projects ========

# Batch 7
dl awesto-django-shop awesto/django-shop master && scan awesto-django-shop python
dl celery-celery-3f4d8d7 celery/celery 3f4d8d7 && scan celery-celery-3f4d8d7 python
dl celery-celery-92514ac celery/celery 92514ac && scan celery-celery-92514ac python
dl fantomas42-django-blog-zinnia fantomas42/django-blog-zinnia master && scan fantomas42-django-blog-zinnia python
dl fastapi-fastapi-866b7a3 fastapi/fastapi 866b7a3 && scan fastapi-fastapi-866b7a3 python
dl fastapi-fastapi-f057f4a fastapi/fastapi f057f4a && scan fastapi-fastapi-f057f4a python
dl feincms-feincms feincms/feincms main && scan feincms-feincms python
dl flexxui-flexx flexxui/flexx master && scan flexxui-flexx python
dl frappe-app frappe/frappe develop && scan frappe-app python
dl gozargah-marzban gozargah/marzban master && scan gozargah-marzban python
dl kivy-kivy-c75e8af kivy/kivy c75e8af && scan kivy-kivy-c75e8af python
dl lucifer1993-angelsword lucifer1993/angelsword master && scan lucifer1993-angelsword python
dl matplotlib-matplotlib-e312a92 matplotlib/matplotlib e312a92 && scan matplotlib-matplotlib-e312a92 python
dl mcp-brasil-mcp-brasil mcp-brasil/mcp-brasil main && scan mcp-brasil-mcp-brasil python
dl mirix-ai-mirix mirix-ai/mirix main && scan mirix-ai-mirix python
dl nathanborror-django-basic-apps nathanborror/django-basic-apps master && scan nathanborror-django-basic-apps python
dl nduckmink-arkon nduckmink/arkon master && scan nduckmink-arkon python
dl pallets-flask-2efaec1 pallets/flask 2efaec1 && scan pallets-flask-2efaec1 python
dl pallets-flask-5364652 pallets/flask 5364652 && scan pallets-flask-5364652 python
dl pallets-flask-8d05782 pallets/flask 8d05782 && scan pallets-flask-8d05782 python

# Batch 8
dl pelican getpelican/pelican master && scan pelican python
dl pgadmin4 pgadmin-org/pgadmin4 master && scan pgadmin4 python
dl pybind-pybind11-a2e59f0 pybind/pybind11 a2e59f0 && scan pybind-pybind11-a2e59f0 python
dl pyca-cryptography-cc45554 pyca/cryptography cc45554 && scan pyca-cryptography-cc45554 python
dl pydantic-pydantic-7cedbfb pydantic/pydantic 7cedbfb && scan pydantic-pydantic-7cedbfb python
dl pydantic-pydantic-c326748 pydantic/pydantic c326748 && scan pydantic-pydantic-c326748 python
dl quenary-tugtainer quenary/tugtainer main && scan quenary-tugtainer python
dl sanic-org-sanic sanic-org/sanic master && scan sanic-org-sanic python
dl scrapy-scrapy-8c85937 scrapy/scrapy 8c85937 && scan scrapy-scrapy-8c85937 python
dl sqlalchemy-sqlalchemy-66e3181 sqlalchemy/sqlalchemy 66e3181 && scan sqlalchemy-sqlalchemy-66e3181 python
dl streamlit-1 streamlit/streamlit develop && scan streamlit-1 python
dl tuhinshubhra-cmseek tuhinshubhra/cmseek master && scan tuhinshubhra-cmseek python
dl wooey-wooey wooey/wooey main && scan wooey-wooey python
dl zeronet HelloZeroNet/ZeroNet master && scan zeronet python
# ======== RUBY: 8 projects ========

# Batch 9
dl faker-ruby-faker-46130d9 faker/ruby-faker 46130d9 && scan faker-ruby-faker-46130d9 ruby
dl heartcombo-devise-af0be8f heartcombo/devise af0be8f && scan heartcombo-devise-af0be8f ruby
dl paper-trail-gem-paper_trail-7834c67 paper/trail-gem-paper_trail 7834c67 && scan paper-trail-gem-paper_trail-7834c67 ruby
dl rack-rack-09f2f66 rack/rack 09f2f66 && scan rack-rack-09f2f66 ruby
dl rails-rails-3c0df2c rails/rails 3c0df2c && scan rails-rails-3c0df2c ruby
dl rails-rails-9c50861 rails/rails 9c50861 && scan rails-rails-9c50861 ruby
dl resque-resque-2f9d080 resque/resque 2f9d080 && scan resque-resque-2f9d080 ruby
dl rspec-rspec-core-62fed98 rspec/rspec-core 62fed98 && scan rspec-rspec-core-62fed98 ruby
# ======== KOTLIN: 5 projects ========

# Batch 10
dl Kotlin-kotlinx Kotlin/kotlinx master && scan Kotlin-kotlinx kotlin
dl Kotlin-kotlinx.coroutines-d8d6f8f Kotlin/kotlinx.coroutines d8d6f8f && scan Kotlin-kotlinx.coroutines-d8d6f8f kotlin
dl Kotlin-kotlinx.serialization-6956af2 Kotlin/kotlinx.serialization 6956af2 && scan Kotlin-kotlinx.serialization-6956af2 kotlin
dl Kotlin-kotlinx.serialization-c75b46d Kotlin/kotlinx.serialization c75b46d && scan Kotlin-kotlinx.serialization-c75b46d kotlin
dl sqldelight-sqldelight-4584a67 sqldelight/sqldelight 4584a67 && scan sqldelight-sqldelight-4584a67 kotlin
# ======== LUA: 4 projects ========

# Batch 11
dl awesomeWM-awesome-30a42f5 awesomeWM/awesome 30a42f5 && scan awesomeWM-awesome-30a42f5 lua
dl koreader-koreader-041e20b koreader/koreader 041e20b && scan koreader-koreader-041e20b lua
dl luarocks-luarocks-539cb55 luarocks/luarocks 539cb55 && scan luarocks-luarocks-539cb55 lua
dl lunarmodules-busted-bc8ae8c lunarmodules/busted bc8ae8c && scan lunarmodules-busted-bc8ae8c lua
# ======== CSHARP: 5 projects ========

# Batch 12
dl dotnet-aspnetcore-2adedfc dotnet/aspnetcore 2adedfc && scan dotnet-aspnetcore-2adedfc csharp
dl dotnet-aspnetcore-af22eff dotnet/aspnetcore af22eff && scan dotnet-aspnetcore-af22eff csharp
dl dotnet-efcore-645f313 dotnet/efcore 645f313 && scan dotnet-efcore-645f313 csharp
dl dotnet-efcore-db55508 dotnet/efcore db55508 && scan dotnet-efcore-db55508 csharp
dl dotnet-orleans-55f292f dotnet/orleans 55f292f && scan dotnet-orleans-55f292f csharp
# ======== TYPESCRIPT: 3 projects ========

# Batch 13
dl outline outline/outline main && scan outline typescript
dl prisma-prisma-0f63437 prisma/prisma 0f63437 && scan prisma-prisma-0f63437 typescript
dl prisma-prisma-7a5c965 prisma/prisma 7a5c965 && scan prisma-prisma-7a5c965 typescript
# ======== JAVA: 4 projects ========

# Batch 14
dl allen7d-mini-shop-server allen7d/mini-shop-server master && scan allen7d-mini-shop-server java
dl elastic-elasticsearch-js-436cd88 elastic/elasticsearch-js 436cd88 && scan elastic-elasticsearch-js-436cd88 java
dl jellyfin-jellyfin-1fbd873 jellyfin/jellyfin 1fbd873 && scan jellyfin-jellyfin-1fbd873 java
dl jet-admin-jet-bridge jet-admin/jet-bridge master && scan jet-admin-jet-bridge java
# ======== PHP: 9 projects ========

# Batch 15
dl WordPress-wordpress-develop-855551c WordPress/wordpress-develop 855551c && scan WordPress-wordpress-develop-855551c php
dl elementor elementor/elementor master && scan elementor php
dl octobercms octobercms/october develop && scan octobercms php
dl shish-shimmie2 shish/shimmie2 master && scan shish-shimmie2 php
dl silverstripe-silverstripe-framework-1eaf57b silverstripe/silverstripe-framework 1eaf57b && scan silverstripe-silverstripe-framework-1eaf57b php
dl symfony-symfony-fd9802a symfony/symfony fd9802a && scan symfony-symfony-fd9802a php
dl the-events-calendar the-events-calendar/the-events-calendar master && scan the-events-calendar php
dl vlucas-phpdotenv-a59a137 vlucas/phpdotenv a59a137 && scan vlucas-phpdotenv-a59a137 php
dl woocommerce woocommerce/woocommerce master && scan woocommerce php

echo "[$(date %%H:%%M:%%S)] RESCAN 173 ALL DONE" >> "$LOG"
