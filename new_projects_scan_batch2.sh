#!/bin/bash
cd /home/ubuntu/.hermes/hermes-agent/Kunlun-M
source /home/ubuntu/Kunlun-M-venv/bin/activate
unset DJANGO_SETTINGS_MODULE

DOWNLOAD_DIR=/home/ubuntu/realworld_scan_redownload
PROXY="https://ghfast.top"
FALLBACK="https://ghproxy.net"
LOG_PREFIX=/tmp/new_scan_b2

PROJECTS="strapi/strapi|v4.25.1|javascript
adonisjs/core|v6.5.0|javascript
gatsbyjs/gatsby|v5.13.7|typescript
vercel/next.js|canary|javascript
ejs模板/ejs|v3.1.10|javascript
labstack/echo|v4.12.0|go
avelino/go-sql-mock|main|go
-go-chi/chi|v5.1.0|go
pion/webrtc|v3.3.4|go
shirou/gopsutil|v3.24.3|go
denoland/deno|v1.40.3|typescript
fastify/fastify|v4.28.0|javascript
rethinkdb/rethinkdb|v2.4.4|javascript
expressjs/morgan|1.10.0|javascript
molnarmark/colly|v1.2.0|go
kenanbek/validator.go|main|go
gofiber/fiber|v2.52.4|go
kataras/iris|v12.2.10|go
"