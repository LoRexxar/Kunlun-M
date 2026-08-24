#!/bin/bash
set -e
KDIR=/home/ubuntu/.hermes/hermes-agent/Kunlun-M
VENV=/home/ubuntu/Kunlun-M-venv
DLDIR=/home/ubuntu/realworld_scan_redownload
PROXY=https://ghfast.top
PROXY2=https://ghproxy.net
mkdir -p $DLDIR

# Clean pyc
find $KDIR -name '*.pyc' -delete 2>/dev/null
find $KDIR -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null

LOG=/tmp/batch_new_scan.log
> $LOG

TOTAL=0
OK=0
FAIL_DL=0
FAIL_SCAN=0

while IFS= read -r line; do
  repo=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['repo'])")
  branch=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['branch'])")
  lang=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['lang'])")
  task_name=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['task_name'])")
  stars=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('stars',0))")
  note=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('note',''))")

  # Skip giant projects (timeout risk) and special cases
  if [ "$stars" -gt 80000 ]; then
    echo "[SKIP] $repo (too large: $stars stars)" >> $LOG
    continue
  fi
  if [ "$note" = "skip if timeout" ]; then
    echo "[SKIP] $repo (known timeout)" >> $LOG
    continue
  fi

  # Skip C# and Rust for now (limited rules)
  # Actually keep them - engine supports them

  TARGET="$DLDIR/$task_name"
  rm -rf "$TARGET"
  mkdir -p "$TARGET"

  # Download
  DL_OK=0
  for proxy in "$PROXY" "$PROXY2"; do
    curl -sL --connect-timeout 10 --max-time 120 "$proxy/https://github.com/$repo/archive/$branch.tar.gz" -o "/tmp/${task_name}.tar.gz" 2>/dev/null && DL_OK=1 && break
  done

  if [ "$DL_OK" != "1" ]; then
    echo "[FAIL-DL] $repo" >> $LOG
    FAIL_DL=$((FAIL_DL+1))
    rm -rf "$TARGET" "/tmp/${task_name}.tar.gz" 2>/dev/null
    continue
  fi

  tar xzf "/tmp/${task_name}.tar.gz" -C "$TARGET" --strip-components=1 2>/dev/null
  rm -f "/tmp/${task_name}.tar.gz"

  FILE_COUNT=$(find "$TARGET" -type f | wc -l)
  echo "[SCAN] $repo ($FILE_COUNT files, lang=$lang)" >> $LOG

  # Skip if too many files (timeout risk, >3000)
  if [ "$FILE_COUNT" -gt 3000 ]; then
    echo "  [SKIP-TOO-BIG] $FILE_COUNT files" >> $LOG
    rm -rf "$TARGET"
    continue
  fi

  # Determine timeout based on file count
  TIMEOUT=1800
  if [ "$FILE_COUNT" -gt 1500 ]; then
    TIMEOUT=3600
  fi

  # Scan
  SCAN_OK=0
  timeout $TIMEOUT $VENV/bin/python3 $KDIR/kunlun.py scan -t "$TARGET" --yes -lan "$lang" --no-cache >> $LOG 2>&1 && SCAN_OK=1 || echo "  [TIMEOUT]" >> $LOG

  if [ "$SCAN_OK" = "1" ]; then
    OK=$((OK+1))
    echo "  [OK]" >> $LOG
  else
    echo "  [FAIL]" >> $LOG
    FAIL_SCAN=$((FAIL_SCAN+1))
  fi

  # Clean source
  rm -rf "$TARGET"
  TOTAL=$((TOTAL+1))
  echo "Progress: $TOTAL done, $OK ok, $FAIL_DL dl-fail, $FAIL_SCAN scan-fail" >> $LOG
  echo "---" >> $LOG

done < /tmp/batch_new.json

echo "" >> $LOG
echo "=== FINAL: $TOTAL total, $OK ok, $FAIL_DL dl-fail, $FAIL_SCAN scan-fail ===" >> $LOG
echo "Done. Log: $LOG"