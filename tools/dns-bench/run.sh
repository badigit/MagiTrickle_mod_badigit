#!/usr/bin/env bash
# DNS benchmark runner.
#  ./run.sh [scenario] [rps] [duration]
#  scenario: in-group | out-of-group | mix | all
#  пример: ./run.sh mix 200 60s
set -euo pipefail

cd "$(dirname "$0")"

SCENARIO="${1:-mix}"
RPS="${2:-100}"
DUR="${3:-30s}"
SERVER="${SERVER:-10.9.0.1:53}"
RAPI="${RAPI:-http://10.9.0.1:9090}"

run_one() {
  local file="$1" name="$2"
  echo "============================================================"
  echo "  СЦЕНАРИЙ: $name  ($file, rps=$RPS, dur=$DUR, server=$SERVER)"
  echo "============================================================"

  local before after
  before=$(curl -sf "$RAPI/connections/inner-stats" 2>/dev/null || echo '{}')
  echo "inner-stats до: $before"

  ./dns-bench.exe -server "$SERVER" -domains "data/$file" -rps "$RPS" -duration "$DUR" -concurrency 32

  after=$(curl -sf "$RAPI/connections/inner-stats" 2>/dev/null || echo '{}')
  echo "inner-stats после: $after"

  # дельта alive (видна растёт ли утечка)
  local a_before a_after
  a_before=$(echo "$before" | grep -oE '"alive":[-0-9]+' | grep -oE '[-0-9]+$')
  a_after=$(echo "$after"  | grep -oE '"alive":[-0-9]+' | grep -oE '[-0-9]+$')
  if [[ -n "$a_before" && -n "$a_after" ]]; then
    echo "Δ alive: $((a_after - a_before))  (>0 = leak under load)"
  fi
  echo
}

case "$SCENARIO" in
  in-group)     run_one in-group.txt     "in-group (через прокси)" ;;
  out-of-group) run_one out-of-group.txt "out-of-group (DIRECT)" ;;
  mix)          run_one mix.txt          "mix (50/50)" ;;
  all)
    run_one out-of-group.txt "out-of-group (DIRECT)"
    sleep 5
    run_one in-group.txt     "in-group (через прокси)"
    sleep 5
    run_one mix.txt          "mix (50/50)"
    ;;
  *)
    echo "scenario: in-group | out-of-group | mix | all" >&2
    exit 2
    ;;
esac
