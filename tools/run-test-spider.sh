#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-start}
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
STATE_DIR=${SMITHPROXY_TEST_STATE_DIR:-/root/.local/state/smithproxy-spider-test}
SPIDER_PORT=${SPIDER_TEST_PORT:-18080}
UI_PORT=${SPIDER_TEST_UI_PORT:-15173}

stop_process() {
    local file=$1
    if [[ -f "$file" ]]; then
        local pid; pid=$(<"$file")
        if [[ "$pid" =~ ^[0-9]+$ ]]; then kill "$pid" 2>/dev/null || true; fi
        rm -f "$file"
    fi
}

case "$ACTION" in
stop)
    stop_process "$STATE_DIR/spider.pid"
    stop_process "$STATE_DIR/frontend.pid"
    echo "Spider test server stopped."
    exit 0 ;;
status)
    if [[ -f "$STATE_DIR/spider.pid" ]] && kill -0 "$(<"$STATE_DIR/spider.pid")" 2>/dev/null; then
        echo "running pid=$(<"$STATE_DIR/spider.pid")"; exit 0
    fi
    echo "stopped"; exit 1 ;;
start) ;;
*) echo "Usage: $0 {start|stop|status}" >&2; exit 2 ;;
esac

if [[ ! -r "$STATE_DIR/state.env" ]]; then
    echo "Run tools/run-test-smithproxy.sh start first." >&2
    exit 1
fi
source "$STATE_DIR/state.env"
mkdir -p "$STATE_DIR"
stop_process "$STATE_DIR/spider.pid"
stop_process "$STATE_DIR/frontend.pid"

cmake -S "$ROOT" -B "$ROOT/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$ROOT/build" -j"$(nproc)"

SPIDER_SMITHPROXY_KEY="$SMITHPROXY_API_KEY" SPIDER_TOKEN="$SPIDER_TOKEN" \
    "$ROOT/build/smithproxy-spider" --bind 0.0.0.0 --port "$SPIDER_PORT" \
    --smithproxy-url "$SMITHPROXY_API_URL" --callback-url "$SMITHPROXY_CALLBACK_URL" \
    --smithproxy-insecure >"$STATE_DIR/spider.log" 2>&1 &
echo $! >"$STATE_DIR/spider.pid"

python3 -m http.server "$UI_PORT" --bind 0.0.0.0 --directory "$ROOT/frontend" \
    >"$STATE_DIR/frontend.log" 2>&1 &
echo $! >"$STATE_DIR/frontend.pid"

for _ in {1..60}; do
    if curl -fsS "http://127.0.0.1:$SPIDER_PORT/api/health" >/dev/null 2>&1; then break; fi
    sleep 0.1
done
if ! curl -fsS "http://127.0.0.1:$SPIDER_PORT/api/health" >/dev/null; then
    tail -80 "$STATE_DIR/spider.log" >&2
    exit 1
fi

HOST_IP=${SPIDER_TEST_HOST_IP:-$(hostname -I | awk '{print $1}')}
echo "Spider test server is ready."
echo "UI:      http://$HOST_IP:$UI_PORT/"
echo "Backend: http://$HOST_IP:$SPIDER_PORT"
echo "Token:   $SPIDER_TOKEN"
echo "Proxy:   $SMITHPROXY_CONNECT_URL"
echo "Logs:    $STATE_DIR/{smithproxy,spider,frontend}.log"
