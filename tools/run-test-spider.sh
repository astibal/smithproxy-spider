#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-start}
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TEST_ROOT=${SMITHPROXY_TEST_ROOT:-${HOME}/smithproxy-spider-test}
STATE_DIR=${SMITHPROXY_TEST_STATE_DIR:-$TEST_ROOT/state}
BUILD_DIR=${SPIDER_TEST_BUILD_DIR:-$TEST_ROOT/build/spider}
SPIDER_PORT=${SPIDER_TEST_PORT:-18080}
SIFT_PORT=${SIFT_TEST_PORT:-18081}
UI_PORT=${SPIDER_TEST_UI_PORT:-15173}

stop_process() {
    local file=$1
    if [[ -f "$file" ]]; then
        local pid; pid=$(<"$file")
        if [[ "$pid" =~ ^[0-9]+$ ]]; then kill "$pid" 2>/dev/null || true; fi
        rm -f "$file"
    fi
}

print_howto() {
    local host_ip
    host_ip=${SPIDER_TEST_HOST_IP:-$(hostname -I | awk '{print $1}')}
    echo "Spider:"
    echo "  UI:      http://$host_ip:$UI_PORT/"
    echo "  Backend: http://$host_ip:$SPIDER_PORT"
    echo "  Token:   $SPIDER_TOKEN"
    echo "  Sift:    http://$host_ip:$SIFT_PORT/api/status"
    echo
    echo "Test from Helmut:"
    echo "  curl --proxy $SMITHPROXY_CONNECT_URL --cacert $SMITHPROXY_CA_CERT https://root.cz/"
    echo "  HTTP_CONNECT_PROXY=$SMITHPROXY_CONNECT_URL socksify curl --cacert $SMITHPROXY_CA_CERT https://root.cz/"
    echo "  telnet $SMITHPROXY_CLI"
    echo
    echo "Test from another test-LAN machine:"
    echo "curl -o test-ca.pem http://$host_ip:$UI_PORT/test-ca.pem"
    echo "curl --proxy http://$host_ip:33128 --cacert test-ca.pem https://root.cz/"
    echo "HTTP_CONNECT_PROXY=http://$host_ip:33128 socksify curl --cacert test-ca.pem https://root.cz/"
    echo "telnet $host_ip 55000"
    echo "socksify is provided by the dante-client package."
    echo "Logs:    $STATE_DIR/{smithproxy,spider,sift,frontend}.log"
    echo
}

case "$ACTION" in
stop)
    stop_process "$STATE_DIR/spider.pid"
    stop_process "$STATE_DIR/sift.pid"
    stop_process "$STATE_DIR/frontend.pid"
    echo "Spider test server stopped."
    exit 0 ;;
status)
    if [[ -f "$STATE_DIR/spider.pid" ]] && kill -0 "$(<"$STATE_DIR/spider.pid")" 2>/dev/null \
       && [[ -f "$STATE_DIR/sift.pid" ]] && kill -0 "$(<"$STATE_DIR/sift.pid")" 2>/dev/null; then
        if [[ ! -r "$STATE_DIR/state.env" ]]; then
            echo "running pid=$(<"$STATE_DIR/spider.pid") (state.env missing)"; exit 1
        fi
        source "$STATE_DIR/state.env"
        if ! curl -fsS "http://127.0.0.1:$SPIDER_PORT/api/health" >/dev/null 2>&1; then
            echo "process alive but backend unhealthy pid=$(<"$STATE_DIR/spider.pid")" >&2
            exit 1
        fi
        if ! curl -fsS "http://127.0.0.1:$SIFT_PORT/api/health" >/dev/null 2>&1; then
            echo "process alive but Sift unhealthy pid=$(<"$STATE_DIR/sift.pid")" >&2
            exit 1
        fi
        echo "running pid=$(<"$STATE_DIR/spider.pid")"
        print_howto
        exit 0
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
stop_process "$STATE_DIR/sift.pid"
stop_process "$STATE_DIR/frontend.pid"

cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" -j"$(nproc)"

"$BUILD_DIR/sift/sx-siftd" --bind 0.0.0.0 --port "$SIFT_PORT" \
    >"$STATE_DIR/sift.log" 2>&1 &
echo $! >"$STATE_DIR/sift.pid"

SPIDER_SMITHPROXY_KEY="$SMITHPROXY_API_KEY" SPIDER_TOKEN="$SPIDER_TOKEN" \
    "$BUILD_DIR/smithproxy-spider" --bind 0.0.0.0 --port "$SPIDER_PORT" \
    --smithproxy-url "$SMITHPROXY_API_URL" --callback-url "$SMITHPROXY_CALLBACK_URL" \
    --smithproxy-insecure >"$STATE_DIR/spider.log" 2>&1 &
echo $! >"$STATE_DIR/spider.pid"

mkdir -p "$STATE_DIR/frontend"
cp -a "$ROOT/frontend/." "$STATE_DIR/frontend/"
cp "$SMITHPROXY_CA_CERT" "$STATE_DIR/frontend/test-ca.pem"
python3 -m http.server "$UI_PORT" --bind 0.0.0.0 --directory "$STATE_DIR/frontend" \
    >"$STATE_DIR/frontend.log" 2>&1 &
echo $! >"$STATE_DIR/frontend.pid"

for _ in {1..90}; do
    if curl -fsS "http://127.0.0.1:$SPIDER_PORT/api/health" >/dev/null 2>&1 \
       && curl -fsS "http://127.0.0.1:$SIFT_PORT/api/health" >/dev/null 2>&1; then break; fi
    sleep 1
done
if ! curl -fsS "http://127.0.0.1:$SPIDER_PORT/api/health" >/dev/null; then
    tail -80 "$STATE_DIR/spider.log" >&2
    exit 1
fi
if ! curl -fsS "http://127.0.0.1:$SIFT_PORT/api/health" >/dev/null; then
    tail -80 "$STATE_DIR/sift.log" >&2
    exit 1
fi

echo "Spider test server is ready."
print_howto
