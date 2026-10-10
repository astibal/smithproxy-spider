#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-start}
TEST_ROOT=${SMITHPROXY_TEST_ROOT:-${HOME}/smithproxy-spider-test}
STATE_DIR=${SMITHPROXY_TEST_STATE_DIR:-$TEST_ROOT/state}
SOURCE_DIR=${SMITHPROXY_TEST_SOURCE_DIR:-$TEST_ROOT/src/smithproxy}
BUILD_DIR=${SMITHPROXY_TEST_BUILD_DIR:-$TEST_ROOT/build/smithproxy}
SOURCE_REF_FILE=$STATE_DIR/source-ref
NS=sxp-test
HOST_IF=sxp-test0
NS_ADDR=10.254.77.2
HOST_ADDR=10.254.77.1
API_PORT=55580
CONNECT_PORT=33128
CLI_PORT=55000

require_root() {
    if [[ ${EUID} -ne 0 ]]; then echo "Run as root." >&2; exit 1; fi
}

source_ref() {
    if [[ -n ${2:-} ]]; then
        printf '%s\n' "$2"
    elif [[ -n ${SMITHPROXY_TEST_REF:-} ]]; then
        printf '%s\n' "$SMITHPROXY_TEST_REF"
    elif [[ -r "$SOURCE_REF_FILE" ]]; then
        local remembered_ref
        IFS= read -r remembered_ref <"$SOURCE_REF_FILE"
        printf '%s\n' "$remembered_ref"
    else
        printf '%s\n' master
    fi
}

sync_source() {
    local ref=$1
    local protect_changes=${2:-false}
    if [[ ! $ref =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ || $ref == *..* ]]; then
        echo "Invalid Smithproxy source ref: $ref" >&2
        exit 2
    fi

    if [[ ! -d "$SOURCE_DIR/.git" ]]; then
        if [[ -e "$SOURCE_DIR" ]]; then
            echo "Refusing to replace unmanaged path: $SOURCE_DIR" >&2
            exit 1
        fi
        git clone https://github.com/astibal/smithproxy.git "$SOURCE_DIR"
        touch "$SOURCE_DIR/.spider-test-managed"
    elif [[ ! -f "$SOURCE_DIR/.spider-test-managed" ]]; then
        echo "Refusing to reset checkout without .spider-test-managed: $SOURCE_DIR" >&2
        exit 1
    fi

    local tracked_changes
    tracked_changes=$(git -C "$SOURCE_DIR" status --porcelain --untracked-files=no)
    if [[ $tracked_changes == " M .gitmodules" ]]; then
        # Older runner versions wrote HTTPS overrides into the tracked file.
        git -C "$SOURCE_DIR" restore -- .gitmodules
        tracked_changes=
    fi
    if [[ $protect_changes == true && -n $tracked_changes ]]; then
        echo "Refusing to replace local changes in $SOURCE_DIR" >&2
        exit 1
    fi

    git -C "$SOURCE_DIR" fetch origin "$ref"
    git -C "$SOURCE_DIR" checkout -B "$ref" FETCH_HEAD
    git -C "$SOURCE_DIR" config submodule.socle.url https://github.com/astibal/socle.git
    git -C "$SOURCE_DIR" config submodule.src/ext/lmhpp.url https://github.com/astibal/lmhpp.git
    git -C "$SOURCE_DIR" submodule update --init --recursive
    printf '%s\n' "$ref" >"$SOURCE_REF_FILE"
    echo "Smithproxy source: $ref @ $(git -C "$SOURCE_DIR" rev-parse --short HEAD)"
}

print_howto() {
    local host_ip
    host_ip=${SPIDER_TEST_HOST_IP:-$(hostname -I | awk '{print $1}')}
    echo "From Helmut (namespace route):"
    echo "  API:          $SMITHPROXY_API_URL"
    echo "  HTTP CONNECT: $SMITHPROXY_CONNECT_URL"
    echo "  CLI:          $SMITHPROXY_CLI"
    echo "  CA:           $SMITHPROXY_CA_CERT"
    echo
    echo "From another test-LAN machine (Helmut DNAT):"
    echo "  API:          https://$host_ip:$API_PORT"
    echo "  HTTP CONNECT: http://$host_ip:$CONNECT_PORT"
    echo "  CLI:          $host_ip:$CLI_PORT"
    echo "State:        $STATE_DIR/state.env"
    echo
}

stop_instance() {
    if [[ -f "$STATE_DIR/cli-forward.pid" ]]; then
        forward_pid=$(<"$STATE_DIR/cli-forward.pid")
        if [[ "$forward_pid" =~ ^[0-9]+$ ]]; then kill "$forward_pid" 2>/dev/null || true; fi
        rm -f "$STATE_DIR/cli-forward.pid"
    fi
    if [[ -f "$STATE_DIR/smithproxy.pid" ]]; then
        pid=$(<"$STATE_DIR/smithproxy.pid")
        if [[ "$pid" =~ ^[0-9]+$ ]]; then kill "$pid" 2>/dev/null || true; fi
        for _ in {1..30}; do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    fi
    iptables -t nat -D POSTROUTING -s "$NS_ADDR/32" -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport "$API_PORT" -j DNAT --to-destination "$NS_ADDR:$API_PORT" 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport "$CONNECT_PORT" -j DNAT --to-destination "$NS_ADDR:$CONNECT_PORT" 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport "$CLI_PORT" -j DNAT --to-destination "$NS_ADDR:$CLI_PORT" 2>/dev/null || true
    iptables -D FORWARD -i "$HOST_IF" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$HOST_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$HOST_IF" 2>/dev/null || true
    rm -f "$STATE_DIR/smithproxy.pid"
}

case "$ACTION" in
stop)
    require_root; stop_instance; echo "Test Smithproxy stopped."; exit 0 ;;
status)
    if [[ -f "$STATE_DIR/smithproxy.pid" ]] && kill -0 "$(<"$STATE_DIR/smithproxy.pid")" 2>/dev/null; then
        source "$STATE_DIR/state.env"
        echo "running pid=$(<"$STATE_DIR/smithproxy.pid")"
        print_howto
        exit 0
    fi
    echo "stopped"; exit 1 ;;
fetch)
    require_root
    for command in git; do
        command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
    done
    mkdir -p "$STATE_DIR"
    sync_source "$(source_ref "$@")" true
    exit 0 ;;
start) ;;
*) echo "Usage: $0 {start|stop|status|fetch [ref]}" >&2; exit 2 ;;
esac

require_root
for command in git cmake ip iptables openssl python3 curl socat; do
    command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done
mkdir -p "$STATE_DIR"
stop_instance
sync_source "$(source_ref "$@")"

cmake -S "$SOURCE_DIR" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build "$BUILD_DIR" -j"$(nproc)" --target smithproxy

API_KEY=$(openssl rand -hex 24)
SPIDER_TOKEN=$(openssl rand -hex 24)
CONFIG="$STATE_DIR/smithproxy.cfg"
CERT_DIR="$STATE_DIR/certs/default"
mkdir -p "$CERT_DIR"
cp "$SOURCE_DIR/etc/certs/default/sslca.json" "$CERT_DIR/sslca.json"
openssl req -x509 -newkey rsa:3072 -sha256 -days 30 -nodes \
    -keyout "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/ca-cert.pem" \
    -subj "/CN=Smithproxy Spider Test CA/O=Smithproxy Test Lab/C=CZ" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$CERT_DIR/srv-key.pem" \
    -out "$STATE_DIR/server.csr" -subj "/CN=smithproxy-test" >/dev/null 2>&1
cat >"$STATE_DIR/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:smithproxy-test,IP:$NS_ADDR,IP:$HOST_ADDR
EOF
openssl x509 -req -in "$STATE_DIR/server.csr" -CA "$CERT_DIR/ca-cert.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" -CAcreateserial -out "$CERT_DIR/srv-cert.pem" \
    -days 30 -sha256 -extfile "$STATE_DIR/server.ext" >/dev/null 2>&1
cp "$CERT_DIR/srv-key.pem" "$CERT_DIR/portal-key.pem"
cp "$CERT_DIR/srv-cert.pem" "$CERT_DIR/portal-cert.pem"
cp "$CERT_DIR/srv-key.pem" "$CERT_DIR/cl-key.pem"
cp "$CERT_DIR/srv-cert.pem" "$CERT_DIR/cl-cert.pem"
chmod 600 "$CERT_DIR"/*-key.pem

python3 - "$SOURCE_DIR/etc/smithproxy.cfg" "$CONFIG" "$SOURCE_DIR" "$STATE_DIR" "$CERT_DIR" \
    "$API_KEY" "$API_PORT" "$CONNECT_PORT" "$CLI_PORT" <<'PY'
import pathlib, sys
source, destination, tree, state, cert_dir = map(pathlib.Path, sys.argv[1:6])
api_key, api_port, connect_port, cli_port = sys.argv[6:]
text = source.read_text()
replacements = {
    "accept_tproxy = TRUE;": "accept_tproxy = FALSE;",
    "accept_redirect = TRUE;": "accept_redirect = FALSE;",
    "accept_socks = TRUE;": "accept_socks = FALSE;",
    "accept_http_connect = FALSE;": "accept_http_connect = TRUE;",
    'nameservers = [ "8.8.8.8", "8.8.4.4" ];': 'nameservers = [ "1.1.1.1" ];',
    'http_connect_port = "3128";': f'http_connect_port = "{connect_port}";',
    "http_connect_workers = 0;": "http_connect_workers = 1;",
    'certs_path = "/etc/smithproxy/certs/default/";': f'certs_path = "{cert_dir}/";',
    'certs_ca_key_password = "smithproxy";': 'certs_ca_key_password = "";',
    'messages_dir = "/etc/smithproxy/msg/en/";': f'messages_dir = "{tree / "etc/msg/en"}/";',
    "port = 50000;": f"port = {cli_port};",
    'log_file = "/var/log/smithproxy/messages.%s.log";': f'log_file = "{state}/messages.%s.log";',
    'sslkeylog_file = "/var/log/smithproxy/sslkeylog.%s.log";': f'sslkeylog_file = "{state}/sslkeylog.%s.log";',
    'dir = "/var/smithproxy/data"': f'dir = "{state}"',
    "  local =\n  {\n    enabled = true": "  local =\n  {\n    enabled = false",
}
for old, new in replacements.items():
    if old not in text:
        raise SystemExit(f"master config no longer contains expected value: {old!r}")
    text = text.replace(old, new, 1)
tls_profile_anchors = (
    ("tls_profiles = {\n    default = {", "tls_profiles = {\n    default = {\n        ct_enable = FALSE;"),
    ("    bypass = {\n        inspect = FALSE;", "    bypass = {\n        inspect = FALSE;\n        ct_enable = FALSE;"),
)
for old, new in tls_profile_anchors:
    if old not in text:
        raise SystemExit(f"master config no longer contains TLS profile anchor: {old!r}")
    text = text.replace(old, new, 1)
extra = f'''settings = {{
    accept_api = TRUE;
    http_api = {{
        keys = [ "{api_key}" ];
        key_timeout = 3600;
        key_extend_on_access = TRUE;
        loopback_only = FALSE;
        bind_address = "0.0.0.0";
        allow_api_header = TRUE;
        port = {api_port};
        pam_login = FALSE;
    }};
    webhook = {{
        enabled = TRUE;
        url = "http://10.254.77.1:9/unconfigured";
        tls_verify = FALSE;
        api_override = TRUE;
        ping_interval = 5;
    }};
'''
if "settings = {" not in text:
    raise SystemExit("master config has no settings block")
destination.write_text(text.replace("settings = {", extra, 1))
PY

ip netns add "$NS"
ip link add "$HOST_IF" type veth peer name eth0 netns "$NS"
ip addr add "$HOST_ADDR/30" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip addr add "$NS_ADDR/30" dev eth0
ip netns exec "$NS" ip link set eth0 up
ip netns exec "$NS" ip route add default via "$HOST_ADDR"
sysctl -q -w net.ipv4.ip_forward=1
iptables -I FORWARD -i "$HOST_IF" -j ACCEPT
iptables -I FORWARD -o "$HOST_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -s "$NS_ADDR/32" -j MASQUERADE
iptables -t nat -A PREROUTING -p tcp --dport "$API_PORT" -j DNAT --to-destination "$NS_ADDR:$API_PORT"
iptables -t nat -A PREROUTING -p tcp --dport "$CONNECT_PORT" -j DNAT --to-destination "$NS_ADDR:$CONNECT_PORT"
iptables -t nat -A PREROUTING -p tcp --dport "$CLI_PORT" -j DNAT --to-destination "$NS_ADDR:$CLI_PORT"

cat >"$STATE_DIR/state.env" <<EOF
SMITHPROXY_API_KEY=$API_KEY
SPIDER_TOKEN=$SPIDER_TOKEN
SMITHPROXY_API_URL=https://$NS_ADDR:$API_PORT
SMITHPROXY_CONNECT_URL=http://$NS_ADDR:$CONNECT_PORT
SMITHPROXY_CALLBACK_URL=http://$HOST_ADDR:18080/webhook
SMITHPROXY_CA_CERT=$CERT_DIR/ca-cert.pem
SMITHPROXY_CLI=$NS_ADDR:$CLI_PORT
EOF
chmod 600 "$STATE_DIR/state.env"
source "$STATE_DIR/state.env"

ip netns exec "$NS" env SMITHPROXY_PID_FILE="$STATE_DIR/service.pid" \
    "$BUILD_DIR/smithproxy" --config-file "$CONFIG" --diagnose \
    >"$STATE_DIR/smithproxy.log" 2>&1 &
echo $! >"$STATE_DIR/smithproxy.pid"

ip netns exec "$NS" socat \
    "TCP4-LISTEN:$CLI_PORT,bind=$NS_ADDR,reuseaddr,fork" "TCP4:127.0.0.1:$CLI_PORT" \
    >"$STATE_DIR/cli-forward.log" 2>&1 &
echo $! >"$STATE_DIR/cli-forward.pid"

for _ in {1..100}; do
    if curl -ksS -H "X-API-Key: $API_KEY" "$SMITHPROXY_API_URL/api/status/ping" >/dev/null 2>&1; then
        echo "Test Smithproxy is ready."
        print_howto
        exit 0
    fi
    if ! kill -0 "$(<"$STATE_DIR/smithproxy.pid")" 2>/dev/null; then
        tail -80 "$STATE_DIR/smithproxy.log" >&2
        exit 1
    fi
    sleep 0.2
done
echo "Smithproxy did not become ready; see $STATE_DIR/smithproxy.log" >&2
exit 1
