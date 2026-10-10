#!/usr/bin/env bash
set -euo pipefail

TEST_ROOT=${1:-${HOME}/smithproxy-spider-test}
SMITHPROXY_REF=${2:-api-ng}
SPIDER_REPOSITORY=${SPIDER_TEST_REPOSITORY:-https://github.com/astibal/smithproxy-spider.git}

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root; the test runners create a network namespace and firewall rules." >&2
    exit 1
fi

for command in git; do
    command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done

if [[ -e "$TEST_ROOT" ]] && [[ -n $(find "$TEST_ROOT" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
    echo "Refusing to initialize non-empty directory: $TEST_ROOT" >&2
    exit 1
fi

mkdir -p "$TEST_ROOT/src" "$TEST_ROOT/build/spider" "$TEST_ROOT/build/smithproxy" "$TEST_ROOT/state"
git clone --branch main --recurse-submodules "$SPIDER_REPOSITORY" "$TEST_ROOT/src/smithproxy-spider"

SMITHPROXY_TEST_ROOT="$TEST_ROOT" \
    "$TEST_ROOT/src/smithproxy-spider/tools/run-test-smithproxy.sh" fetch "$SMITHPROXY_REF"

echo
echo "Smithproxy Spider test workspace initialized:"
echo "  root:             $TEST_ROOT"
echo "  Spider source:    $TEST_ROOT/src/smithproxy-spider"
echo "  Smithproxy source: $TEST_ROOT/src/smithproxy ($SMITHPROXY_REF)"
echo
echo "Start it with:"
echo "  cd $TEST_ROOT/src/smithproxy-spider"
echo "  tools/run-test-smithproxy.sh start"
echo "  tools/run-test-spider.sh start"
