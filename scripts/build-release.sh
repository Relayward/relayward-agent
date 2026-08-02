#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 VERSION [OUTPUT_DIRECTORY]" >&2
    exit 2
fi

VERSION=${1#v}
OUTPUT_DIRECTORY=${2:-dist}
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
case "$OUTPUT_DIRECTORY" in
    /*) ;;
    *) OUTPUT_DIRECTORY="$ROOT/$OUTPUT_DIRECTORY" ;;
esac
case "$OUTPUT_DIRECTORY" in
    /|"$ROOT") echo "refusing unsafe output directory: $OUTPUT_DIRECTORY" >&2; exit 2 ;;
esac

COMMIT=$(git rev-parse HEAD 2>/dev/null || printf 'unknown')
BUILD_DATE=$(git show -s --format=%cI HEAD 2>/dev/null || printf 'unknown')
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD 2>/dev/null || date +%s)}

rm -rf "$OUTPUT_DIRECTORY"
mkdir -p "$OUTPUT_DIRECTORY"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid= -X github.com/Relayward/relayward-agent/internal/buildinfo.Version=$VERSION -X github.com/Relayward/relayward-agent/internal/buildinfo.Commit=$COMMIT -X github.com/Relayward/relayward-agent/internal/buildinfo.Date=$BUILD_DATE" \
    -o "$OUTPUT_DIRECTORY/relayward-agent-linux-amd64" ./cmd/relayward-agent

reported_version=$("$OUTPUT_DIRECTORY/relayward-agent-linux-amd64" version --short)
if [ "$reported_version" != "$VERSION" ]; then
    echo "release binary reports $reported_version instead of $VERSION" >&2
    exit 1
fi

install -m 0755 deploy/relayward-agent-launcher "$OUTPUT_DIRECTORY/relayward-agent-launcher"
install -m 0755 deploy/relayward-agent.openrc "$OUTPUT_DIRECTORY/relayward-agent.openrc"
install -m 0644 deploy/relayward-agent.service "$OUTPUT_DIRECTORY/relayward-agent.service"
install -m 0755 deploy/uninstall.sh "$OUTPUT_DIRECTORY/uninstall.sh"

published_at=$(git show -s --format=%cI HEAD 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
go run ./cmd/relayward-agent-release \
    -dist "$OUTPUT_DIRECTORY" \
    -version "$VERSION" \
    -published-at "$published_at"

staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT HUP INT TERM
install -m 0755 "$OUTPUT_DIRECTORY/relayward-agent-linux-amd64" "$staging/relayward-agent"
for asset in relayward-agent-launcher relayward-agent.openrc relayward-agent.service uninstall.sh; do
    install -m 0755 "$OUTPUT_DIRECTORY/$asset" "$staging/$asset"
done
chmod 0644 "$staging/relayward-agent.service"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
    -C "$staging" -czf "$OUTPUT_DIRECTORY/relayward-agent-linux-amd64.tar.gz" \
    relayward-agent relayward-agent-launcher relayward-agent.openrc relayward-agent.service uninstall.sh
rm -rf "$staging"
trap - EXIT HUP INT TERM

install -m 0755 deploy/install.sh "$OUTPUT_DIRECTORY/install.sh"
(
    cd "$OUTPUT_DIRECTORY"
    sha256sum \
        install.sh \
        relayward-agent-linux-amd64 \
        relayward-agent-linux-amd64.tar.gz \
        relayward-agent-manifest.json > SHA256SUMS
)
rm -f \
    "$OUTPUT_DIRECTORY/relayward-agent-launcher" \
    "$OUTPUT_DIRECTORY/relayward-agent.openrc" \
    "$OUTPUT_DIRECTORY/relayward-agent.service" \
    "$OUTPUT_DIRECTORY/uninstall.sh"
