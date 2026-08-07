#!/bin/sh
set -eu

REPOSITORY=Relayward/relayward-agent
VERSION=${RELAYWARD_AGENT_VERSION:-latest}
SERVER_URL=${RELAYWARD_AGENT_SERVER_URL:-}
SERVER_CERT_SHA256=${RELAYWARD_AGENT_SERVER_CERT_SHA256:-}
ALLOW_INSECURE=false
ARCHIVE_PATH=
CHECKSUMS_PATH=
CONFIG_PATH=/etc/relayward-agent/config.json
STATE_DIRECTORY=/var/lib/relayward-agent
RUNTIME_ASSETS_PATH=/etc/relayward-agent/runtime-assets.sha256
INIT_SYSTEM=
asset_temporary=
runtime_marker_temporary=

usage() {
    cat <<'EOF'
Usage: install.sh --server-url URL [options]

Options:
  --version VERSION              Semantic release version (default: latest)
  --server-cert-sha256 DIGEST    Pin the center certificate SHA-256
  --allow-insecure               Allow unencrypted HTTP connections to the center
  --archive PATH                 Install a local release archive
  --checksums PATH               SHA256SUMS for a local archive
  --help                         Show this help

Set RELAYWARD_REGISTRATION_TOKEN for first enrollment.
EOF
}

validate_version() {
    value=$1
    if [ -z "$value" ] || [ "$value" = . ] || [ "$value" = .. ] || [ "${#value}" -gt 128 ]; then
        return 1
    fi
    case "$value" in
        *[!A-Za-z0-9.+_-]*) return 1 ;;
    esac
}

install_root_asset() {
    source=$1
    destination=$2
    mode=$3
    asset_temporary="$destination.tmp-$$"
    rm -f "$asset_temporary"
    install -m "$mode" -o root -g root "$source" "$asset_temporary"
    mv -f "$asset_temporary" "$destination"
    asset_temporary=
}

run_as_agent() {
    if [ "$INIT_SYSTEM" = systemd ]; then
        runuser -u relayward-agent -- "$@"
    else
        su -s /bin/sh -- relayward-agent -c 'exec "$@"' sh "$@"
    fi
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) VERSION=${2:?missing value for --version}; shift 2 ;;
        --server-url) SERVER_URL=${2:?missing value for --server-url}; shift 2 ;;
        --server-cert-sha256) SERVER_CERT_SHA256=${2:?missing value for --server-cert-sha256}; shift 2 ;;
        --allow-insecure) ALLOW_INSECURE=true; shift ;;
        --archive) ARCHIVE_PATH=${2:?missing value for --archive}; shift 2 ;;
        --checksums) CHECKSUMS_PATH=${2:?missing value for --checksums}; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must run as root" >&2
    exit 1
fi
if [ -z "$SERVER_URL" ]; then
    echo "--server-url is required" >&2
    exit 2
fi
if [ "$VERSION" != latest ]; then
    VERSION=${VERSION#v}
    if ! validate_version "$VERSION"; then
        echo "--version is invalid" >&2
        exit 2
    fi
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    INIT_SYSTEM=systemd
elif [ -d /run/openrc ] && command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
    INIT_SYSTEM=openrc
else
    echo "unsupported init system: systemd or OpenRC must be running" >&2
    exit 1
fi

required_commands="getent install readlink sha256sum tar"
if [ "$INIT_SYSTEM" = systemd ]; then
    required_commands="$required_commands groupadd useradd runuser systemctl"
else
    required_commands="$required_commands addgroup adduser su rc-service rc-update"
fi
for command in $required_commands; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "$command is required" >&2
        exit 1
    fi
done

case "$(uname -m)" in
    x86_64|amd64) ;;
    *) echo "unsupported architecture: $(uname -m); only Linux AMD64 is supported" >&2; exit 1 ;;
esac

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"; if [ -n "$runtime_marker_temporary" ]; then rm -f "$runtime_marker_temporary"; fi; if [ -n "$asset_temporary" ]; then rm -f "$asset_temporary"; fi' EXIT HUP INT TERM
archive_name=relayward-agent-linux-amd64.tar.gz

if [ -n "$ARCHIVE_PATH" ]; then
    if [ -z "$CHECKSUMS_PATH" ]; then
        echo "--checksums is required with --archive" >&2
        exit 2
    fi
    cp "$ARCHIVE_PATH" "$temporary/$archive_name"
    cp "$CHECKSUMS_PATH" "$temporary/SHA256SUMS"
else
    if ! command -v curl >/dev/null 2>&1; then
        echo "curl is required for a GitHub release install" >&2
        exit 1
    fi
    if [ "$VERSION" = latest ]; then
        release_url="https://github.com/$REPOSITORY/releases/latest/download"
    else
        release_url="https://github.com/$REPOSITORY/releases/download/v$VERSION"
    fi
    curl --proto '=https' --tlsv1.2 -fsSL "$release_url/$archive_name" -o "$temporary/$archive_name"
    curl --proto '=https' --tlsv1.2 -fsSL "$release_url/SHA256SUMS" -o "$temporary/SHA256SUMS"
fi

expected=$(awk -v name="$archive_name" '$2 == name { print $1 }' "$temporary/SHA256SUMS")
if [ "${#expected}" -ne 64 ] || printf '%s' "$expected" | grep -q '[^0-9a-fA-F]'; then
    echo "checksum for $archive_name is missing or invalid" >&2
    exit 1
fi
actual=$(sha256sum "$temporary/$archive_name" | awk '{print $1}')
if [ "$actual" != "$expected" ]; then
    echo "release archive checksum mismatch" >&2
    exit 1
fi

entries=$(tar -tzf "$temporary/$archive_name" | LC_ALL=C sort)
expected_entries=$(printf '%s\n' \
    relayward-agent \
    relayward-agent-launcher \
    relayward-agent.openrc \
    relayward-agent.service \
    uninstall.sh | LC_ALL=C sort)
if [ "$entries" != "$expected_entries" ]; then
    echo "release archive contains unexpected files" >&2
    exit 1
fi
tar -xzf "$temporary/$archive_name" -C "$temporary"
chmod 0755 "$temporary"
candidate_version=$("$temporary/relayward-agent" version --short)
if ! validate_version "$candidate_version"; then
    echo "release binary reports an invalid version" >&2
    exit 1
fi
if [ "$VERSION" != latest ] && [ "$candidate_version" != "$VERSION" ]; then
    echo "release binary version does not match --version" >&2
    exit 1
fi
candidate_digest=$(sha256sum "$temporary/relayward-agent" | awk '{print $1}')
candidate_target="versions/$candidate_version-$candidate_digest/relayward-agent"
runtime_assets_digest=$(
    cd "$temporary"
    for asset in relayward-agent-launcher relayward-agent.openrc relayward-agent.service uninstall.sh; do
        sha256sum "$asset" | awk '{print $1}'
    done | sha256sum | awk '{print $1}'
)

if ! getent group relayward-agent >/dev/null 2>&1; then
    if [ "$INIT_SYSTEM" = systemd ]; then
        groupadd --system relayward-agent
    else
        addgroup -S relayward-agent
    fi
fi
if ! id relayward-agent >/dev/null 2>&1; then
    if [ "$INIT_SYSTEM" = systemd ]; then
        useradd --system --gid relayward-agent --home-dir "$STATE_DIRECTORY" --shell /usr/sbin/nologin relayward-agent
    else
        adduser -S -D -H -h "$STATE_DIRECTORY" -s /sbin/nologin -G relayward-agent relayward-agent
    fi
fi
install -d -m 0750 -o root -g relayward-agent /etc/relayward-agent
install -d -m 0700 -o relayward-agent -g relayward-agent "$STATE_DIRECTORY"
install -d -m 0700 -o relayward-agent -g relayward-agent "$STATE_DIRECTORY/versions"
install -d -m 0755 -o root -g root /usr/local/bin /usr/local/libexec /usr/local/sbin

existing_install=false
if [ -L "$STATE_DIRECTORY/current" ]; then
    existing_install=true
    current_resolved=$(readlink -f "$STATE_DIRECTORY/current") || {
        echo "existing current Agent link cannot be resolved" >&2
        exit 1
    }
    case "$current_resolved" in
        "$STATE_DIRECTORY"/versions/*/relayward-agent) ;;
        *) echo "existing current Agent is outside the managed versions directory" >&2; exit 1 ;;
    esac
    if [ -e "$STATE_DIRECTORY/update-pending.json" ] || [ -L "$STATE_DIRECTORY/update-pending.json" ]; then
        echo "an Agent update is already pending" >&2
        exit 1
    fi
elif [ -e "$STATE_DIRECTORY/current" ]; then
    echo "existing current Agent path is not a symbolic link" >&2
    exit 1
fi

candidate_directory="$STATE_DIRECTORY/versions/$candidate_version-$candidate_digest"
if [ -e "$candidate_directory/relayward-agent" ]; then
    installed_digest=$(sha256sum "$candidate_directory/relayward-agent" | awk '{print $1}')
    if [ "$installed_digest" != "$candidate_digest" ]; then
        echo "existing immutable Agent version has an invalid checksum" >&2
        exit 1
    fi
else
    run_as_agent install -d -m 0700 "$candidate_directory"
    run_as_agent install -m 0755 "$temporary/relayward-agent" "$candidate_directory/relayward-agent"
fi

install_root_asset "$temporary/relayward-agent-launcher" /usr/local/libexec/relayward-agent-launcher 0755
install_root_asset "$temporary/uninstall.sh" /usr/local/sbin/relayward-agent-uninstall 0755
if [ "$INIT_SYSTEM" = systemd ]; then
    install_root_asset "$temporary/relayward-agent.service" /etc/systemd/system/relayward-agent.service 0644
    systemctl daemon-reload
else
    install_root_asset "$temporary/relayward-agent.openrc" /etc/init.d/relayward-agent 0755
fi
runtime_marker_temporary="$RUNTIME_ASSETS_PATH.tmp-$$"
printf '%s\n' "$runtime_assets_digest" > "$runtime_marker_temporary"
chown root:relayward-agent "$runtime_marker_temporary"
chmod 0640 "$runtime_marker_temporary"
mv -f "$runtime_marker_temporary" "$RUNTIME_ASSETS_PATH"
runtime_marker_temporary=

if [ "$existing_install" = false ]; then
    run_as_agent ln -s "$candidate_target" "$STATE_DIRECTORY/current"
fi
ln -sfn "$STATE_DIRECTORY/current" /usr/local/bin/relayward-agent

if [ ! -f "$CONFIG_PATH" ]; then
    set -- init-config \
        --config "$CONFIG_PATH" \
        --server-url "$SERVER_URL" \
        --state-directory "$STATE_DIRECTORY" \
        --server-cert-sha256 "$SERVER_CERT_SHA256"
    if [ "$ALLOW_INSECURE" = true ]; then
        set -- "$@" --allow-insecure
    fi
    /usr/local/bin/relayward-agent "$@"
fi
chown root:relayward-agent "$CONFIG_PATH"
chmod 0640 "$CONFIG_PATH"

if [ ! -f "$STATE_DIRECTORY/identity.json" ] && [ -z "${RELAYWARD_REGISTRATION_TOKEN:-}" ]; then
    echo "RELAYWARD_REGISTRATION_TOKEN is required for first enrollment" >&2
    exit 2
fi
if [ -n "${RELAYWARD_REGISTRATION_TOKEN:-}" ]; then
    service_stopped=false
    if [ "$INIT_SYSTEM" = systemd ]; then
        if systemctl --quiet is-active relayward-agent.service; then
            systemctl stop relayward-agent.service
            service_stopped=true
        fi
    elif rc-service relayward-agent status >/dev/null 2>&1; then
        rc-service relayward-agent stop
        service_stopped=true
    fi
    if ! run_as_agent env RELAYWARD_REGISTRATION_TOKEN="$RELAYWARD_REGISTRATION_TOKEN" \
        /usr/local/bin/relayward-agent enroll -config "$CONFIG_PATH"; then
        if [ "$service_stopped" = true ]; then
            if [ "$INIT_SYSTEM" = systemd ]; then
                systemctl start relayward-agent.service
            else
                rc-service relayward-agent start
            fi
        fi
        exit 1
    fi
fi

if [ "$INIT_SYSTEM" = systemd ]; then
    systemctl enable relayward-agent.service
    if systemctl --quiet is-active relayward-agent.service; then
        systemctl restart relayward-agent.service
    else
        systemctl start relayward-agent.service
    fi
    systemctl --quiet is-active relayward-agent.service
else
    rc-update add relayward-agent default
    if rc-service relayward-agent status >/dev/null 2>&1; then
        rc-service relayward-agent restart
    else
        rc-service relayward-agent start
    fi
    rc-service relayward-agent status >/dev/null
fi

if [ "$existing_install" = true ]; then
    active_target=$(readlink "$STATE_DIRECTORY/current")
    if [ "$active_target" != "$candidate_target" ]; then
        echo "Relayward runtime assets updated; activate Agent $candidate_version from the center"
        exit 0
    fi
fi
echo "Relayward Agent $candidate_version installed and running"
