#!/bin/sh
# Install the pinned Herdr-dog Relay release into a user-owned bin directory.
set -eu

# Fixed GitHub repository containing same-source checksummed release archives.
REPOSITORY="mithyer/herdr-dog-relay"
# Optional exact release tag; the latest release is used when it is omitted.
RELEASE_VERSION="${HERDRDOGRELAY_VERSION:-}"
# User-owned destination; no sudo or system directory writes are used.
INSTALL_DIRECTORY="${HERDRDOGRELAY_BIN_DIR:-$HOME/.local/bin}"

# Print a bounded installer error and stop before changing the destination.
fail() {
    printf '%s\n' "herdogrelay installer: $1" >&2
    exit 1
}

# Print the installer options without exposing environment or credential data.
print_help() {
    cat <<'HELP'
Usage: install.sh [--version TAG] [--bin-dir PATH]

Environment:
  HERDRDOGRELAY_VERSION     Exact release tag override.
  HERDRDOGRELAY_BIN_DIR     User-owned installation directory override.
HELP
}

# Parse only installer-owned options; all other values fail closed.
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || fail "--version requires a release tag"
            RELEASE_VERSION="$2"
            shift 2
            ;;
        --bin-dir)
            [ "$#" -ge 2 ] || fail "--bin-dir requires a destination"
            INSTALL_DIRECTORY="$2"
            shift 2
            ;;
        --help|-h)
            print_help
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

# Select only the explicitly released operating-system/architecture pairs.
case "$(uname -s)" in
    Darwin)
        ARCHIVE_OS="macos"
        case "$(uname -m)" in
            arm64) ARCHIVE_ARCH="arm64" ;;
            x86_64) ARCHIVE_ARCH="x86_64" ;;
            *) fail "unsupported macOS architecture" ;;
        esac
        ;;
    Linux)
        ARCHIVE_OS="linux"
        [ "$(uname -m)" = "x86_64" ] || fail "unsupported Linux architecture"
        ARCHIVE_ARCH="x86_64"
        ;;
    *) fail "this release supports macOS and Linux only" ;;
esac

# Verify the small set of host tools required for HTTPS download and extraction.
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
command -v install >/dev/null 2>&1 || fail "install is required"
command -v awk >/dev/null 2>&1 || fail "awk is required"
command -v od >/dev/null 2>&1 || fail "od is required"
command -v tr >/dev/null 2>&1 || fail "tr is required"
command -v cp >/dev/null 2>&1 || fail "cp is required"
if command -v sha256sum >/dev/null 2>&1; then
    CHECKSUM_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    CHECKSUM_TOOL="shasum"
else
    fail "sha256sum or shasum is required"
fi

# Resolve the final tag through GitHub's HTTPS redirect without parsing JSON.
if [ -z "$RELEASE_VERSION" ]; then
    LATEST_URL=$(curl --fail --silent --show-error --location --head --proto '=https' --tlsv1.2 --output /dev/null --write-out '%{url_effective}' \
        "https://github.com/$REPOSITORY/releases/latest") \
        || fail "could not resolve the latest GitHub release"
    RELEASE_VERSION=${LATEST_URL##*/}
    [ -n "$RELEASE_VERSION" ] || fail "GitHub returned an empty release tag"
fi

# Keep all downloaded material outside the destination until checksum verification succeeds.
TEMP_DIRECTORY=$(mktemp -d "${TMPDIR:-/tmp}/herdogrelay-install.XXXXXX")
trap 'rm -rf "$TEMP_DIRECTORY"' EXIT HUP INT TERM
ARCHIVE_NAME="herdogrelay-$ARCHIVE_OS-$ARCHIVE_ARCH.tar.gz"
RELEASE_BASE="https://github.com/$REPOSITORY/releases/download/$RELEASE_VERSION"
ARCHIVE_PATH="$TEMP_DIRECTORY/$ARCHIVE_NAME"
CHECKSUM_PATH="$TEMP_DIRECTORY/checksums.txt"

# Download only over HTTPS and fail on missing or partial release assets.
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "$RELEASE_BASE/$ARCHIVE_NAME" --output "$ARCHIVE_PATH" \
    || fail "could not download release $RELEASE_VERSION"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "$RELEASE_BASE/checksums.txt" --output "$CHECKSUM_PATH" \
    || fail "could not download release checksums"

# Compare the release checksum before extracting or replacing the installed binary.
EXPECTED_CHECKSUM=$(awk -v archive="$ARCHIVE_NAME" '$2 == archive { print $1; exit }' "$CHECKSUM_PATH")
[ -n "$EXPECTED_CHECKSUM" ] || fail "release checksum entry is missing"
if [ "$CHECKSUM_TOOL" = "sha256sum" ]; then
    ACTUAL_CHECKSUM=$(sha256sum "$ARCHIVE_PATH" | awk '{ print $1 }')
else
    ACTUAL_CHECKSUM=$(shasum -a 256 "$ARCHIVE_PATH" | awk '{ print $1 }')
fi
[ "$EXPECTED_CHECKSUM" = "$ACTUAL_CHECKSUM" ] || fail "release checksum does not match"

# Reject scripts and data files before any executable is installed or started.
validate_native_binary() {
    MAGIC=$(od -An -tx1 -N4 "$1" 2>/dev/null | tr -d ' \n') || fail "native executable header could not be read"
    case "$ARCHIVE_OS" in
        macos)
            case "$MAGIC" in
                feedface|feedfacf|cefaedfe|cffaedfe|cafebabe|cafebabf|bebafeca|bfbafeca) ;;
                *) fail "release does not contain a supported macOS executable" ;;
            esac
            ;;
        linux)
            [ "$MAGIC" = "7f454c46" ] || fail "release does not contain a supported Linux executable"
            ;;
    esac
}

# Run the fixed startup probe without allowing a downloaded process to outlive the installer.
probe_native_binary() {
    "$1" --version >/dev/null 2>&1 &
    PROBE_PID=$!
    PROBE_TICKS=0
    while kill -0 "$PROBE_PID" 2>/dev/null; do
        [ "$PROBE_TICKS" -lt 50 ] || {
            kill "$PROBE_PID" 2>/dev/null || :
            wait "$PROBE_PID" 2>/dev/null || :
            fail "release executable startup probe timed out"
        }
        sleep 0.1
        PROBE_TICKS=$((PROBE_TICKS + 1))
    done
    if ! wait "$PROBE_PID"; then
        fail "release executable startup probe failed"
    fi
}

# Extract the verified archive into a private temporary directory and require the expected file.
EXTRACT_DIRECTORY="$TEMP_DIRECTORY/extracted"
mkdir -m 700 "$EXTRACT_DIRECTORY"
# Reject archives containing paths, links or files other than the one executable.
ARCHIVE_ENTRIES=$(tar -tzf "$ARCHIVE_PATH") || fail "release archive is invalid"
[ "$ARCHIVE_ENTRIES" = "herdogrelay" ] || fail "release archive contains unexpected entries"
ARCHIVE_TYPES=$(tar -tvzf "$ARCHIVE_PATH") || fail "release archive metadata is invalid"
printf '%s\n' "$ARCHIVE_TYPES" | awk 'NF && substr($1, 1, 1) == "-" && $NF == "herdogrelay" { count++ } END { exit !(count == 1) }' || fail "release archive entry is not a regular executable"
tar -xzf "$ARCHIVE_PATH" --no-same-owner --no-same-permissions -C "$EXTRACT_DIRECTORY"
[ -f "$EXTRACT_DIRECTORY/herdogrelay" ] || fail "release archive has no herdogrelay binary"
validate_native_binary "$EXTRACT_DIRECTORY/herdogrelay"
probe_native_binary "$EXTRACT_DIRECTORY/herdogrelay"

# Create the destination only when needed, preserving an existing custom directory mode.
if [ ! -d "$INSTALL_DIRECTORY" ]; then
    mkdir -p "$INSTALL_DIRECTORY"
    chmod 755 "$INSTALL_DIRECTORY"
fi
INSTALL_PATH="$INSTALL_DIRECTORY/herdogrelay"
BACKUP_PATH="$TEMP_DIRECTORY/previous-herdogrelay"
HAD_PREVIOUS_BINARY=0
INSTALL_STARTED=0
INSTALL_COMPLETED=0
if [ -L "$INSTALL_PATH" ] 2>/dev/null || [ -h "$INSTALL_PATH" ] 2>/dev/null; then
    fail "installation destination must not be a symlink"
fi
if [ -e "$INSTALL_PATH" ]; then
    [ -f "$INSTALL_PATH" ] || fail "installation destination is not a regular file"
    cp "$INSTALL_PATH" "$BACKUP_PATH" || fail "existing Relay binary could not be backed up"
    chmod 755 "$BACKUP_PATH"
    HAD_PREVIOUS_BINARY=1
fi

# Restore the previous binary if installation or its post-install probe fails.
rollback_install() {
    if [ "$INSTALL_STARTED" -eq 1 ] && [ "$INSTALL_COMPLETED" -eq 0 ]; then
        if [ "$HAD_PREVIOUS_BINARY" -eq 1 ]; then
            if ! install -m 755 "$BACKUP_PATH" "$INSTALL_PATH"; then
                printf '%s\n' "herdogrelay installer: rollback failed; inspect the installation directory" >&2
            fi
        else
            rm -f "$INSTALL_PATH"
        fi
    fi
    rm -rf "$TEMP_DIRECTORY"
}
trap rollback_install EXIT HUP INT TERM

# Replace only after native-header and bounded startup checks have passed.
INSTALL_STARTED=1
install -m 755 "$EXTRACT_DIRECTORY/herdogrelay" "$INSTALL_PATH" || fail "Relay binary installation failed"
validate_native_binary "$INSTALL_PATH"
probe_native_binary "$INSTALL_PATH"
INSTALL_COMPLETED=1

# Report the stable install location and leave configuration untouched.
printf 'Installed herdogrelay %s to %s/herdogrelay\n' "$RELEASE_VERSION" "$INSTALL_DIRECTORY"
printf 'Create or review a config with: herdogrelay --print-default-config\n'
printf 'Run with: herdogrelay --config ~/.config/herdr-dog/relay.toml\n'
