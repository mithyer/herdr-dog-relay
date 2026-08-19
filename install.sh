#!/bin/sh
# Install the pinned Herdr-dog Relay release into a user-owned bin directory.
set -eu

# GitHub repository containing the signed release archives.
REPOSITORY="${HERDRDOGRELAY_REPOSITORY:-mithyer/herdr-dog-relay}"
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
  HERDRDOGRELAY_REPOSITORY  GitHub owner/repository override.
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

# Restrict this release installer to the supported user-level macOS targets.
[ "$(uname -s)" = "Darwin" ] || fail "this release currently supports macOS only"
case "$(uname -m)" in
    arm64) ARCHIVE_ARCH="arm64" ;;
    x86_64) ARCHIVE_ARCH="x86_64" ;;
    *) fail "unsupported macOS architecture" ;;
esac

# Verify the small set of host tools required for HTTPS download and extraction.
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v shasum >/dev/null 2>&1 || fail "shasum is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
command -v install >/dev/null 2>&1 || fail "install is required"
command -v awk >/dev/null 2>&1 || fail "awk is required"

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
ARCHIVE_NAME="herdogrelay-macos-$ARCHIVE_ARCH.tar.gz"
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
ACTUAL_CHECKSUM=$(shasum -a 256 "$ARCHIVE_PATH" | awk '{ print $1 }')
[ "$EXPECTED_CHECKSUM" = "$ACTUAL_CHECKSUM" ] || fail "release checksum does not match"

# Extract the verified archive into a private temporary directory and require the expected file.
EXTRACT_DIRECTORY="$TEMP_DIRECTORY/extracted"
mkdir -m 700 "$EXTRACT_DIRECTORY"
tar -xzf "$ARCHIVE_PATH" -C "$EXTRACT_DIRECTORY"
[ -f "$EXTRACT_DIRECTORY/herdogrelay" ] || fail "release archive has no herdogrelay binary"

# Create the destination only when needed, preserving an existing custom directory mode.
if [ ! -d "$INSTALL_DIRECTORY" ]; then
    mkdir -p "$INSTALL_DIRECTORY"
    chmod 755 "$INSTALL_DIRECTORY"
fi
install -m 755 "$EXTRACT_DIRECTORY/herdogrelay" "$INSTALL_DIRECTORY/herdogrelay"

# Report the stable install location and leave configuration untouched.
printf 'Installed herdogrelay %s to %s/herdogrelay\n' "$RELEASE_VERSION" "$INSTALL_DIRECTORY"
printf 'Create or review a config with: herdogrelay --print-default-config\n'
printf 'Run with: herdogrelay --config ~/.config/herdr-dog/relay.toml\n'
