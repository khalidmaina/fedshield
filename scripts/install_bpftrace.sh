#!/bin/bash
# Install the exact bpftrace the collector was verified with (decision 0007):
# the official statically linked v0.20.2 binary from bpftrace's GitHub releases.
# It does not depend on the distribution's libraries, so Ubuntu 22.04 and 24.04 run the same build.
# Usage:  ./scripts/install_bpftrace.sh        (asks for sudo to copy into /usr/local/bin)
set -euo pipefail
VERSION=v0.20.2
SHA256=44857efb90a4d3f7cb2495695c1b03b60736d3e286ba1f9cf1b8bc048f9e0adf
URL="https://github.com/bpftrace/bpftrace/releases/download/$VERSION/bpftrace"

if command -v bpftrace >/dev/null && [ "$(bpftrace --version 2>/dev/null)" = "bpftrace $VERSION" ]; then
  echo "bpftrace $VERSION is already installed at $(command -v bpftrace)"
  exit 0
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
echo "Downloading bpftrace $VERSION (about 160 MB)..."
curl -fL --progress-bar -o "$TMP" "$URL"
echo "$SHA256  $TMP" | sha256sum -c --quiet || { echo "Checksum mismatch: not installing." >&2; exit 1; }
sudo install -m 755 "$TMP" /usr/local/bin/bpftrace
echo "Installed: $(/usr/local/bin/bpftrace --version) at /usr/local/bin/bpftrace"
if [ "$(command -v bpftrace)" != /usr/local/bin/bpftrace ]; then
  echo "Note: another bpftrace comes first on your PATH: $(command -v bpftrace). Remove it (sudo apt remove bpftrace)."
fi
