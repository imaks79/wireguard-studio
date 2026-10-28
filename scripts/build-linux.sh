#!/usr/bin/env bash
# Builds Linux release tarballs into dist/ inside Docker (works from macOS).
#   ./scripts/build-linux.sh              # x86_64 and aarch64
#   ./scripts/build-linux.sh x86_64       # just one
# Built on Debian bookworm, so it runs on glibc 2.36+ (Ubuntu 22.10+, Debian 12+).
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
ARCHES=("${@:-x86_64 aarch64}")
ARCHES=(${ARCHES[@]})
IMAGE="rust:1-bookworm"

mkdir -p dist

for ARCH in "${ARCHES[@]}"; do
  case "$ARCH" in
    x86_64)  PLATFORM=linux/amd64 ;;
    aarch64) PLATFORM=linux/arm64 ;;
    *) echo "unknown arch: $ARCH" >&2; exit 1 ;;
  esac

  echo "==> Building for linux-$ARCH ($PLATFORM)"
  docker run --rm --platform "$PLATFORM" \
    -v "$ROOT":/src -w /src \
    -v "wgstudio-cargo-$ARCH":/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR="/src/target/linux-$ARCH" \
    "$IMAGE" bash -euc '
      apt-get update -qq
      apt-get install -y -qq --no-install-recommends \
        pkg-config perl make libxkbcommon-dev libwayland-dev >/dev/null
      cargo build --release --locked -p wireguard-studio-gui
    '

  PKG="wireguard-studio-$VERSION-linux-$ARCH"
  STAGE="dist/$PKG"
  rm -rf "$STAGE"
  mkdir -p "$STAGE"
  cp "target/linux-$ARCH/release/wireguard-studio" "$STAGE/"
  cat > "$STAGE/wireguard-studio.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=WireGuard Studio
Comment=Build WireGuard configurations
Exec=wireguard-studio
Terminal=false
Categories=Network;Utility;
EOF
  cat > "$STAGE/README.txt" <<'EOF'
WireGuard Studio for Linux

Run:      ./wireguard-studio
Install:  sudo install -m755 wireguard-studio /usr/local/bin/
          install -Dm644 wireguard-studio.desktop ~/.local/share/applications/wireguard-studio.desktop

Needs a desktop session (X11 or Wayland) with OpenGL, plus libxkbcommon
(present on any standard desktop install). File dialogs use the XDG desktop
portal (xdg-desktop-portal), which GNOME/KDE ship by default.
EOF
  tar -C dist -czf "dist/$PKG.tar.gz" "$PKG"
  rm -rf "$STAGE"
  echo "Built: $ROOT/dist/$PKG.tar.gz"
done
