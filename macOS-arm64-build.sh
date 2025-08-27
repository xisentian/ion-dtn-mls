#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./examplebuild.sh             # build MLSpp if missing, then link demo
#   ./examplebuild.sh --build     # always build MLSpp before linking
#   ./examplebuild.sh --rebuild   # clean MLSpp build dir, then build and link
#   ./examplebuild.sh --clean     # clean everything, then build from scratch and link
#   ./examplebuild.sh --help      # show help

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  sed -n '2,12p' "$0"
  exit 0
fi

# Only run on arm64 macOS
if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
  echo "Skipping: requires arm64 macOS" >&2
  exit 1
fi

ACTION="${1:-}"

OPENSSL_PREFIX="$(brew --prefix openssl@3 2>/dev/null || true)"
if [ -z "${OPENSSL_PREFIX}" ]; then
  echo "Error: openssl@3 not found. Install with: brew install openssl@3" >&2
  exit 1
fi

MLS_ROOT="mlspp"
MLS_BUILD="$MLS_ROOT/build"

# --clean: remove all build artifacts first
if [ "$ACTION" = "--clean" ]; then
  echo "[info] Cleaning MLSpp build and demo artifacts..."
  rm -rf "$MLS_BUILD"
  rm -f mls_testing
  ACTION="--rebuild"
fi

need_build=false
# Trigger build if missing artifacts or user requested
if [ ! -f "$MLS_BUILD/libmlspp.a" ] || \
   [ ! -f "$MLS_BUILD/lib/hpke/libhpke.a" ] || \
   [ ! -f "$MLS_BUILD/lib/tls_syntax/libtls_syntax.a" ] || \
   [ ! -f "$MLS_BUILD/lib/bytes/libbytes.a" ] || \
   [ "$ACTION" = "--build" ] || [ "$ACTION" = "--rebuild" ]; then
  need_build=true
fi

if $need_build; then
  echo "[info] Preparing MLSpp build..."
  if [ "$ACTION" = "--rebuild" ] && [ -d "$MLS_BUILD" ]; then
    rm -rf "$MLS_BUILD"
  fi

  # Ensure submodules are present (if repo is a git clone)
  if [ -d "$MLS_ROOT/.git" ]; then
    git -C "$MLS_ROOT" submodule update --init --recursive
  fi

  echo "[info] Configuring MLSpp with CMake (Release, arm64)..."
  cmake -S "$MLS_ROOT" -B "$MLS_BUILD" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_ARCHITECTURES=arm64

  echo "[info] Building MLSpp..."
  CORES="$(sysctl -n hw.ncpu 2>/dev/null || echo 8)"
  cmake --build "$MLS_BUILD" -j"$CORES"
fi

echo "[info] Linking demo..."
g++ -std=c++17 -o mls_testing mls_testing.cpp \
  -Imlspp/include \
  -Imlspp/lib/bytes/include \
  -Imlspp/lib/tls_syntax/include \
  -Imlspp/lib/hpke/include \
  -Lmlspp/build \
  -Lmlspp/build/lib/bytes \
  -Lmlspp/build/lib/hpke \
  -Lmlspp/build/lib/tls_syntax \
  -L"${OPENSSL_PREFIX}/lib" \
  -Wl,-rpath,"${OPENSSL_PREFIX}/lib" \
  -lmlspp -lhpke -ltls_syntax -lbytes -lssl -lcrypto -v

echo "[ok] Built ./mls_testing"