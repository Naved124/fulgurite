#!/usr/bin/env bash
# Installs what the M1 step 8 measurement needs on a fresh Ubuntu 24.04 server:
# the compilers corpus.sh uses, Rust, and Xvfb and xdotool for ida-export.sh,
# with the libraries IDA's Qt GUI loads. IDA Free itself is not here: install
# it from its .run file and copy the licence (see docs/progress/m1-step8.md).
#
#   tools/measure/setup-ubuntu.sh
set -eu

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential gcc-multilib g++-multilib clang lld llvm \
    libc6-dev-arm64-cross libgcc-13-dev-arm64-cross libstdc++-13-dev-arm64-cross \
    binutils-aarch64-linux-gnu \
    mingw-w64 golang-go \
    curl git unzip xz-utils perl pkg-config \
    xvfb xdotool x11-apps imagemagick \
    libgl1 libegl1 libglib2.0-0t64 libfontconfig1 libdbus-1-3 libxkbcommon-x11-0 \
    libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
    libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 libxcb-xkb1

if ! command -v cargo >/dev/null; then
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi

echo "done; open a new shell (or run: . ~/.cargo/env) so cargo is on PATH"
