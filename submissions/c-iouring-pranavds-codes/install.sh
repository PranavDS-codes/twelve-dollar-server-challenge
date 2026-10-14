#!/usr/bin/env bash
# Runs once as root on a clean Ubuntu 24.04: compiler, liburing and OpenSSL headers from apt.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends build-essential curl ca-certificates \
  liburing-dev=2.5-1build1 libssl-dev
gcc --version | head -1
