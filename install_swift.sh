#!/usr/bin/env bash
# Install Swift from swift.org (Swift is not packaged in apt).
#
# Usage: install_swift.sh [version]
#   (no arg) or "6" -> latest supported 6.x   |   "5" -> latest 5.x
#   a full version like "6.0.3" is used as given
#
# Referenced from supported_deps.json as the "swift" install-cmd. Output goes to
# stdout/stderr; install_app.sh captures and timestamps it into setup.log.

set -e

V="${1:-}"
[ -z "$V" ] && V=6.0.3
[ "$V" = 6 ] && V=6.0.3
[ "$V" = 5 ] && V=5.10.1

ARCH=$(dpkg --print-architecture)
if [ "$ARCH" = arm64 ]; then
    SUFFIX=-aarch64
    PLATFORM=ubuntu2404-aarch64
else
    SUFFIX=
    PLATFORM=ubuntu2404
fi

echo "Installing Swift $V ($ARCH)"
apt-get install -y \
    binutils libc6-dev libcurl4-openssl-dev libedit2 libpython3-dev \
    libsqlite3-0 libxml2-dev libz3-dev pkg-config unzip zlib1g-dev

TAG="swift-$V-RELEASE"
URL="https://download.swift.org/swift-$V-release/$PLATFORM/$TAG/$TAG-ubuntu24.04$SUFFIX.tar.gz"

curl -fSL "$URL" -o /tmp/swift.tar.gz
mkdir -p /opt/swift
tar xzf /tmp/swift.tar.gz -C /opt/swift --strip-components=2
ln -sf /opt/swift/bin/swift /usr/local/bin/swift
ln -sf /opt/swift/bin/swiftc /usr/local/bin/swiftc
echo 'export PATH=/opt/swift/bin:$PATH' > /etc/profile.d/swift.sh
rm -f /tmp/swift.tar.gz

echo "Swift $V installed"
