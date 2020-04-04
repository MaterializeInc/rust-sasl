#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"

if [[ $# -ne 1 ]]; then
    echo "fatal: usage: $0 VERSION" >&2
    exit 1
fi

version=$1

set -x
for ext in tar.gz tar.gz.sig; do
    curl -fsSL "https://github.com/cyrusimap/cyrus-sasl/releases/download/cyrus-sasl-$version/cyrus-sasl-$version.$ext" > "sasl2.$ext"
done

gpg --verify sasl2.tar.gz.sig sasl2.tar.gz

rm -rf sasl2
mkdir -p sasl2
tar --strip-components=1 -C sasl2 -xf sasl2.tar.gz
find sasl2 -name .gitignore -delete

rm sasl2.tar.gz sasl2.tar.gz.sig
