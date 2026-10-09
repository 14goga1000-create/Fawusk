#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p dist
go run github.com/tc-hib/go-winres@v0.3.3 make --arch amd64
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -H=windowsgui' -o dist/Fawusk-alpha-0.6.exe .
(cd dist && sha256sum Fawusk-alpha-0.6.exe > SHA256SUMS.txt)
echo 'Built dist/Fawusk-alpha-0.6.exe (unsigned alpha).'
