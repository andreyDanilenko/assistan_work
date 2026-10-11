#!/bin/sh
# Сборка четырех переносимых комплектов без личных настроек и реальных логов.
set -eu
cd "$(dirname "$0")/.."

for target in darwin-arm64 darwin-amd64 linux-amd64 windows-amd64; do
    target_os=${target%-*}
    target_arch=${target#*-}
    executable=lokictl
    if [ "$target_os" = windows ]; then executable=lokictl.exe; fi

    bundle="dist/$target"
    mkdir -p "$bundle/examples"
    env GOOS="$target_os" GOARCH="$target_arch" CGO_ENABLED=0 \
        go build -trimpath -o "$bundle/$executable" ./cmd/lokictl
    cp .env.example QUICKSTART.md THIRD_PARTY_NOTICES.txt "$bundle/"
    cp examples/orders-analysis.txt "$bundle/examples/"
    set -- "$executable" .env.example QUICKSTART.md THIRD_PARTY_NOTICES.txt examples/orders-analysis.txt
    if [ -f examples/data.json ]; then
        cp examples/data.json "$bundle/examples/"
        set -- "$@" examples/data.json
    fi

    # Передаем zip только перечисленные файлы, без личного .env или базы.
    archive="lokictl-$target.zip"
    rm -f "dist/$archive"
    (cd "$bundle" && zip -q "../$archive" "$@")
done

(cd dist && shasum -a 256 lokictl-*.zip > SHA256SUMS)
printf 'Готово: dist/lokictl-*.zip и dist/SHA256SUMS\n'
