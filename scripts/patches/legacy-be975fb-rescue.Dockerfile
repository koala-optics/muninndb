# Exact-source rollback-rescue build. Every remote input is immutable or hash-checked.
FROM node:20-bookworm-slim@sha256:3d0f05455dea2c82e2f76e7e2543964c30f6b7d673fc1a83286736d44fe4c41c AS web-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN --network=none npm run build

FROM golang:1.25-bookworm@sha256:eecd15e52d06149b84ac1caa56cfd07f584da6803e5621a77024f38827f342ec AS builder
ENV GOTOOLCHAIN=local
WORKDIR /src

ARG MODEL_URL=https://huggingface.co/Xenova/bge-small-en-v1.5/resolve/ea104dacec62c0de699686887e3f920caeb4f3e3/onnx/model_int8.onnx
ARG MODEL_SHA256=bf64d05457cb391fa88d045faf5927a15ea36d96228ddf23ea970087afdc1197
ARG TOKENIZER_URL=https://huggingface.co/BAAI/bge-small-en-v1.5/resolve/5c38ec7c405ec4b44b94cc5a9bb96e735b38267a/tokenizer.json
ARG TOKENIZER_SHA256=d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66
ARG ORT_URL=https://github.com/microsoft/onnxruntime/releases/download/v1.24.2/onnxruntime-linux-x64-1.24.2.tgz
ARG ORT_SHA256=43725474ba5663642e17684717946693850e2005efbd724ac72da278fead25e6

COPY . .
COPY --from=web-builder /src/web/static/dist/ web/static/dist/

RUN set -eux; \
    asset_dir=internal/plugin/embed/assets; \
    mkdir -p "$asset_dir"; \
    curl --fail --location --silent --show-error "$MODEL_URL" -o "$asset_dir/model_int8.onnx"; \
    printf '%s  %s\n' "$MODEL_SHA256" "$asset_dir/model_int8.onnx" | sha256sum --check --strict; \
    curl --fail --location --silent --show-error "$TOKENIZER_URL" -o "$asset_dir/tokenizer.json"; \
    printf '%s  %s\n' "$TOKENIZER_SHA256" "$asset_dir/tokenizer.json" | sha256sum --check --strict; \
    curl --fail --location --silent --show-error "$ORT_URL" -o /tmp/onnxruntime-linux-x64.tgz; \
    printf '%s  %s\n' "$ORT_SHA256" /tmp/onnxruntime-linux-x64.tgz | sha256sum --check --strict; \
    tar -xzf /tmp/onnxruntime-linux-x64.tgz -C /tmp \
      onnxruntime-linux-x64-1.24.2/lib/libonnxruntime.so.1.24.2; \
    cp /tmp/onnxruntime-linux-x64-1.24.2/lib/libonnxruntime.so.1.24.2 \
      "$asset_dir/libonnxruntime_linux_amd64.so"; \
    rm -rf /tmp/onnxruntime-linux-x64.tgz /tmp/onnxruntime-linux-x64-1.24.2

RUN go mod download
RUN --network=none go build -mod=readonly -tags localassets -ldflags="-s -w" \
    -o /muninndb-server ./cmd/muninn/...

FROM debian:bookworm-slim@sha256:63a496b5d3b99214b39f5ed70eb71a61e590a77979c79cbee4faf991f8c0783e
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /muninndb-server /usr/local/bin/muninndb-server
VOLUME ["/data"]
EXPOSE 8474 8475 8476 8477 8750
ENTRYPOINT ["muninndb-server"]
CMD ["--daemon", "--data", "/data"]
