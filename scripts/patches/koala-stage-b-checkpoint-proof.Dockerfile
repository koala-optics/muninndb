# Builds only the standalone Stage B checkpoint verifier. Remote inputs are
# owner-published and checksum-pinned; the runtime preserves the exact qualified
# production baseline image and its existing muninndb-server binary.
FROM debian:bookworm-slim@sha256:63a496b5d3b99214b39f5ed70eb71a61e590a77979c79cbee4faf991f8c0783e AS builder

ARG GO_ARCHIVE_URL=https://go.dev/dl/go1.26.6.linux-amd64.tar.gz
ARG GO_ARCHIVE_SHA256=708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89
ARG BASELINE_BINARY_SHA256
ARG HELPER_SOURCE_COMMIT

ENV PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin \
    GOTOOLCHAIN=local \
    CGO_ENABLED=0
WORKDIR /src

RUN set -eux; \
    apt-get update; \
    apt-get install --yes --no-install-recommends ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*; \
    curl --fail --location --silent --show-error "$GO_ARCHIVE_URL" -o /tmp/go.tar.gz; \
    printf '%s  %s\n' "$GO_ARCHIVE_SHA256" /tmp/go.tar.gz | sha256sum --check --strict; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm /tmp/go.tar.gz; \
    go version | grep -Fx 'go version go1.26.6 linux/amd64'

COPY go.mod go.sum ./
RUN go mod download
COPY cmd/koala-stage-b-checkpoint-proof/ ./cmd/koala-stage-b-checkpoint-proof/
RUN --network=none test -n "$BASELINE_BINARY_SHA256"; \
    test -n "$HELPER_SOURCE_COMMIT"; \
    go test -mod=readonly ./cmd/koala-stage-b-checkpoint-proof; \
    go build -mod=readonly -trimpath \
      -ldflags="-s -w -X main.baselineBinarySHA256=$BASELINE_BINARY_SHA256 -X main.helperSourceCommit=$HELPER_SOURCE_COMMIT" \
      -o /koala-stage-b-checkpoint-proof ./cmd/koala-stage-b-checkpoint-proof; \
    test "$(stat -c '%a' /koala-stage-b-checkpoint-proof)" = 755

FROM registry.fly.io/koala-muninndb@sha256:1c9d9581f06d075aba948581f90451004d010d4e2623573fad8e87c58341f4d2
ARG BASELINE_BINARY_SHA256
RUN test "$(sha256sum /usr/local/bin/muninndb-server | awk '{print $1}')" = "$BASELINE_BINARY_SHA256"
COPY --from=builder /koala-stage-b-checkpoint-proof /usr/local/bin/koala-stage-b-checkpoint-proof
ENTRYPOINT ["koala-stage-b-checkpoint-proof"]
