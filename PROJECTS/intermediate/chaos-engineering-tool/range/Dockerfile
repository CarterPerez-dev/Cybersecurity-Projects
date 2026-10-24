# ©AngelaMos | 2026
# Dockerfile

FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY bundle.go ./
COPY range ./range
RUN CGO_ENABLED=0 go build -trimpath -o /out/khaos-range ./cmd/khaos-range

FROM alpine:3.22

RUN adduser -D -u 10001 range
COPY --from=build /out/khaos-range /usr/local/bin/khaos-range

# The secret the HMAC fixture verifies with, baked at BUILD time so a fresh
# named volume is seeded from the image when it is first mounted. That is what
# lets the fixture mount it READ-ONLY, which is how secrets are conventionally
# delivered and the shape khaos's archive-API route cannot write at all - the
# mutator container mounting the same volume read-write is the only route to
# it. Not a secret in any real sense: this range exists to be broken.
RUN mkdir -p /run/khaos-secrets \
    && head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' \
        > /run/khaos-secrets/hmac \
    && chown -R range:range /run/khaos-secrets \
    && chmod 0400 /run/khaos-secrets/hmac

USER range
ENTRYPOINT ["/usr/local/bin/khaos-range"]
