# ©AngelaMos | 2026
# Dockerfile

FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /out/khaos-range ./cmd/khaos-range

FROM alpine:3.22

RUN adduser -D -u 10001 range
COPY --from=build /out/khaos-range /usr/local/bin/khaos-range

USER range
ENTRYPOINT ["/usr/local/bin/khaos-range"]
