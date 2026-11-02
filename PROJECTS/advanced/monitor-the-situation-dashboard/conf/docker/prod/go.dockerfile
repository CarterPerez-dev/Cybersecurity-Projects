# ©AngelaMos | 2026
# go.dockerfile

FROM golang:1.25-bookworm AS builder

WORKDIR /build

COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ .

RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" -o /app ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /app /app
COPY --from=builder /build/migrations /migrations
COPY --from=builder /build/config.yaml /config.yaml

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/app", "-config", "/config.yaml"]
