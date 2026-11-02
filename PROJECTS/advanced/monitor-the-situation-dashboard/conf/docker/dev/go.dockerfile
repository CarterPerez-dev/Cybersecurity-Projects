# ©AngelaMos | 2026
# go.dockerfile

FROM golang:1.25-bookworm

WORKDIR /app

RUN go install github.com/air-verse/air@latest \
 && go install github.com/pressly/goose/v3/cmd/goose@latest

COPY backend/go.mod backend/go.sum ./
RUN go mod download

ENV GO_ENV=development \
    PATH=/go/bin:$PATH

EXPOSE 8080

CMD ["air", "-c", ".air.toml"]
