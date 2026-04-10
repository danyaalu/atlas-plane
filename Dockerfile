# syntax=docker/dockerfile:1.7

FROM golang:1.24-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/atlas-plane .

FROM alpine:3.21 AS runtime
WORKDIR /app

RUN apk add --no-cache su-exec \
  && addgroup -S app && adduser -S app -G app \
  && mkdir -p /keys /auth \
  && chown -R app:app /app /keys /auth \
  && chmod 700 /keys /auth

COPY --from=build /out/atlas-plane /app/atlas-plane
COPY docker/backend/entrypoint.sh /app/entrypoint.sh
RUN chmod 755 /app/entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/app/atlas-plane", "serve"]
