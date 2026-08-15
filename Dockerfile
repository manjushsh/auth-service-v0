FROM golang:1.26-alpine AS dev

WORKDIR /app

RUN go install github.com/air-verse/air@latest

COPY go.mod go.sum ./
RUN go mod download

CMD ["air", "-c", ".air.docker.toml"]

FROM golang:1.26-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/server ./cmd/server
# adminctl ships alongside the server: promoting the first admin needs database
# access, so it has to be runnable where the database is reachable — which in a
# container deployment is here and nowhere else.
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/adminctl ./cmd/adminctl

FROM alpine:3.23 AS prod

# Binaries live outside /app deliberately. The dev target bind-mounts the source
# tree over /app, so anything installed there is invisible the moment the two
# get mixed up — which is exactly how a stale prod image plus a dev compose file
# produces "stat ./server: no such file or directory".
COPY --from=builder /out/server /usr/local/bin/server
COPY --from=builder /out/adminctl /usr/local/bin/adminctl

# Nothing here writes to disk, so it has no reason to run as root.
RUN adduser -D -u 10001 app
USER app

EXPOSE 8080
# Admin plane, when ADMIN_API_ENABLED=true. Reachable only if ADMIN_BIND_ADDR is
# widened past loopback — inside a container, loopback means this container.
EXPOSE 8081

CMD ["server"]
