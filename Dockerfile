# The security service as a container. Build context is the repository root.
FROM golang:1.26.9-alpine3.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/security ./cmd/security

FROM alpine:3.24.2
# a user with no shell and no home: the process owns nothing it does not need
RUN adduser -D -H -s /sbin/nologin -u 10001 security
COPY --from=build /out/security /usr/local/bin/security
USER 10001
EXPOSE 8086
# busybox wget ships with alpine; /health needs no token
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:8086/health || exit 1
ENTRYPOINT ["/usr/local/bin/security"]