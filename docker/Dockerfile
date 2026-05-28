FROM rust:1-alpine AS builder

WORKDIR /app

RUN apk add --no-cache build-base ca-certificates pkgconf

COPY Cargo.toml Cargo.lock rust-toolchain.toml build.rs ./
COPY proto ./proto
COPY src ./src
COPY tests ./tests
COPY examples ./examples

RUN cargo build --release --bin mumblersd

FROM alpine:3.20

RUN apk add --no-cache ca-certificates
RUN addgroup -S -g 1000 mumblers \
    && adduser -S -D -H -u 1000 -G mumblers mumblers

WORKDIR /data

ENV MUMBLERS_CONFIG=/data/mumblers.toml
ENV MUMBLERS_CERT_PATH=/data/certs/mumblers.crt
ENV MUMBLE_BIND_HOST=0.0.0.0
ENV MUMBLE_BIND_PORT=64738
ENV MUMBLE_UDP_BIND_PORT=64738
ENV MUMBLE_SERVER_NAME=mumblers
ENV MUMBLE_ALLOW_ANONYMOUS=true

RUN mkdir -p /data/certs \
    && chown -R mumblers:mumblers /data

COPY --from=builder /app/target/release/mumblersd /usr/local/bin/mumblersd
COPY docker/docker-entrypoint.sh /usr/local/bin/mumblers-entrypoint

RUN chmod +x /usr/local/bin/mumblers-entrypoint

EXPOSE 64738/tcp 64738/udp

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD /bin/busybox nc -z 127.0.0.1 64738 || exit 1

USER mumblers

ENTRYPOINT ["/usr/local/bin/mumblers-entrypoint"]
CMD ["serve"]
