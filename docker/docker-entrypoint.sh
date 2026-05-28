#!/bin/sh
set -eu

CONFIG_PATH="${MUMBLERS_CONFIG:-/data/mumblers.toml}"
CERT_PATH="${MUMBLERS_CERT_PATH:-/data/certs/mumblers.crt}"
KEY_PATH="${MUMBLERS_KEY_PATH:-/data/certs/mumblers.key}"

if [ "$#" -eq 0 ]; then
  set -- serve
fi

ensure_config() {
  if [ ! -f "$CONFIG_PATH" ]; then
    mkdir -p "$(dirname "$CONFIG_PATH")"
    mumblersd config --path "$CONFIG_PATH" --init
  fi
}

apply_config_overrides() {
  if [ -n "${MUMBLE_BIND_HOST:-}" ]; then
    sed -i "s|^bind_host = .*|bind_host = \"${MUMBLE_BIND_HOST}\"|" "$CONFIG_PATH"
  fi
  if [ -n "${MUMBLE_BIND_PORT:-}" ]; then
    sed -i "s|^bind_port = .*|bind_port = ${MUMBLE_BIND_PORT}|" "$CONFIG_PATH"
  fi
  if [ -n "${MUMBLE_UDP_BIND_PORT:-}" ]; then
    sed -i "s|^udp_bind_port = .*|udp_bind_port = ${MUMBLE_UDP_BIND_PORT}|" "$CONFIG_PATH"
  fi
}

case "$1" in
  config)
    exec mumblersd "$@"
    ;;
  serve)
    ensure_config
    apply_config_overrides
    if [ "$#" -eq 1 ]; then
      exec mumblersd serve --config "$CONFIG_PATH"
    fi
    exec mumblersd "$@"
    ;;
  *)
    exec mumblersd "$@"
    ;;
esac
