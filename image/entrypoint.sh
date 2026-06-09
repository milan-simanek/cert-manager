#!/bin/sh
set -e

CERT_DIR="${CERT_DIR:-/certs}"

echo "[entrypoint] Ensuring ${CERT_DIR} is writable by certmgr and readable by certreaders…"
mkdir -p "${CERT_DIR}"
chown certmgr:certreaders "${CERT_DIR}"
chmod 750 "${CERT_DIR}"

if getent group docker >/dev/null
then
  echo "[entrypoint] Docker group already present."
elif [ -S /var/run/docker.sock ]
then
  DOCKER_GID=$(stat -c '%g' /var/run/docker.sock)
  groupadd -g "$DOCKER_GID" -U certmgr docker
  echo "[entrypoint] Docker group created."
else
  echo "[entrypoint] Docker socket not found. Restarting dependent container not posible."
fi

echo "[entrypoint] Dropping privileges, starting certmgr"
exec gosu certmgr "$@"
