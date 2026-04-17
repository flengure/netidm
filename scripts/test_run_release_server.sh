#!/bin/bash

# this script runs the server in release mode and tries to set up a dev environment, which catches failures between the
# server and CLI, and ensures clap/etc rules actually work
#
# you really really really really don't want to run this when an environment you like exists, it'll mess it up

set -e

WAIT_TIMER=5
if [ -z "${BUILD_MODE}" ]; then
    BUILD_MODE="--release"
fi

echo "Building release binaries..."
# shellcheck disable=SC2086
cargo build --locked $BUILD_MODE --bin netidm --bin netidmd --quiet || {
    echo "Failed to build release binaries, please check the output above."
    exit 1
}

if [ -d '.git' ]; then
    echo "You're in the root dir, let's move you!"
    CURRENT_DIR="$(pwd)"
    cd server/daemon/ || exit 1
fi


if [ ! -f "run_insecure_dev_server.sh" ]; then
    echo "I'm not sure where you are, please run this from the root of the repository or the server/daemon directory"
    exit 1
fi

export NETIDM_CONFIG="./insecure_server.toml"

mkdir -p /tmp/netidm/client_ca

echo "Generating certificates..."
# shellcheck disable=SC2086
cargo run --bin netidmd $BUILD_MODE cert-generate

echo "Making sure it runs with the DB..."
# shellcheck disable=SC2086
cargo run --bin netidmd $BUILD_MODE scripting recover-account idm_admin

echo "Running the server..."
# shellcheck disable=SC2086
cargo run --bin netidmd $BUILD_MODE server  &
NETIDMD_PID=$!
echo "Netidm PID: ${NETIDMD_PID}"

if [ "$(jobs -p | wc -l)" -eq 0 ]; then
    echo "Netidmd failed to start!"
    exit 1
fi

ATTEMPT=0

NETIDM_CONFIG_FILE="./insecure_server.toml"
if [ -f "${NETIDM_CONFIG_FILE}" ]; then
    echo "Found config file ${NETIDM_CONFIG_FILE}"
else
    echo "Config file ${NETIDM_CONFIG_FILE} not found!"
    exit 1
fi
NETIDM_URL="$(grep -E '^origin.*https' "${NETIDM_CONFIG_FILE}" | awk '{print $NF}' | tr -d '"')"
NETIDM_CA_PATH="/tmp/netidm/ca.pem"

while true; do
    echo "Waiting for the server to start... testing url '${NETIDM_URL}'"
    curl --cacert "${NETIDM_CA_PATH}" -f "${NETIDM_URL}/status" >/dev/null && break
    sleep 2
    ATTEMPT="$((ATTEMPT + 1))"
    if [ "${ATTEMPT}" -gt 3 ]; then
        echo "Netidmd failed to start!"
        exit 1
    fi
done

BUILD_MODE=$BUILD_MODE ../../scripts/setup_dev_environment.sh || kill -9 "${NETIDMD_PID}"


if [ -n "$CURRENT_DIR" ]; then
    cd "$CURRENT_DIR" || exit 1
fi

echo "Running the OpenAPI schema checks"

bash -c ./scripts/openapi_tests/check_openapi_spec.sh || exit 1

echo "Waiting ${WAIT_TIMER} seconds and terminating Netidmd"
sleep "${WAIT_TIMER}"
if [ "$(pgrep netidmd | wc -l)" -gt 0 ]; then
    kill $(pgrep netidmd)
fi
