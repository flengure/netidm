#!/bin/bash
set -x


if [ -z "${IMAGE}" ]; then
    IMAGE="netidm/radius:devel"
fi
echo "Running docker container: ${IMAGE}"

if [ ! -z "${IMAGE_ARCH}" ]; then
    IMAGE_ARCH="--platform ${IMAGE_ARCH}"
fi

if [ -z "${CONFIG_FILE}" ]; then
    CONFIG_FILE="$(pwd)/../examples/netidm"
fi
echo "Using config file: ${CONFIG_FILE}"

if [ ! -d "/tmp/netidm/" ]; then
	echo "Can't find /tmp/netidm - you may need to run run_insecure_dev_server"
fi

echo "Starting the dev container..."
#shellcheck disable=SC2068
docker run --rm -it \
    ${IMAGE_ARCH} \
    --network host \
    --name radiusd \
    -v /tmp/netidm/:/data/ \
    -v /tmp/netidm/:/tmp/netidm/ \
    -v /tmp/netidm/:/certs/ \
    -v "${CONFIG_FILE}:/data/netidm" \
    "${IMAGE}" $@
