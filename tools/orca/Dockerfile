# This builds the netidm CLI tools
ARG BASE_IMAGE=opensuse/tumbleweed:latest
# ARG BASE_IMAGE=opensuse/leap:15.5

FROM ${BASE_IMAGE} AS repos
ADD ../../scripts/zypper_fixing.sh /zypper_fixing.sh
RUN --mount=type=cache,id=zypp,target=/var/cache/zypp /zypper_fixing.sh

FROM repos AS builder
ARG NETIDM_FEATURES
ARG NETIDM_BUILD_PROFILE
ARG NETIDM_BUILD_OPTIONS=""

# Set the build profile
ENV NETIDM_BUILD_PROFILE=${NETIDM_BUILD_PROFILE:-container_generic}
ENV RUSTFLAGS="-Clinker=clang"

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper install -y --no-recommends \
        sccache \
        cargo \
        clang \
        gcc \
        make \
        automake \
        autoconf \
        pam-devel \
        libudev-devel \
        sqlite3-devel \
        rsync

COPY . /usr/src/netidm

WORKDIR /usr/src/netidm/

# build the CLI
RUN \
    --mount=type=cache,id=cargo,target=/cargo \
    --mount=type=cache,id=sccache,target=/sccache \
    export CARGO_HOME=/cargo; \
    export SCCACHE_DIR=/sccache; \
    export RUSTC_WRAPPER=/usr/bin/sccache; \
    export CC="/usr/bin/clang"; \
    cargo build --locked -p orca ${NETIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/netidm/target/" \
        --features="${NETIDM_FEATURES}" \
        --release && \
    cargo install \
        --git https://github.com/netidm/webauthn-rs.git \
        --rev 5f4db4172f8e22aedc68c282d177e98db2b1892f \
        --force fido-mds-tool \
        --target-dir="/usr/src/netidm/target/" && \
    sccache -s

# == Construct the orca container
FROM repos

ENV RUST_BACKTRACE=1

COPY --from=builder /usr/src/netidm/target/release/orca /sbin/
COPY ./tools/orca/profile-sample.toml /etc/netidm/profile-sample.toml

RUN chmod +x /sbin/orca


CMD [ "/sbin/orca", "-h" ]

