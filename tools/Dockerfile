# This builds the netidm CLI tools
ARG BASE_IMAGE=opensuse/tumbleweed:latest
# ARG BASE_IMAGE=opensuse/leap:15.5

FROM ${BASE_IMAGE} AS repos
ADD ../scripts/zypper_fixing.sh /zypper_fixing.sh
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
        cargo-auditable \
        clang \
        gcc \
        make \
        automake \
        autoconf \
        pam-devel \
        libudev-devel \
        sqlite3-devel \
        xmlsec1-devel \
        xmlsec1-openssl-devel \
        libxml2-devel \
        pkgconf-pkg-config \
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
    cargo auditable build --locked -p netidm_tools ${NETIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/netidm/target/" \
        --features="${NETIDM_FEATURES}" \
        --release && \
    cargo auditable build --locked -p netidm-ipa-sync ${NETIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/netidm/target/" \
        --features="${NETIDM_FEATURES}" \
        --release && \
    cargo auditable build --locked -p netidm-ldap-sync ${NETIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/netidm/target/" \
        --features="${NETIDM_FEATURES}" \
        --release && \
    cargo auditable build --locked -p netidm-mail-sender ${NETIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/netidm/target/" \
        --features="${NETIDM_FEATURES}" \
        --release && \
    cargo auditable install \
        --git https://github.com/kanidm/webauthn-rs.git \
        --rev 2ac5ff0e20f323cd904856a38a15899adf13fa5b \
        --force fido-mds-tool \
        --target-dir="/usr/src/netidm/target/" && \
    sccache -s

# == Construct the tools container
FROM repos

ENV RUST_BACKTRACE=1

RUN \
    --mount=type=cache,id=zypp,target=/var/cache/zypp \
    zypper install -y \
        timezone \
        openssl-3

COPY --from=builder /usr/src/netidm/target/release/netidm /sbin/
COPY --from=builder /usr/src/netidm/target/release/netidm-ipa-sync /sbin/
COPY --from=builder /usr/src/netidm/target/release/netidm-ldap-sync /sbin/
COPY --from=builder /usr/src/netidm/target/release/fido-mds-tool /sbin/
RUN chmod +x /sbin/netidm
RUN chmod +x /sbin/netidm-ipa-sync
RUN chmod +x /sbin/netidm-ldap-sync
RUN chmod +x /sbin/fido-mds-tool

RUN mkdir /etc/netidm && \
    touch /etc/netidm/config

CMD [ "/sbin/netidm", "-h" ]
