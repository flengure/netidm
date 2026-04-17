# Installing Client Tools

> [!NOTE]
>
> Running different release versions will likely present incompatibilities. Ensure you're running matching release
> versions of client and server binaries. If you have any issues, check that you are running the latest version of
> Netidm.

## From packages

Netidm currently is packaged for the following systems:

- OpenSUSE Tumbleweed
- OpenSUSE Leap 15.6 / SUSE Linux Enterprise 15.7
- macOS
- Arch Linux
- CentOS Stream 9
- Debian
- Fedora 38
- NixOS
- Ubuntu
- Alpine Linux
- FreeBSD

The `netidm` client has been built and tested from Windows, but is not (yet) packaged routinely.

### OpenSUSE Tumbleweed / Leap 15.6 / SLE 15.7

Netidm is available in Tumbleweed, Leap 15.6, and SLE 15.7. You can install the clients with:

```bash
zypper ref
zypper in netidm-clients
```

> NOTE Leap 16.0 / SLE 16.0 are not yet supported.

### FreeBSD

The netidm client is available through ports or packages. The port is named `security/netidm`.

```
pkg install netidm-client
```

### macOS - Homebrew

[Netidm provides a Homebrew cask](https://github.com/netidm/homebrew-netidm), which lets [Homebrew](https://brew.sh/)
build and install the CLI client tools from source:

```bash
brew tap netidm/netidm
brew install netidm
```

> [!TIP]
>
> **Rust developers:** this formula will install a Rust toolchain with Homebrew, and add it to your `PATH`. _This may
> interfere with any Rust toolchain you've installed with [`rustup`](https://rustup.rs/)._
>
> You can unlink Homebrew's Rust toolchain (removing it from your `PATH`) with:
>
> ```sh
> brew unlink rust
> ```
>
> Homebrew will always use its version of Rust when building Rust packages, even when it is unlinked.
>
> Alternatively, you may wish to [install the Netidm CLI with `cargo`](#cargo) instead – this will use whatever Rust
> toochain you've already installed.

### Arch Linux

[Netidm on AUR](https://aur.archlinux.org/packages?O=0&K=netidm)

### Fedora / Centos Stream

> [!NOTE]
>
> Netidm frequently uses new Rust versions and features, however Fedora and CentOS frequently are behind in Rust
> releases. As a result, they may not always have the latest Netidm versions available.

Fedora has limited support through the development repository. You need to add the repository metadata into the correct
directory:

```bash
# Fedora
wget https://download.opensuse.org/repositories/network:/idm/Fedora_$(rpm -E %fedora)/network:idm.repo
# Centos Stream
wget https://download.opensuse.org/repositories/network:/idm/CentOS_$(rpm -E %rhel)_Stream/network:idm.repo
```

You can then install with:

```bash
dnf install netidm-clients
```

### NixOS

[Netidm in NixOS](https://search.nixos.org/packages?sort=relevance&type=packages&query=netidm)

### Ubuntu and Debian

See <https://netidm.github.io/netidm_ppa/> for nightly-built packages of the current development builds, and how to
install them.

## Alpine Linux

Netidm is available in the [Alpine Linux testing repository](https://pkgs.alpinelinux.org/packages?name=netidm%2A).

To install the Netidm client use:

```bash
apk add netidm-clients
```

## Tools Container

In some cases if your distribution does not have native netidm-client support, and you can't access cargo for the
install for some reason, you can use the cli tools from a docker container instead.

This is a "last resort" and we don't really recommend this for day to day usage.

```bash
echo '{}' > ~/.cache/netidm_tokens
chmod 666 ~/.cache/netidm_tokens
docker pull netidm/tools:latest
docker run --rm -i -t \
    --network host \
    --mount "type=bind,src=/etc/netidm/config,target=/data/config:ro" \
    --mount "type=bind,src=$HOME/.config/netidm,target=/root/.config/netidm" \
    --mount "type=bind,src=$HOME/.cache/netidm_tokens,target=/root/.cache/netidm_tokens" \
    netidm/tools:latest \
    /sbin/netidm --help
```

If you have a ca.pem you may need to bind mount this in as required as well.

> [!TIP]
>
> You can alias the docker run command to make the tools easier to access such as:

```bash
alias netidm="docker run ..."
```

## Cargo

The tools are available as a cargo download if you have a rust tool chain available. To install rust you should follow
the documentation for [rustup](https://rustup.rs/). These will be installed into your home directory. To update these,
re-run the install command. You will likely need to install additional development libraries, specified in the
[Developer Guide](developers/).

```bash
cargo install netidm_tools --locked
```
