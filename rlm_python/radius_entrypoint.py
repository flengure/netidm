"""entrypoint for netidm's RADIUS module"""

import atexit
import os
from pathlib import Path
import subprocess
import shutil
import signal
import sys
from typing import Any, Optional

# import toml
import netidm.radius
from netidm.radius import CONFIG_PATHS
from netidm.types import NetidmClientConfig
from netidm.utils import load_config

DEBUG = False
if os.environ.get("DEBUG", False):
    DEBUG = True

CERT_SERVER_DEST = "/etc/raddb/certs/server.pem"
CERT_CA_DEST = "/etc/raddb/certs/ca.pem"
CERT_CA_DIR = "/etc/raddb/certs/"
CERT_DH_DEST = "/etc/raddb/certs/dh.pem"


# pylint: disable=unused-argument
def _sigchild_handler(
    *args: Any,
    **kwargs: Any,
) -> None:
    """handler for SIGCHLD call"""
    print("Received SIGCHLD ...", file=sys.stderr)
    os.waitpid(-1, os.WNOHANG)


def write_clients_conf(
    netidm_config_object: NetidmClientConfig,
) -> None:
    """writes out the config file"""
    raddb_config_file = Path("/etc/raddb/clients.conf")

    with raddb_config_file.open("w", encoding="utf-8") as file_handle:
        for client in netidm_config_object.radius_clients:
            file_handle.write(f"client {client.name} {{\n")
            file_handle.write(f"    ipaddr = {client.ipaddr}\n")
            file_handle.write(f"    secret = {client.secret}\n")
            file_handle.write("    proto = *\n")
            file_handle.write("}\n")


def setup_certs(
    netidm_config_object: NetidmClientConfig,
) -> None:
    """sets up certificates"""

    if netidm_config_object.radius_ca_path:
        cert_ca = Path(netidm_config_object.radius_ca_path).expanduser().resolve()
        if not cert_ca.exists():
            print(
                f"Failed to find radiusd ca file ({cert_ca}), quitting!",
                file=sys.stderr,
            )
            sys.exit(1)
        if cert_ca != Path(CERT_CA_DEST):
            print(f"Copying {cert_ca} to {CERT_CA_DEST}")
            try:
                shutil.copyfile(cert_ca, CERT_CA_DEST)
            except shutil.SameFileError:
                pass

    # This dir can also contain crls!
    if netidm_config_object.radius_ca_dir:
        cert_ca_dir = Path(netidm_config_object.radius_ca_dir).expanduser().resolve()
        if not cert_ca_dir.exists():
            print(
                f"Failed to find radiusd ca dir ({cert_ca_dir}), quitting!",
                file=sys.stderr,
            )
            sys.exit(1)
        if cert_ca_dir != Path(CERT_CA_DIR):
            print(f"Copying {cert_ca_dir} to {CERT_CA_DIR}")
            shutil.copytree(cert_ca_dir, CERT_CA_DIR, dirs_exist_ok=True)

    # Setup the ca-dir correctly now. We do this before we add server.pem so that it's
    # not hashed as a ca.
    subprocess.check_call(["openssl", "rehash", CERT_CA_DIR])

    server_key = Path(netidm_config_object.radius_key_path).expanduser().resolve()
    if not server_key.exists() or not server_key.is_file():
        print(
            f"Failed to find server keyfile ({server_key}), quitting!",
            file=sys.stderr,
        )
        sys.exit(1)

    server_cert = Path(netidm_config_object.radius_cert_path).expanduser().resolve()
    if not server_cert.exists() or not server_cert.is_file():
        print(
            f"Failed to find server cert file ({server_cert}), quitting!",
            file=sys.stderr,
        )
        sys.exit(1)
    # concat key + cert into /etc/raddb/certs/server.pem
    with open(CERT_SERVER_DEST, "w", encoding="utf-8") as file_handle:
        file_handle.write(server_cert.read_text(encoding="utf-8"))
        file_handle.write("\n")
        file_handle.write(server_key.read_text(encoding="utf-8"))


def kill_radius(
    proc: subprocess.Popen[Any],
) -> None:
    """handler to kill the radius server once the script exits"""
    if proc is None:
        pass
    else:
        try:
            os.kill(proc.pid, signal.SIGTERM)
        except OSError:
            print("sever is already gone...", file=sys.stderr)
    print("Stopping radiusd ...", file=sys.stderr)
    # To make sure we really do shutdown, we actually re-block on the proc
    # again here to be sure it's done.

    proc.wait()


def find_freeradius_bin() -> Optional[str]:
    """finds the binary"""
    binary_paths = [
        "/usr/sbin/radiusd",
        "/usr/sbin/freeradius",
    ]
    for path in binary_paths:
        if Path(path).exists():
            return path
    lookedin = ", ".join(binary_paths)
    print(f"Failed to find FreeRADIUS binary, looked in {lookedin}")
    sys.exit(1)


def run_radiusd() -> None:
    """run the server"""

    if DEBUG:
        cmd_args = ["-X"]
    else:
        # NOTE: the python3 module for radiusd does not seem to work correctly
        # when multithreading is enabled, hence -t. See #4168 for details.
        cmd_args = ["-f", "-t", "-l", "stdout"]
    freeradius_bin = find_freeradius_bin()
    if freeradius_bin is None:
        print("Failed to find FreeRADIUS binary, quitting!", file=sys.stderr)
        sys.exit(1)
    else:
        with subprocess.Popen(
            [freeradius_bin] + cmd_args,
            stderr=subprocess.STDOUT,
        ) as proc:
            # print(proc, file=sys.stderr)
            atexit.register(kill_radius, proc)
            proc.wait()


if __name__ == "__main__":
    signal.signal(signal.SIGCHLD, _sigchild_handler)

    config_file = netidm.radius.find_radius_config_path()
    if config_file is None:
        print(
            f"Failed to find configuration file in ({CONFIG_PATHS}), quitting!",
            file=sys.stderr,
        )
        sys.exit(1)
    else:
        netidm_config = NetidmClientConfig.model_validate(load_config(config_file))
        setup_certs(netidm_config)
        write_clients_conf(netidm_config)
        print("Configuration set up, starting...")
        try:
            run_radiusd()
        except KeyboardInterrupt as ki:
            print(ki)
