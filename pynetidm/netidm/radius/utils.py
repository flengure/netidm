""" class utils """

from typing import Optional
import logging
import os

from .. import NetidmClient
from ..types import RadiusTokenGroup


def check_vlan(
    acc: int,
    group: RadiusTokenGroup,
    netidm_client: Optional[NetidmClient] = None,
) -> int:
    """checks if a vlan is in the config,

    acc is the default vlan
    """
    logging.debug("acc=%s", acc)
    if netidm_client is None:
        if "NETIDM_CONFIG_FILE" in os.environ:
            netidm_client = NetidmClient(config_file=os.environ["NETIDM_CONFIG_FILE"])
        else:
            raise ValueError("Need to pass this a netidm_client")

    for radius_group in netidm_client.config.radius_groups:
        logging.debug(
            "Checking vlan group '%s' against user group %s",
            radius_group.spn,
            group.spn,
        )
        if radius_group.spn == group.spn:
            logging.info("returning new vlan: %s", radius_group.vlan)
            return radius_group.vlan
    logging.debug("returning already set vlan: %s", acc)
    return acc
