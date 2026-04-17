"""tests the check_vlan function"""

import asyncio
from typing import Any

import pytest

from netidm import NetidmClient
from netidm.types import NetidmClientConfig, RadiusTokenGroup

from netidm.radius.utils import check_vlan


@pytest.mark.asyncio
async def test_check_vlan() -> None:
    """test 1"""

    # event_loop = asyncio.get_running_loop()

    testconfig = NetidmClientConfig.parse_toml(
        """
    uri='https://netidm.example.com'
    radius_groups = [
        { spn = "crabz@example.com", "vlan" = 1234 },
        { spn = "hello@world", "vlan" = 12345 },
    ]
    """
    )

    print(f"{testconfig=}")

    netidm_client = NetidmClient(
        config=testconfig,
    )
    print(f"{netidm_client.config=}")

    assert (
        check_vlan(
            acc=12345678,
            group=RadiusTokenGroup(spn="crabz@example.com", uuid="crabz"),
            netidm_client=netidm_client,
        )
        == 1234
    )

    assert (
        check_vlan(
            acc=12345678,
            group=RadiusTokenGroup(spn="foo@bar.com", uuid="lol"),
            netidm_client=netidm_client,
        )
        == 12345678
    )
