"""test validation of urls"""

import pytest

from netidm import NetidmClient


def test_bad_origin() -> None:
    """testing with a bad origin"""

    client = NetidmClient(uri="http://localhost:8000")

    with pytest.raises(ValueError):
        client._validate_is_valid_origin_url("ftp://example.com")
