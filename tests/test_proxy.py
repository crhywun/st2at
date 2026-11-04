import re

import pytest

from st2at.client import ST2ATClient
from st2at.proxy import parse_proxy, prepare_proxy

RAW = (
    "us.rrp.example.test:10000:"
    "USER1-zone-custom-region-JP-session-abc123-sessTime-5:secret"
)


def test_parses_bestgo_style_raw_proxy():
    spec = parse_proxy(RAW)
    assert spec.host == "us.rrp.example.test"
    assert spec.port == 10000
    assert spec.region == "JP"
    assert spec.session == "abc123"
    assert spec.sess_time == 5
    assert spec.scheme == "socks5h"


def test_prepare_rotates_session_but_keeps_region_and_sess_time():
    first = prepare_proxy(RAW)
    second = prepare_proxy(RAW)
    assert first != second
    assert "region-JP" in first
    assert "region-JP" in second
    assert "-sessTime-5" in first
    assert "-sessTime-5" in second
    assert first.startswith("socks5h://")


def test_region_override_rewrites_country_code():
    prepared = prepare_proxy(RAW, region="US")
    assert "region-US" in prepared
    assert "region-JP" not in prepared


def test_static_http_proxy_is_unchanged():
    value = "http://127.0.0.1:8080"
    assert prepare_proxy(value) == value


def test_invalid_proxy_raises():
    with pytest.raises(ValueError):
        prepare_proxy("not-a-proxy")


class FakeResponse:
    status_code = 200

    @staticmethod
    def json():
        return {"accessToken": "x.y.z"}


class FakeSession:
    def __init__(self):
        self.calls = 0

    async def get(self, url, headers):
        self.calls += 1
        return FakeResponse()

    async def close(self):
        pass


class FakeFactory:
    def __init__(self):
        self.proxies = []

    def __call__(self, **kwargs):
        self.proxies.append(kwargs["proxy"])
        return FakeSession()


@pytest.mark.asyncio
async def test_client_uses_new_proxy_session_for_each_refresh():
    factory = FakeFactory()
    client = ST2ATClient(proxy=RAW, proxy_region="JP", session_factory=factory)

    await client.refresh("st-one")
    await client.refresh("st-two")

    assert len(factory.proxies) == 2
    sessions = [
        re.search(r"-session-([A-Za-z0-9]+)-", p).group(1) for p in factory.proxies
    ]
    assert sessions[0] != sessions[1]
    assert all("region-JP" in p for p in factory.proxies)


def test_session_inserted_before_sesstime_when_missing():
    raw = "proxy.example:10000:user-region-JP-sessTime-5:secret"
    prepared = prepare_proxy(raw, session="fixed")
    assert "-session-fixed-sessTime-5" in prepared


def test_no_auth_proxy_gets_no_synthetic_credentials():
    prepared = prepare_proxy("127.0.0.1:1080")
    assert prepared == "socks5h://127.0.0.1:1080"
