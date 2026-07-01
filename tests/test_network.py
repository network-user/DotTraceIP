import re
import socket

import aiohttp
import dns.resolver
from aioresponses import aioresponses

import app.network as net
from app.network import NO_DATA

# Регекс-матчеры URL для aioresponses (совпадают независимо от query-строки).
IP_API_RE = re.compile(r"http://ip-api\.com/json/.*")
IP_API_PRO_RE = re.compile(r"https://pro\.ip-api\.com/json/.*")
BGPVIEW_RE = re.compile(r"https://api\.bgpview\.io/ip/.*")
ABUSEIPDB_RE = re.compile(r"https://api\.abuseipdb\.com/api/v2/check.*")


class _FakeTXT:
    """Имитация TXT-rdata dnspython (поле strings - кортеж bytes)."""

    def __init__(self, text: str) -> None:
        self.strings = (text.encode(),)


def _fake_resolver(mapping: dict[str, str]):
    def resolve(name, rdtype, lifetime=None):
        if name in mapping:
            return [_FakeTXT(mapping[name])]
        raise dns.resolver.NXDOMAIN()

    return resolve


# --------------------------------------------------------------------------- #
# Прокси-утилиты (sync)
# --------------------------------------------------------------------------- #
def test_format_proxy_url_with_at_credentials() -> None:
    assert net.format_proxy_url("user:pass@1.2.3.4:1080", "socks5") == "socks5://user:pass@1.2.3.4:1080"


def test_format_proxy_url_colon_credentials() -> None:
    # ip:port:user:pass -> scheme://user:pass@ip:port
    assert net.format_proxy_url("1.2.3.4:3128:bob:secret", "http") == "http://bob:secret@1.2.3.4:3128"


def test_format_proxy_url_plain() -> None:
    assert net.format_proxy_url("1.2.3.4:8080", "socks4") == "socks4://1.2.3.4:8080"


def test_hide_credentials_with_at() -> None:
    assert net.hide_credentials("user:pass@10.20.30.40:1080") == "10.20.30.***"


def test_hide_credentials_plain_ipv4() -> None:
    assert net.hide_credentials("10.20.30.40:8080") == "10.20.30.***"


def test_hide_credentials_non_ipv4() -> None:
    assert net.hide_credentials("weird-host") == "***.***.***.***"


def test_empty_info_contract() -> None:
    info = net.empty_info("8.8.8.8")
    assert info["IP"] == "8.8.8.8"
    assert info["Status"] == "OK"
    assert info["Proxy"] == "Нет"
    for key in ("Country", "ASN", "BGP_Prefix", "Abuse_Score", "Spamhaus"):
        assert info[key] == NO_DATA


# --------------------------------------------------------------------------- #
# Spamhaus (sync, мок socket)
# --------------------------------------------------------------------------- #
def test_spamhaus_listed_true(monkeypatch) -> None:
    monkeypatch.setattr(net.socket, "gethostbyname_ex", lambda q: ("", [], ["127.0.0.2"]))
    assert net._spamhaus_listed("8.8.8.8") is True


def test_spamhaus_listed_false_on_nxdomain(monkeypatch) -> None:
    def raise_gaierror(q):
        raise socket.gaierror()

    monkeypatch.setattr(net.socket, "gethostbyname_ex", raise_gaierror)
    assert net._spamhaus_listed("8.8.8.8") is False


def test_spamhaus_public_resolver_returns_none(monkeypatch) -> None:
    # 127.255.255.254 = запрос через публичный/блокируемый резолвер -> неизвестно,
    # а НЕ "в списке" (иначе ложное срабатывание на каждом IP).
    monkeypatch.setattr(
        net.socket, "gethostbyname_ex", lambda q: ("", [], ["127.255.255.254"])
    )
    assert net._spamhaus_listed("8.8.8.8") is None


def test_spamhaus_ipv6_returns_none() -> None:
    assert net._spamhaus_listed("::1") is None


# --------------------------------------------------------------------------- #
# Team Cymru (sync, мок dnspython)
# --------------------------------------------------------------------------- #
def test_cymru_origin_parses(monkeypatch) -> None:
    mapping = {"8.8.8.8.origin.asn.cymru.com": "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"}
    monkeypatch.setattr(net.dns.resolver, "resolve", _fake_resolver(mapping))
    assert net._cymru_origin("8.8.8.8") == {"asn": "15169", "prefix": "8.8.8.0/24", "country": "US"}


def test_cymru_origin_nxdomain_returns_none(monkeypatch) -> None:
    monkeypatch.setattr(net.dns.resolver, "resolve", _fake_resolver({}))
    assert net._cymru_origin("8.8.8.8") is None


def test_cymru_asname_parses(monkeypatch) -> None:
    mapping = {"AS15169.asn.cymru.com": "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"}
    monkeypatch.setattr(net.dns.resolver, "resolve", _fake_resolver(mapping))
    assert net._cymru_asname("15169") == "GOOGLE - Google LLC, US"


# --------------------------------------------------------------------------- #
# Источники по HTTP (async, aioresponses)
# --------------------------------------------------------------------------- #
async def test_part_geo_success(geo_payload) -> None:
    with aioresponses() as m:
        m.get(IP_API_RE, payload=geo_payload)
        async with aiohttp.ClientSession() as session:
            out = await net._part_geo(session, "8.8.8.8")
    assert out["Country"] == "США"
    assert out["ISP"] == "Google LLC"
    assert out["Lat"] == 39.03


async def test_part_geo_fail_status() -> None:
    with aioresponses() as m:
        m.get(IP_API_RE, payload={"status": "fail", "message": "reserved range"})
        async with aiohttp.ClientSession() as session:
            out = await net._part_geo(session, "10.0.0.1")
    assert out == {}


async def test_part_geo_http_error() -> None:
    with aioresponses() as m:
        m.get(IP_API_RE, status=500)
        async with aiohttp.ClientSession() as session:
            out = await net._part_geo(session, "8.8.8.8")
    assert out == {}


async def test_part_geo_retries_on_429(monkeypatch) -> None:
    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(net.asyncio, "sleep", fake_sleep)
    with aioresponses() as m:
        m.get(IP_API_RE, status=429)  # первая попытка - rate limit
        m.get(IP_API_RE, payload={"status": "success", "country": "США"})  # ретрай ок
        async with aiohttp.ClientSession() as session:
            out = await net._part_geo(session, "8.8.8.8")
    assert out["Country"] == "США"
    assert slept  # был backoff перед повтором


async def test_part_bgpview_parses(bgpview_payload) -> None:
    with aioresponses() as m:
        m.get(BGPVIEW_RE, payload=bgpview_payload)
        async with aiohttp.ClientSession() as session:
            out = await net._part_bgpview(session, "8.8.8.8")
    assert out["BGP_Prefix"] == "8.8.8.0/24"
    assert out["ASN_Name"] == "GOOGLE"
    assert out["RIR_Country"] == "US"


async def test_part_abuseipdb_no_key() -> None:
    async with aiohttp.ClientSession() as session:
        out = await net._part_abuseipdb(session, "8.8.8.8", "")
    assert out == {}


async def test_part_abuseipdb_parses(abuseipdb_payload) -> None:
    with aioresponses() as m:
        m.get(ABUSEIPDB_RE, payload=abuseipdb_payload)
        async with aiohttp.ClientSession() as session:
            out = await net._part_abuseipdb(session, "8.8.8.8", "test-key")
    assert out["Abuse_Score"] == 42
    assert out["Abuse_Reports"] == 7
    assert out["Abuse_Last_Reported"].startswith("2026")


# --------------------------------------------------------------------------- #
# get_ip_info (async, интеграция источников)
# --------------------------------------------------------------------------- #
async def test_get_ip_info_merges_sources(
    no_blocking, base_config, geo_payload, bgpview_payload
) -> None:
    with aioresponses() as m:
        m.get(IP_API_RE, payload=geo_payload)
        m.get(BGPVIEW_RE, payload=bgpview_payload)
        info = await net.get_ip_info("8.8.8.8", None, "http", base_config)

    assert info["IP"] == "8.8.8.8"
    assert info["Country"] == "США"
    assert info["BGP_Prefix"] == "8.8.8.0/24"
    assert info["Abuse_Score"] == NO_DATA  # ключ не задан -> источник пропущен
    assert info["Status"] == "OK"


async def test_get_ip_info_includes_abuse_when_key(
    no_blocking, base_config, geo_payload, bgpview_payload, abuseipdb_payload
) -> None:
    base_config["abuseipdb_api_key"] = "test-key"
    with aioresponses() as m:
        m.get(IP_API_RE, payload=geo_payload)
        m.get(BGPVIEW_RE, payload=bgpview_payload)
        m.get(ABUSEIPDB_RE, payload=abuseipdb_payload)
        info = await net.get_ip_info("8.8.8.8", None, "http", base_config)

    assert info["Abuse_Score"] == 42


async def test_get_ip_info_survives_all_failures(no_blocking, base_config) -> None:
    with aioresponses() as m:
        m.get(IP_API_RE, status=500)
        m.get(BGPVIEW_RE, status=500)
        info = await net.get_ip_info("8.8.8.8", None, "http", base_config)

    # Ни один источник не сработал, но результат корректен с дефолтами.
    assert info["IP"] == "8.8.8.8"
    assert info["Status"] == "OK"
    assert info["Country"] == NO_DATA


async def test_get_ip_info_sets_hostname_from_dns(base_config, monkeypatch, geo_payload) -> None:
    monkeypatch.setattr(net, "_reverse_dns", lambda ip: "dns.google")
    monkeypatch.setattr(net, "_rdap_cidr", lambda ip: "8.8.8.0/24")
    monkeypatch.setattr(net, "_spamhaus_listed", lambda ip: False)
    monkeypatch.setattr(net, "_cymru_origin", lambda ip: None)
    with aioresponses() as m:
        m.get(IP_API_RE, payload=geo_payload)
        m.get(BGPVIEW_RE, payload={"status": "error"})
        info = await net.get_ip_info("8.8.8.8", None, "http", base_config)

    assert info["Hostname"] == "dns.google"
    assert info["Network_CIDR"] == "8.8.8.0/24"
    assert info["Spamhaus"] == "Чисто"


async def test_get_ip_info_uses_cymru_as_primary(base_config, monkeypatch, geo_payload) -> None:
    # Cymru отдаёт данные -> bgpview-фолбэк не вызывается (мок для него не нужен).
    monkeypatch.setattr(net, "_reverse_dns", lambda ip: None)
    monkeypatch.setattr(net, "_rdap_cidr", lambda ip: None)
    monkeypatch.setattr(net, "_spamhaus_listed", lambda ip: None)
    monkeypatch.setattr(
        net, "_cymru_origin", lambda ip: {"asn": "15169", "prefix": "8.8.8.0/24", "country": "US"}
    )
    monkeypatch.setattr(net, "_cymru_asname", lambda asn: "GOOGLE")
    with aioresponses() as m:
        m.get(IP_API_RE, payload=geo_payload)
        info = await net.get_ip_info("8.8.8.8", None, "http", base_config)

    assert info["BGP_Prefix"] == "8.8.8.0/24"
    assert info["ASN_Name"] == "GOOGLE"
    assert info["RIR_Country"] == "US"


async def test_get_ip_info_invalid_proxy_skips_http(base_config, monkeypatch) -> None:
    # Регресс: битый прокси (connector=None) НЕ должен уводить HTTP-источники
    # в прямое соединение и раскрывать реальный IP.
    monkeypatch.setattr(net, "_reverse_dns", lambda ip: "host.example")
    monkeypatch.setattr(net, "_rdap_cidr", lambda ip: None)
    monkeypatch.setattr(net, "_spamhaus_listed", lambda ip: None)
    monkeypatch.setattr(net, "_cymru_origin", lambda ip: None)
    monkeypatch.setattr(net, "_make_connector", lambda url: None)
    with aioresponses() as m:
        # Если бы HTTP-запрос ушёл напрямую, Country стал бы "LEAK".
        m.get(IP_API_RE, payload={"status": "success", "country": "LEAK"})
        info = await net.get_ip_info("8.8.8.8", ["bad-proxy"], "socks5", base_config)

    assert info["Proxy"] == "Ошибка прокси"
    assert info["Country"] == NO_DATA  # HTTP пропущен, утечки нет
    assert info["Hostname"] == "host.example"  # DNS-источник отработал
    assert info["Status"] == "OK"


# --------------------------------------------------------------------------- #
# check_single_proxy (async)
# --------------------------------------------------------------------------- #
async def test_check_single_proxy_ok() -> None:
    with aioresponses() as m:
        m.get(IP_API_RE, payload={"status": "success"})
        proxy, ok = await net.check_single_proxy("1.2.3.4:8080", "http")
    assert proxy == "1.2.3.4:8080"
    assert ok is True


async def test_check_single_proxy_bad_status() -> None:
    with aioresponses() as m:
        m.get(IP_API_RE, status=502)
        _, ok = await net.check_single_proxy("1.2.3.4:8080", "http")
    assert ok is False


async def test_check_single_proxy_connection_error() -> None:
    with aioresponses() as m:
        m.get(IP_API_RE, exception=aiohttp.ClientError("boom"))
        _, ok = await net.check_single_proxy("1.2.3.4:8080", "http")
    assert ok is False


# --------------------------------------------------------------------------- #
# Безопасность: валидация IP, маскирование прокси-кредов
# --------------------------------------------------------------------------- #
def test_hide_credentials_colon_format_drops_creds() -> None:
    # host:port:user:pass -> креды отброшены, последний октет скрыт.
    assert net.hide_credentials("10.20.30.40:3128:bob:secret") == "10.20.30.***"


async def test_get_ip_info_rejects_invalid_ip(base_config) -> None:
    # Defense-in-depth: невалидный «IP» не приводит к сетевым запросам.
    info = await net.get_ip_info("not-an-ip", None, "http", base_config)
    assert info["Status"] == "Error"
    assert info["IP"] == "not-an-ip"


async def test_get_ip_info_masks_proxy_credentials(
    no_blocking, base_config, geo_payload, monkeypatch
) -> None:
    # user:pass из прокси не должны попасть ни в одно поле результата.
    monkeypatch.setattr(net, "_make_connector", lambda url: aiohttp.TCPConnector())
    with aioresponses() as m:
        m.get(IP_API_RE, payload=geo_payload)
        m.get(BGPVIEW_RE, payload={"status": "error"})
        info = await net.get_ip_info(
            "8.8.8.8", ["user:secretpass@10.20.30.40:1080"], "http", base_config
        )

    blob = " ".join(str(value) for value in info.values())
    assert "secretpass" not in blob
    assert info["Proxy"] == "10.20.30.***"


async def test_part_geo_uses_https_with_pro_key(geo_payload) -> None:
    # С Pro-ключом геолокация идёт по HTTPS (pro.ip-api.com), не по HTTP.
    with aioresponses() as m:
        m.get(IP_API_PRO_RE, payload=geo_payload)
        async with aiohttp.ClientSession() as session:
            out = await net._part_geo(session, "8.8.8.8", "pro-key")
    assert out["Country"] == "США"
    assert out["ISP"] == "Google LLC"


async def test_get_ip_info_geo_uses_https_when_key_set(
    no_blocking, base_config, geo_payload, bgpview_payload
) -> None:
    # ip_api_key в config → гео-запрос уходит на HTTPS-эндпоинт, а не на HTTP.
    base_config["ip_api_key"] = "pro-key"
    with aioresponses() as m:
        m.get(IP_API_PRO_RE, payload=geo_payload)
        m.get(BGPVIEW_RE, payload=bgpview_payload)
        info = await net.get_ip_info("8.8.8.8", None, "http", base_config)
    assert info["Country"] == "США"
