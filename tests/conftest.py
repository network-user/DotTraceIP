from typing import Any

import pytest

import app.network as net
from app.network import empty_info


@pytest.fixture
def base_config() -> dict[str, Any]:
    return {
        "threads": 5,
        "proxy_type": "http",
        "proxies_file": "data/proxies.txt",
        "targets_file": "data/target_ips.txt",
        "output_file": "data/results.txt",
        "export_format": "all",
        "abuseipdb_api_key": "",
        "enable_bgp": True,
        "enable_spamhaus": True,
    }


@pytest.fixture
def geo_payload() -> dict[str, Any]:
    return {
        "status": "success",
        "country": "США",
        "city": "Эшберн",
        "isp": "Google LLC",
        "as": "AS15169 Google LLC",
        "lat": 39.03,
        "lon": -77.5,
    }


@pytest.fixture
def bgpview_payload() -> dict[str, Any]:
    return {
        "status": "ok",
        "data": {
            "prefixes": [
                {"prefix": "8.8.8.0/24", "asn": {"name": "GOOGLE", "description": "Google LLC"}}
            ],
            "rir_allocation": {"country_code": "US"},
        },
    }


@pytest.fixture
def abuseipdb_payload() -> dict[str, Any]:
    return {
        "data": {
            "abuseConfidenceScore": 42,
            "totalReports": 7,
            "lastReportedAt": "2026-01-01T00:00:00+00:00",
        }
    }


@pytest.fixture
def sample_results() -> list[dict[str, Any]]:
    ok = empty_info("8.8.8.8")
    ok.update(
        {"Country": "США", "City": "Эшберн", "ISP": "Google", "Abuse_Score": 0,
         "Spamhaus": "Чисто", "Lat": 39.03}
    )
    ok2 = empty_info("1.1.1.1")
    ok2.update({"Country": "Австралия", "Abuse_Score": 15, "Lat": -33.49})
    err = {"IP": "5.5.5.5", "Status": "Error", "Error_Msg": "timeout"}
    return [ok, ok2, err]


@pytest.fixture
def no_blocking(monkeypatch: pytest.MonkeyPatch) -> None:
    """Нейтрализует блокирующие сетевые вызовы внутри get_ip_info."""
    monkeypatch.setattr(net, "_reverse_dns", lambda ip: None)
    monkeypatch.setattr(net, "_rdap_cidr", lambda ip: None)
    monkeypatch.setattr(net, "_spamhaus_listed", lambda ip: None)
    monkeypatch.setattr(net, "_cymru_origin", lambda ip: None)
    monkeypatch.setattr(net, "_cymru_asname", lambda asn: None)
