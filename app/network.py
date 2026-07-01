import asyncio
import ipaddress
import json
import random
import socket
import warnings
from collections.abc import Callable
from typing import Any

import aiohttp
import dns.resolver
from aiohttp_socks import ProxyConnector
from ipwhois import IPWhois

# Глушим UserWarning только от прокси/whois-библиотек, а не глобально, чтобы не
# прятать предупреждения из нашего кода и стандартной библиотеки.
for _noisy_module in ("aiohttp_socks", "python_socks", "ipwhois"):
    warnings.filterwarnings("ignore", category=UserWarning, module=_noisy_module)

NO_DATA = "Нет данных"
DEFAULT_TIMEOUT = 8
PROXY_TIMEOUT = 5
# Потолок размера тела ответа: защита от раздувания памяти (злой прокси/MITM).
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
# Таймаут на блокирующие резолверы в thread pool (reverse DNS, RDAP, Spamhaus).
BLOCKING_TIMEOUT = 6.0
# ip-api.com: бесплатный тариф отдаёт только HTTP. По этому каналу идёт лишь
# публичный целевой IP и общедоступная геолокация, без ключей и кредов. Для TLS
# задай ip-api Pro-ключ (config.ip_api_key) - тогда запрос идёт по HTTPS через
# pro.ip-api.com. Данные ip-api не считаем доверенными - BGP/ASN дублируются
# через Team Cymru (DNS) и bgpview (HTTPS).
GEO_API_URL = "http://ip-api.com/json/"
GEO_API_PRO_URL = "https://pro.ip-api.com/json/"


# --------------------------------------------------------------------------- #
# Прокси-утилиты
# --------------------------------------------------------------------------- #
def format_proxy_url(proxy_string: str, proxy_type: str) -> str:
    """Нормализует строку прокси в URL вида ``scheme://[user:pass@]host:port``."""
    if "@" not in proxy_string and proxy_string.count(":") == 3:
        ip, port, user, pwd = proxy_string.split(":")
        return f"{proxy_type}://{user}:{pwd}@{ip}:{port}"
    return f"{proxy_type}://{proxy_string}"


def hide_credentials(proxy_string: str) -> str:
    """Маскирует прокси для вывода: прячет логин/пароль и последний октет IP."""
    try:
        if "@" in proxy_string:
            clean_str = proxy_string.split("@")[-1]
            ip = clean_str.split(":")[0]
        else:
            ip = proxy_string.split(":")[0]

        ip_parts = ip.split(".")
        if len(ip_parts) == 4:
            ip_parts[-1] = "***"
            return ".".join(ip_parts)

        return "***.***.***.***"
    except Exception:
        return "Скрыто"


def _make_connector(proxy_url: str | None) -> ProxyConnector | None:
    """Строит aiohttp-коннектор для прокси (http/socks4/socks5) или None."""
    if not proxy_url:
        return None
    try:
        return ProxyConnector.from_url(proxy_url)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Низкоуровневый HTTP
# --------------------------------------------------------------------------- #
async def _get_json(
    session: aiohttp.ClientSession,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    retries: int = 0,
    backoff: float = 2.0,
) -> dict[str, Any] | None:
    """GET с тихим возвратом None при любой ошибке/не-200.

    На 429 (rate limit) делает до ``retries`` повторов с задержкой: уважает
    заголовок ``X-Ttl`` (ip-api), но ждёт не дольше 10 секунд на попытку.
    """
    for attempt in range(retries + 1):
        try:
            async with session.get(url, headers=headers, params=params) as resp:
                if resp.status == 200:
                    # Потолок на тело ответа применяется к фактически прочитанным
                    # байтам (в т.ч. chunked без Content-Length); объём также
                    # ограничен общим таймаутом запроса.
                    raw = await resp.read()
                    if len(raw) > MAX_RESPONSE_BYTES:
                        return None
                    try:
                        data = json.loads(raw)
                    except (json.JSONDecodeError, ValueError):
                        return None
                    return data if isinstance(data, dict) else None
                if resp.status == 429 and attempt < retries:
                    ttl = resp.headers.get("X-Ttl", "")
                    delay = (
                        min(float(ttl), 10.0)
                        if ttl.isascii() and ttl.isdigit()
                        else backoff * (attempt + 1)
                    )
                    await asyncio.sleep(delay)
                    continue
                return None
        except Exception:
            return None
    return None


# --------------------------------------------------------------------------- #
# Блокирующие источники (исполняются в thread pool)
# --------------------------------------------------------------------------- #
def _reverse_dns(ip: str) -> str | None:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None


def _rdap_cidr(ip: str) -> str | None:
    try:
        obj = IPWhois(ip)
        rdap = obj.lookup_rdap(depth=1)
        cidr = rdap.get("network", {}).get("cidr")
        return cidr or None
    except Exception:
        return None


def _spamhaus_listed(ip: str) -> bool | None:
    """Проверка IPv4 в zen.spamhaus.org через DNS.

    True - только для валидных кодов листинга 127.0.0.2-127.0.0.11.
    Коды 127.255.255.x (запрос через публичный/блокируемый резолвер или ошибка)
    -> None (неизвестно), иначе ложные срабатывания на каждом IP. NXDOMAIN -> False.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None

    query = ".".join(reversed(ip.split("."))) + ".zen.spamhaus.org"
    try:
        _, _, answers = socket.gethostbyname_ex(query)
    except socket.gaierror:
        return False  # NXDOMAIN -> не в списке
    except OSError:
        return None

    blocked = False
    for answer in answers:
        if answer.startswith("127.0.0."):
            last = answer.rsplit(".", 1)[-1]
            if last.isdigit() and 2 <= int(last) <= 11:
                return True
        elif answer.startswith("127.255.255."):
            blocked = True
    return None if blocked else False


def _cymru_query_name(ip: str) -> str:
    """Имя для Team Cymru origin-запроса (IPv4 origin / IPv6 origin6)."""
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _cymru_txt(name: str) -> str | None:
    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=5)
    except Exception:
        return None
    for rdata in answer:
        try:
            return b" ".join(rdata.strings).decode("utf-8", "ignore")
        except Exception:
            continue
    return None


def _cymru_origin(ip: str) -> dict[str, str] | None:
    """Team Cymru: ASN, BGP-префикс и country_code одним DNS-запросом."""
    try:
        name = _cymru_query_name(ip)
    except ValueError:
        return None
    txt = _cymru_txt(name)
    if not txt:
        return None
    # Формат: "ASN[ ASN...] | prefix | country | registry | date"
    parts = [p.strip() for p in txt.split("|")]
    if len(parts) < 3:
        return None
    out: dict[str, str] = {}
    asn = parts[0].split()[0] if parts[0] else ""
    if asn:
        out["asn"] = asn
    if parts[1]:
        out["prefix"] = parts[1]
    if parts[2]:
        out["country"] = parts[2]
    return out or None


def _cymru_asname(asn: str) -> str | None:
    """Team Cymru: человекочитаемое имя автономной системы."""
    txt = _cymru_txt(f"AS{asn}.asn.cymru.com")
    if not txt:
        return None
    # Формат: "ASN | country | registry | date | NAME"
    parts = [p.strip() for p in txt.split("|")]
    name = parts[-1] if parts else ""
    return name or None


# --------------------------------------------------------------------------- #
# Сборщики (partial dict per источник)
# --------------------------------------------------------------------------- #
async def _run_blocking(
    loop: asyncio.AbstractEventLoop, func: Callable[[str], Any], ip: str
) -> Any:
    """Блокирующий резолвер в thread pool с жёстким таймаутом.

    reverse DNS / RDAP / Spamhaus используют системный резолвер без программного
    таймаута; без обёртки зависший DNS забивает пул потоков и тормозит весь скан.
    """
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, func, ip), BLOCKING_TIMEOUT
        )
    except Exception:
        return None


async def _part_reverse_dns(loop: asyncio.AbstractEventLoop, ip: str) -> dict[str, Any]:
    host = await _run_blocking(loop, _reverse_dns, ip)
    return {"Hostname": host} if host else {}


async def _part_rdap(loop: asyncio.AbstractEventLoop, ip: str) -> dict[str, Any]:
    cidr = await _run_blocking(loop, _rdap_cidr, ip)
    return {"Network_CIDR": cidr} if cidr else {}


async def _part_spamhaus(loop: asyncio.AbstractEventLoop, ip: str) -> dict[str, Any]:
    listed = await _run_blocking(loop, _spamhaus_listed, ip)
    if listed is None:
        return {}
    return {"Spamhaus": "В списке" if listed else "Чисто"}


async def _part_geo(
    session: aiohttp.ClientSession, ip: str, api_key: str = ""
) -> dict[str, Any]:
    """Геолокация и ASN через ip-api.com.

    С Pro-ключом (``api_key``) запрос идёт по HTTPS (pro.ip-api.com); без ключа -
    по бесплатному HTTP.
    """
    params = {"lang": "ru", "fields": "status,country,city,isp,as,lat,lon"}
    if api_key:
        url = GEO_API_PRO_URL + ip
        params["key"] = api_key
    else:
        url = GEO_API_URL + ip
    data = await _get_json(session, url, params=params, retries=2)
    if not data or data.get("status") != "success":
        return {}
    out: dict[str, Any] = {}
    for src, dst in (("country", "Country"), ("city", "City"), ("isp", "ISP"), ("as", "ASN")):
        value = data.get(src)
        if value:
            out[dst] = value
    if data.get("lat") is not None:
        out["Lat"] = data["lat"]
    if data.get("lon") is not None:
        out["Lon"] = data["lon"]
    return out


async def _part_bgpview(session: aiohttp.ClientSession, ip: str) -> dict[str, Any]:
    """BGP-префикс, имя ASN и RIR country_code через bgpview.io."""
    data = await _get_json(session, f"https://api.bgpview.io/ip/{ip}")
    if not data or data.get("status") != "ok":
        return {}
    payload = data.get("data") or {}
    out: dict[str, Any] = {}

    prefixes = payload.get("prefixes") or []
    if prefixes:
        first = prefixes[0]
        if first.get("prefix"):
            out["BGP_Prefix"] = first["prefix"]
        asn = first.get("asn") or {}
        name = asn.get("name") or asn.get("description")
        if name:
            out["ASN_Name"] = name

    rir = payload.get("rir_allocation") or {}
    if rir.get("country_code"):
        out["RIR_Country"] = rir["country_code"]

    return out


async def _part_cymru(loop: asyncio.AbstractEventLoop, ip: str) -> dict[str, Any]:
    """BGP-префикс, country_code и имя ASN через Team Cymru (DNS)."""
    origin = await loop.run_in_executor(None, _cymru_origin, ip)
    if not origin:
        return {}
    out: dict[str, Any] = {}
    if origin.get("prefix"):
        out["BGP_Prefix"] = origin["prefix"]
    if origin.get("country"):
        out["RIR_Country"] = origin["country"]
    asn = origin.get("asn")
    if asn:
        name = await loop.run_in_executor(None, _cymru_asname, asn)
        if name:
            out["ASN_Name"] = name
    return out


async def _part_bgp(
    loop: asyncio.AbstractEventLoop,
    ip: str,
    session: aiohttp.ClientSession | None,
) -> dict[str, Any]:
    """BGP/ASN: Team Cymru (DNS) - основной источник, bgpview.io - HTTP-фолбэк."""
    out = await _part_cymru(loop, ip)
    if out or session is None:
        return out
    return await _part_bgpview(session, ip)


async def _part_abuseipdb(
    session: aiohttp.ClientSession, ip: str, api_key: str
) -> dict[str, Any]:
    """Репутация через AbuseIPDB. Без ключа источник не вызывается."""
    if not api_key:
        return {}
    data = await _get_json(
        session,
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": "90"},
    )
    if not data or not isinstance(data.get("data"), dict):
        return {}
    d = data["data"]
    out: dict[str, Any] = {}
    if d.get("abuseConfidenceScore") is not None:
        out["Abuse_Score"] = d["abuseConfidenceScore"]
    if d.get("totalReports") is not None:
        out["Abuse_Reports"] = d["totalReports"]
    if d.get("lastReportedAt"):
        out["Abuse_Last_Reported"] = d["lastReportedAt"]
    return out


# --------------------------------------------------------------------------- #
# Контракт результата
# --------------------------------------------------------------------------- #
def empty_info(ip: str) -> dict[str, Any]:
    """Базовый результат с дефолтами. Источники перезаписывают свои поля."""
    return {
        "IP": ip,
        "Hostname": NO_DATA,
        "Country": NO_DATA,
        "City": NO_DATA,
        "Lat": NO_DATA,
        "Lon": NO_DATA,
        "ISP": NO_DATA,
        "ASN": NO_DATA,
        "ASN_Name": NO_DATA,
        "Network_CIDR": NO_DATA,
        "BGP_Prefix": NO_DATA,
        "RIR_Country": NO_DATA,
        "Abuse_Score": NO_DATA,
        "Abuse_Reports": NO_DATA,
        "Abuse_Last_Reported": NO_DATA,
        "Spamhaus": NO_DATA,
        "Proxy": "Нет",
        "Status": "OK",
    }


# --------------------------------------------------------------------------- #
# Публичный API
# --------------------------------------------------------------------------- #
async def get_ip_info(
    ip: str,
    proxies_list: list[str] | None = None,
    proxy_type: str = "http",
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Собирает все данные по одному IP параллельно через asyncio.gather.

    Любой сбойный источник не прерывает остальные - его поля остаются дефолтными.
    """
    config = config or {}

    # Defense-in-depth: функция безопасна независимо от вызывающего - на вход
    # принимаются только валидные IP, иначе по «IP» не строится ни одного запроса.
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        bad = empty_info(ip)
        bad["Status"] = "Error"
        bad["Error_Msg"] = "Некорректный IP"
        return bad

    info = empty_info(ip)

    proxy_url: str | None = None
    if proxies_list:
        proxy = random.choice(proxies_list)
        proxy_url = format_proxy_url(proxy, proxy_type)
        info["Proxy"] = hide_credentials(proxy)

    connector = _make_connector(proxy_url)
    # Прокси запрошен, но не распарсился: НЕ выходим в сеть по HTTP напрямую,
    # иначе реальный IP утечёт мимо прокси. DNS/RDAP-источники остаются best-effort.
    proxy_failed = bool(proxy_url) and connector is None
    if proxy_failed:
        info["Proxy"] = "Ошибка прокси"

    loop = asyncio.get_running_loop()
    timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)

    async def collect(session: aiohttp.ClientSession | None) -> list[Any]:
        parts: list[Any] = [
            _part_reverse_dns(loop, ip),
            _part_rdap(loop, ip),
        ]
        if config.get("enable_spamhaus", True):
            parts.append(_part_spamhaus(loop, ip))
        if config.get("enable_bgp", True):
            parts.append(_part_bgp(loop, ip, session))
        if session is not None:
            parts.append(_part_geo(session, ip, config.get("ip_api_key", "")))
            if config.get("abuseipdb_api_key"):
                parts.append(_part_abuseipdb(session, ip, config["abuseipdb_api_key"]))
        return await asyncio.gather(*parts, return_exceptions=True)

    if proxy_failed:
        results = await collect(None)
    else:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            results = await collect(session)

    for result in results:
        if isinstance(result, dict):
            info.update(result)

    return info


async def check_single_proxy(proxy: str, proxy_type: str) -> tuple[str, bool]:
    """Проверяет работоспособность прокси запросом к ip-api.com."""
    proxy_url = format_proxy_url(proxy, proxy_type)
    connector = _make_connector(proxy_url)
    if connector is None:
        return proxy, False

    timeout = aiohttp.ClientTimeout(total=PROXY_TIMEOUT)
    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get(GEO_API_URL + "8.8.8.8") as resp:
                return proxy, resp.status == 200
    except Exception:
        return proxy, False
