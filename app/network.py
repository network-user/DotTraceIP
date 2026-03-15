import socket
import requests
import random
from ipwhois import IPWhois
import warnings

warnings.filterwarnings("ignore", category=UserWarning)


def format_proxy_url(proxy_string, proxy_type):
    if "@" not in proxy_string and proxy_string.count(":") == 3:
        ip, port, user, pwd = proxy_string.split(":")
        return f"{proxy_type}://{user}:{pwd}@{ip}:{port}"
    return f"{proxy_type}://{proxy_string}"


def check_single_proxy(proxy, proxy_type):
    proxy_url = format_proxy_url(proxy, proxy_type)
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        res = requests.get("http://ip-api.com/json/8.8.8.8", proxies=proxies, timeout=5)
        if res.status_code == 200:
            return proxy, True
    except Exception:
        pass
    return proxy, False


def get_ip_info(ip, proxies_list=None, proxy_type="http"):
    info = {
        "IP": ip,
        "Hostname": "Нет данных",
        "Country": "Нет данных",
        "City": "Нет данных",
        "ISP": "Нет данных",
        "ASN": "Нет данных",
        "Network_CIDR": "Нет данных",
        "Proxy": "Нет",
    }

    try:
        host, _, _ = socket.gethostbyaddr(ip)
        info["Hostname"] = host
    except socket.herror:
        pass

    try:
        req_proxies = None
        if proxies_list:
            proxy = random.choice(proxies_list)
            proxy_url = format_proxy_url(proxy, proxy_type)
            req_proxies = {"http": proxy_url, "https": proxy_url}
            info["Proxy"] = proxy

        res = requests.get(
            f"http://ip-api.com/json/{ip}?lang=ru", proxies=req_proxies, timeout=8
        ).json()

        if res.get("status") == "success":
            info["Country"] = res.get("country", "")
            info["City"] = res.get("city", "")
            info["ISP"] = res.get("isp", "")
            info["ASN"] = res.get("as", "")
    except Exception:
        info["Proxy"] = "Ошибка соединения"

    try:
        obj = IPWhois(ip)
        rdap = obj.lookup_rdap(depth=1)
        info["Network_CIDR"] = rdap.get("network", {}).get("cidr", "Нет данных")
    except Exception:
        pass

    return info