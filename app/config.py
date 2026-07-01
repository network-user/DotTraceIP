import json
import os
from typing import Any

CONFIG_FILE = "config.json"

# Допустимые значения перечислимых ключей и потолок конкурентности.
ALLOWED_PROXY_TYPES = {"http", "socks4", "socks5"}
ALLOWED_EXPORT_FORMATS = {"txt", "json", "csv", "html", "all"}
MAX_THREADS = 500
_PATH_KEYS = ("proxies_file", "targets_file", "output_file")


def default_config() -> dict[str, Any]:
    """Дефолтные настройки. Источник правды для всех ключей config.json."""
    return {
        "threads": 10,
        "proxy_type": "socks5",
        "proxies_file": "data/proxies.txt",
        "targets_file": "data/target_ips.txt",
        "output_file": "data/results.txt",
        "export_format": "all",
        "abuseipdb_api_key": "",
        "ip_api_key": "",
        "enable_bgp": True,
        "enable_spamhaus": True,
    }


def _within_cwd(path: str) -> bool:
    """True, если путь не выходит за пределы текущего рабочего каталога.

    Защита от path traversal через config.json: значение из подменённого конфига
    не должно указывать на файл вне рабочей директории (перезапись произвольных
    файлов через output_file/targets_file/proxies_file).
    """
    try:
        base = os.path.realpath(os.getcwd())
        target = os.path.realpath(os.path.join(base, path))
    except (OSError, ValueError):
        return False
    return target == base or target.startswith(base + os.sep)


def _sanitize_config(cfg: dict[str, Any], defaults: dict[str, Any]) -> dict[str, Any]:
    """Приводит значения из config.json к безопасным типам и диапазонам.

    Подменённый/повреждённый конфиг не должен ронять приложение или включать
    опасное поведение - некорректные значения заменяются дефолтами.
    """
    try:
        threads = int(cfg.get("threads", defaults["threads"]))
    except (TypeError, ValueError):
        threads = defaults["threads"]
    cfg["threads"] = min(max(1, threads), MAX_THREADS)

    if cfg.get("proxy_type") not in ALLOWED_PROXY_TYPES:
        cfg["proxy_type"] = defaults["proxy_type"]

    if str(cfg.get("export_format", "")).lower() not in ALLOWED_EXPORT_FORMATS:
        cfg["export_format"] = defaults["export_format"]

    cfg["enable_bgp"] = bool(cfg.get("enable_bgp", defaults["enable_bgp"]))
    cfg["enable_spamhaus"] = bool(cfg.get("enable_spamhaus", defaults["enable_spamhaus"]))

    if not isinstance(cfg.get("abuseipdb_api_key", ""), str):
        cfg["abuseipdb_api_key"] = ""

    if not isinstance(cfg.get("ip_api_key", ""), str):
        cfg["ip_api_key"] = ""

    for key in _PATH_KEYS:
        value = cfg.get(key, defaults[key])
        if not isinstance(value, str) or not value.strip() or not _within_cwd(value):
            cfg[key] = defaults[key]

    return cfg


def load_config(path: str = CONFIG_FILE) -> dict[str, Any]:
    """Читает config.json, дополняя недостающие ключи дефолтами.

    Если файла нет - создаёт его с дефолтами. Если файл повреждён или содержит
    не-объект - молча возвращает дефолты, не падая.
    """
    defaults = default_config()

    if not os.path.exists(path):
        save_config(defaults, path)
        return defaults

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return defaults

    if not isinstance(data, dict):
        return defaults

    return _sanitize_config({**defaults, **data}, defaults)


def save_config(config: dict[str, Any], path: str = CONFIG_FILE) -> None:
    """Сохраняет настройки в config.json."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)
