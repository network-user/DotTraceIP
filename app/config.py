import json
import os
from typing import Any

CONFIG_FILE = "config.json"


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
        "enable_bgp": True,
        "enable_spamhaus": True,
    }


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

    return {**defaults, **data}


def save_config(config: dict[str, Any], path: str = CONFIG_FILE) -> None:
    """Сохраняет настройки в config.json."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)
