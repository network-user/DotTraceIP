import ipaddress
import os
from typing import Any

# Папки/файлы данных, создаваемые при первом запуске.
DATA_DIR = "data"
DEFAULT_FILES = ["data/target_ips.txt", "data/proxies.txt"]


def init_files() -> None:
    """Создаёт каталог data/ и пустые входные файлы при первом запуске."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

    for file in DEFAULT_FILES:
        if not os.path.exists(file):
            open(file, "w", encoding="utf-8").close()


def read_lines(filepath: str) -> list[str]:
    """Читает непустые строки файла, обрезая пробелы. Нет файла -> []."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def is_valid_ip(value: str) -> bool:
    """True, если строка - корректный IPv4 или IPv6 адрес."""
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def filter_valid_ips(values: list[str]) -> tuple[list[str], list[str]]:
    """Делит список на (валидные IP, всё остальное)."""
    valid: list[str] = []
    invalid: list[str] = []
    for value in values:
        (valid if is_valid_ip(value) else invalid).append(value)
    return valid, invalid


def init_result_file(filename: str) -> None:
    """Создаёт каталог для результата и очищает файл вывода."""
    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
    open(filename, "w", encoding="utf-8").close()


def append_result(data: dict[str, Any], filename: str) -> None:
    """Дописывает один результат в plain-text отчёт."""
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"=== IP: {data.get('IP', '?')} ===\n")
        for key, value in data.items():
            if key != "IP":
                f.write(f"{key}: {value}\n")
        f.write("\n")
