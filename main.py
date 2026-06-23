import argparse
import sys

from rich.console import Console

from app.cli import run_app
from app.config import load_config
from app.engine import run_scan
from app.utils import filter_valid_ips, init_files, read_lines


def _run_headless(args: argparse.Namespace) -> int:
    """Неинтерактивный скан: python main.py scan <файл>."""
    console = Console()
    init_files()
    config = load_config()

    if args.proxy_type:
        config["proxy_type"] = args.proxy_type
    if args.export:
        config["export_format"] = args.export
    if args.threads:
        config["threads"] = args.threads
    if args.output:
        config["output_file"] = args.output
    if args.proxies:
        config["proxies_file"] = args.proxies
    if args.no_bgp:
        config["enable_bgp"] = False
    if args.no_spamhaus:
        config["enable_spamhaus"] = False

    targets_file = args.file or config["targets_file"]
    raw_targets = read_lines(targets_file)
    if not raw_targets:
        console.print(f"[red]Файл {targets_file} пуст или не найден.[/red]")
        return 1

    targets, invalid = filter_valid_ips(raw_targets)
    if invalid:
        console.print(f"[yellow]Пропущено некорректных строк: {len(invalid)}[/yellow]")
    if not targets:
        console.print("[red]Нет корректных IP для сканирования.[/red]")
        return 1

    proxies = read_lines(config["proxies_file"])
    run_scan(targets, proxies, config, console, use_live=False)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="DotTraceIP", description="Массовый async-анализ IP-адресов"
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="неинтерактивный скан файла с IP")
    scan.add_argument("file", nargs="?", help="файл с IP (по умолчанию из config.json)")
    scan.add_argument("--export", choices=["txt", "json", "csv", "html", "all"])
    scan.add_argument("--proxy-type", dest="proxy_type", choices=["http", "socks4", "socks5"])
    scan.add_argument("--proxies", help="файл с прокси")
    scan.add_argument("--output", help="файл результата")
    scan.add_argument("--threads", type=int, help="лимит конкурентности")
    scan.add_argument("--no-bgp", action="store_true", help="отключить BGP/ASN")
    scan.add_argument("--no-spamhaus", action="store_true", help="отключить Spamhaus")

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(_run_headless(args))

    run_app()


if __name__ == "__main__":
    main()
