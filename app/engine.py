import asyncio
import os
from typing import Any

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table

from app.export import export_csv, export_html, export_json
from app.network import NO_DATA, check_single_proxy, get_ip_info
from app.utils import append_result, init_result_file


# --------------------------------------------------------------------------- #
# Проверка прокси
# --------------------------------------------------------------------------- #
async def _check_proxies_async(
    proxies: list[str], proxy_type: str, threads: int, console: Console
) -> list[str]:
    working: list[str] = []
    sem = asyncio.Semaphore(max(1, threads))

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
    )
    task = progress.add_task("Проверка прокси...", total=len(proxies))

    async def worker(proxy: str) -> tuple[str, bool]:
        async with sem:
            return await check_single_proxy(proxy, proxy_type)

    with Live(
        Panel(progress, title="[cyan]Менеджер прокси[/cyan]"),
        console=console,
        refresh_per_second=10,
    ):
        tasks = [asyncio.create_task(worker(p)) for p in proxies]
        try:
            for future in asyncio.as_completed(tasks):
                proxy, is_working = await future
                if is_working:
                    working.append(proxy)
                progress.update(task, advance=1)
        except (KeyboardInterrupt, asyncio.CancelledError):
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            progress.update(
                task, description="[bold red]Проверка прервана пользователем[/bold red]"
            )

    return working


def run_proxy_check(
    proxies: list[str], proxy_type: str, threads: int, console: Console
) -> list[str]:
    """Синхронная обёртка для CLI: проверяет пул прокси через asyncio."""
    try:
        return asyncio.run(_check_proxies_async(proxies, proxy_type, threads, console))
    except KeyboardInterrupt:
        return []


# --------------------------------------------------------------------------- #
# Live-дашборд
# --------------------------------------------------------------------------- #
def _reputation_cell(res: dict[str, Any]) -> str:
    parts: list[str] = []
    score = res.get("Abuse_Score")
    if isinstance(score, (int, float)):
        color = "green" if score == 0 else ("yellow" if score < 50 else "red")
        parts.append(f"[{color}]abuse {score}[/{color}]")
    spam = res.get("Spamhaus")
    if spam == "В списке":
        parts.append("[red]spamhaus[/red]")
    elif spam == "Чисто":
        parts.append("[green]чисто[/green]")
    return " / ".join(parts) if parts else "-"


def generate_live_table(recent_results: list[dict[str, Any]]) -> Table:
    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("IP")
    table.add_column("Локация / Ошибка")
    table.add_column("Провайдер")
    table.add_column("Хост")
    table.add_column("Репутация")

    for res in recent_results:
        if res.get("Status") == "Error":
            table.add_row(
                f"[red]{res.get('IP', '?')}[/red]",
                f"[red]{res.get('Error_Msg', '-')}[/red]",
                "[red]-[/red]",
                "[red]-[/red]",
                "[red]-[/red]",
            )
        else:
            location = f"{res.get('Country', NO_DATA)}, {res.get('City', NO_DATA)}"
            table.add_row(
                res.get("IP", "?"),
                location,
                res.get("ISP", NO_DATA),
                res.get("Hostname", NO_DATA),
                _reputation_cell(res),
            )

    return table


# --------------------------------------------------------------------------- #
# Сканирование
# --------------------------------------------------------------------------- #
async def _scan_async(
    targets: list[str],
    proxies: list[str] | None,
    config: dict[str, Any],
    console: Console,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    recent: list[dict[str, Any]] = []
    proxy_type = str(config.get("proxy_type", "http"))
    proxy_list = proxies if proxies else None

    init_result_file(config["output_file"])

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}"),
    )
    task = progress.add_task("Инициализация...", total=len(targets))

    def renderable() -> Group:
        return Group(
            Panel(progress, border_style="cyan"),
            Panel(
                generate_live_table(recent),
                title="[cyan]Журнал сканирования (последние 5)[/cyan]",
                border_style="cyan",
            ),
        )

    sem = asyncio.Semaphore(max(1, int(config.get("threads", 10))))

    async def worker(ip: str) -> dict[str, Any]:
        async with sem:
            try:
                return await get_ip_info(ip, proxy_list, proxy_type, config)
            except Exception as exc:
                return {"IP": ip, "Status": "Error", "Error_Msg": str(exc)}

    with Live(renderable(), console=console, refresh_per_second=4) as live:
        tasks = [asyncio.create_task(worker(ip)) for ip in targets]
        try:
            for future in asyncio.as_completed(tasks):
                data = await future
                append_result(data, config["output_file"])
                results.append(data)

                recent.insert(0, data)
                del recent[5:]

                ip = data.get("IP", "?")
                if data.get("Status") == "Error":
                    desc = f"[red]Ошибка на {ip}[/red]"
                else:
                    desc = f"Обработка: [bold green]{ip}[/bold green]"
                progress.update(task, advance=1, description=desc)
                live.update(renderable())
        except (KeyboardInterrupt, asyncio.CancelledError):
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            progress.update(
                task,
                description="[bold red]Остановка процесса... ожидание активных задач.[/bold red]",
            )
            live.update(renderable())

    return results


def _export_results(results: list[dict[str, Any]], config: dict[str, Any]) -> list[str]:
    """Дополнительный экспорт по export_format. TXT уже записан построчно."""
    fmt = str(config.get("export_format", "txt")).lower()
    if fmt in ("", "txt"):
        return []

    base, _ = os.path.splitext(str(config.get("output_file", "data/results.txt")))
    written: list[str] = []
    do_all = fmt == "all"

    if do_all or fmt == "json":
        path = base + ".json"
        export_json(results, path)
        written.append(path)
    if do_all or fmt == "csv":
        path = base + ".csv"
        export_csv(results, path)
        written.append(path)
    if do_all or fmt == "html":
        path = base + ".html"
        export_html(results, path)
        written.append(path)

    return written


def run_scan(
    targets: list[str],
    proxies: list[str] | None,
    config: dict[str, Any],
    console: Console,
) -> None:
    """Синхронная обёртка для CLI: сканирует цели через asyncio и экспортирует."""
    try:
        results = asyncio.run(_scan_async(targets, proxies, config, console))
    except KeyboardInterrupt:
        results = []

    if not results:
        console.print("\n[bold red]Нет результатов для сохранения.[/bold red]")
        return

    success = sum(1 for r in results if r.get("Status") != "Error")
    console.print(
        f"\n[bold cyan]Сбор завершён. Записей: {len(results)} из {len(targets)} "
        f"(успешно: {success}).[/bold cyan]"
    )
    console.print(f"[bold cyan]Текстовый отчёт: {config['output_file']}[/bold cyan]")

    for path in _export_results(results, config):
        console.print(f"[bold cyan]Экспорт: {path}[/bold cyan]")
