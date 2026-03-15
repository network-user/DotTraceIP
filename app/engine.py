from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)
from rich.table import Table
from rich.live import Live
from rich.console import Group
from rich.panel import Panel

from app.network import get_ip_info, check_single_proxy
from app.utils import init_result_file, append_result


def run_proxy_check(proxies, proxy_type, threads, console):
    working_proxies = []

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
    )
    task = progress.add_task("Проверка прокси...", total=len(proxies))

    with Live(
        Panel(progress, title="[cyan]Менеджер прокси[/cyan]"),
        console=console,
        refresh_per_second=10,
    ) as live:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(check_single_proxy, p, proxy_type): p for p in proxies
            }

            try:
                for future in as_completed(futures):
                    proxy, is_working = future.result()
                    if is_working:
                        working_proxies.append(proxy)
                    progress.update(task, advance=1)
            except KeyboardInterrupt:
                progress.update(
                    task,
                    description="[bold red]Проверка прервана пользователем[/bold red]",
                )
                for f in futures:
                    f.cancel()

    return working_proxies


def generate_live_table(recent_results):
    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("IP")
    table.add_column("Локация / Ошибка")
    table.add_column("Провайдер")
    table.add_column("Хост")

    for res in recent_results:
        if res.get("Status") == "Error":
            table.add_row(
                f"[red]{res['IP']}[/red]",
                f"[red]{res.get('Error_Msg')}[/red]",
                "[red]-[/red]",
                "[red]-[/red]",
            )
        else:
            location = (
                f"{res.get('Country', 'Нет данных')}, {res.get('City', 'Нет данных')}"
            )
            table.add_row(
                res["IP"],
                location,
                res.get("ISP", "Нет данных"),
                res.get("Hostname", "Нет данных"),
            )

    return table


def run_scan(targets, proxies, config, console):
    results_count = 0
    recent_results = []

    init_result_file(config["output_file"])

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}"),
    )
    task = progress.add_task("Инициализация потоков...", total=len(targets))

    def get_renderable():
        return Group(
            Panel(progress, border_style="cyan"),
            Panel(
                generate_live_table(recent_results),
                title="[cyan]Журнал сканирования (последние 5)[/cyan]",
                border_style="cyan",
            ),
        )

    with Live(get_renderable(), console=console, refresh_per_second=4) as live:
        with ThreadPoolExecutor(max_workers=config["threads"]) as executor:
            futures = {
                executor.submit(
                    get_ip_info, ip, proxies if proxies else None, config["proxy_type"]
                ): ip
                for ip in targets
            }

            try:
                for future in as_completed(futures):
                    current_ip = futures[future]
                    try:
                        data = future.result()
                        append_result(data, config["output_file"])
                        results_count += 1

                        recent_results.insert(0, data)
                        if len(recent_results) > 5:
                            recent_results.pop()

                        progress.update(
                            task,
                            advance=1,
                            description=f"Обработка: [bold green]{current_ip}[/bold green]",
                        )
                        live.update(get_renderable())

                    except Exception as e:
                        error_data = {
                            "IP": current_ip,
                            "Status": "Error",
                            "Error_Msg": str(e),
                        }
                        recent_results.insert(0, error_data)
                        if len(recent_results) > 5:
                            recent_results.pop()

                        progress.update(
                            task,
                            advance=1,
                            description=f"[red]Критическая ошибка на {current_ip}[/red]",
                        )
                        live.update(get_renderable())

            except KeyboardInterrupt:
                progress.update(
                    task,
                    description="[bold red]Остановка процесса... Ожидание завершения активных потоков.[/bold red]",
                )
                for f in futures:
                    f.cancel()
                live.update(get_renderable())

    if results_count > 0:
        console.print(
            f"\n[bold cyan]Сбор завершен. Сохранено записей: {results_count} из {len(targets)}.[/bold cyan]"
        )
        console.print(
            f"[bold cyan]Отчет доступен в файле: {config['output_file']}[/bold cyan]"
        )
    else:
        console.print("\n[bold red]Нет успешных проверок для сохранения.[/bold red]")