from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)
from rich.table import Table
from app.network import get_ip_info, check_single_proxy
from app.utils import save_results


def run_proxy_check(proxies, proxy_type, threads, console):
    working_proxies = []
    console.print(f"\n[cyan]Запуск проверки на {threads} потоках...[/cyan]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Проверка прокси...", total=len(proxies))

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(check_single_proxy, p, proxy_type): p for p in proxies
            }
            for future in as_completed(futures):
                proxy, is_working = future.result()
                if is_working:
                    working_proxies.append(proxy)
                progress.update(task, advance=1)

    return working_proxies


def run_scan(targets, proxies, config, console):
    console.print(
        f"\n[bold cyan]Начинаем сканирование {len(targets)} IP адресов...[/bold cyan]"
    )

    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Сбор информации...", total=len(targets))

        with ThreadPoolExecutor(max_workers=config["threads"]) as executor:
            futures = {
                executor.submit(
                    get_ip_info, ip, proxies if proxies else None, config["proxy_type"]
                ): ip
                for ip in targets
            }
            for future in as_completed(futures):
                current_ip = futures[future]
                try:
                    data = future.result()
                    results.append(data)
                    progress.update(
                        task,
                        advance=1,
                        description=f"[cyan]Обработка: [bold green]{current_ip}[/bold green]",
                    )
                except Exception as e:
                    console.print(f"[red]Ошибка на {current_ip}: {e}[/red]")

    console.print("\n[bold cyan]Результаты:[/bold cyan]")
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("IP")
    table.add_column("Локация")
    table.add_column("Провайдер")
    table.add_column("Хост")

    for res in results:
        location = (
            f"{res.get('Country', 'Нет данных')}, {res.get('City', 'Нет данных')}"
        )
        table.add_row(
            res["IP"],
            location,
            res.get("ISP", "Нет данных"),
            res.get("Hostname", "Нет данных"),
        )

    console.print(table)

    save_results(results, config["output_file"])
    console.print(
        f"[bold cyan]Полный отчет сохранен в {config['output_file']}[/bold cyan]\n"
    )