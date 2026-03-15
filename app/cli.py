import sys
from rich.console import Console
from rich.prompt import Prompt, IntPrompt
from rich.panel import Panel

from app.config import load_config, save_config
from app.utils import init_files, read_lines
from app.engine import run_proxy_check, run_scan

console = Console()


def pause():
    """Приостанавливает выполнение до нажатия Enter."""
    console.input(
        "\n[bold black on white] Нажмите Enter для продолжения... [/bold black on white]"
    )


def settings_menu(config):
    while True:
        console.clear()
        console.print("\n[bold cyan]--- НАСТРОЙКИ СИСТЕМЫ ---[/bold cyan]")
        console.print(f"[1] Потоки: [cyan]{config['threads']}[/cyan]")
        console.print(f"[2] Тип прокси: [cyan]{config['proxy_type']}[/cyan]")
        console.print(f"[3] Файл целей: [cyan]{config['targets_file']}[/cyan]")
        console.print(f"[4] Файл прокси: [cyan]{config['proxies_file']}[/cyan]")
        console.print(f"[5] Файл результата: [cyan]{config['output_file']}[/cyan]")
        console.print("[0] Назад")

        choice = Prompt.ask("Выбор", choices=["0", "1", "2", "3", "4", "5"])

        if choice == "1":
            config["threads"] = IntPrompt.ask("Введите количество потоков")
        elif choice == "2":
            config["proxy_type"] = Prompt.ask(
                "Тип прокси", choices=["http", "socks4", "socks5"]
            )
        elif choice == "3":
            config["targets_file"] = Prompt.ask("Путь к файлу с IP")
        elif choice == "4":
            config["proxies_file"] = Prompt.ask("Путь к файлу с прокси")
        elif choice == "5":
            config["output_file"] = Prompt.ask("Путь для сохранения результата")
        elif choice == "0":
            save_config(config)
            console.print("[bold cyan]Настройки сохранены.[/bold cyan]")
            pause()
            break


def proxy_menu(config):
    while True:
        console.clear()
        console.print("\n[bold cyan]--- МЕНЕДЖЕР ПРОКСИ ---[/bold cyan]")
        console.print(
            f"Текущий файл: [cyan]{config['proxies_file']}[/cyan] | Тип: [cyan]{config['proxy_type']}[/cyan]"
        )
        console.print("[1] Показать количество загруженных прокси")
        console.print("[2] Проверить прокси")
        console.print("[0] Назад")

        choice = Prompt.ask("Выбор", choices=["0", "1", "2"])

        proxies = read_lines(config["proxies_file"])

        if choice == "1":
            if proxies:
                console.print(
                    f"Всего прокси в файле: [bold cyan]{len(proxies)}[/bold cyan]"
                )
            else:
                console.print("[red]Файл пуст или не найден.[/red]")
            pause()

        elif choice == "2":
            if not proxies:
                console.print("[red]Нет прокси для проверки.[/red]")
                pause()
                continue

            working_proxies = run_proxy_check(
                proxies, config["proxy_type"], config["threads"], console
            )

            with open(config["proxies_file"], "w") as f:
                f.write("\n".join(working_proxies))
            console.print(
                f"[bold cyan]Проверка завершена. Осталось рабочих прокси: {len(working_proxies)}[/bold cyan]"
            )
            pause()

        elif choice == "0":
            break


def run_app():
    init_files()
    config = load_config()

    while True:
        console.clear()
        console.print(
            Panel.fit(
                "[bold cyan]DotTraceIP - Главное меню[/bold cyan]\n"
                "Выберите необходимое действие:",
                border_style="cyan",
            )
        )

        console.print("[1] Запустить сканирование")
        console.print("[2] Настройки системы")
        console.print("[3] Менеджер прокси")
        console.print("[0] Выход")

        choice = Prompt.ask("Ваш выбор", choices=["0", "1", "2", "3"])

        if choice == "1":
            targets = read_lines(config["targets_file"])
            proxies = read_lines(config["proxies_file"])

            if not targets:
                console.print(
                    f"[red]Файл {config['targets_file']} пуст или не существует.[/red]"
                )
            else:
                run_scan(targets, proxies, config, console)
            pause()

        elif choice == "2":
            settings_menu(config)
        elif choice == "3":
            proxy_menu(config)
        elif choice == "0":
            console.clear()
            console.print("[bold cyan]Завершение работы.[/bold cyan]")
            sys.exit(0)