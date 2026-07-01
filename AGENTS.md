# AGENTS.md

> Инструкции для AI coding agents. Человеческий обзор - в [README.md](README.md).
> Перегенерировано скиллом `generate-readme`. Источник правды - код репозитория.

## Профиль проекта

- **Тип:** cli
- **Аудитория:** internal
- **Runtime:** Python 3.12+
- **Монорепо:** нет

## Быстрый старт

```bash
pip install -r requirements.txt   # или: pip install -e ".[dev]"
python main.py
```

Интерактивное TUI-меню. Данные: `data/target_ips.txt` (IP для сканирования), `data/proxies.txt` (пул прокси), `data/results.*` (отчёты). Настройки и ключ AbuseIPDB - в `config.json` (не в git).

## Сборка и проверки

| Действие | Команда |
|----------|---------|
| Установка | `pip install -r requirements.txt` |
| Установка (dev) | `pip install -e ".[dev]"` |
| Запуск (TUI) | `python main.py` |
| Запуск (headless) | `python main.py scan <файл> [--export …]` |
| Тесты | `pytest` (CI: `pytest --cov=app`) |
| Lint | `ruff check app tests` |
| Typecheck | `mypy app/` |
| Аудит зависимостей | `pip-audit` (CI, informational) |
| Build | - |

Команды - из `pyproject.toml`, `requirements.txt` и `.github/workflows/ci.yml`.

## Структура репозитория

```
DotTraceIP/
├── main.py              # точка входа → run_app()
├── config.json          # настройки (не в git)
├── pyproject.toml       # зависимости + extra dev, конфиг pytest/mypy
├── requirements.txt
├── app/
│   ├── cli.py           # TUI-меню (Rich)
│   ├── engine.py        # async-движок: семафор, asyncio.gather, Live-дашборд
│   ├── network.py       # источники: ip-api, Team Cymru/bgpview, RDAP, AbuseIPDB, Spamhaus
│   ├── export.py        # экспорт TXT/JSON/CSV/HTML
│   ├── config.py        # load/save config.json с merge дефолтов
│   └── utils.py         # файлы, валидация IP
├── tests/               # pytest + pytest-asyncio + aioresponses
├── .github/
│   ├── workflows/ci.yml # ruff + pytest + mypy + pip-audit
│   └── dependabot.yml   # обновления pip + github-actions
├── docs/audit/          # отчёты pre-deploy-audit (latest.md)
└── data/                # входные/выходные данные (не в git)
```

## Соглашения

- **Язык документации и UI:** русский. Весь вывод в `cli.py` - на русском.
- **Async:** HTTP-запросы через `aiohttp.ClientSession`; блокирующие вызовы (reverse DNS, RDAP, DNSBL) - через `loop.run_in_executor`. Новые источники добавляй как `_part_*`-корутины и включай в `asyncio.gather` внутри `get_ip_info`.
- **Совместимость CLI:** `run_scan` и `run_proxy_check` остаются синхронными обёртками над `asyncio.run` - не меняй их сигнатуры.
- **Контракт результата:** один dict на IP с ключами из `network.empty_info`; те же ключи - каноничные столбцы в `export.COLUMNS`. Добавил поле - обнови оба места.
- **Type hints:** обязательны для всех функций (стиль Python 3.12: `list[dict]`, `str | None`). `mypy app/` должен проходить.
- **Вывод в терминал:** через `rich.console.Console`, не `print`.
- **Именование:** snake_case для функций и переменных.

## Внешние источники

- Используй только бесплатные API или free tier. AbuseIPDB пропускается без ключа; bgpview.io - фолбэк к Team Cymru.
- Геолокация ip-api: без ключа - бесплатный HTTP; с `ip_api_key` - HTTPS через `pro.ip-api.com` (платный тариф ip-api).
- Любой источник опционален: его сбой не должен прерывать сбор остальных полей или весь скан.

## Конфигурация (`config.json`)

| Ключ | Назначение |
|------|------------|
| `threads` | лимит конкурентности (семафор) |
| `proxy_type` | `http` / `socks4` / `socks5` |
| `targets_file` / `proxies_file` / `output_file` | пути к данным |
| `export_format` | `txt` / `json` / `csv` / `html` / `all` |
| `abuseipdb_api_key` | ключ AbuseIPDB (пусто - источник пропускается) |
| `ip_api_key` | ip-api Pro-ключ: задан - геолокация по HTTPS (pro.ip-api.com); пусто - бесплатный HTTP |
| `enable_bgp` / `enable_spamhaus` | тумблеры обогащения BGP/ASN и Spamhaus |

Значения из `config.json` валидируются при загрузке (`config.load_config`): типы и диапазоны (`threads` ≤ `MAX_THREADS`), `proxy_type`/`export_format` по allowlist, пути целей/вывода удерживаются в пределах рабочего каталога.

Не читай и не коммить `config.json` с реальным ключом. Не выводи значение ключа в логи.

## Что делать агенту

- Перед правками прочитай затронутые файлы и соседний код.
- После изменений запусти `ruff check app tests`, `pytest` и `mypy app/`; для UI - вручную проверь `python main.py`.
- **README-sync:** при глобальных изменениях функционала (новые/удалённые команды, модули, зависимости, источники, смена архитектуры или runtime) обнови `README.md` и `AGENTS.md` через скилл `generate-readme` - в том числе пересчёт LoC. Мелкие правки (опечатки, внутренний рефактор) README не трогают.
- Не латай разметку README вручную - перегенерируй скиллом.
- Минимальный diff - не рефактори несвязанный код.
- Числа, пути, версии - только из репозитория.

## Чего не делать

- Не выдумывать команды, зависимости, env, API endpoints.
- Не добавлять `<details>`, centered hero, emoji в README DotCore.
- Не менять `docs/cover.svg` без регенерации обложки через скилл.
- Не менять `LICENSE` и текст лицензии без явного запроса пользователя.
- Не коммитить `config.json`, `data/*`, секреты, API-ключи.
- Не удалять маркеры `<!-- loc:start -->` / `<!-- loc:end -->` в README.

## Документация

- [README.md](README.md) - запуск, команды, стек, архитектура

## DotCore

Проект следует стандарту DotCore: плоский технический README, SVG-обложка DotBioSite, LoC-бейдж. При запросе «обнови README» используй скилл `generate-readme`.
