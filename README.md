# DotTraceIP

<p>
  <img src="https://img.shields.io/badge/Python-3.12%2B-3776AB?style=flat" alt="Python" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-555?style=flat" alt="Platform" />
  <img src="https://img.shields.io/badge/Category-CLI%20%2F%20Network-orange?style=flat" alt="Category" />
  <!-- loc:start --><img src="https://img.shields.io/badge/lines_of_code-1k%2B-lightgrey?style=flat" alt="1k+ lines of code" /><!-- loc:end -->
</p>

<img src="docs/cover.svg" width="720" alt="DotTraceIP" />

Асинхронный CLI для массового анализа IP-адресов: геолокация, ASN и BGP-префикс, обратный DNS, проверка репутации. Инструмент вырос из практической задачи - разобрать по логам сервера, из каких стран боты перебирают пароли к SSH/RDP; так же подходит для анализа трафика сайта или продукта. Движок на `asyncio` + `aiohttp` опрашивает по каждому IP несколько источников параллельно и пишет отчёт в TXT, JSON, CSV или HTML.

## Что внутри

- **Геолокация**: страна, город, координаты, ISP через ip-api.com.
- **ASN и BGP**: номер и имя автономной системы, BGP-префикс (CIDR), country_code через Team Cymru (DNS), HTTP-фолбэк на bgpview.io.
- **Сеть владельца**: CIDR через RDAP (ipwhois).
- **Обратный DNS**: PTR-запись хоста.
- **Репутация**: AbuseIPDB (confidence score, число жалоб - нужен бесплатный ключ) и Spamhaus DNSBL с разбором кодов ответа.
- **Прокси**: HTTP, SOCKS4, SOCKS5 (aiohttp-socks), случайная ротация пула против rate-limit, маскировка кредов в выводе.
- **Экспорт**: TXT, JSON, CSV и самодостаточный HTML с сортировкой по столбцам без внешних зависимостей.
- **Async-движок**: до N IP параллельно (семафор), живой Rich-дашборд с журналом последних результатов.

6 источников данных на один IP, 4 формата экспорта, 64 теста.

## Запуск

```bash
pip install -r requirements.txt
python main.py
```

Первый запуск создаёт `data/target_ips.txt` и `data/proxies.txt`. Добавь IP-адреса (по одному в строке), при необходимости прокси, затем выбери «Запустить сканирование» в меню. Ключ AbuseIPDB и формат экспорта задаются в «Настройки системы».

Для автоматизации и анализа логов есть неинтерактивный режим:

```bash
python main.py scan logs.txt --export csv
```

## Команды

| Команда | Назначение |
|---------|------------|
| `pip install -r requirements.txt` | установка runtime-зависимостей |
| `python main.py` | интерактивное TUI-меню |
| `python main.py scan logs.txt` | неинтерактивный скан файла с IP |
| `pip install -e ".[dev]"` | установка с dev-зависимостями |
| `pytest` | запуск тестов |
| `ruff check app tests` | линтер |
| `mypy app/` | проверка типов |

## Стек

<p>
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/aiohttp-2C5BB4?style=for-the-badge" alt="aiohttp" />
  <img src="https://img.shields.io/badge/aiohttp--socks-555555?style=for-the-badge" alt="aiohttp-socks" />
  <img src="https://img.shields.io/badge/dnspython-1a365d?style=for-the-badge" alt="dnspython" />
  <img src="https://img.shields.io/badge/ipwhois-1a365d?style=for-the-badge" alt="ipwhois" />
  <img src="https://img.shields.io/badge/rich-2d3748?style=for-the-badge" alt="rich" />
  <img src="https://img.shields.io/badge/pytest-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white" alt="pytest" />
  <img src="https://img.shields.io/badge/mypy-2C5282?style=for-the-badge" alt="mypy" />
  <img src="https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white" alt="GitHub Actions" />
</p>

## Тесты

```bash
pip install -e ".[dev]"
ruff check app tests
pytest --cov=app
mypy app/
```

64 теста на `pytest` + `pytest-asyncio` + `aioresponses` (мок aiohttp). GitHub Actions гоняет `ruff`, `pytest --cov` и `mypy app/` на Python 3.12 при push и pull request в `main`.

## Архитектура

`cli.py` рисует TUI-меню (Rich Prompt + Panel), `engine.py` - асинхронный движок: семафор ограничивает конкурентность, `asyncio.gather` собирает источники по каждому IP, `Live` рисует прогресс и журнал. `network.py` опрашивает источники (HTTP через `aiohttp`, DNS/RDAP - в thread pool), `export.py` пишет отчёты, `config.py` и `utils.py` - вспомогательные. `main.py` зовёт синхронные обёртки `run_scan`/`run_proxy_check`, которые внутри запускают `asyncio.run`, поэтому интерфейс CLI остался прежним.

```
DotTraceIP/
├── main.py              # точка входа → run_app()
├── config.json          # настройки (не в git)
├── pyproject.toml       # зависимости + extra dev, конфиг pytest/mypy
├── requirements.txt
├── app/
│   ├── cli.py           # TUI-меню (Rich Prompt + Panel)
│   ├── engine.py        # async-движок: семафор, asyncio.gather, Live-дашборд
│   ├── network.py       # источники: ip-api, Team Cymru/bgpview, RDAP, AbuseIPDB, Spamhaus
│   ├── export.py        # экспорт TXT / JSON / CSV / HTML
│   ├── config.py        # load/save config.json с merge дефолтов
│   └── utils.py         # файлы, валидация IP
├── tests/               # pytest + pytest-asyncio + aioresponses
├── .github/workflows/
│   └── ci.yml           # pytest + mypy на Python 3.12
└── data/                # входные/выходные данные (не в git)
```

- каждый IP собирается через `asyncio.gather`; сбой одного источника не прерывает остальные и не роняет скан
- синхронные `run_scan` / `run_proxy_check` - обёртки над `asyncio.run`, CLI-интерфейс не менялся
- AbuseIPDB включается только при заданном ключе в `config.json`; bgpview.io - фолбэк к Team Cymru
- при нераспарсиваемом прокси HTTP-источники не уходят в прямое соединение - реальный IP не утекает
- `config.json` и `data/*` не коммитятся


## Отказ от ответственности

Программное обеспечение DotTraceIP предоставляется "как есть" (as is). Данный инструмент разработан исключительно для сетевого администрирования, легитимного анализа данных и образовательных целей. Разработчик не несет ответственности за любой прямой или косвенный ущерб, а также за любые неправомерные действия, совершенные конечным пользователем с использованием данного программного обеспечения. Вся ответственность за применение инструмента, корректную настройку интервалов запросов и соблюдение действующего законодательства полностью лежит на пользователе.

## Лицензия

© 2026 DotCore. Все права защищены.

Проприетарный код. Использование, копирование, изменение и распространение запрещены без письменного разрешения автора. Исходный код открыт только для ознакомления. См. [LICENSE](LICENSE).
