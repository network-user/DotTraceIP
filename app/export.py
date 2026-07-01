import csv
import html
import json
import os
from typing import Any

# Каноничный порядок столбцов (совпадает с network.empty_info).
COLUMNS: list[str] = [
    "IP",
    "Hostname",
    "Country",
    "City",
    "Lat",
    "Lon",
    "ISP",
    "ASN",
    "ASN_Name",
    "Network_CIDR",
    "BGP_Prefix",
    "RIR_Country",
    "Abuse_Score",
    "Abuse_Reports",
    "Abuse_Last_Reported",
    "Spamhaus",
    "Proxy",
    "Status",
    "Error_Msg",
]


def _ordered_columns(results: list[dict[str, Any]]) -> list[str]:
    """Каноничные столбцы плюс любые нестандартные ключи, появившиеся в данных."""
    present = [col for col in COLUMNS if any(col in row for row in results)]
    seen = set(COLUMNS)
    extra: list[str] = []
    for row in results:
        for key in row:
            if key not in seen:
                seen.add(key)
                extra.append(key)
    return present + extra


# Символы, с которых формульный парсер Excel/LibreOffice/Sheets начинает
# вычисление. Нейтрализуем ведущим апострофом - защита от CSV formula injection
# в полях из недоверенных источников (PTR, whois, текст ошибок).
_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_cell(value: Any) -> Any:
    """Экранирует строковую ячейку CSV от инъекции формул. Числа не трогает.

    Ведущие пробелы игнорируются: `" =SUM()"` тоже нейтрализуется, иначе часть
    парсеров таблиц обрежет пробел и выполнит формулу.
    """
    if isinstance(value, str):
        stripped = value.lstrip()
        if stripped and stripped[0] in _CSV_INJECTION_PREFIXES:
            return "'" + value
    return value


def _atomic_write(path: str, text: str) -> None:
    """Пишет файл атомарно: во временный файл рядом, затем os.replace.

    Защищает от частично записанного отчёта при сбое и не следует по симлинку
    на месте конечного файла (replace заменяет сам симлинк, а не его цель).
    """
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    os.replace(tmp, path)


def export_json(results: list[dict[str, Any]], path: str) -> None:
    """Записывает результаты в JSON (UTF-8, с отступами, без экранирования кириллицы)."""
    _atomic_write(path, json.dumps(results, indent=2, ensure_ascii=False))


def export_csv(results: list[dict[str, Any]], path: str) -> None:
    """Записывает результаты в CSV. Заголовок - объединение встреченных столбцов.

    Значения экранируются от инъекции формул (см. _sanitize_cell).
    """
    columns = _ordered_columns(results) or list(COLUMNS)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore", restval="")
        writer.writeheader()
        for row in results:
            writer.writerow({key: _sanitize_cell(value) for key, value in row.items()})
    os.replace(tmp, path)


def export_html(results: list[dict[str, Any]], path: str) -> None:
    """Записывает самодостаточный HTML с таблицей и JS-сортировкой по столбцам."""
    columns = _ordered_columns(results) or list(COLUMNS)

    head_cells = "".join(
        f'<th onclick="sortTable({i})">{html.escape(col)}<span class="arrow"></span></th>'
        for i, col in enumerate(columns)
    )

    body_rows = []
    for row in results:
        cells = "".join(
            f"<td>{html.escape(str(row.get(col, '')))}</td>" for col in columns
        )
        body_rows.append(f"<tr>{cells}</tr>")
    body_html = "\n".join(body_rows) or (
        f'<tr><td colspan="{len(columns)}" class="empty">Нет данных</td></tr>'
    )

    document = _HTML_TEMPLATE.format(
        count=len(results),
        head=head_cells,
        body=body_html,
    )
    _atomic_write(path, document)


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DotTraceIP - отчёт</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin: 0; padding: 24px; background: #0d1117; color: #e6edf3;
         font-family: "Segoe UI", system-ui, sans-serif; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .meta {{ color: #8b949e; font-size: 13px; margin-bottom: 16px; }}
  .wrap {{ overflow-x: auto; border: 1px solid #30363d; border-radius: 8px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
  th, td {{ padding: 8px 10px; text-align: left; white-space: nowrap;
            border-bottom: 1px solid #21262d; }}
  th {{ position: sticky; top: 0; background: #161b22; cursor: pointer;
        user-select: none; color: #58a6ff; }}
  th:hover {{ background: #1f2630; }}
  tr:hover td {{ background: #161b22; }}
  td.empty {{ text-align: center; color: #8b949e; padding: 24px; }}
  .arrow {{ font-size: 10px; margin-left: 4px; color: #8b949e; }}
</style>
</head>
<body>
<h1>DotTraceIP - отчёт по IP</h1>
<div class="meta">Записей: {count}. Клик по заголовку столбца - сортировка.</div>
<div class="wrap">
<table id="report">
<thead><tr>{head}</tr></thead>
<tbody>
{body}
</tbody>
</table>
</div>
<script>
function sortTable(col) {{
  var table = document.getElementById("report");
  var tbody = table.tBodies[0];
  var rows = Array.prototype.slice.call(tbody.rows).filter(function (r) {{
    return !r.querySelector("td.empty");
  }});
  var asc = table.getAttribute("data-col") != col ||
            table.getAttribute("data-dir") != "asc";
  rows.sort(function (a, b) {{
    var x = a.cells[col].textContent.trim();
    var y = b.cells[col].textContent.trim();
    var nx = parseFloat(x), ny = parseFloat(y);
    var both = !isNaN(nx) && !isNaN(ny) && x !== "" && y !== "";
    var cmp = both ? nx - ny : x.localeCompare(y, "ru");
    return asc ? cmp : -cmp;
  }});
  rows.forEach(function (r) {{ tbody.appendChild(r); }});
  table.setAttribute("data-col", col);
  table.setAttribute("data-dir", asc ? "asc" : "desc");
  var heads = table.tHead.rows[0].cells;
  for (var i = 0; i < heads.length; i++) {{
    var arrow = heads[i].querySelector(".arrow");
    if (arrow) arrow.textContent = (i == col) ? (asc ? "\\u25B2" : "\\u25BC") : "";
  }}
}}
</script>
</body>
</html>
"""
