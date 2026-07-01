import csv
import json
import re

from app import export


def test_export_json_writes_list(tmp_path, sample_results) -> None:
    path = tmp_path / "r.json"
    export.export_json(sample_results, str(path))

    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) == 3
    assert data[0]["IP"] == "8.8.8.8"


def test_export_json_preserves_unicode(tmp_path, sample_results) -> None:
    path = tmp_path / "r.json"
    export.export_json(sample_results, str(path))

    raw = path.read_text(encoding="utf-8")
    assert "США" in raw
    assert "\\u" not in raw  # кириллица не экранирована


def test_export_csv_header_has_canonical_columns(tmp_path, sample_results) -> None:
    path = tmp_path / "r.csv"
    export.export_csv(sample_results, str(path))

    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []

    for col in ("IP", "Country", "ASN", "BGP_Prefix", "Abuse_Score", "Spamhaus"):
        assert col in fields


def test_export_csv_row_count(tmp_path, sample_results) -> None:
    path = tmp_path / "r.csv"
    export.export_csv(sample_results, str(path))

    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == len(sample_results)


def test_export_csv_includes_error_column(tmp_path, sample_results) -> None:
    path = tmp_path / "r.csv"
    export.export_csv(sample_results, str(path))

    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert "Error_Msg" in (reader.fieldnames or [])
    err_row = next(r for r in rows if r["IP"] == "5.5.5.5")
    assert err_row["Error_Msg"] == "timeout"


def test_export_html_is_self_contained(tmp_path, sample_results) -> None:
    path = tmp_path / "r.html"
    export.export_html(sample_results, str(path))

    html_txt = path.read_text(encoding="utf-8")
    external = re.findall(r"(?:src|href)\s*=\s*['\"]https?://", html_txt)
    assert external == []


def test_export_html_has_sort_script_and_data(tmp_path, sample_results) -> None:
    path = tmp_path / "r.html"
    export.export_html(sample_results, str(path))

    html_txt = path.read_text(encoding="utf-8")
    assert "sortTable" in html_txt
    assert "<table" in html_txt
    assert "Эшберн" in html_txt
    assert "timeout" in html_txt


def test_export_html_escapes_values(tmp_path) -> None:
    results = [{"IP": "8.8.8.8", "ISP": "<b>evil</b>", "Status": "OK"}]
    path = tmp_path / "r.html"
    export.export_html(results, str(path))

    html_txt = path.read_text(encoding="utf-8")
    assert "&lt;b&gt;evil&lt;/b&gt;" in html_txt
    assert "<b>evil</b>" not in html_txt


def test_export_html_empty_results(tmp_path) -> None:
    path = tmp_path / "r.html"
    export.export_html([], str(path))

    html_txt = path.read_text(encoding="utf-8")
    assert "<table" in html_txt
    assert "Нет данных" in html_txt


def test_ordered_columns_skips_absent_canonical() -> None:
    # Каноничные столбцы, которых нет ни в одной строке, не попадают в вывод.
    results = [{"IP": "8.8.8.8", "Country": "США", "Status": "OK"}]
    cols = export._ordered_columns(results)
    assert "IP" in cols
    assert "Country" in cols
    assert "RIR_Country" not in cols
    assert "Abuse_Score" not in cols


def test_ordered_columns_appends_unknown_keys() -> None:
    results = [{"IP": "8.8.8.8", "Custom_Field": "x"}]
    cols = export._ordered_columns(results)
    assert cols[0] == "IP"
    assert "Custom_Field" in cols


# --------------------------------------------------------------------------- #
# Безопасность экспорта (CSV-инъекция, атомарная запись)
# --------------------------------------------------------------------------- #
def test_export_csv_neutralizes_formula_injection(tmp_path) -> None:
    # Поля из недоверенных источников (PTR/whois) не должны исполняться как формулы.
    results = [
        {"IP": "8.8.8.8", "Hostname": "=cmd|'/c calc'!A1", "ISP": "+evil", "Status": "OK"}
    ]
    path = tmp_path / "r.csv"
    export.export_csv(results, str(path))

    with open(path, encoding="utf-8", newline="") as f:
        row = next(csv.DictReader(f))
    assert row["Hostname"].startswith("'=")
    assert row["ISP"].startswith("'+")


def test_export_csv_neutralizes_leading_whitespace_formula(tmp_path) -> None:
    # Ведущий пробел не должен позволять формуле проскочить санитайзер.
    results = [{"IP": "8.8.8.8", "Hostname": " =SUM(A1)", "Status": "OK"}]
    path = tmp_path / "r.csv"
    export.export_csv(results, str(path))

    with open(path, encoding="utf-8", newline="") as f:
        row = next(csv.DictReader(f))
    assert row["Hostname"].startswith("'")


def test_export_csv_keeps_numbers_intact(tmp_path, sample_results) -> None:
    # Отрицательные координаты (float) не должны получать ведущий апостроф.
    path = tmp_path / "r.csv"
    export.export_csv(sample_results, str(path))

    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    row = next(r for r in rows if r["IP"] == "1.1.1.1")
    assert row["Lat"] == "-33.49"


def test_export_leaves_no_tmp_file(tmp_path, sample_results) -> None:
    for ext, fn in (
        ("json", export.export_json),
        ("csv", export.export_csv),
        ("html", export.export_html),
    ):
        path = tmp_path / f"r.{ext}"
        fn(sample_results, str(path))
        assert path.exists()
        assert not (tmp_path / f"r.{ext}.tmp").exists()
