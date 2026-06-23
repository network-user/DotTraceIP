import io

from rich.console import Console

import app.engine as engine
from app.network import empty_info


def _console() -> Console:
    return Console(file=io.StringIO(), width=100)


def test_run_scan_headless_exports(tmp_path, base_config, monkeypatch) -> None:
    out = tmp_path / "results.txt"
    base_config["output_file"] = str(out)
    base_config["export_format"] = "json"

    async def fake_get_ip_info(ip, proxy_list, proxy_type, config):
        info = empty_info(ip)
        info["Country"] = "США"
        return info

    monkeypatch.setattr(engine, "get_ip_info", fake_get_ip_info)
    engine.run_scan(["8.8.8.8", "1.1.1.1"], None, base_config, _console(), use_live=False)

    assert out.exists()
    assert (tmp_path / "results.json").exists()


def test_run_scan_dedups_targets(tmp_path, base_config, monkeypatch) -> None:
    out = tmp_path / "results.txt"
    base_config["output_file"] = str(out)
    base_config["export_format"] = "txt"
    seen: list[str] = []

    async def fake_get_ip_info(ip, proxy_list, proxy_type, config):
        seen.append(ip)
        return empty_info(ip)

    monkeypatch.setattr(engine, "get_ip_info", fake_get_ip_info)
    engine.run_scan(
        ["8.8.8.8", "8.8.8.8", "1.1.1.1"], None, base_config, _console(), use_live=False
    )

    assert sorted(seen) == ["1.1.1.1", "8.8.8.8"]  # дубль 8.8.8.8 убран


def test_reputation_cell_marks_abuse() -> None:
    high = engine._reputation_cell({"Abuse_Score": 80, "Spamhaus": "В списке"})
    clean = engine._reputation_cell({"Abuse_Score": 0, "Spamhaus": "Чисто"})
    empty = engine._reputation_cell({})
    assert "spamhaus" in high and "80" in high
    assert "чисто" in clean
    assert empty == "-"
