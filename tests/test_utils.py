import os

from app import utils


def test_read_lines_missing_file_returns_empty(tmp_path) -> None:
    assert utils.read_lines(str(tmp_path / "nope.txt")) == []


def test_read_lines_strips_and_skips_blanks(tmp_path) -> None:
    path = tmp_path / "ips.txt"
    path.write_text("  8.8.8.8 \n\n   \n1.1.1.1\n", encoding="utf-8")

    assert utils.read_lines(str(path)) == ["8.8.8.8", "1.1.1.1"]


def test_is_valid_ip_ipv4() -> None:
    assert utils.is_valid_ip("8.8.8.8")
    assert utils.is_valid_ip(" 192.168.0.1 ")


def test_is_valid_ip_ipv6() -> None:
    assert utils.is_valid_ip("2001:4860:4860::8888")
    assert utils.is_valid_ip("::1")


def test_is_valid_ip_rejects_junk() -> None:
    assert not utils.is_valid_ip("not-an-ip")
    assert not utils.is_valid_ip("999.999.999.999")
    assert not utils.is_valid_ip("")


def test_filter_valid_ips_splits() -> None:
    valid, invalid = utils.filter_valid_ips(["8.8.8.8", "garbage", "::1", "1.2.3"])
    assert valid == ["8.8.8.8", "::1"]
    assert invalid == ["garbage", "1.2.3"]


def test_dedup_preserve_order() -> None:
    items = ["8.8.8.8", "1.1.1.1", "8.8.8.8", "9.9.9.9", "1.1.1.1"]
    assert utils.dedup_preserve(items) == ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def test_init_result_file_creates_dir_and_empties(tmp_path) -> None:
    target = tmp_path / "sub" / "out.txt"
    utils.init_result_file(str(target))

    assert target.exists()
    assert target.read_text(encoding="utf-8") == ""


def test_init_result_file_truncates_existing(tmp_path) -> None:
    target = tmp_path / "out.txt"
    target.write_text("старые данные", encoding="utf-8")

    utils.init_result_file(str(target))

    assert target.read_text(encoding="utf-8") == ""


def test_append_result_writes_header_and_fields(tmp_path) -> None:
    target = tmp_path / "out.txt"
    utils.init_result_file(str(target))
    utils.append_result({"IP": "8.8.8.8", "Country": "США", "City": "Эшберн"}, str(target))

    content = target.read_text(encoding="utf-8")
    lines = content.splitlines()
    assert "=== IP: 8.8.8.8 ===" in lines
    assert "Country: США" in lines
    assert "City: Эшберн" in lines
    assert "IP: 8.8.8.8" not in lines  # IP идёт только в заголовок, не как поле


def test_append_result_appends_multiple(tmp_path) -> None:
    target = tmp_path / "out.txt"
    utils.init_result_file(str(target))
    utils.append_result({"IP": "8.8.8.8", "Country": "США"}, str(target))
    utils.append_result({"IP": "1.1.1.1", "Country": "Австралия"}, str(target))

    content = target.read_text(encoding="utf-8")
    assert content.count("=== IP:") == 2


def test_init_files_creates_data_dir(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    utils.init_files()

    assert os.path.isdir("data")
    assert os.path.exists("data/target_ips.txt")
    assert os.path.exists("data/proxies.txt")
