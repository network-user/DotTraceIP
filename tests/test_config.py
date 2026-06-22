import json

from app import config


def test_default_config_has_expected_keys() -> None:
    cfg = config.default_config()
    for key in (
        "threads", "proxy_type", "proxies_file", "targets_file", "output_file",
        "export_format", "abuseipdb_api_key", "enable_bgp", "enable_spamhaus",
    ):
        assert key in cfg


def test_load_config_creates_file_when_missing(tmp_path) -> None:
    path = tmp_path / "config.json"
    assert not path.exists()

    cfg = config.load_config(str(path))

    assert path.exists()
    assert cfg == config.default_config()


def test_load_config_returns_all_default_keys(tmp_path) -> None:
    path = tmp_path / "config.json"
    cfg = config.load_config(str(path))
    assert set(cfg) == set(config.default_config())


def test_load_config_merges_missing_keys(tmp_path) -> None:
    path = tmp_path / "config.json"
    # Старый конфиг без новых полей.
    path.write_text(json.dumps({"threads": 99}), encoding="utf-8")

    cfg = config.load_config(str(path))

    assert cfg["threads"] == 99  # пользовательское значение сохранено
    assert "export_format" in cfg  # недостающее поле добавлено
    assert cfg["export_format"] == config.default_config()["export_format"]


def test_load_config_invalid_json_returns_defaults(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text("{ это не json", encoding="utf-8")

    cfg = config.load_config(str(path))

    assert cfg == config.default_config()


def test_load_config_non_dict_returns_defaults(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")

    cfg = config.load_config(str(path))

    assert cfg == config.default_config()


def test_save_and_load_roundtrip(tmp_path) -> None:
    path = tmp_path / "config.json"
    custom = config.default_config()
    custom["threads"] = 50
    custom["export_format"] = "csv"
    custom["abuseipdb_api_key"] = "secret-key"

    config.save_config(custom, str(path))
    loaded = config.load_config(str(path))

    assert loaded["threads"] == 50
    assert loaded["export_format"] == "csv"
    assert loaded["abuseipdb_api_key"] == "secret-key"


def test_save_config_writes_utf8(tmp_path) -> None:
    path = tmp_path / "config.json"
    cfg = config.default_config()
    cfg["targets_file"] = "данные/цели.txt"

    config.save_config(cfg, str(path))
    raw = path.read_text(encoding="utf-8")

    assert "данные/цели.txt" in raw  # кириллица не экранирована в \uXXXX
