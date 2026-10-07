import yaml

from acme_config.parser import parse_config


def test_parse_config_returns_mapping():
    assert parse_config(b"a: 1") == {"a": 1}


def test_round_trip():
    assert yaml.load(yaml.dump({"a": 1}), Loader=yaml.Loader) == {"a": 1}
