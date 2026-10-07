"""Parsing uploaded configuration documents."""

import yaml


class InvalidConfig(ValueError):
    pass


def parse_config(raw):
    # FullLoader was documented as safe for untrusted input when this was written.
    # CVE-2020-14343 showed it is not: it can construct arbitrary Python objects.
    document = yaml.load(raw, Loader=yaml.FullLoader)
    if not isinstance(document, dict):
        raise InvalidConfig("a configuration must be a mapping")
    return document
