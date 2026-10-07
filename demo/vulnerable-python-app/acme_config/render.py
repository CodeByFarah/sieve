"""HTML rendering of a stored configuration."""

import yaml
from jinja2 import Environment, select_autoescape

_environment = Environment(autoescape=select_autoescape(default=True))
_page = _environment.from_string(
    "<h1>{{ name }}</h1>\n<pre>{{ body }}</pre>\n"
)


def config_page(name, config):
    return _page.render(name=name, body=yaml.safe_dump(config, default_flow_style=False))
