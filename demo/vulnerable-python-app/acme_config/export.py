"""Command-line export of stored configurations."""

import click
import yaml

from acme_config.store import ConfigStore


@click.command()
@click.argument("destination", type=click.File("w"))
def export(destination):
    """Write every stored configuration to DESTINATION as one YAML document."""
    yaml.dump(ConfigStore().all(), destination, default_flow_style=False)


if __name__ == "__main__":
    export()
