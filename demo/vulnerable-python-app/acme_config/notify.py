"""Webhook notifications to subscribers."""

import requests

TIMEOUT_SECONDS = 5


def config_changed(name, subscriber_urls):
    for url in subscriber_urls:
        requests.post(url, json={"event": "config.changed", "config": name}, timeout=TIMEOUT_SECONDS)
