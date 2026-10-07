"""In-memory configuration store (the demo has no database)."""


class ConfigStore:
    def __init__(self):
        self._configs = {}
        self._subscribers = {}

    def save(self, name, config):
        self._configs[name] = config

    def get(self, name):
        return self._configs.get(name)

    def all(self):
        return dict(self._configs)

    def subscribe(self, name, url):
        self._subscribers.setdefault(name, []).append(url)

    def subscribers(self, name):
        return list(self._subscribers.get(name, []))
