"""HTTP routes."""

from flask import Flask, abort, jsonify, request

from acme_config import auth, notify, parser, render
from acme_config.store import ConfigStore

app = Flask(__name__)
store = ConfigStore()


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/configs/<name>", methods=["PUT"])
@auth.require_token
def upload_config(name):
    config = parser.parse_config(request.get_data())
    store.save(name, config)
    notify.config_changed(name, store.subscribers(name))
    return jsonify(name=name, keys=sorted(config))


@app.route("/configs/<name>", methods=["GET"])
@auth.require_token
def show_config(name):
    config = store.get(name)
    if config is None:
        abort(404)
    return render.config_page(name, config)


@app.route("/configs/<name>/subscribers", methods=["POST"])
@auth.require_token
def subscribe(name):
    store.subscribe(name, request.get_json()["url"])
    return jsonify(subscribed=True)


if __name__ == "__main__":
    app.run()
