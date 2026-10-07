# acme-config — a deliberately vulnerable sample application

> **Do not deploy this.** It exists only as the scan target for Sieve's public demo.

A small Flask service that stores YAML configuration documents, renders them as HTML, and
notifies subscriber webhooks when a document changes. It pins dependency versions from 2018–2021
on purpose, so that real, published advisories apply to it.

Sieve never runs this code. The demo parses it statically, exactly like any customer repository.

What the code does with its dependencies (and therefore what a reachability analysis should find):

| Dependency | How the app uses it |
|---|---|
| PyYAML | `yaml.load(..., Loader=FullLoader)` on uploaded request bodies; `safe_dump` for display; `dump` in a CLI export |
| PyJWT | `jwt.decode(token, key, algorithms=["HS256"])` on every config route |
| requests (→ urllib3) | `requests.post` to subscriber webhooks |
| Jinja2 | renders one inline template with autoescaping, no sandbox |
| Flask / Werkzeug / click | the web framework and the export CLI |
| Pillow | listed in requirements but no longer imported (left over from a removed feature) |

`tests/` calls `yaml.load` directly; Sieve excludes test code from application roots, so those calls
do not make anything reachable.
