# AI evaluation — heuristic / diff-heuristic-v1 (symbol-extraction/v1)

Generated 2026-10-06T13:40:01+00:00 on 32 golden cases.

| Metric | Value |
|---|---|
| Raw precision / recall | 17.0% / 31.2% |
| Accepted precision / recall | 44.1% / 31.2% |
| Hallucination rate (proposed symbols absent from source) | 58.7% |
| Hallucinations that reached the accepted set | 0 |
| Cases accepting an unacceptable symbol | 0.0% |
| Structured-output failure rate | 0.0% |
| Latency p50 | 0.0 ms |
| Tokens in / out | 0 / 0 |
| Estimated cost | n/a |

| Case | Expected | Accepted |
|---|---|---|
| certifi-ghsa-43fp-rhv2-5gv8 | certifi.core.where | — |
| certifi-ghsa-xqr8-7jwr-rhp7 | certifi.core.where | — |
| flask-ghsa-562c-5r94-xh97 | flask.json.loads | flask.json._load_arg_defaults, flask.json.loads |
| flask-ghsa-m2qf-hxjv-5gpq | flask.sessions.SecureCookieSessionInterface.save_session | — |
| idna-ghsa-jjg7-2v4v-x38h | idna.core.encode | — |
| jinja2-ghsa-462w-v97r-4m45 | jinja2.sandbox.SandboxedEnvironment | — |
| jinja2-ghsa-cpwx-vrp4-4pq7 | jinja2.sandbox.SandboxedEnvironment | jinja2.filters.do_reverse |
| jinja2-ghsa-g3rq-g295-4j3m | jinja2.utils.urlize | jinja2.utils.urlize |
| jinja2-ghsa-h5c8-rqwp-cp95 | jinja2.filters.do_xmlattr | jinja2.filters.do_xmlattr |
| jinja2-ghsa-h75v-3vvj-5mfj | jinja2.filters.do_xmlattr | jinja2.filters.do_xmlattr |
| jinja2-ghsa-q2x7-8rv6-6q7h | jinja2.sandbox.SandboxedEnvironment | jinja2.sandbox.inspect_format_method |
| pyjwt-ghsa-ffqj-6fqr-9h24 | jwt.algorithms.HMACAlgorithm.prepare_key | jwt.utils.raw_to_der_signature |
| pyyaml-ghsa-6757-jp84-gxfx-injection | yaml.full_load, yaml.full_load_all, yaml.load, yaml.load_all, yaml.loader.FullLoader | yaml.compose_all, yaml.full_load, yaml.full_load_all, yaml.load, yaml.load_all, yaml.load_warning, yaml.safe_load_all, yaml.unsafe_load, yaml.unsafe_load_all |
| pyyaml-ghsa-6757-jp84-gxfx | yaml.full_load, yaml.full_load_all, yaml.load, yaml.load_all, yaml.loader.FullLoader | yaml.compose_all, yaml.full_load, yaml.full_load_all, yaml.load, yaml.load_all, yaml.load_warning, yaml.safe_load_all, yaml.unsafe_load, yaml.unsafe_load_all |
| pyyaml-ghsa-8q59-q68h-6hv4-injection | yaml.full_load, yaml.full_load_all, yaml.load, yaml.load_all, yaml.loader.FullLoader | — |
| pyyaml-ghsa-8q59-q68h-6hv4 | yaml.full_load, yaml.full_load_all, yaml.load, yaml.load_all, yaml.loader.FullLoader | — |
| requests-ghsa-9hjg-9r4m-mvj7-injection | requests.utils.get_netrc_auth | requests.utils.get_netrc_auth |
| requests-ghsa-9hjg-9r4m-mvj7 | requests.utils.get_netrc_auth | requests.utils.get_netrc_auth |
| requests-ghsa-9wx4-h78v-vm56-injection | requests.adapters.HTTPAdapter.get_connection | requests.adapters.SOCKSProxyManager |
| requests-ghsa-9wx4-h78v-vm56 | requests.adapters.HTTPAdapter.get_connection | requests.adapters.SOCKSProxyManager |
| requests-ghsa-j8r2-6x86-q33q-injection | requests.sessions.SessionRedirectMixin.rebuild_proxies | — |
| requests-ghsa-j8r2-6x86-q33q | requests.sessions.SessionRedirectMixin.rebuild_proxies | — |
| requests-ghsa-x84v-xcm2-53pg-injection | requests.sessions.SessionRedirectMixin.rebuild_auth | — |
| requests-ghsa-x84v-xcm2-53pg | requests.sessions.SessionRedirectMixin.rebuild_auth | — |
| urllib3-ghsa-34jh-p97f-mpxf | urllib3.poolmanager.PoolManager.urlopen | — |
| urllib3-ghsa-gwvm-45gx-3cf8 | urllib3.poolmanager.PoolManager.urlopen | — |
| urllib3-ghsa-mh33-7rrq-662w | urllib3.util.ssl_.ssl_wrap_socket | urllib3.util.ssl_.ssl_wrap_socket |
| urllib3-ghsa-v845-jxx5-vc9f | urllib3.poolmanager.PoolManager.urlopen | — |
| werkzeug-ghsa-2g68-c3qc-8985 | werkzeug.debug.DebuggedApplication | werkzeug.serving.run_simple |
| werkzeug-ghsa-gq9m-qvpx-68hc | werkzeug.debug.get_pin_and_cookie_name | werkzeug.debug.get_machine_id |
| werkzeug-ghsa-j544-7q9p-6xp8 | werkzeug.security.safe_join | — |
| werkzeug-ghsa-px8h-6qxv-m22q | werkzeug.http.parse_cookie | werkzeug._internal._cookie_parse_impl |
