"""Small HTTP/WebSocket client + JSON-Schema validator for the MESTIO gateway API (docs/API.md).

Shared by tools/hw_smoke.py and tests/test_api_contract.py. Standard library only, except
`jsonschema` (schema checks; optional: SchemaSet.available is False without it) and `websockets`
(WebSocket checks). Works the same against the firmware and tools/mock_server.mjs.

Never opens serial devices; only talks HTTP/WS to the URL it is given.
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / 'docs' / 'api'
API = '/api/v1'
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class SchemaSet:
    """docs/api/*.schema.json in one referencing registry (relative $ref like
    common.schema.json#/$defs/u32 resolve against the shared $id base)."""

    def __init__(self, directory: Path = SCHEMA_DIR):
        self.directory = directory
        self.schemas: dict[str, dict] = {}
        for p in sorted(directory.glob('*.schema.json')):
            self.schemas[p.name[:-len('.schema.json')]] = json.loads(p.read_text(encoding='utf-8'))
        try:
            import jsonschema
            from referencing import Registry, Resource
        except ImportError:
            self.available = False
            return
        self.available = True
        self._jsonschema = jsonschema
        resources = [(s['$id'], Resource.from_contents(s)) for s in self.schemas.values() if '$id' in s]
        self.registry = Registry().with_resources(resources)
        self._validators = {}

    def validator(self, name: str):
        if name not in self._validators:
            schema = self.schemas[name]
            cls = self._jsonschema.validators.validator_for(schema)
            self._validators[name] = cls(schema, registry=self.registry,
                                         format_checker=cls.FORMAT_CHECKER)
        return self._validators[name]

    def errors(self, name: str, instance) -> list[str]:
        """Validation errors of instance against schema `name` ([] = valid). Unknown schema raises."""
        if name not in self.schemas:
            raise KeyError(f'no schema {name}.schema.json')
        if not self.available:
            return []
        out = []
        for e in sorted(self.validator(name).iter_errors(instance), key=lambda e: list(e.absolute_path)):
            where = '/'.join(map(str, e.absolute_path)) or '(root)'
            out.append(f'{name}: {where}: {e.message[:300]}')
        return out


@dataclass
class Response:
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]

    @property
    def json(self):
        try:
            return json.loads(self.body.decode('utf-8')) if self.body else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    def short(self) -> str:
        body = self.body[:200].decode('utf-8', 'replace')
        return f'HTTP {self.status} {body}'


@dataclass
class GwClient:
    """One logical client (one cookie jar). A new TCP connection per request keeps the client
    independent of server keep-alive limits (the firmware closes idle sockets via LRU purge)."""
    base_url: str
    timeout: float = 15.0
    sid: str | None = None
    csrf: str | None = None
    log: list = field(default_factory=list)

    def __post_init__(self):
        u = urllib.parse.urlsplit(self.base_url)
        if u.scheme != 'http' or not u.hostname:
            raise ValueError(f'only http://host[:port] URLs are supported: {self.base_url!r}')
        self.host = u.hostname
        self.port = u.port or 80
        self.host_header = u.netloc.rsplit('@', 1)[-1]
        self.origin = f'http://{self.host_header}'

    # ------------------------------------------------------------------ raw requests
    def raw(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None,
            host: str | None = '', skip_cookie: bool = False, read_timeout: float | None = None) -> Response:
        """host='' -> the URL's host; host=None -> no Host header at all; otherwise that value."""
        conn = http.client.HTTPConnection(self.host, self.port, timeout=read_timeout or self.timeout)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            if host is not None:
                conn.putheader('Host', self.host_header if host == '' else host)
            hdrs = dict(headers or {})
            if self.sid and not skip_cookie and 'Cookie' not in hdrs:
                hdrs['Cookie'] = f'gw_sid={self.sid}'
            if body is not None and 'Content-Length' not in hdrs:
                hdrs['Content-Length'] = str(len(body))
            for k, v in hdrs.items():
                if v is not None:
                    conn.putheader(k, v)
            conn.endheaders()
            if body:
                conn.send(body)
            r = conn.getresponse()
            data = r.read()
            resp = Response(r.status, r.reason, list(r.getheaders()), data)
        finally:
            conn.close()
        self.log.append((method, path, resp.status))
        self._take_cookie(resp)
        return resp

    def _take_cookie(self, resp: Response) -> None:
        for sc in resp.header_all('Set-Cookie'):
            name, _, rest = sc.partition('=')
            if name.strip() == 'gw_sid':
                val = rest.split(';', 1)[0].strip()
                self.sid = val or None

    def api(self, method: str, path: str, data=None, *, csrf: bool | str = True, origin: str | None = None,
            referer: str | None = None, headers: dict | None = None, host: str | None = '',
            content_type: str = 'application/json', raw_body: bytes | None = None) -> Response:
        """JSON request to /api/v1<path>. csrf=True sends the session token on mutating methods,
        False omits it, a string sends that value."""
        h = dict(headers or {})
        body = raw_body
        if data is not None:
            body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        if body is not None and content_type:
            h.setdefault('Content-Type', content_type)
        if method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            if csrf is True and self.csrf:
                h['X-CSRF-Token'] = self.csrf
            elif isinstance(csrf, str):
                h['X-CSRF-Token'] = csrf
        if origin is not None:
            h['Origin'] = origin
        if referer is not None:
            h['Referer'] = referer
        return self.raw(method, API + path, body, h, host=host)

    def get(self, path: str, **kw) -> Response:
        return self.api('GET', path, **kw)

    def login(self, user: str, password: str, **kw) -> Response:
        r = self.api('POST', '/auth/login', {'user': user, 'pass': password}, **kw)
        if r.status == 200 and isinstance(r.json, dict):
            self.csrf = r.json.get('csrf')
        return r

    def logout(self) -> Response:
        r = self.api('POST', '/auth/logout')
        if r.status == 204:
            self.sid = self.csrf = None
        return r

    # ------------------------------------------------------------------ WebSocket
    def ws_upgrade_status(self, host: str | None = '', origin: str | None = '', cookie: bool = True) -> Response:
        """Plain HTTP upgrade request (no WebSocket library) to observe refusals: 101 = accepted."""
        h = {'Upgrade': 'websocket', 'Connection': 'Upgrade', 'Sec-WebSocket-Version': '13',
             'Sec-WebSocket-Key': base64.b64encode(os.urandom(16)).decode()}
        if origin is not None:
            h['Origin'] = self.origin if origin == '' else origin
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            conn.putrequest('GET', '/ws', skip_host=True, skip_accept_encoding=True)
            if host is not None:
                conn.putheader('Host', self.host_header if host == '' else host)
            if cookie and self.sid:
                conn.putheader('Cookie', f'gw_sid={self.sid}')
            for k, v in h.items():
                conn.putheader(k, v)
            conn.endheaders()
            r = conn.getresponse()
            status, reason, hdrs = r.status, r.reason, list(r.getheaders())
            data = b'' if status == 101 else r.read()
        finally:
            conn.close()
        return Response(status, reason, hdrs, data)

    def ws_connect(self, timeout: float = 10.0):
        """websockets.sync client with this session's cookie and a same-origin Origin."""
        from websockets.sync.client import connect
        hdrs = {'Cookie': f'gw_sid={self.sid}'} if self.sid else {}
        return connect(f'ws://{self.host_header}/ws', origin=self.origin, additional_headers=hdrs,
                       open_timeout=timeout, close_timeout=2, proxy=None, compression=None,
                       max_size=256 * 1024, user_agent_header=None)


def port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
