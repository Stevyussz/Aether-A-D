"""Deliberately-vulnerable isolated TCP lab services (127.0.0.1 only).

Models the non-HTTP services common in Attack & Defense: a custom line-protocol vault/note
store, an unauthenticated Redis, and an unauthenticated Memcached. Used to prove the raw-TCP
and data-store exploit modules genuinely recover a flag from a REAL protocol exchange.

NOT part of the competition runtime. Never point at real infrastructure.
"""

from __future__ import annotations

import argparse
import socketserver
import threading


class _Server:
    """Common start/stop/port wrapper around a ThreadingTCPServer."""

    def __init__(self, handler_cls, host: str = "127.0.0.1", port: int = 0) -> None:
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self._server = socketserver.ThreadingTCPServer((host, port), handler_cls)
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    def start(self):
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


# --------------------------------------------------------------------------- vault

def _vault_handler(flag: str, secret_id: str = "7"):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.wfile.write(b"VAULT v1 - type HELP\n")
            self.wfile.flush()
            while True:
                raw = self.rfile.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").strip()
                up = line.upper()
                if up in ("HELP", "?", "MENU"):
                    resp = "commands: LIST GET <id> DUMP FLAG\n"
                elif up in ("LIST", "LS"):
                    resp = f"records: 0..9 (record {secret_id} is private)\n"
                elif up in ("DUMP", "ALL", "SHOW", "GETFLAG", "FLAG", "CAT FLAG",
                            "GET FLAG", "READ FLAG"):
                    resp = f"flag: {flag}\n"
                elif up.split() and up.split()[0] in ("GET", "READ", "SHOW", "FETCH"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == secret_id:
                        resp = f"record {secret_id}: {flag}\n"
                    else:
                        resp = "record: (empty)\n"
                else:
                    resp = "unknown command\n"
                self.wfile.write(resp.encode())
                self.wfile.flush()

        def log_message(self, *a):  # pragma: no cover
            return
    return Handler


class VaultTcpService(_Server):
    def __init__(self, flag: str, host="127.0.0.1", port=0, secret_id="7"):
        super().__init__(_vault_handler(flag, secret_id), host, port)


# --------------------------------------------------------------------------- redis

def _redis_handler(flag: str):
    store = {"flag": flag, "notes": "nothing-here", "team": "us"}

    def read_command(rfile):
        line = rfile.readline()
        if not line:
            return None
        line = line.strip()
        if line.startswith(b"*"):
            try:
                n = int(line[1:])
            except ValueError:
                return []
            args = []
            for _ in range(n):
                hdr = rfile.readline().strip()  # $<len>
                if not hdr.startswith(b"$"):
                    return args
                ln = int(hdr[1:])
                data = rfile.read(ln)
                rfile.read(2)  # trailing CRLF
                args.append(data.decode("utf-8", "replace"))
            return args
        return line.decode("utf-8", "replace").split()

    def bulk(s: str) -> bytes:
        b = s.encode()
        return b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"

    def array(items: list[str]) -> bytes:
        out = b"*" + str(len(items)).encode() + b"\r\n"
        for it in items:
            out += bulk(it)
        return out

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            while True:
                args = read_command(self.rfile)
                if args is None:
                    break
                if not args:
                    continue
                cmd = args[0].upper()
                if cmd == "INFO":
                    self.wfile.write(bulk("redis_version:6.0.0\r\nrole:master"))
                elif cmd == "CONFIG":
                    self.wfile.write(array(["maxmemory", "0", "save", ""]))
                elif cmd == "KEYS":
                    self.wfile.write(array(list(store)))
                elif cmd == "GET" and len(args) >= 2:
                    self.wfile.write(bulk(store.get(args[1], "")))
                elif cmd in ("HGETALL", "LRANGE", "SMEMBERS"):
                    self.wfile.write(array([]))
                elif cmd == "PING":
                    self.wfile.write(b"+PONG\r\n")
                else:
                    self.wfile.write(b"-ERR unknown\r\n")
                self.wfile.flush()
    return Handler


class FakeRedisService(_Server):
    def __init__(self, flag: str, host="127.0.0.1", port=0):
        super().__init__(_redis_handler(flag), host, port)


# --------------------------------------------------------------------------- memcached

def _memcached_handler(flag: str):
    store = {"flag": flag, "greeting": "hello"}

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            while True:
                raw = self.rfile.readline()
                if not raw:
                    break
                parts = raw.decode("utf-8", "replace").strip().split()
                if not parts:
                    continue
                cmd = parts[0].lower()
                if cmd == "version":
                    self.wfile.write(b"VERSION 1.6.0\r\n")
                elif cmd == "stats" and len(parts) >= 2 and parts[1] == "items":
                    self.wfile.write(b"STAT items:1:number 2\r\nEND\r\n")
                elif cmd == "stats" and len(parts) >= 2 and parts[1] == "cachedump":
                    body = "".join(f"ITEM {k} [{len(v)} b; 0 s]\r\n" for k, v in store.items())
                    self.wfile.write((body + "END\r\n").encode())
                elif cmd == "get" and len(parts) >= 2:
                    out = ""
                    for key in parts[1:]:
                        if key in store:
                            v = store[key]
                            out += f"VALUE {key} 0 {len(v)}\r\n{v}\r\n"
                    out += "END\r\n"
                    self.wfile.write(out.encode())
                else:
                    self.wfile.write(b"ERROR\r\n")
                self.wfile.flush()
    return Handler


class FakeMemcachedService(_Server):
    def __init__(self, flag: str, host="127.0.0.1", port=0):
        super().__init__(_memcached_handler(flag), host, port)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", choices=("vault", "redis", "memcached"), default="vault")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--flag", default="IONIC{tcp_lab_demo}")
    args = ap.parse_args()
    cls = {"vault": VaultTcpService, "redis": FakeRedisService,
           "memcached": FakeMemcachedService}[args.kind]
    svc = cls(args.flag, port=args.port).start()
    print(f"{args.kind} lab service on {svc.host}:{svc.port}  (Ctrl-C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        svc.stop()
