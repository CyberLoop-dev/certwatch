#!/usr/bin/env python3
"""certwatch: check TLS certificate expiry for many hosts at once.

    python certwatch.py example.com github.com:443
    python certwatch.py -f hosts.txt --warn 30 --crit 7
    python certwatch.py -f hosts.txt --json

Exit codes: 0 all fine, 1 at least one warning, 2 at least one critical or failed check.
"""
import argparse
import json
import os
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def col(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)


def split_target(t):
    t = t.strip().replace("https://", "").split("/")[0]
    if t.count(":") == 1:
        host, port = t.split(":")
        return host, int(port)
    return t, 443


def name_of(rdn):
    return ", ".join(v for tup in rdn for k, v in tup if k in ("commonName", "organizationName"))


def check(target, timeout, warn, crit):
    host, port = split_target(target)
    res = {"host": host, "port": port, "status": "ERROR", "days": None, "expires": None,
           "issuer": None, "tls": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                res["tls"] = s.version()
        end = ssl.cert_time_to_seconds(cert["notAfter"])
        days = int((end - time.time()) // 86400)
        res.update(days=days, expires=time.strftime("%Y-%m-%d", time.gmtime(end)),
                   issuer=name_of(cert.get("issuer", ())))
        res["status"] = "CRIT" if days < crit else "WARN" if days < warn else "OK"
    except ssl.SSLCertVerificationError as e:
        msg = e.verify_message or str(e)
        res.update(status="CRIT", error=msg)
    except (OSError, ValueError) as e:
        res["error"] = str(e)
    return res


def main():
    ap = argparse.ArgumentParser(description="Check TLS certificate expiry for hosts.")
    ap.add_argument("hosts", nargs="*", help="host or host:port")
    ap.add_argument("-f", "--file", help="file with one host per line (# comments allowed)")
    ap.add_argument("--warn", type=int, default=30, help="warn when fewer than N days remain (default 30)")
    ap.add_argument("--crit", type=int, default=7, help="critical when fewer than N days remain (default 7)")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    targets = list(a.hosts)
    if a.file:
        try:
            with open(a.file, encoding="utf-8") as f:
                targets += [l.split("#")[0].strip() for l in f if l.split("#")[0].strip()]
        except OSError as e:
            sys.exit(f"certwatch: {e}")
    if not targets:
        ap.error("give at least one host, or -f FILE")

    with ThreadPoolExecutor(max_workers=min(16, len(targets))) as pool:
        results = list(pool.map(lambda t: check(t, a.timeout, a.warn, a.crit), targets))
    results.sort(key=lambda r: (r["days"] is None, r["days"] if r["days"] is not None else 0))

    if a.json:
        print(json.dumps(results, indent=2))
    else:
        colors = {"OK": "32", "WARN": "33", "CRIT": "1;31", "ERROR": "1;31"}
        print(col("1", f"{'HOST':<32}{'STATUS':<8}{'DAYS':<7}{'EXPIRES':<12}ISSUER"))
        for r in results:
            host = r["host"] + ("" if r["port"] == 443 else f":{r['port']}")
            days = "-" if r["days"] is None else r["days"]
            line = f"{host:<32}{col(colors[r['status']], f'{r['status']:<8}')}{days!s:<7}{(r['expires'] or '-'):<12}{r['issuer'] or ''}"
            print(line)
            if r["error"]:
                print(col("2", f"    {r['error']}"))

    worst = {r["status"] for r in results}
    sys.exit(2 if worst & {"CRIT", "ERROR"} else 1 if "WARN" in worst else 0)


if __name__ == "__main__":
    main()
