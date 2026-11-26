# 工位网段 mDNS 打印发现服务

标签打印机换地址后，调度器需要按**工位所在网段**重新发现它。本服务用
FastAPI + dnslib 接收 mDNS 应答（announcement / goodbye），按网段分别缓存
PTR / SRV / A 三类记录，并提供 HTTP 查询接口，把"本段有效"的记录拼成可用的
`实例名 + IP + 端口`。

一个重要前提：mDNS 组播地址 `224.0.0.251:5353` 在单机上无法按网段隔离。
因此本服务把**每个 UDP 监听端口当作一个网段**（端口即网段），用两路 UDP 端口
`5353` / `5354` 模拟两个工位网段；真实部署中一个端口/接口对应一个 VLAN。

## 功能

- **按段隔离**：缓存键包含网段，`10.20.1.0/24` 上的同名实例与
  `10.20.2.0/24` 上的同名实例互不影响，查询永不跨段拼接。
- **只拼本段有效的三条记录**：查询 `_ipp._tcp.local.` 时，只有
  `PTR(_ipp._tcp.local. → 实例)`、`SRV(实例 → 主机:端口)`、`A(主机 → IP)`
  三段链路都仍然有效，才返回结果；任一记录过期即不返回该组合。
- **返回最小剩余有效期**：`remaining_ttl = min(PTR, SRV, A 的剩余 TTL)`，
  同时给出三条记录各自的 TTL / 剩余时间 / 是否处于宽限期。
- **缓存刷新（cache-flush）宽限**：收到带 class 高位（`0x8000`）的 PTR/SRV/A
  记录时，同段同名同类型的旧缓存项，若距上次通告已超过 1 秒且本包未重报，
  就**最多再留 1 秒**；本包重报过的项不受影响。
- **告别（TTL=0）**：只让**精确匹配**（同段 + 同名 + 同类型 + 同 rdata）的缓存
  项最多再留 1 秒；不创建新条目、不触发对兄弟记录的清扫。
- **宽限期内照常查询**：被缩短生命的记录在到期前仍可被查询到，且标记
  `in_grace: true`；期间收到正 TTL 重报会取消宽限并续期（含同包内
  "TTL=0 + 正 TTL" 冲突时正 TTL 获胜）。
- **健壮性**：非应答报文（查询）、非 IN class、非 PTR/SRV/A 类型、畸形报文
  都不会污染缓存，并计入 `/api/status` 统计。
- **定长容量**：缓存超过 `CACHE_MAX_RECORDS` 时按最近到期时间淘汰。

## 快速开始（Docker Compose）

```bash
docker compose up --build -d
curl -s http://127.0.0.1:8000/api/health
```

三路端口：

| 端口 | 用途 |
| --- | --- |
| `5353/udp` | 网段 `station-a`（`10.20.1.0/24`） |
| `5354/udp` | 网段 `station-b`（`10.20.2.0/24`） |
| `8000/tcp` | 查询 API / OpenAPI 文档（`/docs`） |

发送模拟通告并查询：

```bash
# 在 station-a 上通告 "Front Desk" @ 10.20.1.10
python3 -m pip install -r requirements.txt          # 仅发送脚本需要 dnslib
python3 scripts/send_packet.py --port 5353 --instance "Front Desk" --ip 10.20.1.10
python3 scripts/query.py --segment station-a

# 同名实例在 station-b 上使用另一个地址
python3 scripts/send_packet.py --port 5354 --instance "Front Desk" --ip 10.20.2.20
python3 scripts/query.py --segment station-b

# 换地址：只重发 A 记录（带 cache-flush），旧地址 1 秒内仍可查
python3 scripts/send_packet.py --port 5353 --instance "Front Desk" --ip 10.20.1.99 --only a

# 告别：TTL=0
python3 scripts/send_packet.py --port 5353 --instance "Front Desk" --ip 10.20.1.10 --goodbye
```

不装 Docker 也可以直接运行：

```bash
pip install -r requirements.txt
SEGMENTS="station-a:5353:10.20.1.0/24,station-b:5354:10.20.2.0/24" \
JOIN_MULTICAST=false python3 -m app.main
```

### 配置项（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SEGMENTS` | `station-a:5353:10.20.1.0/24,station-b:5354:10.20.2.0/24` | `网段id:UDP端口:CIDR`，逗号分隔 |
| `BIND_HOST` | `0.0.0.0` | UDP 监听地址 |
| `HTTP_HOST` / `HTTP_PORT` | `0.0.0.0` / `8000` | HTTP 监听 |
| `JOIN_MULTICAST` | `false` | 是否加入 `224.0.0.251`（单机多端口模拟时必须关闭，否则两个端口会收到同一份组播） |
| `MULTICAST_GROUP` / `MULTICAST_INTERFACE` | `224.0.0.251` / `0.0.0.0` | 组播组与接口 |
| `CACHE_MAX_RECORDS` | `10000` | 缓存条目上限 |
| `LOG_LEVEL` | `INFO` | 日志级别，每包一行摘要 |

## HTTP API

| 方法与路径 | 说明 |
| --- | --- |
| `GET /api/health` | 存活检查 |
| `GET /api/status` | 配置的网段、UDP 实际端口、收发统计、缓存条目数 |
| `GET /api/segments/{segment}/services?service=_ipp._tcp.local.` | 按网段 id 查询服务 |
| `GET /api/services?segment=<id 或 CIDR>&service=...` | 按网段 id **或子网**查询 |
| `GET /api/segments/{segment}/records` | 该段原始缓存记录（调试用） |
| `GET /api/records` | 全部缓存记录（调试用） |
| `GET /docs`、`/openapi.json` | 交互式文档 |

`/api/segments/{segment}/services` 响应示例：

```json
{
  "segment": "station-a",
  "subnet": "10.20.1.0/24",
  "service": "_ipp._tcp.local.",
  "count": 1,
  "services": [
    {
      "instance": "Front Desk",
      "full_name": "Front Desk._ipp._tcp.local.",
      "host": "front-desk.local.",
      "ip": "10.20.1.10",
      "port": 631,
      "remaining_ttl": 119.5,
      "records": {
        "ptr": {"ttl": 4500, "remaining_ttl": 4499.5, "in_grace": false},
        "srv": {"ttl": 120, "remaining_ttl": 119.5, "in_grace": false},
        "a":   {"ttl": 120, "remaining_ttl": 119.5, "in_grace": false}
      }
    }
  ]
}
```

`remaining_ttl` 为三条记录剩余有效期的最小值；宽限期内的记录
`in_grace` 为 `true`、剩余时间 ≤ 1 秒。DNS 名字比较大小写不敏感，但返回的
实例名保留通告方原始大小写与 UTF-8 字符。

## 规则实现对照

核心逻辑在 `app/cache.py`，语义逐条对应需求：

| 需求 | 实现位置 |
| --- | --- |
| 按段隔离 | `EntryKey.segment`，`Cache.ingest(records, segment)` |
| 只用本段有效 PTR/SRV/A 拼地址 | `Cache.query_service()` 三段链路联查 |
| 返回三条中最短剩余 TTL | `min(ptr.remaining, srv.remaining, a.remaining)` |
| cache-flush：同段同名同类型、>1s 且本包未重报，最多再留 1s | `Cache._flush_sweep()`，`GRACE_SECONDS = 1.0` |
| TTL=0 告别：匹配项最多再留 1s，不新建、不扫兄弟 | `Cache._goodbye()` / `_shorten()` |
| 宽限期内照常查询、正 TTL 重报续期 | `CacheEntry.deadline()` + `_upsert()` 清除 `grace_until` |
| 同包 TTL=0 与正 TTL 冲突时正 TTL 获胜 | `Cache.ingest()` 中 `positive_keys` 保护 |

时间统一走可注入的单调时钟（`Cache(clock=...)`），因此 1 秒边界可以用
假时钟精确验证，不受调度抖动影响。

## 实测结果

环境：本机 Linux + Python 3.11，依赖版本见 `requirements.txt`。
**本环境没有 Docker CLI / daemon**，因此 Compose 文件只做了 YAML 解析校验，
容器内的实际启动未能验证；相同的服务进程已用 `python3 -m app.main` 在本机
以两路真实 UDP 端口（15353/15354）+ HTTP 启动并完整实测。

```bash
$ python3 -m pytest -q
50 passed
$ python3 -m pyflakes app scripts tests
(无输出)
```

真实 UDP 端到端测试（`tests/test_end_to_end.py`，5 项）通过真实 socket 发包、
经监听协程、缓存、HTTP 查询全链路验证，包括：

- 两路 UDP 端口各自收到通告、互不串段；
- 一条通告拆成 3 个数据包陆续到达，重组后地址正确；
- 告别后 1 秒内仍可查（`in_grace` 且 `remaining_ttl ≤ 1`），随后消失；
- 同名实例在两个网段各有不同 IP，A 段告别不影响 B 段；
- 畸形报文与查询报文不会污染缓存，计数正确。

手工实跑（`scripts/send_packet.py` + `scripts/query.py`）结果：

```
=== 1) 两个网段各自通告 ===
segment station-a (10.20.1.0/24) _ipp._tcp.local.
  Back Desk  10.20.1.11:631  remaining=119.536s
  Front Desk 10.20.1.10:631  remaining=119.476s
segment station-b (10.20.2.0/24) _ipp._tcp.local.
  Front Desk 10.20.2.20:631  remaining=119.531s

=== 2) 分包刷新（PTR → SRV → A 三个包）===
三个包到达期间实例始终可查；刷新后
  Front Desk 10.20.1.10:631  remaining=119.519s
  PTR remaining=4499.24s / SRV remaining=119.52s / A remaining=119.79s

=== 3a) 换地址 10.20.1.10 → 10.20.1.99（A 带 cache-flush）===
立刻查询：
  Front Desk 10.20.1.10:631  remaining=0.774s   (A: 0.77s grace)
  Front Desk 10.20.1.99:631  remaining=109.633s
1 秒后：
  Front Desk 10.20.1.99:631  remaining=108.47s

=== 3b) 告别（TTL=0）===
立刻查询：Back Desk 10.20.1.11:631 remaining=0.83s（PTR/SRV/A 全部 grace）
1 秒后：Back Desk 已消失，Front Desk 不受影响

=== 3c) 同名隔离 ===
station-a 的 Front Desk 告别后，station-b 的 Front Desk
（10.20.2.20，remaining≈92s）在宽限期内与宽限期后都保持不变。
```

## 项目结构

```
app/
  config.py    网段/端口/环境变量解析与校验
  mdns.py      dnslib 报文解析、记录构造、名字处理
  cache.py     分段缓存、TTL/宽限/告别/刷新语义、查询拼装
  listener.py  每段一个 asyncio UDP 端点（可选组播加入）
  api.py       FastAPI 路由
  main.py      uvicorn 入口
scripts/
  send_packet.py  发送通告/告别/分包刷新样例
  query.py        查询 API 样例
examples/         可回放的样例报文与说明
tests/            mdns、缓存规则、API、真实 UDP 端到端测试
Dockerfile / docker-compose.yml
```

## 已知限制 / 待完成项

1. **未在 Docker 中实测**：当前环境无 Docker daemon，Compose 只验证了配置
   可解析；需在有 Docker 的机器上执行 `docker compose up --build` 复核端口与
   健康检查。
2. **组播未按段隔离**：一个组播组在同一主机上的两个 socket 都会收到全部报文；
   `JOIN_MULTICAST=false` 的默认值即为规避此问题。真实 VLAN 部署应改为
   "一接口一段 + 组播",并为每段绑定独立接口地址。
3. **不主动发查询**：本服务只被动接收应答，不发送 mDNS 查询/探测；若需要
   主动刷新，可另加周期性 PTR 查询。
4. **仅 IPv4 / 仅 PTR·SRV·A**：AAAA/TXT 等记录被忽略（计数为 unsupported）。
   若打印队列依赖 TXT（如 `rp=`、`ty=`），需要扩展记录类型。
5. **缓存为进程内内存**：重启即清空、不支持多副本共享；如需水平扩展要把
   缓存换成外部存储。
6. **宽限规则的产品取舍**：需求要求"最多再留一秒"，本实现严格按 1 秒实现，
   未采用 RFC 6762 的 1 秒 goodbye 之外的额外立即失效策略；如现场希望告别
   **立即**消失，可加开关切到 0 秒。
7. **未做鉴权/限流**：API 假定在内网可信环境使用。
