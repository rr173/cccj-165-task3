# pwncorpus — 泄露口令指纹语料的匿名查询发布系统

k-匿名（HIBP 风格）的口令泄露查询服务。纯 Python 标准库实现（Python ≥ 3.10，零第三方依赖），SQLite 存储。

## 安全模型与核心不变量

| 要求 | 实现 |
|---|---|
| 永不暴露单条原始口令 | 摄取端入库即 SHA-1 哈希，原始口令只存在于请求作用域，不落盘、不日志、不出现在任何响应；支持客户端预哈希（`{"sha1": "..."}`）使原始口令不离开客户端；测试验证数据库文件与全部 API 面均不含原始口令 |
| 来源批次去重 | 幂等键 + `(source, content_sha256)` 唯一约束；重复批次返回原 `batch_id`，不重复计数；并发提交同批次由 `BEGIN IMMEDIATE` 串行化，有且只有一个"非重复" |
| 授权验证 | 作用域令牌（`ingest` / `retract` / `publish`），库中只存令牌哈希 |
| 固定前缀分桶 | 系统级固定 `PREFIX_LEN = 5`（SHA-1 十六进制前 5 位），每个版本记录 `prefix_len` 供验证器核对 |
| 最小集合规模 | 构建发布时，后缀数 < `threshold_k` 的桶被**整体丢弃**，不出现在版本、导出和查询中；`k` 是版本属性而非全局可变配置 |
| 撤回/修正只产生新版本 | `retract` / `corrections` 只打标记，在**下一次 build + activate** 才生效；当前服务版本不受影哃；发布版本不可变 |
| 草稿不覆盖新来源状态 | 候选版本记录构建时的语料状态标记（`corpus_state`）；批次新增/撤回/纠错在同一写事务内推进该标记；激活时比对，不一致则拒绝（409），现行版本与查询不受影响；冲突后可**刷新草稿**（保留版本号与 k）再继续预览与启用 |
| 旧版本可验证但不可查 | 版本状态机 `candidate → active → retired`；查询只读 `active`；`retired` 版本的清单与桶数据永久保留，可随时导出并用离线验证器校验 |
| 查询不混版 | 激活是单事务原子切换（旧版本退役 + 候选激活 + 指针交换）；查询在单个 SQLite 快照内读取版本指针和桶数据，响应携带 `X-Corpus-Version` 供客户端核对 |

## 架构

```
                ┌──────────── 摄取端（需授权）────────────┐
  批次提交 ───▶ │ 去重(内容哈希/幂等键) → 入库即哈希 → 批次表 │
                └───────────────┬────────────────────────┘
                                ▼
                    活跃语料 = Σ活跃批次 − 撤回 − 修正
                                ▼  build（候选版本，不可变）
                固定前缀分桶 → 丢弃 |桶| < k 的桶 → 清单哈希
                                ▼  审查页 diff（陈旧草稿先刷新）→ activate（比对状态标记 + 单事务原子切换）
                ┌──────────── 发布端（匿名）──────────────┐
  GET /range ─▶ │ 仅服务 active 版本：后缀摘要 + 出现次数     │
                └─────────────────────────────────────────┘
  任意版本 ─▶ export → 离线验证器（清单哈希/格式/阈值/排序全量校验）
```

## 快速开始

```bash
export PYTHONPATH=/workspace

# 初始化 + 发令牌（令牌只显示一次）
python3 -m pwncorpus.cli --db corpus.db init
python3 -m pwncorpus.cli --db corpus.db token --label ingestor --scopes ingest
python3 -m pwncorpus.cli --db corpus.db token --label publisher --scopes publish,retract

# 摄取（文件中每行一个口令，或 sha1:<hex> 预哈希）
python3 -m pwncorpus.cli --db corpus.db ingest --source breach-2026Q3 --file leak.txt

# 构建候选版本（k = 最小集合规模）→ 审查 → 激活
python3 -m pwncorpus.cli --db corpus.db build --k 50
python3 -m pwncorpus.cli --db corpus.db activate --version 1

# 启动服务
python3 -m pwncorpus.cli --db corpus.db serve --host 127.0.0.1 --port 8080
```

## API

### 匿名查询（无需令牌）

```
GET /api/range/{5位十六进制前缀}
→ 200 text/plain:  "SUFFIX:COUNT\n..."   +  X-Corpus-Version: N
→ 404 桶不存在 / 被阈值抑制      503 无活跃版本      400 前缀非法
```

客户端只发送哈希前缀（k-匿名），服务器永远看不到完整口令或完整哈希。

### 批次 API（Bearer 令牌）

| 端点 | 作用域 | 说明 |
|---|---|---|
| `POST /api/batches` | `ingest` | `{"source", "items": [...], "idempotency_key"?}`；items 为原始口令或 `{"sha1":"..."}`；重复批次返回 `200 {"duplicate": true}` |
| `POST /api/batches/{id}/retract` | `retract` | 撤回批次，下一发布版本生效 |
| `POST /api/batches/{id}/corrections` | `retract` | `{"items": [...]}` 误报修正，剔除指定指纹，下一发布版本生效 |
| `POST /api/publications/build` | `publish` | `{"k": 50}` 构建候选版本 |
| `POST /api/publications/{v}/activate` | `publish` | 原子切换；草稿陈旧或确认绑定（可选 `expected_manifest`）不匹配时 409，现行版本不变 |
| `POST /api/publications/{v}/refresh` | `publish` | 用当前来源数据原地重建候选（保留版本号与 k），解除陈旧冲突 |
| `GET /api/publications` `/…/{v}` | `publish` | 版本列表 / 详情 + 与活跃版本的 diff |
| `GET /api/publications/{v}/manifest` | 公开 | 任意版本清单（仅哈希），支撑独立验证 |
| `GET /review` | `publish` | 发布审查页（`?token=` 或 Bearer） |
| `GET /api/health` | 公开 | 健康检查 + 当前版本 |

### 发布审查页

`GET /review?token=<publish令牌>` 展示：活跃版本与候选版本元数据（k、桶数、清单哈希、语料状态标记）、候选与活跃版本的 diff（桶增删、后缀增删、计数变化及抽样）、近期批次、历史版本，以及需要重新输入 publish 令牌的激活按钮。

草稿生成后来源数据可能继续变化。审查页会标明候选草稿是否仍对应当前来源数据：陈旧（STALE）时激活按钮被刷新表单取代——刷新用当前数据原地重建草稿（保留版本号与阈值 k），随后照常预览与启用；未变化时审批流程不变。激活表单通过隐藏字段绑定所审草稿的清单哈希，确认时草稿若已被替换（如他人刷新过）会被拒绝并提示重新加载。

### 离线分桶验证器

```bash
python3 -m pwncorpus.cli --db corpus.db export --version 1 --out export-v1

python3 -m pwncorpus.verifier verify export-v1          # 全量校验导出
python3 -m pwncorpus.verifier check-response export-v1 ABCDE resp.txt  # 在线响应核对发布物
python3 -m pwncorpus.verifier lookup export-v1          # 完全离线的口令查询（不联网）
```

`verify` 校验：清单自哈希、每个桶文件 SHA-256 与清单一致、行格式（后缀长度/计数 ≥ 1）、桶内排序去重、**每个桶满足最小集合规模 k**、无多余/缺失文件。任何篡改（改计数、加小桶、换文件）都会失败。

## 并发设计

- SQLite WAL + 每请求独立连接；写事务 `BEGIN IMMEDIATE`（带忙等待与重试），读事务为快照隔离。
- 并发摄取同批次：唯一约束保证只入库一次，其余线程拿到已有 `batch_id`。
- 构建候选版本读取单语句快照，与并发摄取互不阻塞；候选版本不可变。
- 激活为单事务：旧版本退役、候选激活、指针交换同时提交；进行中的查询要么看到旧版本完整数据、要么看到新版本完整数据，绝不混版（有并发测试覆盖）。
- 激活是与来源写入的 compare-and-swap：候选记录构建时的 `corpus_state` 标记，激活在写事务内复比。**来源更新先提交**则本次确认 409 不生效、现行查询保持不变；**激活先提交**则后来的来源更新只进入下一版。构建/刷新在同一快照中读取语料与状态标记，提交前复核，保证记录的标记与数据严格对应。
- 无实际效果的来源写入（重复批次、重复撤回、重复纠错）不推进状态标记，不会误判草稿为陈旧。
- 阈值 k 是版本属性：调整 k 必须构建新版本，旧版本按其自身 k 继续可验证。

## 部署注意事项

- 开发服务器不终止 TLS；生产环境置于反向代理之后并强制 HTTPS，防止前缀查询被窃听。
- 审查页支持 `?token=` 传参（便于浏览器），令牌会出现在 URL 中——生产环境建议改用反向代理注入 `Authorization` 头或加 SSO 前置；访问日志已对 `token=` 做脱敏。
- 建议客户端优先使用 `{"sha1": "..."}` 预哈希提交，原始口令不跨网络。
- 未实现响应填充（padding）与速率限制；高敏部署可在代理层加 padding 与限流以抵抗流量分析。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

26 个用例覆盖：并发摄取（同批次/不同批次）、批次去重不重复计数、阈值抑制小桶、阈值变更只经新版本、撤回/误报修正只经新版本生效、激活期间查询不混版、旧版本不可查但可离线验证、导出篡改检测、低于阈值桶检测、存储与 API 面均无原始口令、授权作用域、草稿陈旧检测（新增/撤回/纠错均触发）、无操作写入不误判、冲突后刷新保留版本号与阈值、激活与来源写入并发的先后语义、确认与所审草稿的清单绑定。
