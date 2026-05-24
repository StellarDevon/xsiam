# Chronosphere Telemetry Pipeline — 设计参考文档

> 本文档基于对 Chronosphere 官方产品及文档的深度调研（2026-05），
> 结合 XSIAM ETL 管道的实际实现，作为设计对标参考长期保存。

---

## 一、背景

**Chronosphere** 是 Palo Alto Networks（PANW）于 2025 年宣布、**2026 年 1 月以 $33.5 亿完成收购**的可观测性平台公司。其核心产品 **Chronosphere Telemetry Pipeline** 是一个基于 Fluent Bit 的企业级遥测管道产品，PANW 将其整合进 **Cortex XSIAM** 作为数据摄入层。

### 收购链路

```
Calyptia（Fluent Bit 商业公司，Eduardo Silva 创立）
    ↓ 2024 年被 Chronosphere 收购
Chronosphere（下一代可观测性平台）
    ↓ 2025/2026 年被 PANW 收购（$33.5B）
Cortex XSIAM 数据摄入层
```

Chronosphere 成为 **Fluent Bit 的首席企业赞助商**，Fluent Bit 是 CNCF 毕业项目。

---

## 二、产品架构

### 整体架构（混合云模型）

```
┌─────────────────────────────────────────────────────────────┐
│                  SaaS 控制平面（Chronosphere 托管）            │
│  • 拖拽式 Pipeline Builder（低代码/无代码）                    │
│  • Playground 测试沙箱（不影响生产）                          │
│  • Fleet 管理：数百个 Fluent Bit agent 统一配置/升级           │
│  • 自动监控：input/output 性能指标、CPU profiling              │
└──────────────────────────┬──────────────────────────────────┘
                           │ 单条出站 HTTPS 连接（BYOC 模型）
                           │ 管理平面不接触实际数据
┌──────────────────────────▼──────────────────────────────────┐
│                  数据平面（部署在客户环境内）                   │
│                                                             │
│  Core Operator（K8s Operator）                              │
│      └── Core Instance（Pipeline 逻辑分组，对应一个集群）      │
│              └── Pipeline × N                               │
│                    ├── Source Plugin(s)  — 数据入口           │
│                    ├── Processing Rules  — 转换/过滤/富化      │
│                    └── Destination Plugin(s) — 数据出口       │
└─────────────────────────────────────────────────────────────┘
```

### 核心组件

| 组件 | 说明 |
|------|------|
| **Fluent Bit Agent** | C 语言，超轻量；支持 logs / metrics / traces；所有节点部署 |
| **Core Operator** | Kubernetes Operator，监听 K8s API，管理 Pipeline 资源 |
| **Core Instance** | Pipeline 逻辑分组，每个 Core Operator 对应一个 |
| **Pipeline** | Source → Processors → Destinations 完整数据流 |
| **SaaS 控制平面** | Pipeline Builder、Fleet 管理、Playground、Profiling |

### 部署规模参考

| 数据源类型 | 日入量 | 最低资源 |
|----------|--------|---------|
| Push-based（HTTP / Syslog / OTEL）| 2 TB | 1 vCPU, 4-8 GB RAM |
| Pull-based（S3 / API scrape）| 1 TB | 1 vCPU, 4-8 GB RAM |
| Kafka / EventHub | 1 TB | 1 vCPU, 4-8 GB RAM |

---

## 三、Source Plugin（输入）

共支持 **40+ 种** Source Plugin，分推送型（push-based）和拉取型（pull-based）。

### 推送型（被动监听）

| 类型 | 说明 |
|------|------|
| Fluent Bit / Fluentd | 通过 `out_forward` 插件推送到指定 TCP 端口 |
| Splunk HEC | Splunk HTTP Event Collector 格式 |
| OpenTelemetry | OTLP 协议 |
| Telegraf | InfluxData 指标采集器 |
| Syslog | UDP/TCP Syslog |
| TCP / HTTP | 通用协议 |

### 拉取型（主动拉取）

| 类型 | 说明 |
|------|------|
| Amazon Kinesis / S3+SQS | AWS 流式数据源 |
| Azure Event Hubs / Event Grid | Azure 事件流 |
| Google Cloud PubSub | GCP 消息队列 |
| Kafka / Confluent Cloud / Redpanda | Kafka 生态 |
| Okta System Logs | 身份提供商审计日志 |
| Cloudflare LogPush | CDN 日志 |
| Mandiant ASM | 威胁情报 |
| Microsoft Intune Audit | MDM 审计 |
| SQL DB Input | 关系型数据库拉取 |
| S3 One Time / SQS | 对象存储定时拉取 |
| Kubernetes Events | K8s 事件 |
| Vercel Logs / Slack / Bash Command | 其他 |

### Fluent Bit 对接方式

```ini
# fluent-bit 侧配置（out_forward → Chronosphere Pipeline）
[OUTPUT]
    Name          forward
    Match         *
    Host          127.0.0.1
    Port          24244
```

---

## 四、Processing Rules（处理规则）

共 **28 种内置处理规则**，规则顺序执行（非 first-match，每条规则的输出是下一条的输入）。
支持自定义 Lua 脚本（LuaJIT 5.1，保护模式运行）。

### 完整规则列表

#### 字段操作类

| 规则名 | 功能 | 关键参数 |
|--------|------|---------|
| `add/set key/value` | 给所有记录添加同一 key/value | field, value |
| `copy keys` | 复制字段值到新字段 | from, to |
| `rename keys` | 重命名字段 | from, to |
| `delete key` | 删除指定字段 | field |
| `hash key` | SHA 哈希字段值，结果存新字段 | src_key, dst_key |
| `parse number` | 字符串转数值（int/float）| key |

#### 字段过滤类（正则批量）

| 规则名 | 功能 | 关键参数 |
|--------|------|---------|
| `allow keys` | 保留匹配正则的字段，删除其余 | regex |
| `block keys` | 删除匹配正则的字段 | regex |

#### 记录过滤类（条件性 drop）

| 规则名 | 功能 | 关键参数 |
|--------|------|---------|
| `allow records` | 保留字段值匹配正则的记录 | key, regex, match_case |
| `block records` | 丢弃字段值匹配正则的记录 | key, regex, match_case |
| `random sampling` | 随机保留指定百分比记录 | percent (0-100) |
| `deduplicate records` | 时间窗口内去重，只保留第一条 | key, window |

#### 值转换类

| 规则名 | 功能 | 关键参数 |
|--------|------|---------|
| `redact/mask value` | 正则脱敏（PCRE2），替换字符可选 | key, regex, replacement |
| `search/replace value` | 正则查找替换 | key, regex, replacement |

#### 解析类

| 规则名 | 功能 | 关键参数 |
|--------|------|---------|
| `parse` | 正则提取命名分组（Grok 风格）| src_field, pattern |
| `extract keys/values` | 从非结构化字符串提取 k=v 对 | src_field, pattern |
| `decode JSON` | JSON 字符串 → 结构化对象 | src_field |
| `encode JSON` | 结构化对象 → JSON 字符串 | src_key, dst_key |
| `decode CSV` | CSV 字符串 → 字段 map | src_key, headers |
| `encode CSV` | 字段 map → CSV 字符串 | headers |

#### 结构变换类

| 规则名 | 功能 | 关键参数 |
|--------|------|---------|
| `flatten subrecord` | 嵌套 map → 顶层字段（可加前缀）| key, prefix |
| `lift submap` | 嵌套 JSON 对象字段提升到上层 | key |
| `nest keys` | 顶层字段 → 嵌套对象 | key_prefix, dest_key |

#### 多记录操作类

| 规则名 | 功能 | 关键参数 |
|--------|------|---------|
| `multiline join` | 多行日志合并为一条（Java stack trace 等）| pattern |
| `split record` | JSON 数组拆分为多条独立记录 | key |
| `join records` | 多条记录合并为一条的数组字段 | key |
| `aggregate records` | 日志聚合为指标（计数/sum/avg，周期性输出）| interval, fields |

#### 自定义类

| 规则名 | 功能 | 关键参数 |
|--------|------|---------|
| `custom Lua` | LuaJIT 5.1 沙箱脚本，完全自定义逻辑 | script |

### Lua 脚本合约（对齐 Fluent Bit 规范）

```lua
function process(tag, timestamp_ms, record)
    -- tag          : string  — 数据标签
    -- timestamp_ms : number  — 毫秒时间戳
    -- record       : table   — 所有字段 key→value

    -- 返回码：
    --  1  → 保留修改后记录
    --  0  → 保留原始记录（忽略修改）
    -- -1  → 丢弃记录
    return 1, record
end
```

### 正则引擎支持

`redact/mask value` 和 `allow/block records` 支持多种正则引擎：
- **PCRE2**（默认，最强）
- GNU、Oniguruma、POSIX、TRE

### Processing Rules 执行模型

```
Rule 1 输出 → Rule 2 输入 → Rule 3 输入 → ... → Destination
```

- **顺序执行**（非 first-match-wins）：每条规则都会执行
- **CPU Profiling**：UI 中显示每条规则消耗的 CPU 毫秒数，定位瓶颈
- **Playground**：可在不影响生产的情况下测试规则效果

---

## 五、Destination Plugin（输出）

共支持 **56 种** Destination Plugin。

### 安全 / SIEM 类

| 目标 | 说明 |
|------|------|
| **Cortex XSIAM** ⭐ | 原生目标，预格式化为 XSIAM schema，直接命中 XQL |
| CrowdStrike | Falcon 平台 |
| Splunk HEC | Splunk HTTP Event Collector |
| Google Chronicle | Google 安全操作平台 |
| Azure Sentinel | Microsoft SIEM |
| Exabeam | 行为分析 SIEM |

### 可观测性类

| 目标 | 说明 |
|------|------|
| Datadog | 日志 + 指标 + 追踪 |
| New Relic | 可观测平台 |
| Grafana Loki | 日志聚合 |
| Prometheus | 指标（Remote Write / Exporter）|
| InfluxDB / VictoriaMetrics | 时序数据库 |
| Dynatrace | APM |

### 云平台类

| 目标 | 说明 |
|------|------|
| Amazon S3 / CloudWatch / Kinesis | AWS 全线 |
| Azure Blob / Data Explorer / Monitor | Azure 全线 |
| Google BigQuery / Cloud Ops | GCP 全线 |

### 数据平台类

| 目标 | 说明 |
|------|------|
| Kafka / Confluent / Redpanda | 消息队列 |
| ClickHouse | OLAP 列存 |
| Elasticsearch / OpenSearch | 全文搜索 |
| Sumo Logic / Coralogix / Axiom | 日志平台 |

### 通用协议类

| 目标 | 说明 |
|------|------|
| HTTP / TCP / UDP / Syslog | 通用协议 |
| Null / Stdout | 调试用 |

---

## 六、与 Cortex XSIAM 集成

### 数据流

```
[任意数据源]
    ↓ Fluent Bit 采集（轻量 C agent）
[Chronosphere Pipeline]
    ↓ 过滤（降 30%+ 数据量）
    ↓ 富化（GeoIP / 用户角色 / 环境 tag）
    ↓ 脱敏（边缘侧 PII 处理）
    ↓ 压缩（传输前）
    ↓ 预格式化为 XSIAM schema
[Cortex XSIAM 数据湖]
    ↓ XQL 引擎直接可查（无需再解析）
    ↓ AI 检测引擎 / 告警关联
```

### 核心价值

| 价值点 | 说明 |
|--------|------|
| **数据已预解析** | 到达 XSIAM 时已对齐 schema，XQL 零解析开销 |
| **原生目标** | UI 几次点击配置，无需自定义 API |
| **边缘降噪** | 进 XSIAM 之前过滤低价值数据，降低 **30%+** 存储/License 成本 |
| **采样策略** | 如：403/500 错误 100% 保留，其余 HTTP 日志只采 1% |
| **Fleet 统一管理** | 数百个 Fluent Bit 节点单一控制平面管理 |
| **20x 资源效率** | 声称比同类产品少用 20 倍基础设施 |

---

## 七、高可用与运维特性

### 缓冲策略（4 种）

| 策略 | 说明 |
|------|------|
| Memory only | 纯内存，最快，宕机丢数据 |
| Memory + Disk | 内存溢出落盘，防丢失 |
| Memory Ring Buffer | 满时丢弃最老批次，持续不阻塞（UDP 场景） |
| Memory + Storage + Ring | 综合策略 |

### 弹性能力

| 能力 | 实现 |
|------|------|
| 自动负载均衡 | Push-based pipeline 自动轮询多副本 |
| 自动扩缩容 | K8s HPA，基于内存阈值触发 |
| 自动恢复 | OOM / Crash 时自动重部署 |
| 滚动更新 | 配置变更时无中断更新 |
| 跨可用区 | K8s taint/toleration 实现多 AZ 部署 |

### 重试与错误处理

- 每个输出默认 1 次重试，指数退避
- 支持无限重试（关键数据源）
- 失败批次可路由到 S3 供后续重处理
- Checkpointing：Pull-based source 支持断点续传

---

## 八、与 XSIAM ETL 管道的对比（实现对齐状态）

### Action 对照

| Chronosphere 规则 | XSIAM 实现 | 状态 |
|-------------------|-----------|------|
| add/set key/value | `set_field` | ✅ |
| rename keys | `rename_field` | ✅ |
| delete key | `delete_field` | ✅ |
| copy keys | `copy_key` | ✅ |
| hash key | `hash_key` (SHA-256) | ✅ |
| parse number | `parse_number` | ✅ |
| allow keys | `allow_keys` | ✅ |
| block keys | `block_keys` | ✅ |
| allow records | `allow_records` | ✅ |
| block records | `block_records` | ✅ |
| random sampling | `random_sample` | ✅ |
| deduplicate records | `dedup` | ✅ |
| redact/mask value | `redact_value` | ✅ |
| search/replace value | `search_replace` | ✅ |
| parse (Grok) | `grok` | ✅ |
| decode JSON | `parse_json` | ✅ |
| encode JSON | `encode_json` | ✅ |
| decode CSV | `decode_csv` | ✅ |
| flatten subrecord | `flatten_subrecord` | ✅ |
| nest keys | `nest_keys` | ✅ |
| custom Lua | `custom_lua` (gopher-lua) | ✅ |
| GeoIP 富化 | `lookup_geoip` (MaxMind) | ✅ |
| lookup asset | `lookup_asset` | ✅（XSIAM 自有）|
| lookup threat | `lookup_threat` | ✅（XSIAM 自有）|
| set dataset/kind | `set_dataset` / `set_kind` | ✅（XSIAM 自有）|
| drop event | `drop_event` | ✅ |
| encode CSV | `encode_csv` | ✅ |
| lift submap | `lift_submap` | ✅（新增）|
| multiline join | `multiline_join` | ✅ |
| split record | `split_record` | ✅ |
| join records | `join_records` | ✅（新增）|
| aggregate records | — | 🔜 暂缓 |
| extract keys/values | — | 🔜 可扩展 |

### 匹配条件对照

| Chronosphere | XSIAM 实现 | 状态 |
|-------------|-----------|------|
| Tag glob | `TagPattern` (path.Match) | ✅ |
| Dataset 白名单 | `Dataset []string` | ✅ |
| Kind 白名单 | `Kind []uint8` | ✅ |
| 字段等于 `k=v` | `FilterExpr` opEqual | ✅ |
| 字段不等于 `k!=v` | `FilterExpr` opNotEqual | ✅ |
| 正则匹配 `k~=pat` | `FilterExpr` opRegex (RE2) | ✅ |
| 数值比较 `> < >= <=` | `FilterExpr` 数值运算符 | ✅ |
| OR 逻辑 | `FilterMode: "or"` | ✅ |
| AND 逻辑（默认）| `FilterMode: "and"` | ✅ |

### 路由模型对照

| Chronosphere | XSIAM 实现 | 状态 |
|-------------|-----------|------|
| 多目标输出 | `ETLOutput.Sinks []ETLSink` | ✅ |
| Sink 条件过滤 | `ETLSink.Condition` | ✅ |
| 顺序执行链 | `ProcessingMode: "sequential"` | ✅ |
| First-match 模式 | `ProcessingMode: "first_match"` | ✅ |
| Raw 写入控制 | `RawWriteMode: both/etl_only/raw_only` | ✅ |

### 运维特性对照

| Chronosphere | XSIAM 实现 | 状态 |
|-------------|-----------|------|
| 热加载规则 | 60s 定时从 ArangoDB 重载 | ✅ |
| 多租户隔离 | tenant_id 全链路过滤 | ✅ |
| Dry-run 测试 | `/api/etl/rules/:id/test` | ✅ |
| 导入/导出规则 | `/api/etl/rules/export` `/import` | ✅ |
| Fleet 管理 UI | — | ❌（Chronosphere SaaS 控制平面级）|
| CPU Profiling | — | 🔜 可加 |
| Buffer + Disk | — | ❌（基础设施层，非本项目范围）|
| K8s 自动扩缩 | — | ❌（基础设施层）|

---

## 九、关键设计决策记录

### 9.1 Raw 写入无条件性

**决策**：每条日志默认写入 ngx `raw_<tag>` 索引，不受 ETL 规则影响（除非规则显式设置 `etl_only`）。

**理由**：Chronosphere 的核心理念是"raw 数据是不可变的黄金来源"，ETL 处理是在 raw 之上叠加，不是替代。

### 9.2 无 ArangoDB 兜底

**决策**：无规则匹配时，只写 ngx raw，不写 ArangoDB。

**理由**：ArangoDB 是结构化查询（XQL）的热存储，无 schema 对齐的原始数据没有查询价值，且消耗额外存储。

### 9.3 用户定义集合 + 动态 TTL

**决策**：`ETLSink.ArangoCollection` 由用户在规则中命名，首次写入时自动创建集合并设置 TTL 索引。

**理由**：对标 Chronosphere 的"每 Sink 独立 TTL"设计，允许不同数据集有不同保留策略（如身份日志 180 天、NetFlow 仅 ngx 不落库）。

### 9.4 Lua 沙箱（gopher-lua 而非 LuaJIT）

**决策**：使用 `github.com/yuin/gopher-lua`（纯 Go Lua 5.1 实现）而非 LuaJIT。

**理由**：gopher-lua 无 CGO 依赖，Windows 交叉编译友好，与项目 `CGO_ENABLED=0` 构建约束一致。Chronosphere 用 LuaJIT 是因为其运行在 Linux/K8s 环境。

### 9.5 FilterExpr 语法扩展

**决策**：在原有 `k=v AND k2=v2` 基础上，增加 `!=`、`~=`（RE2 正则）、`>` `<` `>=` `<=`（数值比较）和 `FilterMode: or`。

**理由**：对标 Chronosphere `allow_records` / `block_records` 的正则条件能力，同时保持与旧规则格式完全向后兼容。

---

## 十、参考资源

- [Chronosphere Telemetry Pipeline 产品页](https://chronosphere.io/platform/telemetry-pipeline/)
- [Chronosphere 文档中心](https://docs.chronosphere.io/pipelines/concepts)
- [Processing Rules 完整列表](https://docs.chronosphere.io/pipeline-data/processing-rules)
- [Fluent Bit 官方文档](https://docs.fluentbit.io/)
- [PANW 完成收购公告](https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-completes-chronosphere-acquisition--unifying-observability-and-security-for-the-ai-era)
- [XSIAM & Chronosphere 集成博客](https://www.paloaltonetworks.com/blog/security-operations/boost-soc-efficiency-data-control-with-cortex-xsiam-chronosphere/)
- [Redact/Mask Value 文档](https://docs.chronosphere.io/pipeline-data/process/processing-rules/redact-mask-value)
- [Custom Lua 文档](https://docs.chronosphere.io/pipeline-data/processing-rules/custom-lua)
- [gopher-lua](https://github.com/yuin/gopher-lua)
- [maxminddb-golang](https://github.com/oschwald/maxminddb-golang)
- [MaxMind GeoLite2 下载](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
