# XSIAM 技术设计文档

**版本：** v7.0  
**日期：** 2026-05-22  
**关联需求：** XDR产品需求文档 v3.0  
**变更说明：** 程序重命名（xsiam→ngx_console，xdr_cron→ngx_cron）；新增 ngx_svc 基础服务（Auth/RBAC/Notify/Audit）；ngx_cron 统一定时任务管理；数据库由 MongoDB 替换为 ArangoDB 3.12（v7.0）

---

## 目录

1. [技术选型](#1-技术选型)
2. [系统架构](#2-系统架构)
3. [Monorepo 目录结构](#3-monorepo-目录结构)
4. [前端目录结构](#4-前端目录结构)
5. [ngx_svc 设计](#5-ngx_svc-设计)
6. [ngx_cron 设计](#6-ngx_cron-设计)
7. [Go 分层设计详解](#7-go-分层设计详解)
8. [ArangoDB 数据模型](#8-arangodb-数据模型)
9. [API 接口设计](#9-api-接口设计)
10. [接口桩（Stub）设计](#10-接口桩stub设计)
11. [开发规范](#11-开发规范)
12. [新增模块技术设计](#12-新增模块技术设计)
13. [极致轻量高性能优化](#13-极致轻量高性能优化)
14. [告警同步链路设计（ngx → ArangoDB）](#14-告警同步链路设计ngx--arangodb)
15. [进程内缓存设计（Ristretto）](#15-进程内缓存设计ristretto)

---

## 1. 技术选型

### 1.1 选型原则

- **多二进制、单 Monorepo**：Go 代码在同一仓库，编译为 3 个独立可执行文件（ngx_console / ngx_svc / ngx_cron），共享 model/repository/pkg 包，各自职责清晰
- **ngx_console 单端口**：通过 `embed.FS` 内嵌 React SPA，`:8080` 同时服务 API 和前端，零跨域
- **ngx_svc 基础服务下沉**：Auth / RBAC / Notify / Audit 从 ngx_console 剥离，统一由 ngx_svc 提供，ngx_console 通过 HTTP 内部调用
- **直连架构**：浏览器 → ngx_console → ArangoDB，无中间代理层，链路最短
- **功能分层**：Handler → Service → Repository → Model，职责清晰，单向依赖
- **灵活文档数据库**：ArangoDB，同时支持文档（Collection）和图（Graph），因果关联图原生支持，字段按需扩展
- **AI 开发效率优先**：所有 Web 功能基于 ArangoDB CRUD；ETL/设备联动/响应执行留接口桩（Stub）

### 1.2 技术栈

#### 后端（Go，3 个可执行文件）

| 程序 | 端口 | 职责 |
|------|------|------|
| **ngx_console** | :8080 | XSIAM 主控台：业务 API + React SPA embed，调用 ngx_svc 完成鉴权/通知/审计 |
| **ngx_svc** | :8090 | 基础服务：Auth / RBAC / Notify / Audit，供 ngx_console 和 ngx_cron HTTP 内部调用 |
| **ngx_cron** | 无对外端口 | 定时任务：统一管理所有后台定时/周期性任务 |

三个程序共享同一 Monorepo，共用 `internal/model` `internal/repository` `pkg/` 包，各自有独立 `main.go`。

| 层次 | 技术 | 版本 | 选型理由 |
|------|------|------|----------|
| 语言 | **Go** | 1.22+ | 强类型编译期拦截 AI 生成的类型错误；goroutine 高并发；多二进制部署 |
| HTTP 框架 | **Gin** | v1.10 | 最广泛使用的 Go Web 框架；AI 代码生成准确率最高；路由组/中间件/参数绑定完善 |
| 静态文件 | **embed.FS** | 标准库 | ngx_console 内嵌 React dist/，无需独立文件服务器 |
| ArangoDB 驱动 | **arangodb/go-driver** | v2.x | ArangoDB 官方 Go 驱动；支持 AQL 查询、文档 CRUD、图遍历 |
| 配置管理 | **Viper** | v1.19 | yaml/env/flag 多来源，AutomaticEnv 环境变量覆盖 |
| 日志 | **uber-go/zap** | v1.27 | 结构化日志，零分配，高性能 |
| 鉴权 | **golang-jwt/jwt** | v5 | JWT 签发与验证（ngx_svc 签发，ngx_console 验证） |
| 参数校验 | **go-playground/validator** | v10 | struct tag 校验，`binding:"required"` 风格 |
| 请求 ID | **gin-contrib/requestid** | latest | 链路追踪 ID |
| 内部通知 | **net/http** 标准库 | — | ngx_svc Notify 模块对接邮件/钉钉/Slack |

#### 前端（React SPA）

| 层次 | 技术 | 版本 | 选型理由 |
|------|------|------|----------|
| 构建工具 | **Vite** | 6.x | 极快的 HMR，构建 dist/ 供 Go embed |
| 框架 | **React** | 19.x | 无 SSR 复杂度；AI 代码生成质量最高；无 Server/Client 组件边界错误 |
| 语言 | **TypeScript** | 5.x（strict） | AI 生成代码漏洞率最低（2.5%–7.1%），编译期拦截类型错误 |
| 路由 | **TanStack Router** | 1.x | 类型安全路由，无 next/router 幻觉问题 |
| UI 组件库 | **shadcn/ui** | latest | Radix UI + Tailwind，可复制修改，AI 生成友好 |
| 样式 | **Tailwind CSS** | 4.x | 原子化 CSS，AI 输出准确率高 |
| 状态管理 | **Zustand** | 5.x | 轻量无 boilerplate |
| 数据请求 | **TanStack Query** | 5.x | 自动缓存、后台刷新、乐观更新 |
| 图表 | **Recharts** | 2.x | React 原生图表 |
| 攻击链图谱 | **React Flow（@xyflow/react）** | 12.x | 节点图，自定义节点/边 |
| 表格 | **TanStack Table** | 8.x | 虚拟化、排序、筛选、分页 |
| 表单 | **React Hook Form + Zod** | — | 轻量表单 + 运行时校验 |
| 代码编辑器 | **Monaco Editor** | — | XQL 查询中心编辑器 |

#### 数据库 / 数据湖

| 组件 | 技术 | 说明 |
|------|------|------|
| 热数据库 | **ArangoDB 3.12** | 业务数据（告警/事件/资产等），TTL 索引自动清理 30-90 天 |
| 索引策略 | 持久化索引 + TTL 索引 + 全文索引 | 查询性能 + 热数据自动过期 + 关键词搜索 |
| 图数据库 | **ArangoDB 原生图** | 因果关联图（CausalityGraph）使用 Named Graph，原生支持 graph traversal |
| 冷数据湖 | **ngx**（自研，C 实现） | 全量原始日志，zstd 压缩，SPL2 查询，类 Splunk 架构 |

#### 采集 / 基础设施

| 组件 | 技术 | 说明 |
|------|------|------|
| 日志采集网关 | **Fluent-bit** | 多协议输入（syslog/filebeat/OTLP）→ ngx HEC，本地持久化 buffer |
| 消息队列 | **无** | ngx MPSC ring + Fluent-bit 本地 buffer 已覆盖削峰，无需 Kafka |
| Go 可执行文件 | ngx_console / ngx_svc / ngx_cron | CGO_ENABLED=0，静态链接，无运行时依赖 |
| 前端包管理 | pnpm 9.x | |
| 容器化 | Docker + Docker Compose | 5 个 service：arangodb / ngx / ngx_svc / ngx_cron / ngx_console |

### 1.3 架构选型对比

```
前端接入链路演进：

  v2.0 BFF：  Browser → Next.js:3000 → Go:8080 → ArangoDB
              三层链路，两次网络跳转，页面首屏慢

  v5.0 直连：  Browser → Go:8080(/api/* + /*) → ArangoDB
              一层链路，零跨域，单二进制部署

Go embed 原理：
  ① pnpm build → React dist/（纯静态 HTML/JS/CSS）
  ② go build   → Go 二进制内嵌 dist/（embed.FS）
  ③ Gin 路由：/api/* → 业务 handler；/* → embed.FS 文件服务
  ④ SPA 路由 fallback：所有非 /api 未命中路径返回 index.html

日志采集链路（v5.0，无消息队列）：

  Agent/设备 → Fluent-bit → ngx HEC :18088 → zstd journal
                │                    │
                │            MPSC async ring（削峰，替代 MQ）
                │
                └─ storage.type=filesystem（本地持久化，替代 MQ 的持久化）

检测链路（v5.0，ngx 内部，无 MQ）：

  ngx cron（每 5 分钟）→ SPL2 规则查询 → 命中 → webhook → XSIAM :8080
  XSIAM → 写 ArangoDB alerts → CAE goroutine pool（关联分析）

为什么不需要 Kafka/RabbitMQ：
  · ngx MPSC ring 已提供无锁环形缓冲（削峰）
  · Fluent-bit filesystem buffer 已提供持久化重试（可靠投递）
  · ngx saved_search cron 已提供生产者/消费者解耦（异步检测）
  · 当前只有单一消费者（ngx 规则引擎），无 fan-out 需求
```

---

## 2. 系统架构

### 2.1 整体架构

```
╔══════════════════════════════════════════════════════════════════╗
║              终端 / 网络 / 身份 数据源                            ║
║  XSIAM Agent │ 网络探针 │ AD/LDAP │ 防火墙 │ WAF │ 其他设备        ║
╚══════════════════════════╤═══════════════════════════════════════╝
                           │ syslog / filebeat / OTLP / 自定义协议
                           ▼
╔══════════════════════════════════════════════════════════════════╗
║              Fluent-bit（日志采集网关）                           ║
║  · 多协议输入：syslog(:514) tail filebeat forward               ║
║  · 轻量过滤：解析、tag 标记、丢弃噪声字段                         ║
║  · 输出：HTTP output → ngx HEC :18088（批量、带重试）            ║
║  · 本地持久化 buffer（storage.type=filesystem）                  ║
║    ngx 不可达时落盘，恢复后自动重发，零日志丢失                   ║
╚══════════════════════════╤═══════════════════════════════════════╝
                           │ POST /services/collector/event
                           │ Authorization: Splunk <token>
                           ▼
╔══════════════════════════════════════════════════════════════════╗
║              ngx 数据湖（C 实现，类 Splunk 架构）                 ║
║                                                                  ║
║  ┌─────────────────────────────────────────────────────────┐   ║
║  │ HEC 接收层（:18088）                                     │   ║
║  │  ngx_storage_hec — HTTP/1.1 keep-alive + chunked        │   ║
║  │  内置 MPSC async ring（默认 65536 槽，可调至 262144）    │   ║
║  │  ring 满 → NGX_AGAIN → Fluent-bit 触发背压重试          │   ║
║  └──────────────────────────┬──────────────────────────────┘   ║
║                             │                                    ║
║  ┌──────────────────────────▼──────────────────────────────┐   ║
║  │ 存储层（zstd journal）                                   │   ║
║  │  ngx_storage_append_record                               │   ║
║  │  index: xdr_endpoint │ xdr_network │ xdr_identity        │   ║
║  │  per-event ZSTD 帧 → 热桶（hot bucket）                  │   ║
║  │  热桶满（8MB / N事件 / 空闲超时）→ 自动 roll 至暖桶       │   ║
║  └──────────────────────────┬──────────────────────────────┘   ║
║                             │                                    ║
║  ┌──────────────────────────▼──────────────────────────────┐   ║
║  │ 规则引擎（saved_search + cron scheduler）                │   ║
║  │  XSIAM Web 导入规则 → ngx_head_saved_search_store_register │   ║
║  │  内置 cron 线程定时触发（每 5 分钟）                      │   ║
║  │  SPL2 查询 + 富化（eval / stats / search / dedup）       │   ║
║  │  命中阈值 → action_webhook → POST xsiam:8080/api/internal/alerts│
║  └──────────────────────────┬──────────────────────────────┘   ║
║                             │                                    ║
║  ┌──────────────────────────▼──────────────────────────────┐   ║
║  │ 查询层（Head 节点 :8080/services/search）                │   ║
║  │  ngx_head_execute_search + ngx_head_spl_pipe_apply       │   ║
║  │  供 XSIAM Web 的"日志查询中心"（/logs）调用                 │   ║
║  └─────────────────────────────────────────────────────────┘   ║
╚══════════════════════════╤═══════════════════════════════════════╝
          ┌────────────────┘
          │  ① webhook 告警（POST /api/internal/alerts）
          │  ② SPL2 查询结果（XSIAM 发起）
          ▼
╔══════════════════════════════════════════════════════════════════╗
║              XSIAM Go 服务（单一可执行文件 xsiam，:8080）            ║
║                                                                  ║
║  ┌────────────────────────────────────────────────────────┐    ║
║  │ Gin Router                                              │    ║
║  │  ├── /api/internal/alerts  → InternalHandler（规则告警）│    ║
║  │  ├── /api/*                → AuthMiddleware → Handler   │    ║
║  │  └── /*                    → embed.FS（React SPA）      │    ║
║  └────────────────────────────────────────────────────────┘    ║
║                                                                  ║
║  Handler → Service → Repository → Model                         ║
║                                                                  ║
║  Service 层关键异步任务：                                         ║
║  · CAE goroutine pool（4 worker，4096 channel）                  ║
║  · SmartScore 预计算（事件驱动后台重算）                          ║
║  · ITDR 内存聚合（sync.Map + 30s flush）                         ║
║  · ArangoDB 冷数据归档器（1h 归档任务）                          ║
║                                                                  ║
║  datalake.Client（ngx SPL2 查询，只读）                          ║
║  Stub 层: Execution │ ETL │ AI Engine                            ║
║  embed.FS: React dist/（编译时打包）                              ║
╚══════════════════════════╤═══════════════════════════════════════╝
                           │ arangodb/go-driver (AQL)
                           ▼
╔══════════════════════════════════════════════════════════════════╗
║              ArangoDB 3.12（热数据，TTL 自动清理）                ║
║  alerts(30d) │ incidents(90d) │ assets │ vulnerabilities         ║
║  iocs │ intel_feeds │ actions │ devices │ agent_policies         ║
║  datasources │ playbooks │ reports │ users │ audit_logs          ║
║  tenants │ rbac_roles │ detection_rules                          ║
║  causality_nodes(90d) │ causality_edges(90d)  ← Named Graph      ║
║  identity_risks │ privilege_restrictions │ exposure_scores       ║
╚══════════════════════════════════════════════════════════════════╝

注：log_entries collection 已删除，日志全量存 ngx，XSIAM 查询层代理 SPL2 查询
注：causality_graph 拆分为 causality_nodes / causality_edges 两个 Edge Collection，
    由 ArangoDB Named Graph "causality_graph" 管理，支持原生图遍历查询
```

### 2.2 日志采集与检测数据流

```
① 采集路径（实时，无消息队列）
──────────────────────────────────────────────────────
Agent / 设备
  └─[syslog/filebeat/OTLP]→ Fluent-bit
       └─[HTTP batch]→ ngx HEC :18088
            └─[MPSC ring]→ zstd journal（热桶）
                 └─[auto roll]→ 暖桶（可查询）

背压机制（替代 MQ 的削峰能力）：
  ngx ring 满 → HTTP 429 → Fluent-bit 指数退避重试
  Fluent-bit storage.type=filesystem → 本地持久化 buffer
  → ngx 恢复后自动重发，端到端零丢失

② 检测路径（定时，ngx 内部）
──────────────────────────────────────────────────────
ngx cron 线程（每 5 分钟）
  └─ 遍历已注册 saved_search（来自 XSIAM 规则导入）
       └─ SPL2 查询（富化 + 统计 + 条件匹配）
            └─ 命中 → ngx_head_saved_search_store_fire_alert
                 └─ action_webhook → POST xsiam:8080/api/internal/alerts

③ 告警处理路径（XSIAM 侧）
──────────────────────────────────────────────────────
/api/internal/alerts（X-Internal-Token 鉴权）
  └─ AlertService.Create → 写 ArangoDB alerts 集合
       ├─ go: lakeClient.Ingest（归档副本写 ngx）    ← 仅归档，非采集
       └─ correlationPool.Submit（非阻塞，CAE 异步）
            └─ CausalityService.TriggerCorrelation
                 └─ 自动聚合 Incident + 写 causality_nodes / causality_edges（Named Graph）

④ 查询路径（SOC 分析师）
──────────────────────────────────────────────────────
浏览器 /logs（XQL 查询中心）
  └─ GET /api/logs/query?spl2=...
       └─ LogEntryService.Query
            └─ datalake.Client.Query → ngx :8080/services/search
                 └─ ngx_head_execute_search（SPL2 + pipe 算子）
                      └─ JSON 结果 → 前端渲染
```

### 2.3 各组件职责边界

| 组件 | 职责 | 不做 |
|------|------|------|
| **Fluent-bit** | 多源采集、轻量过滤、tag、批量发送、本地持久化 buffer | 不做富化、不做检测 |
| **ngx HEC** | 接收日志、MPSC ring 削峰、写 zstd journal | 不做业务逻辑 |
| **ngx 规则引擎** | SPL2 检测、富化（eval）、阈值判断、webhook 告警 | 不写 ArangoDB |
| **ngx 查询层** | SPL2 历史查询、pipe 聚合（stats/top/dedup）| 不做写入 |
| **XSIAM Go** | 告警/事件/资产 CRUD、关联分析、评分、权限、前端服务 | 不做日志存储、不做检测计算 |
| **ArangoDB** | 热数据存储（30-90 天）、配置数据、因果关联图（Named Graph） | 不存原始日志 |

### 2.4 embed.FS 集成方式

```go
// main.go
//go:embed dist
var staticFiles embed.FS

func main() {
    cfg := config.Load()
    client := db.Connect(cfg.ArangoDB.Endpoints, cfg.ArangoDB.Username, cfg.ArangoDB.Password)
    defer db.Disconnect(client)

    r := router.New(cfg, client, staticFiles)
    // ...
}
```

```go
// internal/router/router.go
func registerStatic(r *gin.Engine, fs embed.FS) {
    // API 路由优先注册（/api/* 不会匹配到静态文件）

    // SPA 静态文件服务
    distFS, _ := fs.Sub("dist")
    fileServer := http.FileServer(http.FS(distFS))

    r.NoRoute(func(c *gin.Context) {
        path := c.Request.URL.Path
        // 尝试返回具体文件（JS/CSS/图片等）
        if _, err := distFS.(fs.FS).Open(path); err == nil {
            fileServer.ServeHTTP(c.Writer, c.Request)
            return
        }
        // SPA fallback：所有未匹配路径返回 index.html
        c.FileFromFS("index.html", http.FS(distFS))
    })
}
```

### 2.5 Go 服务分层职责边界

| 层 | 文件位置 | 职责 | 不做 |
|----|----------|------|------|
| **Handler 层** | `internal/handler/` | 解析 HTTP 请求、参数绑定校验、调用 Service、序列化响应 | 不含业务逻辑，不访问数据库 |
| **Service 层** | `internal/service/` | 业务编排、多 Repository 组合、调用 Stub | 不直接构造 AQL 字符串，不处理 HTTP |
| **Repository 层** | `internal/repository/` | 封装所有 ArangoDB 操作（AQL 查询/Insert/Update/Delete/Graph Traversal） | 不含业务判断 |
| **Model 层** | `internal/model/` | Go struct 定义（json tag）、枚举常量、字段名常量 | 不含方法逻辑 |
| **DataLake 层** | `internal/datalake/` | ngx SPL2 查询客户端 + 冷数据归档写入 | 不做实时日志采集（由 Fluent-bit 负责） |
| **Stub 层** | `internal/stub/` | 设备响应执行、Agent ETL、AI Engine 接口桩 | DataLakeStub 已删除，由 datalake/ 替代 |
| **Middleware** | `internal/middleware/` | JWT 鉴权、日志、RequestID、Recovery、TenantContext | 不含业务逻辑 |
| **Router** | `internal/router/` | API 路由注册 + 内部告警接口 + 静态文件服务 | 不含处理逻辑 |

---

## 3. Monorepo 目录结构

三个可执行文件共用同一 Go module，共享 `internal/model`、`internal/repository`、`internal/datalake`、`pkg/` 包。

```
xsiam/                                  # Monorepo 根目录（Go module: xsiam）
├── go.mod
├── go.sum
├── config.yaml                       # 公共默认配置（各程序可覆盖）
├── .env                              # 本地环境变量（不提交 Git）
│                                     # ARANGO_ENDPOINTS, ARANGO_USERNAME, ARANGO_PASSWORD, ARANGO_DATABASE
│
│ ── 三个可执行文件入口 ──────────────────────────────────────────────
├── cmd/
│   ├── ngx_console/
│   │   └── main.go                   # ngx_console 入口（embed React SPA，:8080）
│   ├── ngx_svc/
│   │   └── main.go                   # ngx_svc 入口（Auth/RBAC/Notify/Audit，:8090）
│   ├── ngx_cron/
│   │   └── main.go                   # ngx_cron 入口（定时任务管理，无对外端口）
│   └── seed/
│       └── main.go                   # 种子数据脚本（go run ./cmd/seed）
│
│ ── 前端构建产物（embed 到 ngx_console）────────────────────────────
├── dist/                             # React SPA 构建产物（pnpm build 输出到此）
│   ├── index.html
│   └── assets/
│
│ ── 共享 internal 包（三个程序均可引用）────────────────────────────
├── internal/
│   │
│   ├── model/                        # 数据模型层（共享）
│   │   ├── common.go                 # 公共枚举 + 字段名常量
│   │   ├── alert.go
│   │   ├── incident.go
│   │   ├── asset.go
│   │   ├── vulnerability.go
│   │   ├── ioc.go
│   │   ├── intel_feed.go
│   │   ├── action.go
│   │   ├── device.go
│   │   ├── agent_policy.go
│   │   ├── datasource.go
│   │   ├── playbook.go
│   │   ├── report.go
│   │   ├── user.go
│   │   ├── audit_log.go
│   │   ├── detection_rule.go         # 检测规则（BIOC/IOC/UEBA）
│   │   ├── causality_graph.go        # CAE 关联图（DAG 节点/边）
│   │   ├── identity_risk.go          # 身份风险状态（ITDR）
│   │   ├── privilege_restriction.go  # 动态权限限制（ITDR）
│   │   ├── exposure_score.go         # 漏洞暴露优先级评分
│   │   └── tenant.go                 # 租户 + RBAC 角色
│   │
│   ├── repository/                   # 数据访问层（共享）
│   │   ├── base.go                   # FindPaged[T any] 泛型分页 + ListOptions
│   │   ├── alert.go
│   │   ├── incident.go
│   │   ├── asset.go
│   │   ├── vulnerability.go
│   │   ├── ioc.go
│   │   ├── intel_feed.go
│   │   ├── action.go
│   │   ├── device.go
│   │   ├── agent_policy.go
│   │   ├── datasource.go
│   │   ├── playbook.go
│   │   ├── report.go
│   │   ├── user.go
│   │   ├── audit_log.go
│   │   ├── detection_rule.go
│   │   ├── causality_graph.go
│   │   ├── identity_risk.go
│   │   ├── privilege_restriction.go
│   │   ├── exposure_score.go
│   │   └── tenant.go
│   │
│   ├── datalake/                     # ngx 数据湖客户端（共享）
│   │   ├── client.go                 # Client struct（queryURL + hecURL）
│   │   ├── query.go                  # Query() — SPL2 查询（public）
│   │   ├── hec.go                    # ingest() — HEC 写入（private，仅归档器调用）
│   │   ├── saved_search.go           # CreateSavedSearch / DeleteSavedSearch
│   │   ├── archiver.go               # 冷数据归档器（告警 TTL 前写入 ngx）
│   │   └── interface.go              # QueryClient interface + DataLakeStub
│   │
│   │ ── ngx_console 专属 ───────────────────────────────────────────
│   ├── service/                      # 业务逻辑层（ngx_console 使用）
│   │   ├── dashboard.go
│   │   ├── asset.go
│   │   ├── alert.go
│   │   ├── incident.go
│   │   ├── vulnerability.go
│   │   ├── ioc.go
│   │   ├── intel_feed.go
│   │   ├── action.go
│   │   ├── log_entry.go
│   │   ├── device.go
│   │   ├── playbook.go
│   │   ├── report.go
│   │   ├── user.go
│   │   ├── detection_rule.go         # 规则 CRUD + 状态流转 + 同步到 ngx saved_search
│   │   ├── causality.go              # CAE goroutine pool + 关联分析
│   │   ├── smart_score.go            # SmartScore 预计算 + LRU 缓存
│   │   ├── identity_risk.go          # ITDR 内存聚合 + 30s flush
│   │   ├── exposure.go               # 暴露管理 + 优先级评分
│   │   └── tenant.go                 # 租户 CRUD（ngx_console 侧）
│   │
│   ├── handler/                      # HTTP 处理层（ngx_console 使用）
│   │   ├── dashboard.go
│   │   ├── asset.go
│   │   ├── alert.go
│   │   ├── incident.go
│   │   ├── vulnerability.go
│   │   ├── ioc.go
│   │   ├── intel_feed.go
│   │   ├── action.go
│   │   ├── log_entry.go
│   │   ├── device.go
│   │   ├── agent_policy.go
│   │   ├── datasource.go
│   │   ├── playbook.go
│   │   ├── report.go
│   │   ├── user.go
│   │   ├── detection_rule.go
│   │   ├── causality.go
│   │   ├── smart_score.go
│   │   ├── identity_risk.go
│   │   ├── exposure.go
│   │   ├── tenant.go
│   │   └── internal.go               # /api/internal/alerts（ngx 规则引擎回调）
│   │
│   ├── router/
│   │   └── router.go                 # ngx_console 路由注册 + embed 静态文件
│   │
│   ├── middleware/
│   │   ├── auth.go                   # JWT 本地验证中间件（不回调 ngx_svc）
│   │   ├── logger.go
│   │   ├── request_id.go
│   │   ├── recovery.go
│   │   └── rbac.go                   # 权限检查（调用 ngx_svc /rbac/check）
│   │
│   ├── stub/                         # 外部系统接口桩（ngx_console 使用）
│   │   ├── execution.go              # 设备响应执行
│   │   ├── etl.go                    # 日志 ETL 管道
│   │   └── ai_engine.go              # AI 引擎
│   │
│   │ ── ngx_svc 专属 ────────────────────────────────────────────────
│   ├── svc/
│   │   ├── auth/
│   │   │   ├── service.go            # JWT 签发 / 刷新 / 验证
│   │   │   └── handler.go            # POST /auth/login  POST /auth/refresh
│   │   ├── rbac/
│   │   │   ├── service.go            # 权限检查 + 角色管理 + 租户隔离
│   │   │   └── handler.go            # POST /rbac/check  CRUD /rbac/roles
│   │   ├── notify/
│   │   │   ├── service.go            # 通知调度（adapter 模式）
│   │   │   ├── email.go              # SMTP adapter
│   │   │   ├── dingtalk.go           # 钉钉 Webhook adapter
│   │   │   ├── slack.go              # Slack Incoming Webhook adapter
│   │   │   └── handler.go            # POST /notify/send
│   │   └── audit/
│   │       ├── service.go            # 审计日志记录 + 查询
│   │       └── handler.go            # POST /audit/record  GET /audit/logs
│   │
│   │ ── ngx_cron 专属 ────────────────────────────────────────────────
│   └── cron/
│       └── manager.go                # CronManager：RegisterWorkerPool / RegisterInterval / RegisterCron
│
│ ── 公共工具包（三个程序均可引用）──────────────────────────────────
├── pkg/
│   ├── response/
│   │   └── response.go               # 统一 API 响应封装（OK/Err/Paginated）
│   ├── errs/
│   │   └── errors.go                 # 业务错误码
│   └── utils/
│       ├── id.go                     # 业务 ID 生成
│       └── ptr.go                    # 指针辅助
│
└── db/
    └── arango.go                     # ArangoDB 连接初始化 + 集合/图确保存在（共享）
```

**编译命令：**

```bash
CGO_ENABLED=0 go build -o ngx_console ./cmd/ngx_console
CGO_ENABLED=0 go build -o ngx_svc     ./cmd/ngx_svc
CGO_ENABLED=0 go build -o ngx_cron    ./cmd/ngx_cron
```

---

## 4. 前端目录结构

```
web/                                  # React SPA 前端根目录
├── index.html                        # Vite 入口 HTML
├── vite.config.ts                    # Vite 配置（构建输出到 ../xsiam/dist）
├── tsconfig.json                     # TypeScript strict 模式
├── package.json
│
├── src/
│   ├── main.tsx                      # React 入口，TanStack Router Provider
│   ├── app.tsx                       # 根组件，全局 QueryClientProvider
│   │
│   ├── routes/                       # TanStack Router 路由定义（文件即路由）
│   │   ├── __root.tsx                # 根路由（AppShell 布局）
│   │   ├── index.tsx                 # / → redirect to /dashboard
│   │   ├── login.tsx                 # /login
│   │   ├── dashboard.tsx             # /dashboard
│   │   ├── assets/
│   │   │   ├── index.tsx             # /assets
│   │   │   └── $id.tsx               # /assets/:id
│   │   ├── alerts/
│   │   │   ├── index.tsx             # /alerts
│   │   │   └── $id.tsx               # /alerts/:id
│   │   ├── incidents/
│   │   │   ├── index.tsx             # /incidents
│   │   │   └── $id.tsx               # /incidents/:id
│   │   ├── vulnerabilities.tsx       # /vulnerabilities
│   │   ├── threat-intel/
│   │   │   ├── index.tsx             # /threat-intel（IOC 列表）
│   │   │   ├── feeds.tsx             # /threat-intel/feeds
│   │   │   └── trc.tsx               # /threat-intel/trc
│   │   ├── actions.tsx               # /actions
│   │   ├── logs.tsx                  # /logs（XQL 查询中心）
│   │   ├── devices/
│   │   │   ├── index.tsx             # /devices（Agent 列表）
│   │   │   ├── datasources.tsx       # /devices/datasources
│   │   │   └── policies.tsx          # /devices/policies
│   │   ├── reports.tsx               # /reports
│   │   ├── playbooks/
│   │   │   ├── index.tsx             # /playbooks
│   │   │   └── $id.tsx               # /playbooks/:id（Canvas 编辑器）
│   │   └── causality.tsx             # /causality
│   │
│   ├── components/
│   │   ├── ui/                       # shadcn/ui 生成组件（Button / Dialog / Table 等）
│   │   ├── layout/
│   │   │   ├── AppShell.tsx
│   │   │   ├── Sidebar.tsx
│   │   │   └── TopBar.tsx
│   │   ├── common/
│   │   │   ├── DataTable.tsx         # TanStack Table 封装（排序/分页/筛选）
│   │   │   ├── FilterBar.tsx
│   │   │   ├── SeverityBadge.tsx
│   │   │   ├── StatusBadge.tsx
│   │   │   ├── SmartScore.tsx
│   │   │   ├── SourceTag.tsx
│   │   │   ├── PageHeader.tsx
│   │   │   ├── DrawerPanel.tsx
│   │   │   ├── ConfirmDialog.tsx
│   │   │   └── EmptyState.tsx
│   │   ├── dashboard/
│   │   │   ├── KpiCard.tsx
│   │   │   ├── AlertTrendChart.tsx
│   │   │   ├── SourceDistributionChart.tsx
│   │   │   ├── MitreHeatmap.tsx
│   │   │   └── RecentIncidents.tsx
│   │   ├── alerts/
│   │   │   ├── AlertsTable.tsx
│   │   │   ├── AlertDetailPanel.tsx
│   │   │   └── ProcessTree.tsx
│   │   ├── incidents/
│   │   │   ├── IncidentsTable.tsx
│   │   │   ├── IncidentDrawer.tsx
│   │   │   ├── SmartScoreBreakdown.tsx
│   │   │   ├── AlertChain.tsx
│   │   │   ├── MitreMapping.tsx
│   │   │   └── IncidentTimeline.tsx
│   │   ├── assets/
│   │   │   ├── AssetsTable.tsx
│   │   │   └── AssetDetailPanel.tsx
│   │   ├── threat-intel/
│   │   │   ├── IocTable.tsx
│   │   │   ├── IocDetailPanel.tsx
│   │   │   ├── FeedCard.tsx
│   │   │   └── TrcEventCard.tsx
│   │   ├── actions/
│   │   │   ├── ActionTable.tsx
│   │   │   ├── NewActionDialog.tsx
│   │   │   └── LiveTerminal.tsx
│   │   ├── logs/
│   │   │   ├── XqlEditor.tsx
│   │   │   ├── QueryResultTable.tsx
│   │   │   └── DatasetBrowser.tsx
│   │   ├── causality/
│   │   │   ├── CausalityGraph.tsx
│   │   │   └── NodeDetailPanel.tsx
│   │   └── playbooks/
│   │       ├── PlaybookList.tsx
│   │       └── PlaybookCanvas.tsx
│   │
│   ├── api/                          # API 客户端层（fetch 封装，与 Go 结构体对应）
│   │   ├── client.ts                 # 基础 fetch 封装（token注入 / 错误处理 / 响应解析）
│   │   ├── dashboard.ts
│   │   ├── alerts.ts
│   │   ├── incidents.ts
│   │   ├── assets.ts
│   │   ├── vulnerabilities.ts
│   │   ├── iocs.ts
│   │   ├── intel-feeds.ts
│   │   ├── actions.ts
│   │   ├── logs.ts
│   │   ├── devices.ts
│   │   ├── playbooks.ts
│   │   └── reports.ts
│   │
│   ├── types/
│   │   └── index.ts                  # 全量 TypeScript 类型（与 Go struct 字段一一对应）
│   │
│   ├── hooks/                        # TanStack Query hooks
│   │   ├── useAlerts.ts
│   │   ├── useIncidents.ts
│   │   ├── useAssets.ts
│   │   ├── useVulnerabilities.ts
│   │   ├── useIocs.ts
│   │   ├── useActions.ts
│   │   ├── useDevices.ts
│   │   └── useDashboard.ts
│   │
│   └── store/
│       ├── auth.store.ts             # JWT token 存储（Zustand + localStorage）
│       ├── ui.store.ts               # 侧边栏折叠等 UI 状态
│       └── filter.store.ts           # 全局筛选条件持久化
│
└── public/                           # 不经 Vite 处理的静态资源（favicon 等）
```

### 4.1 Vite 构建输出配置

前端构建输出直接输出到 Go 项目的 `dist/` 目录，Go embed 打包时自动内嵌：

```typescript
// web/vite.config.ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  build: {
    outDir: '../xsiam/dist',   // 输出到 Go 项目 dist 目录
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8080',  // 开发期代理（生产无需此配置）
    },
  },
})
```

### 4.2 开发 vs 生产模式

```
开发模式（两进程）：
  Terminal 1: cd xsiam && go run .          → Go API :8080
  Terminal 2: cd web && pnpm dev          → Vite HMR :5173（代理 /api 到 :8080）

  浏览器访问 http://localhost:5173

生产模式（单进程）：
  cd web && pnpm build                    → 输出到 xsiam/dist/
  cd xsiam && CGO_ENABLED=0 go build -o xsiam .
  ./xsiam                                   → 一个进程 :8080，API + 静态文件

  浏览器访问 http://localhost:8080
```

---

## 5. ngx_svc 设计

ngx_svc 是独立的基础服务程序（`:8090`），提供 Auth / RBAC / Notify / Audit 四个子服务。ngx_console 和 ngx_cron 通过 HTTP 内部调用 ngx_svc；JWT 由 ngx_svc 签发，ngx_console 在本地用共享密钥验证（无需每次请求回调）。

### 5.1 ngx_svc main.go

```go
// cmd/ngx_svc/main.go
package main

import (
    "context"
    "net/http"
    "os/signal"
    "syscall"
    "time"

    "xsiam/config"
    "xsiam/db"
    "xsiam/internal/svc/auth"
    "xsiam/internal/svc/audit"
    "xsiam/internal/svc/notify"
    "xsiam/internal/svc/rbac"

    "github.com/gin-gonic/gin"
    "go.uber.org/zap"
)

func main() {
    cfg  := config.Load()
    log, _ := zap.NewProduction()
    defer log.Sync()

    adb := db.Connect(cfg.ArangoDB.Endpoints, cfg.ArangoDB.Username, cfg.ArangoDB.Password)
    database := db.Database(adb, cfg.ArangoDB.Database)

    // 依赖装配
    authSvc   := auth.NewService(cfg.Auth)
    rbacSvc   := rbac.NewService(database)
    notifySvc := notify.NewService(cfg.Notify)
    auditSvc  := audit.NewService(database)

    authH   := auth.NewHandler(authSvc)
    rbacH   := rbac.NewHandler(rbacSvc)
    notifyH := notify.NewHandler(notifySvc)
    auditH  := audit.NewHandler(auditSvc)

    r := gin.New()
    r.Use(gin.Recovery())

    // 内部服务无需 JWT 中间件（网络层隔离，仅监听内网）
    r.POST("/auth/login",    authH.Login)
    r.POST("/auth/refresh",  authH.Refresh)
    r.POST("/auth/verify",   authH.Verify)      // ngx_console 可选调用（热路径本地验证更优）

    r.POST("/rbac/check",    rbacH.Check)
    r.GET("/rbac/roles",     rbacH.ListRoles)
    r.POST("/rbac/roles",    rbacH.CreateRole)
    r.PATCH("/rbac/roles/:id", rbacH.UpdateRole)
    r.DELETE("/rbac/roles/:id", rbacH.DeleteRole)

    r.POST("/notify/send",   notifyH.Send)

    r.POST("/audit/record",  auditH.Record)
    r.GET("/audit/logs",     auditH.List)

    srv := &http.Server{Addr: ":" + cfg.SvcServer.Port, Handler: r,
        ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second}

    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()
    go func() { _ = srv.ListenAndServe() }()
    log.Info("ngx_svc started", zap.String("port", cfg.SvcServer.Port))
    <-ctx.Done()

    shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    _ = srv.Shutdown(shutCtx)
}
```

### 5.2 Auth 子服务

负责 JWT 签发与刷新。ngx_console 本地验证 token（共享 `JWT_SECRET`），不走网络热路径。

```go
// internal/svc/auth/service.go
package auth

import (
    "errors"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "xsiam/config"
)

type Claims struct {
    UserID   string `json:"uid"`
    TenantID string `json:"tid"`
    Role     string `json:"role"`
    jwt.RegisteredClaims
}

type Service struct{ cfg config.AuthConfig }

func NewService(cfg config.AuthConfig) *Service { return &Service{cfg: cfg} }

func (s *Service) Issue(userID, tenantID, role string) (string, error) {
    claims := Claims{
        UserID: userID, TenantID: tenantID, Role: role,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(s.cfg.TokenExpireHr) * time.Hour)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }
    return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.cfg.JWTSecret))
}

func (s *Service) Verify(tokenStr string) (*Claims, error) {
    tok, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("unexpected signing method")
        }
        return []byte(s.cfg.JWTSecret), nil
    })
    if err != nil || !tok.Valid {
        return nil, errors.New("invalid token")
    }
    return tok.Claims.(*Claims), nil
}

// Refresh: verify old token（宽容 1h 过期），签发新 token
func (s *Service) Refresh(oldToken string) (string, error) {
    parser := jwt.NewParser(jwt.WithLeeway(time.Hour))
    tok, err := parser.ParseWithClaims(oldToken, &Claims{}, func(t *jwt.Token) (any, error) {
        return []byte(s.cfg.JWTSecret), nil
    })
    if err != nil { return "", err }
    c := tok.Claims.(*Claims)
    return s.Issue(c.UserID, c.TenantID, c.Role)
}
```

**Auth API：**

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/auth/login` | 用户名密码登录，返回 `{token, expires_at}` |
| POST | `/auth/refresh` | 刷新 token（Body: `{token}`） |
| POST | `/auth/verify` | 验证 token 有效性（可选，本地验证更优） |

### 5.3 RBAC 子服务

基于角色的权限模型。权限点格式：`resource:action`（如 `alerts:read`、`incidents:write`）。

```go
// internal/svc/rbac/service.go
package rbac

import (
    "context"
    "fmt"

    "github.com/arangodb/go-driver/v2/arangodb"
    "xsiam/internal/model"
)

type CheckReq struct {
    UserID   string `json:"user_id"`
    TenantID string `json:"tenant_id"`
    Resource string `json:"resource"`
    Action   string `json:"action"`
}

type Service struct{ db arangodb.Database }

func NewService(db arangodb.Database) *Service { return &Service{db: db} }

func (s *Service) Check(ctx context.Context, req CheckReq) (bool, error) {
    query := `
        FOR r IN rbac_roles
            FILTER r.tenant_id == @tenant_id AND @user_id IN r.members
            LIMIT 1
            RETURN r`
    cursor, err := s.db.Query(ctx, query, map[string]any{
        "tenant_id": req.TenantID,
        "user_id":   req.UserID,
    })
    if err != nil { return false, err }
    defer cursor.Close()

    var role model.RBACRole
    if _, err := cursor.ReadDocument(ctx, &role); err != nil { return false, nil }

    perm := req.Resource + ":" + req.Action
    for _, p := range role.Permissions {
        if p == perm || p == req.Resource+":*" { return true, nil }
    }
    return false, nil
}
```

**RBAC API：**

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/rbac/check` | 权限检查，Body: `{user_id, tenant_id, resource, action}`，返回 `{allowed: bool}` |
| GET | `/rbac/roles` | 列出角色（`?tenant_id=xxx`） |
| POST | `/rbac/roles` | 创建角色 |
| PATCH | `/rbac/roles/:id` | 更新角色权限/成员 |
| DELETE | `/rbac/roles/:id` | 删除角色 |

内置角色（seed 数据初始化）：

| 角色 | 权限点 |
|------|--------|
| `admin` | `*:*`（全权限） |
| `analyst` | `alerts:*` `incidents:*` `logs:read` `assets:read` |
| `viewer` | `*:read` |

### 5.4 Notify 子服务

Adapter 模式，统一接口，多渠道实现。调用方（ngx_console / ngx_cron）只调用 `POST /notify/send`，无需关心渠道细节。

```go
// internal/svc/notify/service.go
package notify

import "context"

type Channel string
const (
    ChannelEmail    Channel = "email"
    ChannelDingTalk Channel = "dingtalk"
    ChannelSlack    Channel = "slack"
    ChannelSMS      Channel = "sms"
)

type SendReq struct {
    Channel  Channel  `json:"channel"`
    To       []string `json:"to"`
    Subject  string   `json:"subject"`
    Body     string   `json:"body"`
    TenantID string   `json:"tenant_id"`
}

type Adapter interface {
    Send(ctx context.Context, req SendReq) error
}

type Service struct {
    adapters map[Channel]Adapter
}

func NewService(cfg config.NotifyConfig) *Service {
    s := &Service{adapters: make(map[Channel]Adapter)}
    if cfg.Email.Enabled    { s.adapters[ChannelEmail]    = newEmailAdapter(cfg.Email) }
    if cfg.DingTalk.Enabled { s.adapters[ChannelDingTalk] = newDingTalkAdapter(cfg.DingTalk) }
    if cfg.Slack.Enabled    { s.adapters[ChannelSlack]    = newSlackAdapter(cfg.Slack) }
    return s
}

func (s *Service) Send(ctx context.Context, req SendReq) error {
    a, ok := s.adapters[req.Channel]
    if !ok { return nil } // 渠道未配置时静默跳过（非错误）
    return a.Send(ctx, req)
}
```

**Notify API：**

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/notify/send` | 发送通知，Body: `{channel, to, subject, body, tenant_id}` |

### 5.5 Audit 子服务

记录用户操作审计日志，写入 ArangoDB `audit_logs` collection。

```go
// internal/svc/audit/service.go
package audit

import (
    "context"
    "time"

    "github.com/arangodb/go-driver/v2/arangodb"
    "xsiam/internal/model"
)

type RecordReq struct {
    TenantID   string `json:"tenant_id"`
    OperatorID string `json:"operator_id"`
    Action     string `json:"action"`      // 操作类型，如 "alert.update"
    Resource   string `json:"resource"`    // 资源 ID
    Detail     any    `json:"detail"`      // 变更详情（JSON-serializable）
}

type Service struct{ db arangodb.Database }

func (s *Service) Record(ctx context.Context, req RecordReq) error {
    entry := model.AuditLog{
        TenantID:   req.TenantID,
        OperatorID: req.OperatorID,
        Action:     req.Action,
        Resource:   req.Resource,
        Detail:     req.Detail,
        CreatedAt:  time.Now(),
    }
    col, err := s.db.Collection(ctx, "audit_logs")
    if err != nil { return err }
    _, err = col.CreateDocument(ctx, entry)
    return err
}
```

**Audit API：**

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/audit/record` | 写入一条审计日志 |
| GET | `/audit/logs` | 查询审计日志（`?tenant_id=&operator_id=&from=&to=&page=&page_size=`） |

### 5.6 ngx_console 调用 ngx_svc

ngx_console 通过简单 HTTP 客户端调用 ngx_svc，封装为 `pkg/svcclient/` 包：

```go
// pkg/svcclient/client.go
package svcclient

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
)

type Client struct {
    base string       // http://ngx_svc:8090
    http *http.Client
}

func New(base string) *Client {
    return &Client{base: base, http: &http.Client{Timeout: 5 * time.Second}}
}

func (c *Client) CheckPermission(ctx context.Context, userID, tenantID, resource, action string) (bool, error) {
    body, _ := json.Marshal(map[string]string{
        "user_id": userID, "tenant_id": tenantID, "resource": resource, "action": action,
    })
    resp, err := c.post(ctx, "/rbac/check", body)
    if err != nil { return false, err }
    var result struct{ Allowed bool `json:"allowed"` }
    json.Unmarshal(resp, &result)
    return result.Allowed, nil
}

func (c *Client) RecordAudit(ctx context.Context, req any) error {
    body, _ := json.Marshal(req)
    _, err := c.post(ctx, "/audit/record", body)
    return err
}

func (c *Client) SendNotify(ctx context.Context, req any) error {
    body, _ := json.Marshal(req)
    _, err := c.post(ctx, "/notify/send", body)
    return err
}

func (c *Client) post(ctx context.Context, path string, body []byte) ([]byte, error) {
    req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    resp, err := c.http.Do(req)
    if err != nil { return nil, err }
    defer resp.Body.Close()
    if resp.StatusCode >= 400 {
        return nil, fmt.Errorf("ngx_svc %s: %d", path, resp.StatusCode)
    }
    var buf bytes.Buffer
    buf.ReadFrom(resp.Body)
    return buf.Bytes(), nil
}
```

**JWT 验证方式（本地验证，零网络开销）：**

ngx_console 的 auth 中间件直接用共享 `JWT_SECRET` 在本地解析 token，不调用 ngx_svc：

```go
// internal/middleware/auth.go
func Auth(secret string) gin.HandlerFunc {
    return func(c *gin.Context) {
        token := extractBearerToken(c)
        claims, err := parseJWT(token, secret) // 纯本地操作，< 0.1ms
        if err != nil { c.AbortWithStatus(401); return }
        c.Set("user_id",   claims.UserID)
        c.Set("tenant_id", claims.TenantID)
        c.Set("role",      claims.Role)
        c.Next()
    }
}
```

---

## 6. ngx_cron 设计

ngx_cron 是独立的定时任务管理程序，无对外 HTTP 端口，统一管理所有后台周期性任务，取代散落在各 Service 中的 `go func()`。

### 6.1 CronManager

```go
// internal/cron/manager.go
package cron

import (
    "context"
    "sync"
    "time"

    "github.com/robfig/cron/v3"
    "go.uber.org/zap"
)

type Manager struct {
    c      *cron.Cron
    wg     sync.WaitGroup
    log    *zap.Logger
    ctx    context.Context
    cancel context.CancelFunc
}

func NewManager(log *zap.Logger) *Manager {
    ctx, cancel := context.WithCancel(context.Background())
    return &Manager{
        c:      cron.New(cron.WithSeconds()),
        log:    log,
        ctx:    ctx,
        cancel: cancel,
    }
}

// RegisterInterval 注册固定间隔任务
func (m *Manager) RegisterInterval(name string, interval time.Duration, fn func(ctx context.Context)) {
    m.c.AddFunc("@every "+interval.String(), func() {
        m.wg.Add(1)
        defer m.wg.Done()
        fn(m.ctx)
    })
    m.log.Info("cron registered interval", zap.String("name", name), zap.Duration("interval", interval))
}

// RegisterCron 注册 cron 表达式任务
func (m *Manager) RegisterCron(name string, expr string, fn func(ctx context.Context)) {
    m.c.AddFunc(expr, func() {
        m.wg.Add(1)
        defer m.wg.Done()
        fn(m.ctx)
    })
    m.log.Info("cron registered cron", zap.String("name", name), zap.String("expr", expr))
}

// RegisterWorkerPool 注册固定 goroutine 池（长期运行的 worker）
func (m *Manager) RegisterWorkerPool(name string, workers int, queue chan string, fn func(ctx context.Context, item string)) {
    for i := 0; i < workers; i++ {
        m.wg.Add(1)
        go func() {
            defer m.wg.Done()
            for {
                select {
                case item, ok := <-queue:
                    if !ok { return }
                    fn(m.ctx, item)
                case <-m.ctx.Done():
                    return
                }
            }
        }()
    }
    m.log.Info("cron registered pool", zap.String("name", name), zap.Int("workers", workers))
}

func (m *Manager) Start() { m.c.Start() }

func (m *Manager) Shutdown() {
    m.cancel()          // 通知所有 worker 退出
    m.c.Stop()          // 停止调度新任务
    m.wg.Wait()         // 等待所有运行中任务完成
    m.log.Info("ngx_cron shutdown complete")
}
```

### 6.2 ngx_cron main.go

```go
// cmd/ngx_cron/main.go
package main

import (
    "context"
    "os/signal"
    "syscall"
    "time"

    "xsiam/config"
    "xsiam/db"
    "xsiam/internal/cron"
    "xsiam/internal/datalake"
    "xsiam/internal/repository"
    "xsiam/internal/service"
    "xsiam/pkg/svcclient"

    "go.uber.org/zap"
)

func main() {
    cfg  := config.Load()
    log, _ := zap.NewProduction()
    defer log.Sync()

    adb      := db.Connect(cfg.ArangoDB.Endpoints, cfg.ArangoDB.Username, cfg.ArangoDB.Password)
    database := db.Database(adb, cfg.ArangoDB.Database)

    svcClient := svcclient.New(cfg.SvcServer.InternalURL) // http://ngx_svc:8090
    lakeClient := datalake.New(cfg.DataLake.QueryURL, cfg.DataLake.HECURL, cfg.DataLake.HECToken)

    // 各任务所需的 repo/service
    alertRepo    := repository.NewAlertRepo(database)
    incRepo      := repository.NewIncidentRepo(database)
    riskRepo     := repository.NewIdentityRiskRepo(database)
    expRepo      := repository.NewExposureScoreRepo(database)
    smartScoreSvc := service.NewSmartScoreService(incRepo, alertRepo)
    itdrSvc       := service.NewIdentityRiskService(riskRepo, nil)
    archiverSvc   := datalake.NewArchiver(lakeClient, alertRepo)
    exposureSvc   := service.NewExposureService(expRepo, nil)
    causalityQueue := make(chan string, 4096)
    causalitySvc   := service.NewCausalityService(incRepo, alertRepo)

    mgr := cron.NewManager(log)

    // ── 任务注册 ──────────────────────────────────────────────────────
    // CAE 关联分析 goroutine pool（持续运行，4 worker）
    mgr.RegisterWorkerPool("cae_correlation", 4, causalityQueue, func(ctx context.Context, alertID string) {
        if err := causalitySvc.TriggerCorrelation(ctx, alertID); err != nil {
            log.Warn("cae correlation failed", zap.String("alert_id", alertID), zap.Error(err))
        }
    })

    // ITDR 内存状态 → ArangoDB 批量 flush（每 30 秒）
    mgr.RegisterInterval("itdr_flush", 30*time.Second, func(ctx context.Context) {
        itdrSvc.FlushToDB(ctx)
    })

    // SmartScore LRU 缓存过期清理（每 2 分钟）
    mgr.RegisterInterval("smart_score_evict", 2*time.Minute, func(ctx context.Context) {
        smartScoreSvc.EvictExpired()
    })

    // 冷数据归档：ArangoDB 告警 → ngx HEC（每小时）
    mgr.RegisterInterval("cold_archiver", 1*time.Hour, func(ctx context.Context) {
        if err := archiverSvc.ArchiveAlerts(ctx); err != nil {
            log.Warn("archiver failed", zap.Error(err))
        }
    })

    // 暴露评分重新计算（每天凌晨 2 点）
    mgr.RegisterCron("exposure_recalc", "0 0 2 * * *", func(ctx context.Context) {
        if err := exposureSvc.RecalcAll(ctx); err != nil {
            log.Warn("exposure recalc failed", zap.Error(err))
        }
    })

    _ = svcClient // ngx_cron 可通过 svcClient 记录审计或发送通知

    mgr.Start()
    log.Info("ngx_cron started")

    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()
    <-ctx.Done()

    mgr.Shutdown()
}
```

### 6.3 任务注册表

| 任务名 | 类型 | 调度 | 职责 |
|--------|------|------|------|
| `cae_correlation` | WorkerPool | 4 goroutine 常驻 | CAE 告警关联分析 → 聚合 Incident |
| `itdr_flush` | Interval | 每 30 秒 | ITDR 内存风险状态批量写 ArangoDB |
| `smart_score_evict` | Interval | 每 2 分钟 | SmartScore LRU 缓存过期条目清理 |
| `cold_archiver` | Interval | 每 1 小时 | ArangoDB 告警（TTL 30天）写入 ngx 冷存储 |
| `exposure_recalc` | Cron | `0 0 2 * * *` | 每日凌晨重算全量暴露优先级评分 |

### 6.4 优雅关闭流程

```
SIGINT/SIGTERM
  → Manager.Shutdown()
    → cancel() 通知 WorkerPool goroutine 退出
    → cron.Stop() 停止新任务调度
    → wg.Wait() 等待当前运行任务执行完毕（超时由上层 context 控制）
    → 程序退出
```

---

## 7. Go 分层设计详解

### 7.1 main.go

```go
// main.go
package main

import (
    "context"
    "embed"
    "net/http"
    "os/signal"
    "syscall"
    "time"

    "xsiam/config"
    "xsiam/internal/db"
    "xsiam/internal/router"
)

//go:embed dist
var staticFiles embed.FS

func main() {
    cfg := config.Load()

    arangoClient := db.Connect(cfg.ArangoDB.Endpoints, cfg.ArangoDB.Username, cfg.ArangoDB.Password)

    r := router.New(cfg, arangoClient, staticFiles)

    srv := &http.Server{
        Addr:         ":" + cfg.Server.Port,
        Handler:      r,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    go func() { _ = srv.ListenAndServe() }()
    <-ctx.Done()

    shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    _ = srv.Shutdown(shutCtx)
}
```

### 7.2 config/config.go

```go
// config/config.go
package config

import (
    "strings"
    "github.com/spf13/viper"
)

type Config struct {
    Server   ServerConfig
    ArangoDB ArangoDBConfig
    Auth     AuthConfig
    Stub     StubConfig
}

type ServerConfig   struct { Port string; Mode string }
type ArangoDBConfig struct {
    Endpoints []string // e.g. ["http://localhost:8529"]
    Username  string
    Password  string
    Database  string
}
type AuthConfig struct { JWTSecret string; TokenExpireHr int }
type StubConfig struct { Execution bool; ETL bool; DataLake bool; AIEngine bool }

func Load() *Config {
    viper.SetConfigFile("config.yaml")
    viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
    viper.AutomaticEnv()
    _ = viper.ReadInConfig()

    return &Config{
        Server: ServerConfig{Port: viper.GetString("SERVER_PORT"), Mode: viper.GetString("SERVER_MODE")},
        ArangoDB: ArangoDBConfig{
            Endpoints: viper.GetStringSlice("ARANGO_ENDPOINTS"),
            Username:  viper.GetString("ARANGO_USERNAME"),
            Password:  viper.GetString("ARANGO_PASSWORD"),
            Database:  viper.GetString("ARANGO_DATABASE"),
        },
        Auth: AuthConfig{JWTSecret: viper.GetString("JWT_SECRET"), TokenExpireHr: viper.GetInt("JWT_EXPIRE_HR")},
        Stub: StubConfig{
            Execution: viper.GetBool("STUB_EXECUTION"),
            ETL:       viper.GetBool("STUB_ETL"),
            DataLake:  viper.GetBool("STUB_DATALAKE"),
            AIEngine:  viper.GetBool("STUB_AI_ENGINE"),
        },
    }
}
```

### 7.3 db/arango.go

```go
// db/arango.go
package db

import (
    "context"
    "time"

    "github.com/arangodb/go-driver/v2/arangodb"
    "github.com/arangodb/go-driver/v2/connection"
)

// Connect 建立 ArangoDB 连接（支持单节点与集群 Coordinator）
func Connect(endpoints []string, username, password string) arangodb.Client {
    conn, err := connection.NewHttp2Connection(connection.Http2Configuration{
        Endpoints: endpoints,
        Auth:      &connection.AuthBasic{Username: username, Password: password},
        ContentType: connection.ApplicationJSON,
    })
    if err != nil { panic("arangodb conn: " + err.Error()) }

    client, err := arangodb.NewClient(conn)
    if err != nil { panic("arangodb client: " + err.Error()) }

    // 健康检查
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    if _, err = client.Version(ctx); err != nil {
        panic("arangodb ping: " + err.Error())
    }
    return client
}

// Database 获取指定数据库，不存在则创建
func Database(client arangodb.Client, name string) arangodb.Database {
    ctx := context.Background()
    exists, err := client.DatabaseExists(ctx, name)
    if err != nil { panic("arangodb db check: " + err.Error()) }
    if !exists {
        db, err := client.CreateDatabase(ctx, name, nil)
        if err != nil { panic("arangodb create db: " + err.Error()) }
        EnsureCollections(ctx, db)
        return db
    }
    db, err := client.Database(ctx, name)
    if err != nil { panic("arangodb db: " + err.Error()) }
    return db
}

// EnsureCollections 确保所有集合和图存在（幂等，启动时调用）
func EnsureCollections(ctx context.Context, db arangodb.Database) {
    // 文档集合（Document Collections）
    docCols := []string{
        "alerts", "incidents", "assets", "vulnerabilities",
        "iocs", "intel_feeds", "actions", "devices", "agent_policies",
        "datasources", "playbooks", "reports", "users", "audit_logs",
        "tenants", "rbac_roles", "detection_rules",
        "identity_risks", "privilege_restrictions", "exposure_scores",
        "causality_nodes",   // 因果图节点（文档集合）
    }
    for _, name := range docCols {
        ensureCollection(ctx, db, name, false)
    }

    // 边集合（Edge Collections，用于图遍历）
    ensureCollection(ctx, db, "causality_edges", true)

    // Named Graph：因果关联图
    ensureGraph(ctx, db, "causality_graph", "causality_edges",
        []string{"causality_nodes"}, []string{"causality_nodes"})
}

func ensureCollection(ctx context.Context, db arangodb.Database, name string, isEdge bool) {
    exists, _ := db.CollectionExists(ctx, name)
    if exists { return }
    props := arangodb.CreateCollectionProperties{}
    if isEdge { props.Type = arangodb.CollectionTypeEdge }
    db.CreateCollection(ctx, name, &props)
}

func ensureGraph(ctx context.Context, db arangodb.Database, graphName, edgeCol string, from, to []string) {
    exists, _ := db.GraphExists(ctx, graphName)
    if exists { return }
    db.CreateGraph(ctx, graphName, &arangodb.CreateGraphOptions{
        EdgeDefinitions: []arangodb.EdgeDefinition{{
            Collection: edgeCol, From: from, To: to,
        }},
    }, nil)
}
```

### 7.4 internal/router/router.go

```go
// internal/router/router.go
package router

import (
    "embed"
    "io/fs"
    "net/http"
    "xsiam/config"
    "xsiam/db"
    "xsiam/internal/handler"
    "xsiam/internal/middleware"
    "xsiam/internal/repository"
    "xsiam/internal/service"
    "xsiam/internal/stub"

    "github.com/arangodb/go-driver/v2/arangodb"
    "github.com/gin-contrib/requestid"
    "github.com/gin-gonic/gin"
)

func New(cfg *config.Config, client arangodb.Client, staticFiles embed.FS) *gin.Engine {
    gin.SetMode(cfg.Server.Mode)
    r := gin.New()

    // 全局中间件
    r.Use(requestid.New())
    r.Use(middleware.Logger())
    r.Use(middleware.Recovery())
    // 无需 CORS 中间件：同源（Go 服务同时托管 API 和静态文件）

    database := db.Database(client, cfg.ArangoDB.Database)

    // ── 依赖装配（手动 DI）─────────────────────────────────────────
    execStub   := stub.NewExecutionStub(cfg.Stub.Execution)
    etlStub    := stub.NewETLStub(cfg.Stub.ETL)
    lakeStub   := stub.NewDataLakeStub(cfg.Stub.DataLake)

    assetRepo  := repository.NewAssetRepo(database)
    alertRepo  := repository.NewAlertRepo(database)
    incRepo    := repository.NewIncidentRepo(database)
    vulnRepo   := repository.NewVulnerabilityRepo(database)
    iocRepo    := repository.NewIocRepo(database)
    feedRepo   := repository.NewIntelFeedRepo(database)
    actionRepo := repository.NewActionRepo(database)
    logRepo    := repository.NewLogEntryRepo(database)
    devRepo    := repository.NewDeviceRepo(database)
    policyRepo := repository.NewAgentPolicyRepo(database)
    dsRepo     := repository.NewDataSourceRepo(database)
    pbRepo     := repository.NewPlaybookRepo(database)
    reportRepo := repository.NewReportRepo(database)
    userRepo   := repository.NewUserRepo(database)
    auditRepo  := repository.NewAuditLogRepo(database)

    dashSvc   := service.NewDashboardService(alertRepo, incRepo, assetRepo, vulnRepo)
    assetSvc  := service.NewAssetService(assetRepo, auditRepo)
    alertSvc  := service.NewAlertService(alertRepo, incRepo, auditRepo)
    incSvc    := service.NewIncidentService(incRepo, alertRepo, auditRepo)
    vulnSvc   := service.NewVulnerabilityService(vulnRepo, auditRepo)
    iocSvc    := service.NewIocService(iocRepo, auditRepo)
    feedSvc   := service.NewIntelFeedService(feedRepo, etlStub, auditRepo)
    actionSvc := service.NewActionService(actionRepo, execStub, auditRepo)
    logSvc    := service.NewLogEntryService(logRepo, lakeStub)
    devSvc    := service.NewDeviceService(devRepo, policyRepo, etlStub, auditRepo)
    dsSvc     := service.NewDataSourceService(dsRepo, auditRepo)
    pbSvc     := service.NewPlaybookService(pbRepo, execStub, auditRepo)
    reportSvc := service.NewReportService(reportRepo)
    authSvc   := service.NewAuthService(userRepo, cfg.Auth)

    dashH   := handler.NewDashboardHandler(dashSvc)
    assetH  := handler.NewAssetHandler(assetSvc)
    alertH  := handler.NewAlertHandler(alertSvc)
    incH    := handler.NewIncidentHandler(incSvc)
    vulnH   := handler.NewVulnerabilityHandler(vulnSvc)
    iocH    := handler.NewIocHandler(iocSvc)
    feedH   := handler.NewIntelFeedHandler(feedSvc)
    actionH := handler.NewActionHandler(actionSvc)
    logH    := handler.NewLogEntryHandler(logSvc)
    devH    := handler.NewDeviceHandler(devSvc)
    dsH     := handler.NewDataSourceHandler(dsSvc)
    pbH     := handler.NewPlaybookHandler(pbSvc)
    reportH := handler.NewReportHandler(reportSvc)
    authH   := handler.NewAuthHandler(authSvc)

    // ── API 路由（/api/*）─────────────────────────────────────────
    api := r.Group("/api")

    api.POST("/auth/login", authH.Login)
    api.POST("/auth/refresh", authH.Refresh)

    auth := api.Group("/", middleware.Auth(cfg.Auth.JWTSecret))
    {
        auth.GET("/dashboard/stats", dashH.Stats)

        assets := auth.Group("/assets")
        assets.GET("", assetH.List)
        assets.POST("", assetH.Create)
        assets.GET("/:id", assetH.Get)
        assets.PATCH("/:id", assetH.Update)
        assets.DELETE("/:id", assetH.Delete)

        alerts := auth.Group("/alerts")
        alerts.GET("", alertH.List)
        alerts.POST("", alertH.Create)
        alerts.GET("/:id", alertH.Get)
        alerts.PATCH("/:id", alertH.Update)
        alerts.POST("/:id/link-incident", alertH.LinkIncident)
        alerts.POST("/bulk", alertH.Bulk)

        incidents := auth.Group("/incidents")
        incidents.GET("", incH.List)
        incidents.POST("", incH.Create)
        incidents.GET("/:id", incH.Get)
        incidents.PATCH("/:id", incH.Update)
        incidents.DELETE("/:id", incH.Delete)
        incidents.GET("/:id/alerts", incH.ListAlerts)
        incidents.POST("/:id/notes", incH.AddNote)
        incidents.POST("/:id/merge", incH.Merge)
        incidents.POST("/bulk", incH.Bulk)

        vulns := auth.Group("/vulnerabilities")
        vulns.GET("", vulnH.List)
        vulns.POST("", vulnH.Create)
        vulns.GET("/stats", vulnH.Stats)
        vulns.GET("/:id", vulnH.Get)
        vulns.PATCH("/:id", vulnH.Update)
        vulns.POST("/bulk", vulnH.Bulk)

        iocs := auth.Group("/threat-intel/iocs")
        iocs.GET("", iocH.List)
        iocs.POST("", iocH.Create)
        iocs.POST("/search", iocH.Search)
        iocs.POST("/bulk", iocH.BulkImport)
        iocs.GET("/:id", iocH.Get)
        iocs.PATCH("/:id", iocH.Update)
        iocs.DELETE("/:id", iocH.Delete)

        feeds := auth.Group("/threat-intel/feeds")
        feeds.GET("", feedH.List)
        feeds.POST("", feedH.Create)
        feeds.PATCH("/:id", feedH.Update)
        feeds.POST("/:id/sync", feedH.Sync)

        actions := auth.Group("/actions")
        actions.GET("", actionH.List)
        actions.POST("", actionH.Create)
        actions.GET("/:id", actionH.Get)
        actions.PATCH("/:id", actionH.Update)
        actions.POST("/:id/execute", actionH.Execute)
        actions.GET("/scripts", actionH.ListScripts)
        actions.POST("/scripts", actionH.CreateScript)

        logs := auth.Group("/logs")
        logs.GET("", logH.List)
        logs.POST("", logH.Create)
        logs.POST("/query", logH.Query)
        logs.GET("/datasets", logH.Datasets)

        agents := auth.Group("/devices/agents")
        agents.GET("", devH.ListAgents)
        agents.GET("/:id", devH.GetAgent)
        agents.PATCH("/:id", devH.UpdateAgent)
        agents.POST("/:id/upgrade", devH.UpgradeAgent)
        agents.POST("/:id/uninstall", devH.UninstallAgent)
        auth.GET("/devices/enrollment-token", devH.GenerateEnrollmentToken)

        datasources := auth.Group("/devices/datasources")
        datasources.GET("", dsH.List)
        datasources.POST("", dsH.Create)
        datasources.PATCH("/:id", dsH.Update)
        datasources.DELETE("/:id", dsH.Delete)

        policies := auth.Group("/devices/policies")
        policies.GET("", devH.ListPolicies)
        policies.POST("", devH.CreatePolicy)
        policies.PATCH("/:id", devH.UpdatePolicy)

        reports := auth.Group("/reports")
        reports.GET("", reportH.List)
        reports.POST("", reportH.Create)
        reports.PATCH("/:id", reportH.Update)
        reports.DELETE("/:id", reportH.Delete)
        reports.POST("/:id/generate", reportH.Generate)

        playbooks := auth.Group("/playbooks")
        playbooks.GET("", pbH.List)
        playbooks.POST("", pbH.Create)
        playbooks.GET("/:id", pbH.Get)
        playbooks.PATCH("/:id", pbH.Update)
        playbooks.DELETE("/:id", pbH.Delete)
        playbooks.POST("/:id/execute", pbH.Execute)
    }

    // ── 静态文件服务（SPA fallback）────────────────────────────────
    registerStatic(r, staticFiles)

    return r
}

func registerStatic(r *gin.Engine, staticFiles embed.FS) {
    distFS, err := fs.Sub(staticFiles, "dist")
    if err != nil { panic("embed dist: " + err.Error()) }

    fileServer := http.FileServer(http.FS(distFS))

    r.NoRoute(func(c *gin.Context) {
        // 尝试返回 dist/ 中的具体文件
        filePath := c.Request.URL.Path
        if filePath == "/" { filePath = "/index.html" }

        f, err := distFS.Open(filePath[1:]) // 去掉前缀 /
        if err == nil {
            f.Close()
            fileServer.ServeHTTP(c.Writer, c.Request)
            return
        }
        // SPA fallback：所有未匹配路径返回 index.html（交给 React Router 处理）
        indexFile, _ := distFS.Open("index.html")
        defer indexFile.Close()
        stat, _ := indexFile.Stat()
        http.ServeContent(c.Writer, c.Request, "index.html", stat.ModTime(), indexFile.(interface {
            fs.File
            io.ReadSeeker
        }))
    })
}
```

### 7.5 Model 层（字段名常量 + struct）

```go
// internal/model/common.go
package model

type Severity   string
type SourceType string
type RiskLevel  string

const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
)

const (
    SourceEndpoint SourceType = "endpoint"
    SourceNetwork  SourceType = "network"
    SourceIdentity SourceType = "identity"
    SourceCloud    SourceType = "cloud"
    SourceEmail    SourceType = "email"
    SourceSyslog   SourceType = "syslog"
)

// ArangoDB 字段名常量（构造 AQL bindVars 或 filter 时引用，防止拼写错误）
const (
    FieldSeverity    = "severity"
    FieldStatus      = "status"
    FieldSourceType  = "source_type"
    FieldIncidentID  = "incident_id"
    FieldAssetID     = "asset_id"
    FieldTriggeredAt = "triggered_at"
    FieldCreatedAt   = "created_at"
    FieldUpdatedAt   = "updated_at"
)

type PageMeta struct {
    Total    int64 `json:"total"`
    Page     int   `json:"page"`
    PageSize int   `json:"page_size"`
    Pages    int   `json:"pages"`
}
```

```go
// internal/model/alert.go
package model

import "time"

type AlertStatus string

const (
    AlertStatusActive      AlertStatus = "active"
    AlertStatusInvestigate AlertStatus = "investigating"
    AlertStatusResolved    AlertStatus = "resolved"
    AlertStatusFalsePos    AlertStatus = "false_positive"
    AlertStatusAutoClosed  AlertStatus = "auto_closed"
)

// Alert 字段名常量
const (
    FieldAlertID         = "alert_id"
    FieldAlertName       = "name"
    FieldAlertSeverity   = FieldSeverity
    FieldAlertStatus     = FieldStatus
    FieldAlertSourceType = FieldSourceType
    FieldAlertIncidentID = FieldIncidentID
    FieldAlertAssetID    = FieldAssetID
)

type ProcessNode struct {
    PID         int    `json:"pid"`
    Name        string `json:"name"`
    Path        string `json:"path"`
    CommandLine string `json:"command_line"`
    ParentPID   *int   `json:"parent_pid"`
    IsRoot      bool   `json:"is_root"`
    IsAlertNode bool   `json:"is_alert_node"`
}

type IocEntry struct {
    Type    string `json:"type"`
    Value   string `json:"value"`
    Verdict string `json:"verdict"`
}

// Alert 存储于 ArangoDB `alerts` collection
// ArangoDB 自动管理 _key（= AlertID）、_id、_rev 字段
type Alert struct {
    Key            string         `json:"_key,omitempty"`    // ArangoDB document key（= AlertID）
    AlertID        string         `json:"alert_id"`
    Name           string         `json:"name"`
    Description    string         `json:"description"`
    Severity       Severity       `json:"severity"`
    SourceType     SourceType     `json:"source_type"`
    Status         AlertStatus    `json:"status"`
    AssetID        *string        `json:"asset_id"`
    AssetName      string         `json:"asset_name"`
    UserName       *string        `json:"user_name"`
    IncidentID     *string        `json:"incident_id"`
    DetectionRule  string         `json:"detection_rule"`
    RuleType       string         `json:"rule_type"`
    MitreTactics   []string       `json:"mitre_tactics"`
    MitreTechniques []string      `json:"mitre_techniques"`
    IOCs           []IocEntry     `json:"iocs"`
    ProcessTree    []ProcessNode  `json:"process_tree"`
    RawData        map[string]any `json:"raw_data"`
    AssigneeID     *string        `json:"assignee_id"`
    AssigneeName   *string        `json:"assignee_name"`
    ResolvedAt     *time.Time     `json:"resolved_at"`
    ResolutionNote string         `json:"resolution_note"`
    TriggeredAt    time.Time      `json:"triggered_at"`
    CreatedAt      time.Time      `json:"created_at"`
    UpdatedAt      time.Time      `json:"updated_at"`
}
```

### 7.6 Repository 层（泛型分页 + 字段常量）

```go
// internal/repository/base.go
package repository

import (
    "context"
    "fmt"
    "xsiam/internal/model"

    "github.com/arangodb/go-driver/v2/arangodb"
)

type ListOptions struct {
    Collection string
    Filters    []string        // AQL filter clauses, e.g. "doc.severity == @severity"
    BindVars   map[string]any
    SortBy     string
    SortDesc   bool
    Page       int
    PageSize   int
}

func FindPaged[T any](
    ctx context.Context,
    db arangodb.Database,
    opts ListOptions,
    out *[]T,
) (model.PageMeta, error) {
    if opts.Page < 1      { opts.Page = 1 }
    if opts.PageSize < 1  { opts.PageSize = 20 }
    if opts.PageSize > 100 { opts.PageSize = 100 }

    offset := (opts.Page - 1) * opts.PageSize

    sortDir := "ASC"
    if opts.SortDesc { sortDir = "DESC" }
    sortBy := opts.SortBy
    if sortBy == "" { sortBy = "doc.created_at" }

    filterClause := ""
    for _, f := range opts.Filters {
        filterClause += " FILTER " + f
    }

    countAQL := fmt.Sprintf(
        `FOR doc IN %s%s COLLECT WITH COUNT INTO total RETURN total`,
        opts.Collection, filterClause,
    )
    pageAQL := fmt.Sprintf(
        `FOR doc IN %s%s SORT doc.%s %s LIMIT @offset, @limit RETURN doc`,
        opts.Collection, filterClause, sortBy, sortDir,
    )

    if opts.BindVars == nil { opts.BindVars = map[string]any{} }
    opts.BindVars["offset"] = offset
    opts.BindVars["limit"]  = opts.PageSize

    // count query uses same bind vars minus pagination keys
    countVars := map[string]any{}
    for k, v := range opts.BindVars {
        if k != "offset" && k != "limit" { countVars[k] = v }
    }

    cCursor, err := db.Query(ctx, countAQL, &arangodb.QueryOptions{BindVars: countVars})
    if err != nil { return model.PageMeta{}, err }
    defer cCursor.Close()
    var total int64
    if cCursor.HasMore() {
        if _, err = cCursor.ReadDocument(ctx, &total); err != nil {
            return model.PageMeta{}, err
        }
    }

    cursor, err := db.Query(ctx, pageAQL, &arangodb.QueryOptions{BindVars: opts.BindVars})
    if err != nil { return model.PageMeta{}, err }
    defer cursor.Close()

    for cursor.HasMore() {
        var doc T
        if _, err = cursor.ReadDocument(ctx, &doc); err != nil {
            return model.PageMeta{}, err
        }
        *out = append(*out, doc)
    }

    pages := int(total) / opts.PageSize
    if int(total)%opts.PageSize > 0 { pages++ }

    return model.PageMeta{Total: total, Page: opts.Page, PageSize: opts.PageSize, Pages: pages}, nil
}
```

```go
// internal/repository/alert.go
package repository

import (
    "context"
    "fmt"
    "time"
    "xsiam/internal/model"

    "github.com/arangodb/go-driver/v2/arangodb"
    "github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colAlerts = "alerts"

type AlertRepo struct{ db arangodb.Database }

func NewAlertRepo(ctx context.Context, db arangodb.Database) *AlertRepo {
    col, _ := db.Collection(ctx, colAlerts)
    col.EnsurePersistentIndex(ctx, []string{model.FieldSeverity, model.FieldStatus}, &arangodb.EnsurePersistentIndexOptions{})
    col.EnsurePersistentIndex(ctx, []string{model.FieldTriggeredAt}, &arangodb.EnsurePersistentIndexOptions{})
    col.EnsurePersistentIndex(ctx, []string{model.FieldIncidentID}, &arangodb.EnsurePersistentIndexOptions{})
    col.EnsurePersistentIndex(ctx, []string{model.FieldAssetID}, &arangodb.EnsurePersistentIndexOptions{})
    col.EnsurePersistentIndex(ctx, []string{model.FieldAlertID}, &arangodb.EnsurePersistentIndexOptions{Unique: true})
    return &AlertRepo{db: db}
}

type AlertListFilter struct {
    Severity, Status, SourceType, IncidentID, AssetID, Keyword string
    After, Before *time.Time
    Page, PageSize int
    SortBy   string
    SortDesc bool
}

func (r *AlertRepo) List(ctx context.Context, f AlertListFilter) ([]model.Alert, model.PageMeta, error) {
    var filters []string
    bindVars := map[string]any{}

    if f.Severity   != "" { filters = append(filters, "doc.severity == @severity");     bindVars["severity"]   = f.Severity }
    if f.Status     != "" { filters = append(filters, "doc.status == @status");         bindVars["status"]     = f.Status }
    if f.SourceType != "" { filters = append(filters, "doc.source_type == @sourceType"); bindVars["sourceType"] = f.SourceType }
    if f.IncidentID != "" { filters = append(filters, "doc.incident_id == @incidentId"); bindVars["incidentId"] = f.IncidentID }
    if f.AssetID    != "" { filters = append(filters, "doc.asset_id == @assetId");      bindVars["assetId"]    = f.AssetID }
    if f.Keyword    != "" {
        filters = append(filters, "(CONTAINS(LOWER(doc.name), LOWER(@kw)) OR CONTAINS(LOWER(doc.asset_name), LOWER(@kw)))")
        bindVars["kw"] = f.Keyword
    }
    if f.After  != nil { filters = append(filters, "doc.triggered_at >= @after");  bindVars["after"]  = f.After }
    if f.Before != nil { filters = append(filters, "doc.triggered_at <= @before"); bindVars["before"] = f.Before }

    sortBy := model.FieldTriggeredAt
    if f.SortBy != "" { sortBy = f.SortBy }

    var data []model.Alert
    meta, err := FindPaged(ctx, r.db, ListOptions{
        Collection: colAlerts,
        Filters:    filters,
        BindVars:   bindVars,
        SortBy:     sortBy,
        SortDesc:   f.SortDesc,
        Page:       f.Page,
        PageSize:   f.PageSize,
    }, &data)
    return data, meta, err
}

func (r *AlertRepo) GetByID(ctx context.Context, key string) (*model.Alert, error) {
    col, _ := r.db.Collection(ctx, colAlerts)
    var alert model.Alert
    if _, err := col.ReadDocument(ctx, key, &alert); err != nil {
        if shared.IsNotFound(err) { return nil, fmt.Errorf("alert %s not found", key) }
        return nil, err
    }
    return &alert, nil
}

func (r *AlertRepo) Create(ctx context.Context, alert *model.Alert) error {
    now := time.Now()
    alert.CreatedAt = now
    alert.UpdatedAt = now
    col, _ := r.db.Collection(ctx, colAlerts)
    meta, err := col.CreateDocument(ctx, alert)
    if err != nil { return err }
    alert.Key = meta.Key
    return nil
}

func (r *AlertRepo) Update(ctx context.Context, key string, patch map[string]any) error {
    patch[model.FieldUpdatedAt] = time.Now()
    col, _ := r.db.Collection(ctx, colAlerts)
    _, err := col.UpdateDocument(ctx, key, patch)
    return err
}

func (r *AlertRepo) Delete(ctx context.Context, key string) error {
    col, _ := r.db.Collection(ctx, colAlerts)
    _, err := col.DeleteDocument(ctx, key)
    return err
}
```

### 7.7 Service 层示例

```go
// internal/service/alert.go
package service

import (
    "context"
    "fmt"
    "time"
    "xsiam/internal/model"
    "xsiam/internal/repository"
    "xsiam/pkg/utils"
)

type AlertService struct {
    alertRepo *repository.AlertRepo
    incRepo   *repository.IncidentRepo
    auditRepo *repository.AuditLogRepo
}

func NewAlertService(
    alertRepo *repository.AlertRepo,
    incRepo   *repository.IncidentRepo,
    auditRepo *repository.AuditLogRepo,
) *AlertService {
    return &AlertService{alertRepo: alertRepo, incRepo: incRepo, auditRepo: auditRepo}
}

func (s *AlertService) List(ctx context.Context, f repository.AlertListFilter) ([]model.Alert, model.PageMeta, error) {
    return s.alertRepo.List(ctx, f)
}

func (s *AlertService) Get(ctx context.Context, key string) (*model.Alert, error) {
    alert, err := s.alertRepo.GetByID(ctx, key)
    if err != nil { return nil, fmt.Errorf("alertRepo.GetByID: %w", err) }
    return alert, nil
}

type CreateAlertReq struct {
    Name        string           `json:"name"`
    Description string           `json:"description"`
    Severity    model.Severity   `json:"severity"`
    SourceType  model.SourceType `json:"source_type"`
    AssetName   string           `json:"asset_name"`
}

func (s *AlertService) Create(ctx context.Context, req CreateAlertReq, operatorID string) (*model.Alert, error) {
    alert := &model.Alert{
        AlertID:     utils.GenerateAlertID(),
        Name:        req.Name,
        Description: req.Description,
        Severity:    req.Severity,
        SourceType:  req.SourceType,
        Status:      model.AlertStatusActive,
        AssetName:   req.AssetName,
        TriggeredAt: time.Now(),
    }
    if err := s.alertRepo.Create(ctx, alert); err != nil {
        return nil, fmt.Errorf("create alert: %w", err)
    }
    s.auditRepo.Record(ctx, operatorID, "create", "alert", alert.Key, alert.Name, nil, alert)
    return alert, nil
}

func (s *AlertService) Update(ctx context.Context, key string, patch map[string]any, operatorID string) error {
    return s.alertRepo.Update(ctx, key, patch)
}

func (s *AlertService) LinkIncident(ctx context.Context, alertKey, incidentKey, operatorID string) error {
    if _, err := s.incRepo.GetByID(ctx, incidentKey); err != nil {
        return fmt.Errorf("incident not found: %w", err)
    }
    return s.alertRepo.Update(ctx, alertKey, map[string]any{model.FieldIncidentID: incidentKey})
}
```

### 7.8 Handler 层示例

```go
// internal/handler/alert.go
package handler

import (
    "xsiam/internal/repository"
    "xsiam/internal/service"
    "xsiam/pkg/response"

    "github.com/gin-gonic/gin"
)

type AlertHandler struct{ svc *service.AlertService }

func NewAlertHandler(svc *service.AlertService) *AlertHandler {
    return &AlertHandler{svc: svc}
}

type AlertListQuery struct {
    Severity   string `form:"severity"`
    Status     string `form:"status"`
    SourceType string `form:"source_type"`
    IncidentID string `form:"incident_id"`
    AssetID    string `form:"asset_id"`
    Keyword    string `form:"keyword"`
    Page       int    `form:"page,default=1"`
    PageSize   int    `form:"page_size,default=20"`
    SortBy     string `form:"sort_by,default=triggered_at"`
    SortDesc   bool   `form:"sort_desc,default=true"`
}

func (h *AlertHandler) List(c *gin.Context) {
    var q AlertListQuery
    if err := c.ShouldBindQuery(&q); err != nil {
        response.BadRequest(c, err.Error())
        return
    }
    data, meta, err := h.svc.List(c.Request.Context(), repository.AlertListFilter{
        Severity: q.Severity, Status: q.Status, SourceType: q.SourceType,
        IncidentID: q.IncidentID, AssetID: q.AssetID, Keyword: q.Keyword,
        Page: q.Page, PageSize: q.PageSize, SortBy: q.SortBy, SortDesc: q.SortDesc,
    })
    if err != nil { response.InternalError(c, err); return }
    response.Paginated(c, data, meta)
}

func (h *AlertHandler) Get(c *gin.Context) {
    data, err := h.svc.Get(c.Request.Context(), c.Param("id"))
    if err != nil { response.NotFound(c, "alert"); return }
    response.OK(c, data)
}

type CreateAlertBody struct {
    Name        string `json:"name"        binding:"required"`
    Severity    string `json:"severity"    binding:"required,oneof=critical high medium low"`
    SourceType  string `json:"source_type" binding:"required"`
    AssetName   string `json:"asset_name"`
    Description string `json:"description"`
}

func (h *AlertHandler) Create(c *gin.Context) {
    var body CreateAlertBody
    if err := c.ShouldBindJSON(&body); err != nil { response.BadRequest(c, err.Error()); return }
    operatorID := c.GetString("user_id")
    alert, err := h.svc.Create(c.Request.Context(), service.CreateAlertReq{
        Name: body.Name, Severity: model.Severity(body.Severity),
        SourceType: model.SourceType(body.SourceType),
        AssetName: body.AssetName, Description: body.Description,
    }, operatorID)
    if err != nil { response.InternalError(c, err); return }
    response.Created(c, alert)
}
```

### 7.9 pkg/response/response.go

```go
// pkg/response/response.go
package response

import (
    "net/http"
    "xsiam/internal/model"

    "github.com/gin-gonic/gin"
)

func OK(c *gin.Context, data any) {
    c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}

func Created(c *gin.Context, data any) {
    c.JSON(http.StatusCreated, gin.H{"success": true, "data": data})
}

func Paginated(c *gin.Context, data any, meta model.PageMeta) {
    c.JSON(http.StatusOK, gin.H{"success": true, "data": data, "meta": meta})
}

func BadRequest(c *gin.Context, msg string) {
    c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "BAD_REQUEST", "message": msg}})
}

func Unauthorized(c *gin.Context) {
    c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": "请先登录"}})
}

func Forbidden(c *gin.Context) {
    c.JSON(http.StatusForbidden, gin.H{"success": false, "error": gin.H{"code": "FORBIDDEN", "message": "权限不足"}})
}

func NotFound(c *gin.Context, resource string) {
    c.JSON(http.StatusNotFound, gin.H{"success": false, "error": gin.H{"code": "NOT_FOUND", "message": resource + " 不存在"}})
}

func InternalError(c *gin.Context, err error) {
    c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": gin.H{"code": "INTERNAL_ERROR", "message": err.Error()}})
}
```

### 7.10 internal/middleware/auth.go

```go
// internal/middleware/auth.go
package middleware

import (
    "strings"
    "xsiam/pkg/response"

    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"
)

func Auth(secret string) gin.HandlerFunc {
    return func(c *gin.Context) {
        token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
        if token == "" { response.Unauthorized(c); c.Abort(); return }

        claims := jwt.MapClaims{}
        _, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
            return []byte(secret), nil
        })
        if err != nil { response.Unauthorized(c); c.Abort(); return }

        c.Set("user_id", claims["sub"])
        c.Set("user_role", claims["role"])
        c.Next()
    }
}
```

---

## 8. ArangoDB 数据模型

### 8.1 Collection 索引总览

| Collection | 类型 | 主要索引（`EnsurePersistentIndex` / `EnsureTTLIndex`） |
|------------|------|-------------------------------------------------------|
| `assets` | 文档 | `[type,risk_level]` `[risk_score]` `[agent.status]` `[identifier]` unique |
| `alerts` | 文档 | `[severity,status]` `[triggered_at]` `[incident_id]` `[alert_id]` unique |
| `incidents` | 文档 | `[severity,status]` `[smart_score]` `[assignee_id]` `[incident_id]` unique |
| `vulnerabilities` | 文档 | `[cve_id]` unique `[severity,fix_status]` `[priority_score]` |
| `iocs` | 文档 | `[type,value]` unique `[verdict]` `[expires_at]` TTL |
| `intel_feeds` | 文档 | `[status]` |
| `actions` | 文档 | `[status]` `[incident_id]` `[target_asset_id]` `[created_at]` |
| `log_entries` | 文档 | `[dataset,event_timestamp]` TTL 90天 |
| `devices` | 文档 | `[agent_id]` unique `[agent_status]` `[last_heartbeat]` |
| `agent_policies` | 文档 | `[is_default]` |
| `datasources` | 文档 | `[status]` |
| `playbooks` | 文档 | `[is_enabled]` `[trigger.type]` |
| `reports` | 文档 | `[template_type]` |
| `users` | 文档 | `[email]` unique `[tenant_id]` |
| `audit_logs` | 文档 | `[resource_type,resource_id]` `[created_at]` TTL 365天 |
| `detection_rules` | 文档 | `[rule_type,status]` `[mitre_technique]` `[rule_id]` unique |
| `causality_nodes` | 文档 | `[incident_id]` `[created_at]`（Named Graph: causality_graph） |
| `causality_edges` | 边集合 | `[incident_id]`（Named Graph: causality_graph，from/to → causality_nodes） |
| `identity_risks` | 文档 | `[user_id]` unique `[risk_score]` `[updated_at]` |
| `privilege_restrictions` | 文档 | `[user_id]` `[level]` `[expires_at]` TTL |
| `exposure_scores` | 文档 | `[asset_id,cve_id]` unique `[priority_score]` |
| `tenants` | 文档 | `[tenant_code]` unique `[parent_tenant_id]` |
| `rbac_roles` | 文档 | `[tenant_id,name]` unique |

### 8.2 核心 Model 字段摘要

**Asset**：`name` `type` `identifier` `os{}` `agent{}` `department` `risk_score` `risk_level` `active_incident_count` `open_vuln_count` `tags[]` `last_seen`

**Alert**：`alert_id` `name` `severity` `source_type` `status` `asset_id` `asset_name` `incident_id` `detection_rule` `mitre_tactics[]` `mitre_techniques[]` `iocs[]` `process_tree[]` `raw_data` `assignee_id` `triggered_at`

**Incident**：`incident_id` `name` `severity` `status` `smart_score` `score_factors[]` `alert_ids[]` `alert_count` `affected_assets[]` `mitre_tactics[]` `assignee_id` `timeline[]` `notes[]` `first_seen` `last_activity`

**Vulnerability**：`cve_id` `title` `cvss_score` `severity` `priority_score` `exploited_in_wild` `affected_asset_ids[]` `fix_status` `fix_deadline`

**Ioc**：`type` `value` `verdict` `confidence` `source_name` `hit_count` `last_hit_at` `expires_at` `is_active`

**Action**：`type` `target_type` `target_asset_id` `incident_id` `triggered_by` `status` `requires_approval` `approved_by` `result_summary` `result_detail`

**Device**：`hostname` `ip_addresses[]` `os_type` `agent_version` `agent_status` `agent_id` `policy_id` `last_heartbeat` `asset_id`

**Playbook**：`name` `trigger{}` `canvas{nodes[],edges[]}` `is_enabled` `run_count` `last_run_at`

**DetectionRule**：`rule_id` `name` `rule_type(bioc/ioc/ueba)` `status(draft/testing/active/disabled/deprecated)` `definition{}` `mitre_tactic` `mitre_technique` `severity` `test_result{}` `hit_count` `false_positive_rate` `last_hit_at`

**CausalityGraph**：`graph_id` `incident_id` `time_window_h` `confidence` `nodes[]` `edges[]` `node_count` `edge_count` `generated_at`

**IdentityRisk**：`user_id` `username` `domain` `risk_score` `risk_signals[]` `active_restrictions[]` `last_impossible_travel_at` `baseline{}` `updated_at`

**PrivilegeRestriction**：`user_id` `level(1-5)` `trigger_signal` `trigger_score` `applied_at` `expires_at` `released_at` `released_by` `action_log[]`

**ExposureScore**：`asset_id` `cve_id` `cvss_score` `priority_score` `in_wild_factor` `reachability_factor` `asset_importance_factor` `fix_status` `fix_deadline` `last_scored_at`

**Tenant**：`tenant_id` `tenant_code` `name` `tier(super/child)` `parent_tenant_id` `is_enabled` `settings{}` `created_at`

**RbacRole**：`role_id` `tenant_id` `name` `permissions[]` `resource_scopes{}` `is_builtin`

---

## 9. API 接口设计

### 9.1 统一响应格式

```json
{ "success": true, "data": [...], "meta": { "total": 247, "page": 1, "page_size": 20, "pages": 13 } }
{ "success": true, "data": { ... } }
{ "success": false, "error": { "code": "BAD_REQUEST", "message": "severity 参数无效" } }
```

### 9.2 完整接口清单

| 方法 | 路径 | 说明 | 实现 |
|------|------|------|------|
| POST | `/api/auth/login` | 账号密码登录，返回 JWT | CRUD |
| POST | `/api/auth/refresh` | 刷新 Token | CRUD |
| GET | `/api/dashboard/stats` | 态势总览聚合统计 | Aggregate |
| GET | `/api/assets` | 资产列表 | CRUD |
| POST | `/api/assets` | 创建资产 | CRUD |
| GET | `/api/assets/:id` | 资产详情 | CRUD |
| PATCH | `/api/assets/:id` | 更新资产 | CRUD |
| DELETE | `/api/assets/:id` | 删除资产 | CRUD |
| GET | `/api/alerts` | 告警列表 | CRUD |
| POST | `/api/alerts` | 创建告警 | CRUD |
| GET | `/api/alerts/:id` | 告警详情 | CRUD |
| PATCH | `/api/alerts/:id` | 更新告警 | CRUD |
| POST | `/api/alerts/:id/link-incident` | 关联事件 | CRUD |
| POST | `/api/alerts/bulk` | 批量操作 | CRUD |
| GET | `/api/incidents` | 事件列表 | CRUD |
| POST | `/api/incidents` | 创建事件 | CRUD |
| GET | `/api/incidents/:id` | 事件详情 | CRUD |
| PATCH | `/api/incidents/:id` | 更新事件 | CRUD |
| DELETE | `/api/incidents/:id` | 删除事件 | CRUD |
| GET | `/api/incidents/:id/alerts` | 事件关联告警 | CRUD |
| POST | `/api/incidents/:id/notes` | 添加备注 | CRUD |
| POST | `/api/incidents/:id/merge` | 合并事件 | CRUD |
| POST | `/api/incidents/bulk` | 批量操作 | CRUD |
| GET | `/api/vulnerabilities` | 漏洞列表 | CRUD |
| POST | `/api/vulnerabilities` | 创建漏洞 | CRUD |
| GET | `/api/vulnerabilities/stats` | 漏洞统计 | Aggregate |
| GET | `/api/vulnerabilities/:id` | 漏洞详情 | CRUD |
| PATCH | `/api/vulnerabilities/:id` | 更新修复状态 | CRUD |
| POST | `/api/vulnerabilities/bulk` | 批量更新 | CRUD |
| GET | `/api/threat-intel/iocs` | IOC 列表 | CRUD |
| POST | `/api/threat-intel/iocs` | 创建 IOC | CRUD |
| POST | `/api/threat-intel/iocs/search` | IOC 检索 | CRUD |
| POST | `/api/threat-intel/iocs/bulk` | 批量导入 | CRUD |
| GET | `/api/threat-intel/iocs/:id` | IOC 详情 | CRUD |
| PATCH | `/api/threat-intel/iocs/:id` | 更新 IOC | CRUD |
| DELETE | `/api/threat-intel/iocs/:id` | 删除 IOC | CRUD |
| GET | `/api/threat-intel/feeds` | 情报源列表 | CRUD |
| POST | `/api/threat-intel/feeds` | 添加情报源 | CRUD |
| PATCH | `/api/threat-intel/feeds/:id` | 更新情报源 | CRUD |
| POST | `/api/threat-intel/feeds/:id/sync` | 触发同步 | **Stub** |
| GET | `/api/actions` | 响应动作列表 | CRUD |
| POST | `/api/actions` | 创建动作 | CRUD |
| GET | `/api/actions/:id` | 动作详情 | CRUD |
| PATCH | `/api/actions/:id` | 审批/取消 | CRUD |
| POST | `/api/actions/:id/execute` | 执行动作 | **Stub** |
| GET | `/api/actions/scripts` | 脚本库列表 | CRUD |
| POST | `/api/actions/scripts` | 创建脚本 | CRUD |
| GET | `/api/logs` | 日志列表 | CRUD |
| POST | `/api/logs` | 写入日志 | CRUD |
| POST | `/api/logs/query` | XQL 查询 | **Stub** |
| GET | `/api/logs/datasets` | 数据集列表 | 静态 |
| GET | `/api/devices/agents` | Agent 列表 | CRUD |
| GET | `/api/devices/agents/:id` | Agent 详情 | CRUD |
| PATCH | `/api/devices/agents/:id` | 更新 Agent | CRUD |
| POST | `/api/devices/agents/:id/upgrade` | 升级 Agent | **Stub** |
| POST | `/api/devices/agents/:id/uninstall` | 卸载 Agent | **Stub** |
| GET | `/api/devices/enrollment-token` | 生成注册令牌 | CRUD |
| GET | `/api/devices/datasources` | 数据源列表 | CRUD |
| POST | `/api/devices/datasources` | 添加数据源 | CRUD |
| PATCH | `/api/devices/datasources/:id` | 更新数据源 | CRUD |
| DELETE | `/api/devices/datasources/:id` | 删除数据源 | CRUD |
| GET | `/api/devices/policies` | 策略组列表 | CRUD |
| POST | `/api/devices/policies` | 创建策略组 | CRUD |
| PATCH | `/api/devices/policies/:id` | 更新策略 | CRUD |
| GET | `/api/reports` | 报表列表 | CRUD |
| POST | `/api/reports` | 创建报表配置 | CRUD |
| PATCH | `/api/reports/:id` | 更新报表 | CRUD |
| DELETE | `/api/reports/:id` | 删除报表 | CRUD |
| POST | `/api/reports/:id/generate` | 生成报表 | **Stub** |
| GET | `/api/playbooks` | 剧本列表 | CRUD |
| POST | `/api/playbooks` | 创建剧本 | CRUD |
| GET | `/api/playbooks/:id` | 剧本详情（含 canvas） | CRUD |
| PATCH | `/api/playbooks/:id` | 保存剧本 | CRUD |
| DELETE | `/api/playbooks/:id` | 删除剧本 | CRUD |
| POST | `/api/playbooks/:id/execute` | 手动执行 | **Stub** |
| GET | `/api/detection-rules` | 规则列表 | CRUD |
| POST | `/api/detection-rules` | 创建规则 | CRUD |
| GET | `/api/detection-rules/:id` | 规则详情 | CRUD |
| PATCH | `/api/detection-rules/:id` | 更新规则 | CRUD |
| DELETE | `/api/detection-rules/:id` | 删除规则 | CRUD |
| POST | `/api/detection-rules/:id/test` | 历史回放测试 | **Stub** |
| PATCH | `/api/detection-rules/:id/status` | 状态流转 | CRUD |
| GET | `/api/detection-rules/mitre-coverage` | ATT&CK 覆盖矩阵 | Aggregate |
| GET | `/api/causality/graph/:incident_id` | 获取事件关联图 | CRUD |
| POST | `/api/causality/generate` | 触发关联分析 | **Stub** |
| GET | `/api/incidents/:id/smart-score` | SmartScore 详情（含因子） | CRUD |
| POST | `/api/incidents/:id/smart-score/recalc` | 重新计算评分 | **Stub** |
| GET | `/api/exposures` | 暴露优先级列表 | CRUD |
| POST | `/api/exposures/recalc` | 批量刷新评分 | **Stub** |
| PATCH | `/api/exposures/:id/fix-status` | 更新修复状态 | CRUD |
| GET | `/api/identity-risks` | 身份风险列表 | CRUD |
| GET | `/api/identity-risks/:user_id` | 用户风险详情 | CRUD |
| GET | `/api/identity-risks/:user_id/restrictions` | 权限限制列表 | CRUD |
| POST | `/api/identity-risks/:user_id/restrict` | 手动施加限制 | CRUD |
| POST | `/api/identity-risks/:user_id/release` | 解除限制（L4/L5） | CRUD |
| GET | `/api/tenants` | 租户列表（Super 级） | CRUD |
| POST | `/api/tenants` | 创建子租户 | CRUD |
| PATCH | `/api/tenants/:id` | 更新租户配置 | CRUD |
| GET | `/api/tenants/:id/switch` | 切换租户上下文 | CRUD |
| GET | `/api/rbac/roles` | 角色列表 | CRUD |
| POST | `/api/rbac/roles` | 创建角色 | CRUD |
| PATCH | `/api/rbac/roles/:id` | 更新角色权限 | CRUD |
| DELETE | `/api/rbac/roles/:id` | 删除角色 | CRUD |

---

## 10. 接口桩（Stub）设计

### 10.1 Stub 接口定义

```go
// internal/stub/execution.go
package stub

import (
    "context"
    "fmt"
    "time"
    "go.uber.org/zap"
)

type ExecutionResult struct {
    Success     bool           `json:"success"`
    ExecutionID string         `json:"execution_id"`
    Message     string         `json:"message"`
    Detail      map[string]any `json:"detail"`
}

type ExecutionStub struct {
    enabled bool
    logger  *zap.Logger
}

func NewExecutionStub(enabled bool) *ExecutionStub {
    return &ExecutionStub{enabled: enabled, logger: zap.L()}
}

// Execute 设备响应执行接口桩（真实实现需对接 XSIAM Agent API / NGFW API / AD API）
func (s *ExecutionStub) Execute(ctx context.Context, actionType, targetID string, params map[string]any) (*ExecutionResult, error) {
    s.logger.Info("[STUB] execution called", zap.String("action_type", actionType), zap.String("target_id", targetID))
    time.Sleep(200 * time.Millisecond)
    return &ExecutionResult{
        Success:     true,
        ExecutionID: fmt.Sprintf("EXEC-%d", time.Now().UnixMilli()),
        Message:     fmt.Sprintf("[STUB] %s 已提交（未实际联动设备）", actionType),
        Detail:      map[string]any{"stub": true, "action_type": actionType},
    }, nil
}
```

```go
// internal/stub/datalake.go
package stub

import "context"

type XqlResult struct {
    Rows      []map[string]any `json:"rows"`
    Total     int              `json:"total"`
    ElapsedMs int              `json:"elapsed_ms"`
    ScannedGB float64          `json:"scanned_gb"`
}

type DataLakeStub struct{ enabled bool }

func NewDataLakeStub(enabled bool) *DataLakeStub { return &DataLakeStub{enabled: enabled} }

// Query XQL 数据湖查询桩（真实实现需对接 ClickHouse / Elasticsearch / Doris）
func (s *DataLakeStub) Query(ctx context.Context, xql string, start, end int64) (*XqlResult, error) {
    return &XqlResult{
        Rows: []map[string]any{
            {"event_timestamp": "2026-05-22T09:41:02Z", "process_name": "rclone.exe", "host_ip": "10.0.5.22", "bytes_sent": 8924872704},
            {"event_timestamp": "2026-05-22T08:12:44Z", "process_name": "powershell.exe", "host_ip": "10.0.3.15", "bytes_sent": 412809216},
        },
        Total: 2, ElapsedMs: 800, ScannedGB: 2.3,
    }, nil
}
```

```go
// internal/stub/etl.go
package stub

import (
    "context"
    "fmt"
    "time"
)

type ETLStub struct{ enabled bool }

func NewETLStub(enabled bool) *ETLStub { return &ETLStub{enabled: enabled} }

// TriggerFeedSync 触发情报源同步桩
func (s *ETLStub) TriggerFeedSync(ctx context.Context, feedID string) (string, error) {
    return fmt.Sprintf("JOB-%d", time.Now().UnixMilli()), nil
}

// TriggerAgentUpgrade 触发 Agent 升级桩
func (s *ETLStub) TriggerAgentUpgrade(ctx context.Context, agentID, version string) error { return nil }

// TriggerAgentUninstall 触发 Agent 卸载桩
func (s *ETLStub) TriggerAgentUninstall(ctx context.Context, agentID string) error { return nil }
```

```go
// internal/stub/ai_engine.go
package stub

type ScoreFactor struct {
    Name   string  `json:"name"`
    Score  float64 `json:"score"`
    Weight float64 `json:"weight"`
}

type SmartScoreResult struct {
    Score   float64       `json:"score"`
    Factors []ScoreFactor `json:"factors"`
}

type AIEngineStub struct{ enabled bool }

func NewAIEngineStub(enabled bool) *AIEngineStub { return &AIEngineStub{enabled: enabled} }

// CalcSmartScore SmartScore 计算桩（真实实现需对接 ML 推理服务）
func (s *AIEngineStub) CalcSmartScore(flags map[string]bool) SmartScoreResult {
    var score float64
    var factors []ScoreFactor
    weights := map[string]struct {
        Name string
        W    float64
    }{
        "critical_asset":   {"关键资产受影响", 35},
        "lateral_movement": {"横向移动检测", 28},
        "exfiltration":     {"数据外泄行为", 22},
        "c2_communication": {"外部 C2 通信", 13},
    }
    for key, w := range weights {
        if flags[key] {
            score += w.W
            factors = append(factors, ScoreFactor{Name: w.Name, Score: w.W, Weight: w.W / 100})
        }
    }
    if score > 100 { score = 100 }
    return SmartScoreResult{Score: score, Factors: factors}
}
```

### 10.2 Stub 调用位置示例

```go
// internal/service/action.go
func (s *ActionService) Execute(ctx context.Context, id, operatorID string) error {
    action, err := s.actionRepo.GetByID(ctx, id)
    if err != nil { return err }

    // 1. 状态改为 running
    _ = s.actionRepo.Update(ctx, id, map[string]any{
        "status":     "running",
        "started_at": time.Now(),
    })

    // 2. 调用 Stub（不实现真实联动）
    result, _ := s.execStub.Execute(ctx, string(action.Type), action.TargetAssetID, nil)

    // 3. 写回结果
    status := "completed"
    if result == nil || !result.Success { status = "failed" }
    _ = s.actionRepo.Update(ctx, id, map[string]any{
        "status":         status,
        "completed_at":   time.Now(),
        "result_summary": result.Message,
        "result_detail":  result.Detail,
    })

    s.auditRepo.Record(ctx, operatorID, "execute", "action", id, string(action.Type), nil, result)
    return nil
}
```

---

## 11. 开发规范

### 11.1 config.yaml

```yaml
SERVER_PORT: "8080"
SERVER_MODE: "debug"
ARANGO_ENDPOINTS: "http://localhost:8529"
ARANGO_USERNAME: "root"
ARANGO_PASSWORD: "changeme"
ARANGO_DATABASE: "xsiam"
JWT_SECRET: "change-me-in-production"
JWT_EXPIRE_HR: 24
STUB_EXECUTION: true
STUB_ETL: true
STUB_DATALAKE: true
STUB_AI_ENGINE: true
```

### 11.2 docker-compose.yml

```yaml
version: '3.9'
services:
  arangodb:
    image: arangodb:3.12.9.1
    ports:
      - "8529:8529"
    volumes:
      - arango_data:/var/lib/arangodb3
    environment:
      ARANGO_ROOT_PASSWORD: changeme

  xsiam:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      ARANGO_ENDPOINTS: http://arangodb:8529
      ARANGO_USERNAME: root
      ARANGO_PASSWORD: changeme
      ARANGO_DATABASE: xsiam
      JWT_SECRET: dev-secret
      STUB_EXECUTION: "true"
      STUB_ETL: "true"
      STUB_DATALAKE: "true"
      STUB_AI_ENGINE: "true"
    depends_on:
      - arangodb

volumes:
  arango_data:
```

> **注**：v3.0 只有两个 Docker 服务（arangodb + xsiam），v2.0 的 web 服务已合并进 xsiam 二进制。

### 11.3 Dockerfile（多阶段构建）

```dockerfile
# ── 阶段1：构建前端 ──────────────────────────────────────────────
FROM node:22-alpine AS web-builder
WORKDIR /web
COPY web/package.json web/pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY web/ .
RUN pnpm build   # 输出到 /web/../xsiam/dist（但在 Docker 中我们调整路径）

# 实际 Dockerfile 将 vite.config.ts 的 outDir 改为 ./dist（同级）
# 然后在 Go 阶段复制

# ── 阶段2：构建 Go 服务 ──────────────────────────────────────────
FROM golang:1.22-alpine AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /web/dist ./dist   # 复制前端构建产物
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o xsiam .

# ── 阶段3：最终镜像 ──────────────────────────────────────────────
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=go-builder /app/xsiam .
COPY --from=go-builder /app/config.yaml .
EXPOSE 8080
CMD ["./xsiam"]
```

### 11.4 项目根目录结构（Monorepo）

```
xsiam-project/                          # Monorepo 根目录
├── xsiam/                              # Go 服务（含 embed dist/）
│   ├── main.go
│   ├── go.mod
│   ├── dist/                         # pnpm build 输出（gitignore）
│   └── ...
├── web/                              # React SPA 前端
│   ├── package.json
│   ├── vite.config.ts               # outDir: '../xsiam/dist'
│   └── src/
├── Dockerfile                        # 多阶段构建（根目录）
├── docker-compose.yml
└── Makefile
```

```makefile
# Makefile
.PHONY: dev build run

dev-api:
	cd xsiam && go run .

dev-web:
	cd web && pnpm dev

build:
	cd web && pnpm build
	cd xsiam && CGO_ENABLED=0 go build -ldflags="-s -w" -o xsiam .

run: build
	./xsiam/xsiam
```

### 11.5 前端 API 客户端（同源，无跨域）

```typescript
// web/src/api/client.ts
import { useAuthStore } from '@/store/auth.store'

const BASE = '/api'   // 同源，直接用相对路径

interface ApiResponse<T> {
  success: boolean
  data: T
  meta?: { total: number; page: number; page_size: number; pages: number }
  error?: { code: string; message: string }
}

async function request<T>(path: string, init?: RequestInit): Promise<ApiResponse<T>> {
  const token = useAuthStore.getState().token
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  })

  if (res.status === 401) {
    useAuthStore.getState().logout()
    window.location.href = '/login'
  }

  const json: ApiResponse<T> = await res.json()
  if (!json.success) throw new Error(json.error?.message ?? 'Request failed')
  return json
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body: unknown) =>
    request<T>(path, { method: 'POST', body: JSON.stringify(body) }),
  patch: <T>(path: string, body: unknown) =>
    request<T>(path, { method: 'PATCH', body: JSON.stringify(body) }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
}
```

### 11.6 命名规范

| 场景 | 规范 | 示例 |
|------|------|------|
| Go 包名 | 小写无下划线 | `repository` `handler` `service` |
| Go 文件名 | 小写下划线 | `alert_repo.go` `intel_feed.go` |
| Go struct | PascalCase | `AlertListFilter` `PageMeta` |
| Go 常量（字段名） | Field 前缀 | `FieldAlertSeverity` `FieldIncidentID` |
| ArangoDB Collection | snake_case 复数 | `audit_logs` `intel_feeds` |
| ArangoDB 字段 | snake_case | `alert_id` `triggered_at` |
| API 路径 | kebab-case | `/threat-intel/iocs` `/devices/agents` |
| 环境变量 | SCREAMING_SNAKE_CASE | `ARANGO_ENDPOINTS` `JWT_SECRET` |
| React 组件 | PascalCase | `AlertDetailPanel.tsx` |
| React Hook | camelCase + use 前缀 | `useAlerts.ts` |
| TypeScript 类型 | PascalCase | `Alert` `PageMeta` `AlertListParams` |

### 11.7 go.mod 关键依赖

```
module xsiam

go 1.22

require (
    github.com/gin-gonic/gin               v1.10.0
    github.com/gin-contrib/requestid       v1.0.3
    github.com/arangodb/go-driver/v2       v2.1.0
    github.com/spf13/viper                 v1.19.0
    go.uber.org/zap                        v1.27.0
    github.com/golang-jwt/jwt/v5           v5.2.1
    github.com/go-playground/validator/v10 v10.22.0
)
```

> **注**：v3.0 移除了 `gin-contrib/cors`（同源，不需要 CORS）；v7.0 以 `github.com/arangodb/go-driver/v2` 替换 `go.mongodb.org/mongo-driver`。

---

## 12. 新增模块技术设计

### 10.1 因果关联引擎（CAE）

#### 10.1.1 架构定位

CAE 是一个**离线关联计算服务**，在 Service 层内以 goroutine 形式运行。触发方式：告警创建/更新时由 `AlertService` 调用 `CausalityService.TriggerCorrelation`；结果异步写入 ArangoDB Named Graph（`causality_nodes` + `causality_edges`）。前端通过 `GET /api/causality/graph/:incident_id` 拉取已计算图，后端用 AQL 图遍历查询返回。

```
AlertService.Create()
    └→ go CausalityService.TriggerCorrelation(ctx, alertID)
          ├─ 查询时间窗口内关联告警（asset/ioc/user 维度）
          ├─ 构建 DAG（节点/边）
          ├─ 计算 confidence
          ├─ 判断是否自动创建/合并 Incident
          └─ 写入 causality_nodes / causality_edges（Named Graph: causality_graph）
```

#### 10.1.2 数据模型

```go
// internal/model/causality_graph.go
package model

import "time"

type CausalityNodeType string
type CausalityEdgeType string

const (
    NodeTypeProcess  CausalityNodeType = "process"
    NodeTypeFile     CausalityNodeType = "file"
    NodeTypeNetwork  CausalityNodeType = "network"
    NodeTypeRegistry CausalityNodeType = "registry"
    NodeTypeAlert    CausalityNodeType = "alert"
    NodeTypeUser     CausalityNodeType = "user"
    NodeTypeAsset    CausalityNodeType = "asset"

    EdgeTypeSpawned       CausalityEdgeType = "spawned"
    EdgeTypeWroteFile     CausalityEdgeType = "wrote_file"
    EdgeTypeConnectedTo   CausalityEdgeType = "connected_to"
    EdgeTypeLateralMove   CausalityEdgeType = "lateral_move_to"
    EdgeTypeTriggered     CausalityEdgeType = "triggered_alert"
    EdgeTypeAuthenticated CausalityEdgeType = "authenticated_as"
    EdgeTypeAccessed      CausalityEdgeType = "accessed_resource"
)

const (
    FieldGraphIncidentID = "incident_id"
    FieldGraphCreatedAt  = "created_at"
    FieldGraphConfidence = "confidence"
)

// CausalityNode is stored in the causality_nodes document collection (Named Graph: causality_graph).
type CausalityNode struct {
    Key         string            `json:"_key,omitempty"`
    NodeID      string            `json:"node_id"`
    IncidentID  string            `json:"incident_id"`
    Type        CausalityNodeType `json:"type"`
    Label       string            `json:"label"`
    Properties  map[string]any    `json:"properties"`
    AlertID     *string           `json:"alert_id"`
    AssetID     *string           `json:"asset_id"`
    IsRootCause bool              `json:"is_root"`
    Severity    *Severity         `json:"severity"`
    CreatedAt   time.Time         `json:"created_at"`
}

// CausalityEdge is stored in the causality_edges edge collection (Named Graph: causality_graph).
// _from / _to reference causality_nodes/<key>.
type CausalityEdge struct {
    Key        string            `json:"_key,omitempty"`
    From       string            `json:"_from"` // "causality_nodes/<key>"
    To         string            `json:"_to"`   // "causality_nodes/<key>"
    IncidentID string            `json:"incident_id"`
    Type       CausalityEdgeType `json:"type"`
    Timestamp  *time.Time        `json:"timestamp"`
    Weight     float64           `json:"weight"`
}
```

#### 10.1.3 关联逻辑（Service 层）

```go
// internal/service/causality.go
package service

import (
    "context"
    "fmt"
    "time"
    "xsiam/internal/model"
    "xsiam/internal/repository"
    "xsiam/pkg/utils"
)

const (
    DefaultTimeWindowH  = 24
    DefaultConfidenceMin = 0.70
    MaxGraphNodes       = 500
    AutoIncidentMinAlerts = 2
)

type CausalityService struct {
    graphRepo  *repository.CausalityGraphRepo
    alertRepo  *repository.AlertRepo
    incRepo    *repository.IncidentRepo
    assetRepo  *repository.AssetRepo
}

func NewCausalityService(
    graphRepo  *repository.CausalityGraphRepo,
    alertRepo  *repository.AlertRepo,
    incRepo    *repository.IncidentRepo,
    assetRepo  *repository.AssetRepo,
) *CausalityService {
    return &CausalityService{graphRepo: graphRepo, alertRepo: alertRepo, incRepo: incRepo, assetRepo: assetRepo}
}

// TriggerCorrelation 异步触发关联分析（由 AlertService 在 goroutine 中调用）
func (s *CausalityService) TriggerCorrelation(ctx context.Context, triggerAlertID string) {
    alert, err := s.alertRepo.GetByID(ctx, triggerAlertID)
    if err != nil { return }

    since := alert.TriggeredAt.Add(-time.Duration(DefaultTimeWindowH) * time.Hour)

    // 6 维关联查询：同资产、同 IOC、同用户、同 MITRE tactic
    candidates := s.findCorrelatedAlerts(ctx, alert, since)
    if len(candidates) < AutoIncidentMinAlerts { return }

    graph := s.buildDAG(alert, candidates)
    if graph.Confidence < DefaultConfidenceMin { return }

    // 自动合并或创建 Incident
    s.autoAggregateIncident(ctx, graph, candidates)

    _ = s.graphRepo.Upsert(ctx, graph)
}

func (s *CausalityService) findCorrelatedAlerts(ctx context.Context, root *model.Alert, since time.Time) []*model.Alert {
    // 同资产维度
    byAsset, _ := s.alertRepo.FindByAssetSince(ctx, root.AssetID, since)
    // 同 IOC 维度
    var iocValues []string
    for _, ioc := range root.IOCs { iocValues = append(iocValues, ioc.Value) }
    byIoc, _ := s.alertRepo.FindByIocValues(ctx, iocValues, since)
    // 同用户维度
    byUser, _ := s.alertRepo.FindByUser(ctx, root.UserName, since)
    // 去重合并
    return dedup(append(append(byAsset, byIoc...), byUser...))
}

func (s *CausalityService) buildDAG(root *model.Alert, alerts []*model.Alert) *model.CausalityGraph {
    nodes := make([]model.CausalityNode, 0)
    edges := make([]model.CausalityEdge, 0)
    seen  := map[string]bool{}

    addAlert := func(a *model.Alert, isRoot bool) string {
        nid := "alert:" + a.AlertID
        if seen[nid] { return nid }
        seen[nid] = true
        nodes = append(nodes, model.CausalityNode{
            NodeID: nid, Type: model.NodeTypeAlert,
            Label: a.Name, AlertID: &a.AlertID,
            AssetID: a.AssetID, IsRootCause: isRoot,
            Severity: &a.Severity,
        })
        // 关联资产节点
        if a.AssetID != nil {
            anid := "asset:" + *a.AssetID
            if !seen[anid] {
                seen[anid] = true
                nodes = append(nodes, model.CausalityNode{
                    NodeID: anid, Type: model.NodeTypeAsset, Label: a.AssetName,
                })
            }
            edges = append(edges, model.CausalityEdge{
                Source: nid, Target: anid, Type: model.EdgeTypeTriggered, Weight: 1.0,
            })
        }
        return nid
    }

    rootID := addAlert(root, true)
    for _, a := range alerts {
        if a.AlertID == root.AlertID { continue }
        aid := addAlert(a, false)
        edges = append(edges, model.CausalityEdge{
            Source: rootID, Target: aid,
            Type: model.EdgeTypeTriggered, Weight: s.calcEdgeWeight(root, a),
        })
    }

    // 限制最大节点数
    if len(nodes) > MaxGraphNodes { nodes = nodes[:MaxGraphNodes] }

    confidence := s.calcGraphConfidence(nodes, edges)
    return &model.CausalityGraph{
        GraphID:     utils.GenerateGraphID(),
        TimeWindowH: DefaultTimeWindowH,
        Confidence:  confidence,
        Nodes:       nodes,
        Edges:       edges,
        NodeCount:   len(nodes),
        EdgeCount:   len(edges),
        GeneratedAt: time.Now(),
        CreatedAt:   time.Now(),
    }
}

func (s *CausalityService) calcEdgeWeight(a, b *model.Alert) float64 {
    w := 0.0
    if a.AssetID != nil && b.AssetID != nil && *a.AssetID == *b.AssetID { w += 0.4 }
    for _, ta := range a.MitreTactics {
        for _, tb := range b.MitreTactics { if ta == tb { w += 0.3; break } }
    }
    for _, ia := range a.IOCs {
        for _, ib := range b.IOCs { if ia.Value == ib.Value { w += 0.3; break } }
    }
    if w > 1.0 { return 1.0 }
    return w
}

func (s *CausalityService) calcGraphConfidence(nodes []model.CausalityNode, edges []model.CausalityEdge) float64 {
    if len(edges) == 0 { return 0 }
    var total float64
    for _, e := range edges { total += e.Weight }
    avg := total / float64(len(edges))
    density := float64(len(edges)) / float64(max(len(nodes)*(len(nodes)-1)/2, 1))
    return min(avg*0.7+density*0.3, 1.0)
}

func (s *CausalityService) autoAggregateIncident(ctx context.Context, graph *model.CausalityGraph, alerts []*model.Alert) {
    // 检查是否已有关联 Incident
    for _, a := range alerts {
        if a.IncidentID != nil {
            graph.IncidentID = *a.IncidentID
            return
        }
    }
    // 自动创建 Incident（仅当关联告警 ≥ AutoIncidentMinAlerts 且无现有 Incident）
    if len(alerts) >= AutoIncidentMinAlerts {
        inc := s.buildAutoIncident(alerts)
        _ = s.incRepo.Create(ctx, inc)
        graph.IncidentID = inc.IncidentID
        incID := inc.IncidentID
        for _, a := range alerts {
            _ = s.alertRepo.Update(ctx, a.ID.Hex(), bsonSet("incident_id", incID))
        }
    }
}

func dedup(alerts []*model.Alert) []*model.Alert {
    seen := map[string]bool{}
    result := make([]*model.Alert, 0)
    for _, a := range alerts {
        if !seen[a.AlertID] { seen[a.AlertID] = true; result = append(result, a) }
    }
    return result
}

func max(a, b int) int { if a > b { return a }; return b }
func min(a, b float64) float64 { if a < b { return a }; return b }
```

前端使用 `@xyflow/react`（React Flow）渲染 DAG：节点类型通过 `nodeTypes` map 映射为自定义 React 组件，边宽度对应 `weight` 值。

---

### 10.2 SmartScore 评分引擎

#### 10.2.1 评分计算设计

SmartScore 在 `IncidentService` 内实现。评分公式（4 维加权）：

```
SmartScore = Impact(40%) + Behavior(35%) + Intelligence(15%) + Urgency(10%)
           × AssetImportanceFactor × min(1.0, AlertVelocityBonus)
结果四舍五入至整数，取值 0-100
```

```go
// internal/service/smart_score.go
package service

import (
    "context"
    "math"
    "time"
    "xsiam/internal/model"
    "xsiam/internal/repository"
)

type ScoreBreakdown struct {
    Total       float64       `json:"total"`
    Impact      float64       `json:"impact"`
    Behavior    float64       `json:"behavior"`
    Intelligence float64      `json:"intelligence"`
    Urgency     float64       `json:"urgency"`
    Factors     []ScoreFactor `json:"factors"`
}

type ScoreFactor struct {
    Dimension string  `json:"dimension"`
    Name      string  `json:"name"`
    Value     float64 `json:"value"`
    Weight    float64 `json:"weight"`
}

type SmartScoreService struct {
    incRepo   *repository.IncidentRepo
    assetRepo *repository.AssetRepo
    alertRepo *repository.AlertRepo
}

func NewSmartScoreService(
    incRepo   *repository.IncidentRepo,
    assetRepo *repository.AssetRepo,
    alertRepo *repository.AlertRepo,
) *SmartScoreService {
    return &SmartScoreService{incRepo: incRepo, assetRepo: assetRepo, alertRepo: alertRepo}
}

func (s *SmartScoreService) Calculate(ctx context.Context, incidentID string) (*ScoreBreakdown, error) {
    inc, err := s.incRepo.GetByID(ctx, incidentID)
    if err != nil { return nil, err }

    alerts, _, _ := s.alertRepo.List(ctx, repository.AlertListFilter{IncidentID: incidentID, PageSize: 100})
    assets := s.loadAssets(ctx, inc.AffectedAssets)

    impactScore    := s.calcImpact(inc, assets)
    behaviorScore  := s.calcBehavior(alerts)
    intelScore     := s.calcIntelligence(alerts)
    urgencyScore   := s.calcUrgency(inc, alerts)

    assetFactor := s.maxAssetImportanceFactor(assets)

    raw := impactScore*0.40 + behaviorScore*0.35 + intelScore*0.15 + urgencyScore*0.10
    raw *= assetFactor
    total := math.Round(math.Min(raw, 100))

    // Honeypot 强制 ≥ 80
    if s.hasHoneypotAsset(assets) && total < 80 { total = 80 }

    factors := []ScoreFactor{
        {Dimension: "impact",       Name: "影响面", Value: impactScore,   Weight: 0.40},
        {Dimension: "behavior",     Name: "行为风险", Value: behaviorScore, Weight: 0.35},
        {Dimension: "intelligence", Name: "威胁情报", Value: intelScore,    Weight: 0.15},
        {Dimension: "urgency",      Name: "响应紧迫", Value: urgencyScore,  Weight: 0.10},
    }

    breakdown := &ScoreBreakdown{
        Total:        total,
        Impact:       impactScore,
        Behavior:     behaviorScore,
        Intelligence: intelScore,
        Urgency:      urgencyScore,
        Factors:      factors,
    }

    // 写回 Incident
    _ = s.incRepo.Update(ctx, incidentID, bsonSet("smart_score", total))
    _ = s.incRepo.Update(ctx, incidentID, bsonSet("score_factors", factors))

    s.checkAutoActions(ctx, inc, total)
    return breakdown, nil
}

func (s *SmartScoreService) calcImpact(inc *model.Incident, assets []model.Asset) float64 {
    score := 0.0
    if len(assets) > 0          { score += 30 }
    if inc.Severity == model.SeverityCritical { score += 40 }
    if inc.Severity == model.SeverityHigh     { score += 25 }
    criticalCount := 0
    for _, a := range assets { if a.RiskLevel == "critical" { criticalCount++ } }
    score += float64(min2(criticalCount, 3)) * 10
    return math.Min(score, 100)
}

func (s *SmartScoreService) calcBehavior(alerts []model.Alert) float64 {
    score := 0.0
    tactics := map[string]bool{}
    for _, a := range alerts {
        for _, t := range a.MitreTactics { tactics[t] = true }
    }
    score += float64(len(tactics)) * 12
    if len(alerts) > 5 { score += 20 }
    return math.Min(score, 100)
}

func (s *SmartScoreService) calcIntelligence(alerts []model.Alert) float64 {
    score := 0.0
    for _, a := range alerts {
        for _, ioc := range a.IOCs {
            if ioc.Verdict == "malicious" { score += 15; break }
        }
    }
    return math.Min(score, 100)
}

func (s *SmartScoreService) calcUrgency(inc *model.Incident, alerts []model.Alert) float64 {
    score := 0.0
    age := time.Since(inc.FirstSeen).Hours()
    if age < 1  { score += 40 }
    if age < 6  { score += 20 }
    if inc.Status == "new" { score += 20 }
    return math.Min(score, 100)
}

func (s *SmartScoreService) maxAssetImportanceFactor(assets []model.Asset) float64 {
    factors := map[string]float64{"critical": 1.5, "high": 1.3, "medium": 1.0, "low": 0.8}
    max := 1.0
    for _, a := range assets {
        if f, ok := factors[a.Importance]; ok && f > max { max = f }
    }
    return max
}

func (s *SmartScoreService) hasHoneypotAsset(assets []model.Asset) bool {
    for _, a := range assets { if a.IsHoneypot { return true } }
    return false
}

func (s *SmartScoreService) checkAutoActions(ctx context.Context, inc *model.Incident, score float64) {
    // ≥80：通知 L3；≥90：通知管理层；≥90 + 关键资产 → Webhook 触发 SOAR 紧急剧本
    // 实际通知走 notification stub；SOAR 触发走 webhook stub
}

func min2(a, b int) int { if a < b { return a }; return b }
```

#### 10.2.2 SmartScore API 设计

```go
// internal/handler/smart_score.go
package handler

import (
    "xsiam/internal/service"
    "xsiam/pkg/response"
    "github.com/gin-gonic/gin"
)

type SmartScoreHandler struct{ svc *service.SmartScoreService }

func NewSmartScoreHandler(svc *service.SmartScoreService) *SmartScoreHandler {
    return &SmartScoreHandler{svc: svc}
}

func (h *SmartScoreHandler) Get(c *gin.Context) {
    incidentID := c.Param("incident_id")
    breakdown, err := h.svc.Calculate(c.Request.Context(), incidentID)
    if err != nil { response.NotFound(c, "incident"); return }
    response.OK(c, breakdown)
}

func (h *SmartScoreHandler) Recalc(c *gin.Context) {
    incidentID := c.Param("incident_id")
    breakdown, err := h.svc.Calculate(c.Request.Context(), incidentID)
    if err != nil { response.InternalError(c, err); return }
    response.OK(c, breakdown)
}
```

---

### 10.3 检测规则引擎

#### 10.3.1 数据模型

```go
// internal/model/detection_rule.go
package model

import "time"

type RuleType   string
type RuleStatus string

const (
    RuleTypeBIOC      RuleType = "bioc"
    RuleTypeIOC       RuleType = "ioc"
    RuleTypeUEBA      RuleType = "ueba"

    RuleStatusDraft      RuleStatus = "draft"
    RuleStatusTesting    RuleStatus = "testing"
    RuleStatusActive     RuleStatus = "active"
    RuleStatusDisabled   RuleStatus = "disabled"
    RuleStatusDeprecated RuleStatus = "deprecated"
)

// RuleStatus 合法流转路径：draft→testing→active→disabled→deprecated
// draft 可直接→deprecated；active↔disabled（双向）
var RuleStatusTransitions = map[RuleStatus][]RuleStatus{
    RuleStatusDraft:      {RuleStatusTesting, RuleStatusDeprecated},
    RuleStatusTesting:    {RuleStatusActive, RuleStatusDraft},
    RuleStatusActive:     {RuleStatusDisabled},
    RuleStatusDisabled:   {RuleStatusActive, RuleStatusDeprecated},
    RuleStatusDeprecated: {},
}

const (
    FieldRuleID      = "rule_id"
    FieldRuleType    = "rule_type"
    FieldRuleStatus  = "status"
    FieldMitreTech   = "mitre_technique"
)

type RuleDefinition struct {
    // BIOC 行为序列定义
    Sequence   []BIOCEvent    `json:"sequence,omitempty"`
    TimeWindow string         `json:"time_window,omitempty"` // e.g. "5m"
    // IOC 匹配定义
    IocType    string         `json:"ioc_type,omitempty"`
    IocValues  []string       `json:"ioc_values,omitempty"`
    // UEBA 统计异常定义
    Metric     string         `json:"metric,omitempty"`
    Threshold  float64        `json:"threshold,omitempty"`
    Baseline   string         `json:"baseline,omitempty"` // "7d_avg"
}

type BIOCEvent struct {
    EventType  string            `json:"event_type"`
    Conditions map[string]string `json:"conditions"`
}

type RuleTestResult struct {
    MatchCount     int       `json:"match_count"`
    FalsePositives int       `json:"false_positives"`
    TestedAt       time.Time `json:"tested_at"`
    TimeRangeH     int       `json:"time_range_h"`
    Note           string    `json:"note"`
}

type DetectionRule struct {
    Key              string          `json:"_key,omitempty"`
    RuleID           string          `json:"rule_id"`
    Name             string          `json:"name"`
    Description      string          `json:"description"`
    RuleType         RuleType        `json:"rule_type"`
    Status           RuleStatus      `json:"status"`
    Severity         Severity        `json:"severity"`
    MitreTactic      string          `json:"mitre_tactic"`
    MitreTechnique   string          `json:"mitre_technique"`
    Definition       RuleDefinition  `json:"definition"`
    TestResult       *RuleTestResult `json:"test_result"`
    HitCount         int64           `json:"hit_count"`
    FalsePositiveRate float64        `json:"false_positive_rate"`
    LastHitAt        *time.Time      `json:"last_hit_at"`
    CreatedBy        string          `json:"created_by"`
    CreatedAt        time.Time       `json:"created_at"`
    UpdatedAt        time.Time       `json:"updated_at"`
}
```

#### 10.3.2 状态流转与历史回放

```go
// internal/service/detection_rule.go
package service

import (
    "context"
    "fmt"
    "time"
    "xsiam/internal/model"
    "xsiam/internal/repository"
    "xsiam/internal/stub"
)

type DetectionRuleService struct {
    ruleRepo *repository.DetectionRuleRepo
    lakeStub *stub.DataLakeStub
}

func NewDetectionRuleService(
    ruleRepo *repository.DetectionRuleRepo,
    lakeStub *stub.DataLakeStub,
) *DetectionRuleService {
    return &DetectionRuleService{ruleRepo: ruleRepo, lakeStub: lakeStub}
}

func (s *DetectionRuleService) TransitionStatus(ctx context.Context, key string, toStatus model.RuleStatus, operatorID string) error {
    rule, err := s.ruleRepo.GetByID(ctx, key)
    if err != nil { return err }

    allowed := model.RuleStatusTransitions[rule.Status]
    for _, a := range allowed {
        if a == toStatus {
            return s.ruleRepo.Update(ctx, key, map[string]any{model.FieldRuleStatus: toStatus})
        }
    }
    return fmt.Errorf("不允许从 %s 流转至 %s", rule.Status, toStatus)
}

type TestRequest struct {
    TimeRangeH int    `json:"time_range_h" binding:"required,min=1,max=720"`
    Note       string `json:"note"`
}

// TestReplay 历史回放测试（不产生真实告警）
func (s *DetectionRuleService) TestReplay(ctx context.Context, key string, req TestRequest) (*model.RuleTestResult, error) {
    rule, err := s.ruleRepo.GetByID(ctx, key)
    if err != nil { return nil, err }

    // 调用数据湖 Stub 模拟历史数据匹配（真实实现对接 ClickHouse）
    end   := time.Now().Unix()
    start := end - int64(req.TimeRangeH)*3600
    _, _ = s.lakeStub.Query(ctx, fmt.Sprintf("rule_replay:%s", rule.RuleID), start, end)

    // Stub 返回模拟结果
    result := &model.RuleTestResult{
        MatchCount:     12,
        FalsePositives: 1,
        TestedAt:       time.Now(),
        TimeRangeH:     req.TimeRangeH,
        Note:           req.Note,
    }
    _ = s.ruleRepo.Update(ctx, key, map[string]any{"test_result": result})
    return result, nil
}

// MitreCoverage 返回 ATT&CK 覆盖矩阵（Aggregate）
func (s *DetectionRuleService) MitreCoverage(ctx context.Context) (map[string][]string, error) {
    return s.ruleRepo.AggregateByMitre(ctx)
}
```

---

### 10.4 暴露管理（Exposure Management）

#### 10.4.1 数据模型

```go
// internal/model/exposure_score.go
package model

import "time"

type FixStatus string

const (
    FixStatusUnplanned    FixStatus = "unplanned"
    FixStatusPlanned      FixStatus = "planned"
    FixStatusInProgress   FixStatus = "in_progress"
    FixStatusVerifying    FixStatus = "verifying"
    FixStatusFixed        FixStatus = "fixed"
    FixStatusAccepted     FixStatus = "accepted_risk"
    FixStatusCompensating FixStatus = "compensating_control"
)

const (
    FieldExposureAssetID   = "asset_id"
    FieldExposureCveID     = "cve_id"
    FieldExposurePriority  = "priority_score"
    FieldExposureFixStatus = "fix_status"
)

type ExposureScore struct {
    Key                   string     `json:"_key,omitempty"`
    AssetID               string     `json:"asset_id"`
    AssetName             string     `json:"asset_name"`
    CveID                 string     `json:"cve_id"`
    CvssScore             float64    `json:"cvss_score"`
    PriorityScore         float64    `json:"priority_score"`
    InWildFactor          float64    `json:"in_wild_factor"`          // 1.0 or 1.5
    ReachabilityFactor    float64    `json:"reachability_factor"`     // 0.3/0.7/1.0/1.3
    AssetImportanceFactor float64    `json:"asset_importance_factor"` // 0.8-1.5
    FixStatus             FixStatus  `json:"fix_status"`
    FixDeadline           *time.Time `json:"fix_deadline"`
    LastScoredAt          time.Time  `json:"last_scored_at"`
    CreatedAt             time.Time  `json:"created_at"`
    UpdatedAt             time.Time  `json:"updated_at"`
}
```

#### 10.4.2 优先级评分计算

```go
// internal/service/exposure.go
package service

import (
    "context"
    "math"
    "time"
    "xsiam/internal/model"
    "xsiam/internal/repository"
)

// CalcPriorityScore 暴露优先级评分公式：
// CVSS × 10 × InWildFactor × ReachabilityFactor × AssetImportanceFactor，最高 100
func CalcPriorityScore(cvss, inWild, reachability, assetImportance float64) float64 {
    raw := cvss * 10 * inWild * reachability * assetImportance
    return math.Round(math.Min(raw, 100))
}

type ReachabilityLevel int

const (
    ReachabilityNone      ReachabilityLevel = iota // 0.3：内网隔离，无法到达
    ReachabilityInternal                            // 0.7：内网可达
    ReachabilityExternal                            // 1.0：互联网可达
    ReachabilityExposed                             // 1.3：直接暴露服务
)

var reachabilityFactors = map[ReachabilityLevel]float64{
    ReachabilityNone:     0.3,
    ReachabilityInternal: 0.7,
    ReachabilityExternal: 1.0,
    ReachabilityExposed:  1.3,
}

var assetImportanceFactors = map[string]float64{
    "critical": 1.5, "high": 1.3, "medium": 1.0, "low": 0.8,
}

type ExposureService struct {
    exposureRepo *repository.ExposureScoreRepo
    assetRepo    *repository.AssetRepo
    vulnRepo     *repository.VulnerabilityRepo
}

func NewExposureService(
    exposureRepo *repository.ExposureScoreRepo,
    assetRepo    *repository.AssetRepo,
    vulnRepo     *repository.VulnerabilityRepo,
) *ExposureService {
    return &ExposureService{exposureRepo: exposureRepo, assetRepo: assetRepo, vulnRepo: vulnRepo}
}

// RecalcAll 批量刷新所有资产的漏洞暴露评分（Stub 触发，真实实现对接漏扫数据）
func (s *ExposureService) RecalcAll(ctx context.Context) error {
    vulns, _, _ := s.vulnRepo.List(ctx, repository.VulnerabilityListFilter{PageSize: 1000})
    for _, v := range vulns {
        for _, assetID := range v.AffectedAssetIDs {
            asset, err := s.assetRepo.GetByID(ctx, assetID)
            if err != nil { continue }

            inWild := 1.0
            if v.ExploitedInWild { inWild = 1.5 }
            reach := reachabilityFactors[ReachabilityExternal]     // Stub 默认
            assetFactor := assetImportanceFactors[asset.Importance]
            if assetFactor == 0 { assetFactor = 1.0 }

            score := CalcPriorityScore(v.CvssScore, inWild, reach, assetFactor)

            exp := &model.ExposureScore{
                AssetID:               assetID,
                AssetName:             asset.Name,
                CveID:                 v.CveID,
                CvssScore:             v.CvssScore,
                PriorityScore:         score,
                InWildFactor:          inWild,
                ReachabilityFactor:    reach,
                AssetImportanceFactor: assetFactor,
                FixStatus:             model.FixStatusUnplanned,
                LastScoredAt:          time.Now(),
            }
            _ = s.exposureRepo.Upsert(ctx, exp)
        }
    }
    return nil
}
```

---

### 10.5 身份威胁检测与响应（ITDR）

#### 10.5.1 数据模型

```go
// internal/model/identity_risk.go
package model

import "time"

type RiskSignalType string

const (
    SignalImpossibleTravel     RiskSignalType = "impossible_travel"       // +30
    SignalTimeAnomaly          RiskSignalType = "time_anomaly"            // +15
    SignalNewDevice            RiskSignalType = "new_device"              // +15
    SignalAuthFailureRate      RiskSignalType = "auth_failure_rate"       // +25（递进）
    SignalSensitiveFirstAccess RiskSignalType = "sensitive_first_access"  // +20
    SignalPrivilegeAnomaly     RiskSignalType = "privilege_anomaly"       // +25
    SignalActiveAlert          RiskSignalType = "active_alert"            // ×1.2
    SignalActiveIncident       RiskSignalType = "active_incident"         // ×1.5
)

type RiskSignal struct {
    Type       RiskSignalType `json:"type"`
    Score      float64        `json:"score"`
    Detail     string         `json:"detail"`
    DetectedAt time.Time      `json:"detected_at"`
}

type IdentityBaseline struct {
    LoginHoursP95  [2]int    `json:"login_hours_p95"` // [start, end]
    TypicalCities  []string  `json:"typical_cities"`
    KnownDevices   []string  `json:"known_devices"`
    AvgDailyLogins float64   `json:"avg_daily_logins"`
    UpdatedAt      time.Time `json:"updated_at"`
}

const (
    FieldIdentityUserID    = "user_id"
    FieldIdentityRiskScore = "risk_score"
    FieldIdentityUpdatedAt = "updated_at"
)

type IdentityRisk struct {
    Key                  string           `json:"_key,omitempty"`
    UserID               string           `json:"user_id"`
    Username             string           `json:"username"`
    Domain               string           `json:"domain"`
    RiskScore            float64          `json:"risk_score"`
    RiskSignals          []RiskSignal     `json:"risk_signals"`
    ActiveRestrictions   []int            `json:"active_restrictions"`
    Baseline             IdentityBaseline `json:"baseline"`
    LastImpossibleTravel *time.Time       `json:"last_impossible_travel"`
    UpdatedAt            time.Time        `json:"updated_at"`
    CreatedAt            time.Time        `json:"created_at"`
}
```

```go
// internal/model/privilege_restriction.go
package model

import "time"

const (
    FieldRestrictionUserID  = "user_id"
    FieldRestrictionLevel   = "level"
    FieldRestrictionExpires = "expires_at"
)

// L1(≥70)监控 L2(≥80)封锁高价值 L3(≥85)强制MFA L4(≥90)吊销会话 L5(≥95/手动)禁用账号
var RestrictionThresholds = map[int]float64{1: 70, 2: 80, 3: 85, 4: 90, 5: 95}
var RestrictionExpiry     = map[int]time.Duration{1: 24 * time.Hour, 2: 24 * time.Hour, 3: 8 * time.Hour, 4: 0, 5: 0} // 0 = 需手动解除

type PrivilegeRestriction struct {
    Key           string     `json:"_key,omitempty"`
    UserID        string     `json:"user_id"`
    Level         int        `json:"level"`
    TriggerSignal string     `json:"trigger_signal"`
    TriggerScore  float64    `json:"trigger_score"`
    AppliedAt     time.Time  `json:"applied_at"`
    ExpiresAt     *time.Time `json:"expires_at"`
    ReleasedAt    *time.Time `json:"released_at"`
    ReleasedBy    *string    `json:"released_by"`
    IsActive      bool       `json:"is_active"`
}
```

#### 10.5.2 ITDR Service（风险评分 + 限制下发）

```go
// internal/service/identity_risk.go
package service

import (
    "context"
    "math"
    "time"
    "xsiam/internal/model"
    "xsiam/internal/repository"
    "xsiam/internal/stub"
)

type IdentityRiskService struct {
    riskRepo        *repository.IdentityRiskRepo
    restrictionRepo *repository.PrivilegeRestrictionRepo
    execStub        *stub.ExecutionStub
}

func NewIdentityRiskService(
    riskRepo        *repository.IdentityRiskRepo,
    restrictionRepo *repository.PrivilegeRestrictionRepo,
    execStub        *stub.ExecutionStub,
) *IdentityRiskService {
    return &IdentityRiskService{riskRepo: riskRepo, restrictionRepo: restrictionRepo, execStub: execStub}
}

// AddSignal 添加风险信号并重新计算评分
func (s *IdentityRiskService) AddSignal(ctx context.Context, userID string, signal model.RiskSignal) error {
    risk, _ := s.riskRepo.GetByUserID(ctx, userID)
    if risk == nil {
        risk = &model.IdentityRisk{UserID: userID, CreatedAt: time.Now()}
    }

    risk.RiskSignals = append(risk.RiskSignals, signal)
    risk.RiskScore = s.recalcScore(risk.RiskSignals)
    risk.UpdatedAt = time.Now()

    if err := s.riskRepo.Upsert(ctx, risk); err != nil { return err }

    // 评分变化时自动检查是否需要施加/升级限制
    s.applyRestrictions(ctx, risk)
    return nil
}

func (s *IdentityRiskService) recalcScore(signals []model.RiskSignal) float64 {
    base := 0.0
    multiplier := 1.0
    for _, sig := range signals {
        switch sig.Type {
        case model.SignalActiveAlert:    multiplier = math.Max(multiplier, 1.2)
        case model.SignalActiveIncident: multiplier = math.Max(multiplier, 1.5)
        default: base += sig.Score
        }
    }
    return math.Min(base*multiplier, 100)
}

func (s *IdentityRiskService) applyRestrictions(ctx context.Context, risk *model.IdentityRisk) {
    score := risk.RiskScore
    for level := 5; level >= 1; level-- {
        threshold := model.RestrictionThresholds[level]
        if score >= threshold {
            // 检查是否已有当前级别限制
            existing, _ := s.restrictionRepo.GetActiveByUserLevel(ctx, risk.UserID, level)
            if existing != nil { return }

            expiry := model.RestrictionExpiry[level]
            restriction := &model.PrivilegeRestriction{
                UserID:       risk.UserID,
                Level:        level,
                TriggerScore: score,
                AppliedAt:    time.Now(),
                IsActive:     true,
            }
            if expiry > 0 {
                t := time.Now().Add(expiry)
                restriction.ExpiresAt = &t
            }
            _ = s.restrictionRepo.Create(ctx, restriction)

            // L4/L5 触发实际执行（Stub）
            if level >= 4 {
                _, _ = s.execStub.Execute(ctx, itdrAction(level), risk.UserID, nil)
            }
            return
        }
    }
}

func itdrAction(level int) string {
    switch level {
    case 4: return "revoke_all_sessions"
    case 5: return "suspend_ad_account"
    default: return "monitor"
    }
}

// ReleaseRestriction 手动解除 L4/L5 限制
func (s *IdentityRiskService) ReleaseRestriction(ctx context.Context, userID, operatorID string) error {
    return s.restrictionRepo.ReleaseByUserID(ctx, userID, operatorID)
}
```

---

### 10.6 多租户与权限管理

#### 10.6.1 数据模型

```go
// internal/model/tenant.go
package model

import "time"

type TenantTier string

const (
    TenantTierSuper TenantTier = "super"
    TenantTierChild TenantTier = "child"
)

const (
    FieldTenantCode     = "tenant_code"
    FieldTenantParentID = "parent_tenant_id"
)

type TenantSettings struct {
    LogRetentionDays int    `json:"log_retention_days"`
    MaxUsers         int    `json:"max_users"`
    AllowCustomRules bool   `json:"allow_custom_rules"`
    WhiteLabelName   string `json:"white_label_name"`
}

type Tenant struct {
    Key            string         `json:"_key,omitempty"`
    TenantID       string         `json:"tenant_id"`
    TenantCode     string         `json:"tenant_code"`
    Name           string         `json:"name"`
    Tier           TenantTier     `json:"tier"`
    ParentTenantID *string        `json:"parent_tenant_id"`
    IsEnabled      bool           `json:"is_enabled"`
    Settings       TenantSettings `json:"settings"`
    CreatedAt      time.Time      `json:"created_at"`
    UpdatedAt      time.Time      `json:"updated_at"`
}

// ResourceScope 对象级权限范围
type ResourceScope struct {
    RuleIDs        []string `json:"rule_ids"`
    PlaybookIDs    []string `json:"playbook_ids"`
    ReportIDs      []string `json:"report_ids"`
    AssetGroupIDs  []string `json:"asset_group_ids"`
    DatasetIDs     []string `json:"dataset_ids"`
    IntelSourceIDs []string `json:"intel_source_ids"`
}

type RbacRole struct {
    Key            string        `json:"_key,omitempty"`
    RoleID         string        `json:"role_id"`
    TenantID       string        `json:"tenant_id"`
    Name           string        `json:"name"`
    Permissions    []string      `json:"permissions"` // e.g. "alerts:read" "incidents:write"
    ResourceScopes ResourceScope `json:"resource_scopes"`
    IsBuiltin      bool          `json:"is_builtin"`
    CreatedAt      time.Time     `json:"created_at"`
    UpdatedAt      time.Time     `json:"updated_at"`
}
```

#### 10.6.2 多租户中间件

```go
// internal/middleware/tenant.go
package middleware

import (
    "xsiam/pkg/response"
    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"
)

// TenantContext 从 JWT claims 中提取 tenant_id 并注入 gin.Context
// JWT payload: { "sub": "user123", "role": "analyst", "tenant_id": "t-001", "tier": "child" }
func TenantContext() gin.HandlerFunc {
    return func(c *gin.Context) {
        claims, exists := c.Get("jwt_claims")
        if !exists { response.Unauthorized(c); c.Abort(); return }

        mc, ok := claims.(jwt.MapClaims)
        if !ok { response.Unauthorized(c); c.Abort(); return }

        tenantID, _ := mc["tenant_id"].(string)
        tier, _     := mc["tier"].(string)
        if tenantID == "" { response.Forbidden(c); c.Abort(); return }

        c.Set("tenant_id", tenantID)
        c.Set("tenant_tier", tier)
        c.Next()
    }
}

// RequireSuperTenant 仅 Super 租户可访问（跨租户管理接口）
func RequireSuperTenant() gin.HandlerFunc {
    return func(c *gin.Context) {
        tier := c.GetString("tenant_tier")
        if tier != "super" { response.Forbidden(c); c.Abort(); return }
        c.Next()
    }
}
```

#### 10.6.3 Repository 层 tenant_id 注入

所有 Repository 的 `List/Create/Update/Delete` 操作均在 filter 中自动注入 `tenant_id`，防止跨租户数据访问：

```go
// internal/repository/tenant_aware.go
package repository

// InjectTenantFilter 在 AQL filters 列表中追加 tenant_id 条件
func InjectTenantFilter(filters []string, bindVars map[string]any, tenantID string) ([]string, map[string]any) {
    if tenantID == "" { return filters, bindVars }
    filters = append(filters, "doc.tenant_id == @tenantID")
    bindVars["tenantID"] = tenantID
    return filters, bindVars
}
```

所有多租户资源的 Model 增加 `TenantID` 字段（`json:"tenant_id"`），Repository 调用 `InjectTenantFilter` 后再执行 AQL 查询，**编译时无法遗漏**（Service 层从 `c.GetString("tenant_id")` 取值后传入 Repository）。

#### 10.6.4 RBAC 权限检查中间件

```go
// internal/middleware/rbac.go（扩展版）
package middleware

import (
    "xsiam/pkg/response"
    "github.com/gin-gonic/gin"
)

// RequirePermission 检查用户是否持有指定权限（格式："resource:action"）
// 权限列表从 JWT claims["permissions"] 中读取（登录时写入）
func RequirePermission(perm string) gin.HandlerFunc {
    return func(c *gin.Context) {
        permissions, _ := c.Get("permissions")
        perms, ok := permissions.([]string)
        if !ok { response.Forbidden(c); c.Abort(); return }
        for _, p := range perms {
            if p == perm || p == "*" { c.Next(); return }
        }
        response.Forbidden(c); c.Abort()
    }
}
```

路由注册示例（Super 租户专属接口）：

```go
// 租户管理（仅 Super 租户）
tenantsMgmt := auth.Group("/tenants",
    middleware.TenantContext(),
    middleware.RequireSuperTenant(),
)
tenantsMgmt.GET("",    tenantH.List)
tenantsMgmt.POST("",   tenantH.Create)
tenantsMgmt.PATCH("/:id", tenantH.Update)

// RBAC 角色（各租户内部管理）
roles := auth.Group("/rbac/roles",
    middleware.TenantContext(),
    middleware.RequirePermission("rbac:write"),
)
roles.GET("",       roleH.List)
roles.POST("",      roleH.Create)
roles.PATCH("/:id", roleH.Update)
roles.DELETE("/:id", roleH.Delete)
```

#### 10.6.5 前端路由新增

```
web/src/routes/
├── detection-rules/
│   ├── index.tsx          # /detection-rules（规则列表）
│   ├── $id.tsx            # /detection-rules/:id（规则编辑器）
│   └── mitre-coverage.tsx # /detection-rules/mitre-coverage（ATT&CK矩阵）
├── exposures.tsx          # /exposures（暴露管理）
├── identity-risks/
│   ├── index.tsx          # /identity-risks（身份风险列表）
│   └── $user_id.tsx       # /identity-risks/:user_id（用户风险详情）
└── admin/
    ├── tenants.tsx        # /admin/tenants（租户管理，Super 级）
    └── roles.tsx          # /admin/roles（角色管理）
```

---

## 13. 极致轻量高性能优化

> 核心原则：计算密集/IO 密集推给 ngx（C 实现），Go 层专注状态管理和 API；ArangoDB 只保热数据，冷数据归档 ngx 数据湖。

### 13.1 ngx 数据湖客户端

#### 13.1.1 职责边界厘清

**实时日志不经过 XSIAM Go 进程。** 数据采集链路是：

```
Agent → Fluent-bit → ngx HEC :18088（直接写入）
```

XSIAM Go 进程对 ngx 数据湖只有两种操作：

| 操作 | 发起方 | 接口 | 频率 |
|------|--------|------|------|
| **SPL2 查询** | 分析师操作日志查询中心 | `GET /services/search/...` | 按需，低频 |
| **冷数据归档写入** | Archiver 后台任务 | `POST /services/collector/event`（HEC） | 1次/小时，批量 |

XSIAM 没有实时写入日志到 ngx 的需求，`DataLakeStub` 中的 `IngestAlert` 实时写入接口删除。

#### 13.1.2 目录结构

```
internal/
├── stub/
│   ├── execution.go      # 设备响应执行桩（保留）
│   ├── etl.go            # Agent 升级/卸载桩（保留）
│   └── ai_engine.go      # AI 评分桩（保留）
│   # datalake.go 已删除
│
└── datalake/             # ngx 数据湖客户端
    ├── client.go         # Client 结构体 + New()
    ├── query.go          # SPL2 查询（分析师日志查询、规则回放测试）
    ├── hec.go            # HEC 批量写入（仅归档器使用）
    ├── saved_search.go   # saved_search CRUD（规则同步到 ngx）
    ├── interface.go      # QueryClient 接口定义
    └── archiver.go       # ArangoDB 冷数据归档器
```

#### 13.1.3 客户端实现

```go
// internal/datalake/client.go
package datalake

import (
    "net/http"
    "time"
)

// Client 封装对 ngx 数据湖的所有 HTTP 调用
// queryURL: ngx head 查询节点（:8080）
// hecURL:   ngx HEC 端口（:18088），仅归档器使用
type Client struct {
    queryURL string
    hecURL   string
    hecToken string
    http     *http.Client
}

func New(queryURL, hecURL, hecToken string) *Client {
    return &Client{
        queryURL: queryURL,
        hecURL:   hecURL,
        hecToken: hecToken,
        http:     &http.Client{Timeout: 30 * time.Second},
    }
}
```

```go
// internal/datalake/query.go
package datalake

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
)

type QueryResult struct {
    Rows      []map[string]any `json:"rows"`
    Total     int              `json:"total"`
    ElapsedMs int              `json:"elapsed_ms"`
    ScannedGB float64          `json:"scanned_gb"`
}

// Query 执行 SPL2 查询，对接 ngx head 节点 /services/search/jobs/export
// 供：① 分析师日志查询中心（/logs）  ② 规则历史回放测试
func (c *Client) Query(ctx context.Context, spl2 string, fromTS, toTS int64) (*QueryResult, error) {
    reqURL := fmt.Sprintf("%s/services/search/jobs/export?search=%s&earliest=%d&latest=%d",
        c.queryURL, url.QueryEscape(spl2), fromTS, toTS)
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
    if err != nil {
        return nil, err
    }
    resp, err := c.http.Do(req)
    if err != nil {
        return nil, fmt.Errorf("ngx query: %w", err)
    }
    defer resp.Body.Close()

    var result QueryResult
    if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("ngx query decode: %w", err)
    }
    return &result, nil
}
```

```go
// internal/datalake/hec.go
package datalake

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
)

type HECEvent struct {
    Time       int64          `json:"time"`
    Index      string         `json:"index"`
    Sourcetype string         `json:"sourcetype"`
    Event      map[string]any `json:"event"`
}

// ingest 批量写入到 ngx HEC（私有方法，仅 archiver.go 调用）
// 单批最大 100 条；调用方（Archiver）负责分批
func (c *Client) ingest(ctx context.Context, events []HECEvent) error {
    var buf bytes.Buffer
    enc := json.NewEncoder(&buf)
    for _, e := range events {
        if err := enc.Encode(e); err != nil {
            return err
        }
    }
    req, err := http.NewRequestWithContext(ctx, http.MethodPost,
        c.hecURL+"/services/collector/event", &buf)
    if err != nil {
        return err
    }
    req.Header.Set("Authorization", "Splunk "+c.hecToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.http.Do(req)
    if err != nil {
        return fmt.Errorf("hec ingest: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("hec status %d", resp.StatusCode)
    }
    return nil
}
```

```go
// internal/datalake/interface.go
package datalake

import "context"

// QueryClient Service 层依赖此接口，本地开发由 DataLakeStub 实现（降级），
// 生产环境由 *Client 实现。
type QueryClient interface {
    Query(ctx context.Context, spl2 string, fromTS, toTS int64) (*QueryResult, error)
}

// DataLakeStub 本地开发用（DataLake 未启动时）
type DataLakeStub struct{}

func (s *DataLakeStub) Query(_ context.Context, _ string, _, _ int64) (*QueryResult, error) {
    return &QueryResult{
        Rows: []map[string]any{
            {"_time": "2026-05-22T09:41:02Z", "process_name": "rclone.exe", "host_ip": "10.0.5.22", "bytes_sent": 8924872704},
            {"_time": "2026-05-22T08:12:44Z", "process_name": "powershell.exe", "host_ip": "10.0.3.15", "bytes_sent": 412809216},
        },
        Total: 2, ElapsedMs: 800, ScannedGB: 2.3,
    }, nil
}
```

#### 13.1.4 config.go 新增 ngx 配置项

```go
// config/config.go（新增字段）
type DataLakeConfig struct {
    QueryURL string // ngx head 节点，默认 "http://localhost:8080"
    HECURL   string // ngx HEC，默认 "http://localhost:18088"（归档器使用）
    HECToken string
    Enabled  bool   // false → 使用 DataLakeStub，本地开发用
}
```

#### 13.1.5 router.go 依赖装配

```go
// internal/router/router.go（片段）
var lakeClient datalake.QueryClient
if cfg.DataLake.Enabled {
    lakeClient = datalake.New(cfg.DataLake.QueryURL, cfg.DataLake.HECURL, cfg.DataLake.HECToken)
} else {
    lakeClient = &datalake.DataLakeStub{}
}
// Archiver 单独持有 *Client 引用（需要 HEC 写入权限）
archiver := datalake.NewArchiver(alertRepo, incRepo,
    datalake.New(cfg.DataLake.QueryURL, cfg.DataLake.HECURL, cfg.DataLake.HECToken))
go archiver.Start(appCtx)

logSvc := service.NewLogEntryService(lakeClient)
```

#### 13.1.6 Fluent-bit 配置参考

```ini
# fluent-bit.conf（关键配置片段）

[INPUT]
    Name        syslog
    Listen      0.0.0.0
    Port        514
    Mode        tcp
    Tag         xsiam.syslog

[INPUT]
    Name        forward
    Listen      0.0.0.0
    Port        24224
    Tag         xsiam.filebeat

[FILTER]
    Name        record_modifier
    Match       xsiam.*
    Record      collector fluent-bit
    Record      env production

[OUTPUT]
    Name        http
    Match       xsiam.*
    Host        ngx-host
    Port        18088
    URI         /services/collector/event
    Header      Authorization Splunk ${HEC_TOKEN}
    Format      json
    # 本地持久化 buffer：ngx 不可达时落盘，恢复后自动重发
    storage.type        filesystem
    storage.path        /var/fluent-bit/buffer
    Retry_Limit         False
    # 批量发送，降低 ngx HEC 连接开销
    batch_size          1000
    flush               5
```

#### 13.1.7 ngx 启动参数（write_mode 调整）

```c
// ngx 启动时设置 async 写模式，匹配 Fluent-bit 高并发批量写入
ngx_storage_set_write_mode(
    "async",
    262144,   // queue_depth：4 倍默认值，应对峰值
    4         // flush_threads：4 个落盘线程
);
```

---

### 13.2 CAE：goroutine pool + channel 解耦（告警写入不等待关联计算）

#### 11.2.1 问题

原设计在 `AlertService.Create()` 内 `go CausalityService.TriggerCorrelation(ctx, alertID)` 是无限制 goroutine，高并发写入时可能产生数千个 goroutine 同时运行关联计算，消耗大量 CPU 和内存。

#### 11.2.2 改进：有界 worker pool

```go
// internal/service/correlation_pool.go
package service

import (
    "context"
    "go.uber.org/zap"
)

const (
    correlationQueueSize = 4096 // 最多缓冲 4096 个待关联 alert_id
    correlationWorkers   = 4    // 固定 4 个 worker goroutine
)

// CorrelationPool 有界 goroutine pool，与 CausalityService 生命周期绑定
type CorrelationPool struct {
    queue chan string           // alert_id channel
    svc   *CausalityService
    log   *zap.Logger
}

func NewCorrelationPool(svc *CausalityService) *CorrelationPool {
    p := &CorrelationPool{
        queue: make(chan string, correlationQueueSize),
        svc:   svc,
        log:   zap.L(),
    }
    for i := 0; i < correlationWorkers; i++ {
        go p.worker()
    }
    return p
}

func (p *CorrelationPool) worker() {
    for alertID := range p.queue {
        p.svc.TriggerCorrelation(context.Background(), alertID)
    }
}

// Submit 非阻塞提交，队满时直接丢弃（不影响告警写入主路径）
func (p *CorrelationPool) Submit(alertID string) {
    select {
    case p.queue <- alertID:
    default:
        p.log.Warn("correlation queue full, dropped", zap.String("alert_id", alertID))
    }
}

// Shutdown 优雅关闭（在 main.go 的 graceful shutdown 阶段调用）
func (p *CorrelationPool) Shutdown() {
    close(p.queue)
}
```

```go
// internal/service/alert.go（修改 Create 方法）
type AlertService struct {
    alertRepo       *repository.AlertRepo
    incRepo         *repository.IncidentRepo
    auditRepo       *repository.AuditLogRepo
    correlationPool *CorrelationPool
    // 注意：不持有 lakeClient。
    // 实时日志由 Fluent-bit 直写 ngx，告警冷归档由 Archiver 后台处理。
    // AlertService 只负责 ArangoDB 写入 + 关联计算触发。
}

func (s *AlertService) Create(ctx context.Context, req CreateAlertReq, operatorID string) (*model.Alert, error) {
    alert := buildAlert(req)
    if err := s.alertRepo.Create(ctx, alert); err != nil {
        return nil, fmt.Errorf("create alert: %w", err)
    }
    s.auditRepo.Record(ctx, operatorID, "create", "alert", alert.Key, alert.Name, nil, alert)

    // 提交关联计算（非阻塞，队满丢弃，不影响告警写入 P99）
    s.correlationPool.Submit(alert.AlertID)

    return alert, nil
}
```

#### 11.2.3 main.go 集成

```go
// main.go（片段）
correlationPool := service.NewCorrelationPool(cae)
alertSvc := service.NewAlertService(alertRepo, incRepo, auditRepo, correlationPool)

// graceful shutdown
<-ctx.Done()
correlationPool.Shutdown() // 等待队列消费完毕
shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
_ = srv.Shutdown(shutCtx)
```

**效果：** 告警写入 P99 从"关联计算时间 + ArangoDB 写入"降为"ArangoDB 写入"，关联计算完全异步，最大并发度固定为 4。

---

### 13.3 SmartScore：预计算 + 内存缓存

#### 11.3.1 问题

原设计每次 `GET /api/incidents/:id/smart-score` 都全量重算（查告警列表 + 查资产列表），P99 可达 200ms+。

#### 11.3.2 改进：score 预存 Incident 文档，GET 零计算

**策略：**
- `smart_score` 和 `score_factors` 字段常驻 `incidents` collection
- 触发重算的时机：新告警关联到事件、资产重要性变更、手动 `POST .../recalc`
- `GET /api/incidents/:id/smart-score` 直接读 Incident 文档，不调用 SmartScoreService
- 内存 LRU 缓存热点事件评分（1000 条，5 分钟 TTL）

```go
// internal/service/smart_score.go（修改）
package service

import (
    "context"
    "sync"
    "time"
    "xsiam/internal/model"
    "xsiam/internal/repository"
)

// scoreEntry 内存缓存条目
type scoreEntry struct {
    breakdown *ScoreBreakdown
    expiresAt time.Time
}

type SmartScoreService struct {
    incRepo   *repository.IncidentRepo
    assetRepo *repository.AssetRepo
    alertRepo *repository.AlertRepo

    mu    sync.RWMutex
    cache map[string]*scoreEntry // incident_id → 缓存
}

func NewSmartScoreService(
    incRepo   *repository.IncidentRepo,
    assetRepo *repository.AssetRepo,
    alertRepo *repository.AlertRepo,
) *SmartScoreService {
    s := &SmartScoreService{
        incRepo: incRepo, assetRepo: assetRepo, alertRepo: alertRepo,
        cache: make(map[string]*scoreEntry, 1024),
    }
    go s.evictLoop() // 定期清理过期缓存
    return s
}

// Get 直接读预存值（Handler 层调用此方法，不调用 Calculate）
func (s *SmartScoreService) Get(ctx context.Context, incidentID string) (*ScoreBreakdown, error) {
    // 1. 内存缓存
    s.mu.RLock()
    if e, ok := s.cache[incidentID]; ok && time.Now().Before(e.expiresAt) {
        s.mu.RUnlock()
        return e.breakdown, nil
    }
    s.mu.RUnlock()

    // 2. 读 Incident 文档预存字段（零额外查询）
    inc, err := s.incRepo.GetByID(ctx, incidentID)
    if err != nil {
        return nil, err
    }
    breakdown := &ScoreBreakdown{
        Total:   inc.SmartScore,
        Factors: inc.ScoreFactors,
    }
    s.setCache(incidentID, breakdown)
    return breakdown, nil
}

// Calculate 强制重算（仅 recalc 接口和事件驱动触发）
func (s *SmartScoreService) Calculate(ctx context.Context, incidentID string) (*ScoreBreakdown, error) {
    // ... 原计算逻辑不变 ...
    // 计算完成后写回 Incident 文档并更新内存缓存
    _ = s.incRepo.Update(ctx, incidentID, bsonD(
        "smart_score", breakdown.Total,
        "score_factors", breakdown.Factors,
    ))
    s.setCache(incidentID, breakdown)
    return breakdown, nil
}

// InvalidateCache 告警关联到事件时调用，使缓存失效并触发后台重算
func (s *SmartScoreService) InvalidateAndRecalc(incidentID string) {
    s.mu.Lock()
    delete(s.cache, incidentID)
    s.mu.Unlock()
    go func() {
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()
        _, _ = s.Calculate(ctx, incidentID)
    }()
}

func (s *SmartScoreService) setCache(id string, b *ScoreBreakdown) {
    s.mu.Lock()
    defer s.mu.Unlock()
    if len(s.cache) > 1000 { // 简单容量限制，超出随机淘汰
        for k := range s.cache { delete(s.cache, k); break }
    }
    s.cache[id] = &scoreEntry{breakdown: b, expiresAt: time.Now().Add(5 * time.Minute)}
}

func (s *SmartScoreService) evictLoop() {
    t := time.NewTicker(2 * time.Minute)
    defer t.Stop()
    for range t.C {
        now := time.Now()
        s.mu.Lock()
        for k, e := range s.cache {
            if now.After(e.expiresAt) { delete(s.cache, k) }
        }
        s.mu.Unlock()
    }
}
```

```go
// internal/handler/smart_score.go（修改）
func (h *SmartScoreHandler) Get(c *gin.Context) {
    breakdown, err := h.svc.Get(c.Request.Context(), c.Param("incident_id"))
    if err != nil { response.NotFound(c, "incident"); return }
    response.OK(c, breakdown)  // 直接返回预存值，< 5ms
}
```

**效果：** GET 接口 P99 从 200ms → < 5ms；重算只在事件驱动时后台异步执行。

---

### 13.4 ITDR：内存聚合 + 批量 flush

#### 11.4.1 问题

原设计 `AddSignal()` 每次调用都触发 ArangoDB 读-改-写（GetByUserID + UpdateDocument），身份日志高频场景（AD 每秒数百条认证事件）下 ArangoDB IOPS 直接打满。

#### 11.4.2 改进：sync.Map 内存状态 + 30s 批量 flush

```go
// internal/service/identity_risk.go（重写核心部分）
package service

import (
    "context"
    "math"
    "sync"
    "time"
    "xsiam/internal/model"
    "xsiam/internal/repository"
    "xsiam/internal/stub"
)

// memRiskState 内存中的实时风险状态（不持久化中间状态）
type memRiskState struct {
    mu          sync.Mutex
    userID      string
    username    string
    domain      string
    signals     []model.RiskSignal
    score       float64
    dirty       bool      // 是否有未 flush 的变更
    lastFlushAt time.Time
}

type IdentityRiskService struct {
    riskRepo        *repository.IdentityRiskRepo
    restrictionRepo *repository.PrivilegeRestrictionRepo
    execStub        *stub.ExecutionStub

    states sync.Map // user_id(string) → *memRiskState
}

func NewIdentityRiskService(
    riskRepo        *repository.IdentityRiskRepo,
    restrictionRepo *repository.PrivilegeRestrictionRepo,
    execStub        *stub.ExecutionStub,
) *IdentityRiskService {
    s := &IdentityRiskService{
        riskRepo: riskRepo, restrictionRepo: restrictionRepo, execStub: execStub,
    }
    go s.flushLoop() // 30s 批量 flush goroutine
    return s
}

// AddSignal 纯内存操作，微秒级返回
func (s *IdentityRiskService) AddSignal(ctx context.Context, userID, username, domain string, signal model.RiskSignal) error {
    v, _ := s.states.LoadOrStore(userID, &memRiskState{
        userID: userID, username: username, domain: domain,
    })
    state := v.(*memRiskState)

    state.mu.Lock()
    state.signals = append(state.signals, signal)
    state.score = s.recalcScore(state.signals)
    state.dirty = true
    score := state.score
    state.mu.Unlock()

    // 阈值检查（内存判断，不查 ArangoDB）
    s.checkAndApplyRestrictions(ctx, state, score)
    return nil
}

// flushLoop 每 30s 将 dirty 状态批量写入 ArangoDB
func (s *IdentityRiskService) flushLoop() {
    t := time.NewTicker(30 * time.Second)
    defer t.Stop()
    for range t.C {
        s.flushAll()
    }
}

func (s *IdentityRiskService) flushAll() {
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    s.states.Range(func(key, val any) bool {
        state := val.(*memRiskState)
        state.mu.Lock()
        if !state.dirty {
            state.mu.Unlock()
            return true
        }
        risk := &model.IdentityRisk{
            UserID:      state.userID,
            Username:    state.username,
            Domain:      state.domain,
            RiskScore:   state.score,
            RiskSignals: state.signals,
            UpdatedAt:   time.Now(),
        }
        state.dirty = false
        state.lastFlushAt = time.Now()
        // 只保留最近 50 条信号，防止内存无限增长
        if len(state.signals) > 50 {
            state.signals = state.signals[len(state.signals)-50:]
        }
        state.mu.Unlock()

        _ = s.riskRepo.Upsert(ctx, risk) // 批量写，不阻塞 AddSignal
        return true
    })
}

// Restore 启动时从 ArangoDB 恢复内存状态（防止重启丢失）
func (s *IdentityRiskService) Restore(ctx context.Context) error {
    risks, err := s.riskRepo.ListAll(ctx)
    if err != nil { return err }
    for _, r := range risks {
        s.states.Store(r.UserID, &memRiskState{
            userID: r.UserID, username: r.Username, domain: r.Domain,
            signals: r.RiskSignals, score: r.RiskScore,
        })
    }
    return nil
}

func (s *IdentityRiskService) checkAndApplyRestrictions(ctx context.Context, state *memRiskState, score float64) {
    for level := 5; level >= 1; level-- {
        if score >= model.RestrictionThresholds[level] {
            // L4/L5 立即执行（不等 flush）
            if level >= 4 {
                _, _ = s.execStub.Execute(ctx, itdrAction(level), state.userID, nil)
            }
            // 限制记录直接写（低频事件，单次写可接受）
            restriction := buildRestriction(state.userID, level, score)
            _ = s.restrictionRepo.Create(ctx, restriction)
            return
        }
    }
}

func (s *IdentityRiskService) recalcScore(signals []model.RiskSignal) float64 {
    base, multiplier := 0.0, 1.0
    for _, sig := range signals {
        switch sig.Type {
        case model.SignalActiveAlert:    multiplier = math.Max(multiplier, 1.2)
        case model.SignalActiveIncident: multiplier = math.Max(multiplier, 1.5)
        default:                         base += sig.Score
        }
    }
    return math.Min(base*multiplier, 100)
}
```

**效果：** ArangoDB IOPS 降低 ~97%（每 30s 一次批量写 vs 每条信号一次读写）；AddSignal 响应时间从 5-20ms → < 0.1ms（纯内存）；L4/L5 高危操作仍即时执行。

---

### 13.5 规则引擎：激活时同步到 ngx saved_search

#### 11.5.1 设计

规则匹配计算交给 ngx（C 实现，SPL2 调度），XSIAM 负责规则配置同步。当规则状态变为 `active` 时，自动把规则转换为 SPL2 表达式并写入 ngx saved_search；规则 `disabled/deprecated` 时删除对应 saved_search。

```
XSIAM 规则状态机                     ngx 数据湖
  draft                             （无）
  testing   →  历史回放测试         SPL2 查询（一次性，不创建 saved_search）
  active    →  CreateSavedSearch →  ngx 定时调度（默认每 5 分钟）
               ↓ 命中时
  ngx POST /api/internal/alerts  → XSIAM 创建告警
  disabled  →  DeleteSavedSearch → ngx 停止调度
```

#### 11.5.2 ngx SavedSearch 客户端

```go
// internal/datalake/saved_search.go
package datalake

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
)

type SavedSearch struct {
    Name       string `json:"name"`        // 用 rule_id 作为唯一 name
    Search     string `json:"search"`      // SPL2 表达式
    CronExpr   string `json:"cron_expr"`   // "*/5 * * * *"（每 5 分钟）
    AlertURL   string `json:"alert_url"`   // "http://xsiam:8080/api/internal/alerts"
    AlertToken string `json:"alert_token"` // XSIAM 内部鉴权 token
}

// CreateSavedSearch 在 ngx 中注册定时搜索
func (c *Client) CreateSavedSearch(ctx context.Context, ss SavedSearch) error {
    body, _ := json.Marshal(ss)
    req, err := http.NewRequestWithContext(ctx, http.MethodPost,
        c.queryURL+"/services/saved/searches", bytes.NewReader(body))
    if err != nil { return err }
    req.Header.Set("Content-Type", "application/json")
    resp, err := c.http.Do(req)
    if err != nil { return fmt.Errorf("create saved search: %w", err) }
    defer resp.Body.Close()
    if resp.StatusCode >= 300 {
        return fmt.Errorf("ngx saved search %d", resp.StatusCode)
    }
    return nil
}

// DeleteSavedSearch 删除 ngx 定时搜索
func (c *Client) DeleteSavedSearch(ctx context.Context, name string) error {
    req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
        c.queryURL+"/services/saved/searches/"+name, nil)
    if err != nil { return err }
    resp, err := c.http.Do(req)
    if err != nil { return fmt.Errorf("delete saved search: %w", err) }
    defer resp.Body.Close()
    return nil
}
```

#### 11.5.3 规则 → SPL2 转换

```go
// internal/service/detection_rule.go（新增方法）

// RuleToSPL2 将 DetectionRule.Definition 转换为 ngx SPL2 表达式
func RuleToSPL2(rule *model.DetectionRule) string {
    switch rule.RuleType {
    case model.RuleTypeBIOC:
        // BIOC 行为序列：FROM index WHERE event_type='x' AND conditions
        parts := []string{fmt.Sprintf("FROM xdr_events")}
        if len(rule.Definition.Sequence) > 0 {
            evt := rule.Definition.Sequence[0]
            parts = append(parts, fmt.Sprintf("WHERE event_type='%s'", evt.EventType))
            for k, v := range evt.Conditions {
                parts = append(parts, fmt.Sprintf("AND %s='%s'", k, v))
            }
        }
        if rule.Definition.TimeWindow != "" {
            parts = append(parts, fmt.Sprintf("TIMEWINDOW %s", rule.Definition.TimeWindow))
        }
        return joinSPL2(parts)

    case model.RuleTypeIOC:
        // IOC 匹配：FROM index WHERE ioc_value IN (...)
        vals := quoteList(rule.Definition.IocValues)
        return fmt.Sprintf("FROM xdr_events WHERE %s IN (%s)",
            rule.Definition.IocType, vals)

    case model.RuleTypeUEBA:
        // UEBA 统计：FROM index | STATS avg(metric) | WHERE avg > threshold
        return fmt.Sprintf("FROM xdr_events | STATS avg(%s) AS metric WHERE metric > %g",
            rule.Definition.Metric, rule.Definition.Threshold)

    default:
        return ""
    }
}

// TransitionStatus（修改：active 时同步 ngx，disabled 时删除）
func (s *DetectionRuleService) TransitionStatus(ctx context.Context, id string, toStatus model.RuleStatus, operatorID string) error {
    rule, err := s.ruleRepo.GetByID(ctx, id)
    if err != nil { return err }

    allowed := model.RuleStatusTransitions[rule.Status]
    ok := false
    for _, a := range allowed { if a == toStatus { ok = true; break } }
    if !ok {
        return fmt.Errorf("不允许从 %s 流转至 %s", rule.Status, toStatus)
    }

    if err := s.ruleRepo.Update(ctx, id, map[string]any{model.FieldRuleStatus: toStatus}); err != nil {
        return err
    }

    // 同步 ngx saved_search
    switch toStatus {
    case model.RuleStatusActive:
        spl2 := RuleToSPL2(rule)
        if spl2 != "" && s.lakeClient != nil {
            _ = s.lakeClient.CreateSavedSearch(ctx, datalake.SavedSearch{
                Name:     "xdr_rule_" + rule.RuleID,
                Search:   spl2,
                CronExpr: "*/5 * * * *",
                AlertURL: s.xdrInternalAlertURL,
            })
        }
    case model.RuleStatusDisabled, model.RuleStatusDeprecated:
        if s.lakeClient != nil {
            _ = s.lakeClient.DeleteSavedSearch(ctx, "xdr_rule_"+rule.RuleID)
        }
    }
    return nil
}
```

#### 11.5.4 XSIAM 内部告警接收接口

ngx 规则命中时回调 XSIAM，由专用内部接口接收（不走 JWT 鉴权，走固定 token）：

```go
// internal/handler/internal.go
package handler

import (
    "xsiam/internal/service"
    "xsiam/pkg/response"
    "github.com/gin-gonic/gin"
)

type InternalHandler struct {
    alertSvc  *service.AlertService
    ingestToken string
}

func NewInternalHandler(alertSvc *service.AlertService, token string) *InternalHandler {
    return &InternalHandler{alertSvc: alertSvc, ingestToken: token}
}

// CreateFromRule ngx 规则命中回调（POST /api/internal/alerts）
func (h *InternalHandler) CreateFromRule(c *gin.Context) {
    // 内部 token 鉴权（非 JWT）
    if c.GetHeader("X-Internal-Token") != h.ingestToken {
        response.Forbidden(c); return
    }
    var body service.CreateAlertReq
    if err := c.ShouldBindJSON(&body); err != nil {
        response.BadRequest(c, err.Error()); return
    }
    body.TriggerSource = "rule_engine" // 标记来源为规则引擎
    alert, err := h.alertSvc.Create(c.Request.Context(), body, "rule_engine")
    if err != nil { response.InternalError(c, err); return }
    response.Created(c, alert)
}
```

路由注册（在 API 鉴权组之外单独注册）：

```go
// internal/router/router.go（片段）
internal := r.Group("/api/internal")
internal.POST("/alerts", internalH.CreateFromRule)
```

**效果：** 检测规则真正在 ngx C 引擎执行，XSIAM Go 层零计算开销；新规则激活到开始执行 < 1 分钟（下次 ngx cron 触发）。

---

### 13.6 ArangoDB 热数据 + ngx 冷数据归档

#### 11.6.1 分层策略

```
热数据（ArangoDB）            冷数据（ngx 数据湖）
────────────────────         ──────────────────────
告警：最近 30 天              告警：30 天前历史（SPL2 可查）
事件：最近 90 天              事件：90 天前历史
日志条目：不存 ArangoDB        全量存 ngx（XSIAM 侧只做查询代理）

ArangoDB TTL 索引自动清理热数据过期文档
归档器（Archiver）在 TTL 删除前把数据写入 ngx
```

#### 11.6.2 归档器实现

```go
// internal/datalake/archiver.go
package datalake

import (
    "context"
    "time"
    "xsiam/internal/model"
    "xsiam/internal/repository"

    "go.uber.org/zap"
)

type Archiver struct {
    alertRepo *repository.AlertRepo
    incRepo   *repository.IncidentRepo
    lake      *Client
    log       *zap.Logger
}

func NewArchiver(alertRepo *repository.AlertRepo, incRepo *repository.IncidentRepo, lake *Client) *Archiver {
    return &Archiver{alertRepo: alertRepo, incRepo: incRepo, lake: lake, log: zap.L()}
}

// Start 启动后台归档任务（每小时运行一次）
func (a *Archiver) Start(ctx context.Context) {
    t := time.NewTicker(1 * time.Hour)
    defer t.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-t.C:
            a.archiveAlerts(ctx)
        }
    }
}

const alertArchiveDays = 30

// archiveAlerts 把即将过期的告警（28-30天）写入 ngx 后再让 TTL 删除
func (a *Archiver) archiveAlerts(ctx context.Context) {
    cutoff := time.Now().AddDate(0, 0, -alertArchiveDays+2) // 提前 2 天归档
    oldest := time.Now().AddDate(0, 0, -alertArchiveDays)

    alerts, err := a.alertRepo.FindByTimeRange(ctx, oldest, cutoff)
    if err != nil {
        a.log.Error("archive query failed", zap.Error(err))
        return
    }
    if len(alerts) == 0 { return }

    batch := make([]HECEvent, 0, len(alerts))
    for _, al := range alerts {
        batch = append(batch, HECEvent{
            Time: al.TriggeredAt.Unix(), Index: "xdr_alerts_archive",
            Sourcetype: "xsiam:alert:archived", Event: alertToMap(&al),
        })
        if len(batch) >= 100 { // HEC 每批最多 100 条
            _ = a.lake.Ingest(ctx, batch)
            batch = batch[:0]
        }
    }
    if len(batch) > 0 { _ = a.lake.Ingest(ctx, batch) }
    a.log.Info("archived alerts to ngx", zap.Int("count", len(alerts)))
}
```

#### 11.6.3 ArangoDB TTL 索引配置（与归档配合）

```go
// internal/repository/alert.go（TTL 索引，在 NewAlertRepo 中创建）
// 原有业务持久化索引 ...

// TTL 索引：triggered_at 超过 32 天自动删除（归档器提前 2 天写入 ngx）
col.EnsureTTLIndex(ctx, model.FieldTriggeredAt, 32*24*3600,
    &arangodb.EnsureTTLIndexOptions{})
```

#### 11.6.4 日志查询代理（`/api/logs/query` 直接转发 ngx）

`log_entries` collection 从 ArangoDB 中完全移除，`/api/logs/query` 直接代理到 ngx SPL2 查询：

```go
// internal/service/log_entry.go（简化）
func (s *LogEntryService) Query(ctx context.Context, spl2 string, fromTS, toTS int64) (*datalake.QueryResult, error) {
    return s.lakeClient.Query(ctx, spl2, fromTS, toTS)
}
```

ArangoDB `log_entries` collection 删除，`/api/logs`（列表写入接口）改为直接调用 `lakeClient.Ingest()`。

#### 11.6.5 调整后的 ArangoDB Collection 职责

| Collection | 保留/变更 | 说明 |
|------------|-----------|------|
| `alerts` | 保留，TTL 32天 | 热数据，超期自动删除 |
| `incidents` | 保留，TTL 90天 | 热数据 |
| `assets` | 保留，无 TTL | 资产注册表，长期保留 |
| `vulnerabilities` | 保留，无 TTL | 漏洞记录，手动清理 |
| `iocs` | 保留，TTL 字段驱动 | 按 `expires_at` TTL |
| `log_entries` | **删除** | 全量存 ngx，XQL 查询代理 |
| `detection_rules` | 保留 | 规则配置，长期保留 |
| `causality_nodes` | 保留，TTL 90天 | Named Graph 节点，随事件生命周期 |
| `causality_edges` | 保留，TTL 90天 | Named Graph 边集合 |
| `identity_risks` | 保留 | 内存聚合后 flush |
| `privilege_restrictions` | 保留，TTL 字段驱动 | L1/L2/L3 按 `expires_at` TTL |
| 其余配置类 Collection | 保留，无 TTL | 规则/租户/角色/剧本/报表/用户 |

**综合效果：** ArangoDB 常驻内存从"全量历史数据"降为"30-90 天热数据"，缓存命中率显著提升；日志查询完全走 ngx C 引擎，Go 层零解析开销。

---

## 14. 告警同步链路设计（ngx → ArangoDB）

### 14.1 链路总览

```
Agent/设备
  └─[syslog/OTLP]─→ Fluent-bit
                       └─[HTTP batch]─→ ngx HEC :18088
                                          └─[MPSC ring]─→ zstd journal

ngx 内置 cron（每5分钟）
  └─ 遍历 saved_search（由 ngx_console 激活规则时注册）
       └─ ngx_head_saved_search_store_dispatch()
            └─ SPL2 查询 → 统计 result_count
                 └─ ngx_head_saved_search_store_fire_alert(schedule_id, result_count)
                      └─ 阈值判断（comparator + threshold）
                           └─ 命中 → fire_webhook()
                                       └─ HTTP POST → ngx_console :8080/api/internal/alerts
                                                          └─ InternalHandler
                                                               ├─ 反查规则定义（DetectionRuleRepo）
                                                               ├─ 调 datalake.Query 取事件详情
                                                               ├─ 构建 model.Alert → ArangoDB 写入
                                                               └─ correlationPool.Submit（异步 CAE）
```

### 14.2 ngx webhook payload（源码确认）

ngx `fire_webhook()` 发出的 HTTP POST body（源自 `ngx_head_saved_search_store.c:780`）：

```json
{
  "schedule_id": "xdr_rule_abc123",
  "result_count": 47,
  "alert_type": "number",
  "comparator": "greater than",
  "threshold": "0"
}
```

**注意**：payload 极精简，**只有规则ID和命中数量，没有告警详情**。  
InternalHandler 收到后需用 `schedule_id` 反查规则，再调 ngx SPL2 拉取原始命中事件。

HTTP 请求特征（无鉴权 header，依赖网络层隔离）：
```
POST /api/internal/alerts HTTP/1.0
Host: ngx_console:8080
Content-Type: application/json
Connection: close
```

> ngx 当前 C 实现无 Authorization header 发送能力，**Token 鉴权改为 IP 白名单**（见 14.5）。

### 14.3 规则注册（ngx_console → ngx）

检测规则在 ngx_console 中激活时，`DetectionRuleService.TransitionStatus()` 调用 `datalake.Client.CreateSavedSearch()`，通过 ngx HTTP API 注册 saved_search：

```go
// internal/datalake/saved_search.go

type SavedSearch struct {
    Name           string // "xdr_rule_{rule_id}"
    Search         string // SPL2 表达式，由 RuleToSPL2() 生成
    CronExpr       string // "*/5 * * * *"
    AlertType      string // "number"
    AlertComparator string // "greater than"
    AlertThreshold  string // "0"
    WebhookURL     string // "http://ngx_console:8080/api/internal/alerts"
    ActionWebhook  int    // 1
}

func (c *Client) CreateSavedSearch(ctx context.Context, ss SavedSearch) error {
    // 调用 ngx HTTP API POST /services/saved_searches
    // ngx 内部调用 ngx_head_saved_search_store_register()
    body, _ := json.Marshal(map[string]any{
        "name":              ss.Name,
        "search":            ss.Search,
        "cron_schedule":     ss.CronExpr,
        "alert.type":        ss.AlertType,
        "alert.comparator":  ss.AlertComparator,
        "alert.threshold":   ss.AlertThreshold,
        "action.webhook":    ss.ActionWebhook,
        "webhook_url":       ss.WebhookURL,
        "enable_sched":      1,
    })
    req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
        c.queryURL+"/services/saved_searches", bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Splunk "+c.hecToken)
    resp, err := c.http.Do(req)
    if err != nil { return err }
    defer resp.Body.Close()
    if resp.StatusCode >= 400 { return fmt.Errorf("ngx saved_search register: %d", resp.StatusCode) }
    return nil
}

func (c *Client) DeleteSavedSearch(ctx context.Context, name string) error {
    req, _ := http.NewRequestWithContext(ctx, http.MethodDelete,
        c.queryURL+"/services/saved_searches/"+url.PathEscape(name), nil)
    req.Header.Set("Authorization", "Splunk "+c.hecToken)
    resp, err := c.http.Do(req)
    if err != nil { return err }
    defer resp.Body.Close()
    return nil
}
```

**RuleToSPL2()** — 规则定义转 SPL2 查询语句：

```go
// internal/service/detection_rule.go

func RuleToSPL2(rule *model.DetectionRule) string {
    switch rule.RuleType {
    case model.RuleTypeBIOC:
        // 行为序列规则：搜索特定事件链
        // 示例：process_create → network_connect within 60s
        return fmt.Sprintf(
            `index=xdr_endpoint source=%s | search %s | stats count by host_name`,
            rule.Definition.Source,
            rule.Definition.Condition,
        )
    case model.RuleTypeIOC:
        // IOC 匹配规则：搜索恶意 IP/域名/Hash
        return fmt.Sprintf(
            `index=* | search message="%s" | dedup src_ip | stats count by src_ip`,
            rule.Definition.IOCPattern,
        )
    case model.RuleTypeUEBA:
        // 统计异常规则：用户行为基线偏差
        return fmt.Sprintf(
            `index=xdr_identity | search user_id=* | stats count by user_id | where count > %d`,
            rule.Definition.Threshold,
        )
    default:
        return `index=* | search level=ERROR | stats count`
    }
}
```

**规则状态变更触发注册/注销：**

```go
// internal/service/detection_rule.go

func (s *DetectionRuleService) TransitionStatus(ctx context.Context,
    id, toStatus, operatorID string) error {

    rule, err := s.ruleRepo.FindByID(ctx, id)
    if err != nil { return err }

    savedSearchName := "xdr_rule_" + rule.RuleID

    switch toStatus {
    case "active":
        // 激活 → 注册到 ngx
        err = s.lakeClient.CreateSavedSearch(ctx, datalake.SavedSearch{
            Name:            savedSearchName,
            Search:          RuleToSPL2(rule),
            CronExpr:        "*/5 * * * *",
            AlertType:       "number",
            AlertComparator: "greater than",
            AlertThreshold:  "0",
            WebhookURL:      s.internalAlertURL, // "http://ngx_console:8080/api/internal/alerts"
            ActionWebhook:   1,
        })
    case "disabled", "deprecated":
        // 停用 → 从 ngx 注销
        err = s.lakeClient.DeleteSavedSearch(ctx, savedSearchName)
    }

    if err != nil { return err }

    return s.ruleRepo.UpdateStatus(ctx, id, toStatus, operatorID)
}
```

### 14.4 InternalHandler — 接收 webhook 并写 ArangoDB

```go
// internal/handler/internal.go
package handler

import (
    "net/http"
    "time"

    "github.com/gin-gonic/gin"
    "go.uber.org/zap"
    "xsiam/internal/datalake"
    "xsiam/internal/model"
    "xsiam/internal/repository"
    "xsiam/internal/service"
    "xsiam/pkg/utils"
)

// ngxWebhookPayload 对应 ngx fire_webhook() 发出的 JSON（源码确认字段）
type ngxWebhookPayload struct {
    ScheduleID  string `json:"schedule_id"`   // "xdr_rule_{rule_id}"
    ResultCount uint64 `json:"result_count"`
    AlertType   string `json:"alert_type"`    // "number"
    Comparator  string `json:"comparator"`    // "greater than"
    Threshold   string `json:"threshold"`     // "0"
}

type InternalHandler struct {
    ruleRepo    *repository.DetectionRuleRepo
    alertRepo   *repository.AlertRepo
    lakeClient  datalake.QueryClient
    corrPool    *service.CorrelationPool
    allowedCIDR string // ngx 所在网段，如 "127.0.0.1" 或 "10.0.0.0/8"
    log         *zap.Logger
}

func (h *InternalHandler) CreateFromRule(c *gin.Context) {
    // ① IP 白名单鉴权（ngx 无法发 Authorization header）
    if !h.isAllowed(c.ClientIP()) {
        c.Status(http.StatusForbidden)
        return
    }

    var payload ngxWebhookPayload
    if err := c.ShouldBindJSON(&payload); err != nil {
        c.Status(http.StatusBadRequest)
        return
    }

    ctx := c.Request.Context()

    // ② 从 schedule_id 提取 rule_id（去掉 "xdr_rule_" 前缀）
    ruleID := strings.TrimPrefix(payload.ScheduleID, "xdr_rule_")

    // ③ 反查检测规则获取元数据（名称/严重度/MITRE等）
    rule, err := h.ruleRepo.FindByRuleID(ctx, ruleID)
    if err != nil {
        h.log.Warn("rule not found for webhook", zap.String("schedule_id", payload.ScheduleID))
        c.Status(http.StatusNotFound)
        return
    }

    // ④ 调 ngx SPL2 查询取最近命中事件的详情（最多取 limit=10 条）
    now := time.Now()
    spl2 := RuleToSPL2(rule) + " | head 10"
    qr, err := h.lakeClient.Query(ctx, spl2, now.Add(-5*time.Minute).Unix(), now.Unix())
    firstEvent := extractFirstEvent(qr) // 取第一条事件的 src_ip / host_name 等字段

    // ⑤ 构建 model.Alert 写入 ArangoDB
    alert := &model.Alert{
        AlertID:       utils.NewAlertID(),
        TenantID:      rule.TenantID,
        RuleID:        rule.RuleID,
        RuleName:      rule.Name,
        Severity:      rule.Severity,
        Status:        model.AlertStatusActive,
        TriggerSource: "rule_engine",
        ResultCount:   payload.ResultCount,
        MITRETactic:   rule.MITRETactic,
        MITRETechnique: rule.MITRETechnique,
        SrcIP:         firstEvent["src_ip"],
        HostName:      firstEvent["host_name"],
        TriggeredAt:   now,
        CreatedAt:     now,
        UpdatedAt:     now,
    }

    if err := h.alertRepo.Create(ctx, alert); err != nil {
        h.log.Error("alert create failed", zap.Error(err))
        c.Status(http.StatusInternalServerError)
        return
    }

    // ⑥ 提交 CAE 异步关联分析（非阻塞，queue 满则丢弃）
    h.corrPool.Submit(alert.AlertID)

    h.log.Info("alert created from rule engine",
        zap.String("alert_id", alert.AlertID),
        zap.String("rule_id", ruleID),
        zap.Uint64("result_count", payload.ResultCount))

    c.Status(http.StatusNoContent) // ngx 不读响应 body，204 即可
}

func (h *InternalHandler) isAllowed(clientIP string) bool {
    // 生产：解析 CIDR 段；简化版直接字符串前缀匹配
    return strings.HasPrefix(clientIP, h.allowedCIDR)
}

func extractFirstEvent(qr *datalake.QueryResult) map[string]string {
    result := map[string]string{}
    if qr == nil || len(qr.Events) == 0 {
        return result
    }
    for k, v := range qr.Events[0] {
        if s, ok := v.(string); ok {
            result[k] = s
        }
    }
    return result
}
```

### 14.5 鉴权：IP 白名单（替代 Token）

ngx `fire_webhook()` 的 C 实现发送 HTTP/1.0 请求，**无法附加 Authorization header**（源码确认）。鉴权方案改为 IP 白名单：

```go
// internal/router/router.go

// /api/internal/alerts 在 AuthMiddleware 组之外单独注册
internalH := handler.NewInternalHandler(ruleRepo, alertRepo, lakeClient, corrPool,
    cfg.Internal.AllowedCIDR,  // 如 "127.0.0.1" 或容器网段 "172.17.0."
    log)
r.POST("/api/internal/alerts", internalH.CreateFromRule)

// AuthMiddleware 只保护 /api/* 业务接口
api := r.Group("/api", middleware.Auth(cfg.Auth.JWTSecret))
// ...
```

```yaml
# config.yaml
internal:
  allowed_cidr: "127.0.0.1"   # 开发环境（ngx 和 console 同机）
  # allowed_cidr: "172.17.0." # Docker 网络
  # allowed_cidr: "10.0.0."   # 内网部署
```

### 14.6 完整参数传递表

| 阶段 | 调用方 | 被调用方 | 关键参数 |
|------|--------|----------|---------|
| 规则激活 | `DetectionRuleService` | `datalake.Client.CreateSavedSearch()` | `name=xdr_rule_{id}`, `webhook_url=http://ngx_console:8080/api/internal/alerts`, `action_webhook=1` |
| ngx 注册 | `datalake.Client` | ngx HTTP API `/services/saved_searches` | SPL2, cron, webhook_url, threshold |
| 定时触发 | ngx 内置 cron 线程 | `ngx_head_saved_search_store_dispatch()` | schedule_id, now_ts |
| 阈值判断 | ngx | `ngx_head_saved_search_store_fire_alert()` | schedule_id, result_count |
| webhook 回调 | ngx `fire_webhook()` | `POST /api/internal/alerts` | `{schedule_id, result_count, alert_type, comparator, threshold}` |
| 规则反查 | `InternalHandler` | `DetectionRuleRepo.FindByRuleID()` | ruleID（从 schedule_id 去前缀） |
| 事件详情拉取 | `InternalHandler` | `datalake.Client.Query()` | SPL2 + 时间窗口（last 5min） |
| 告警写入 | `InternalHandler` | `AlertRepo.Create()` | `model.Alert`（含 rule 元数据 + 事件字段） |
| 关联分析 | `InternalHandler` | `CorrelationPool.Submit()` | alert_id（非阻塞） |
| 规则停用 | `DetectionRuleService` | `datalake.Client.DeleteSavedSearch()` | name=xdr_rule_{id} |

### 14.7 config.yaml 新增配置项

```yaml
datalake:
  query_url:  "http://ngx:8080"       # ngx Head 节点查询接口
  hec_url:    "http://ngx:18088"      # ngx HEC 接收端（冷归档写入）
  hec_token:  "your-hec-token"

internal:
  allowed_cidr:       "172.17.0."     # ngx 所在容器网段（IP 白名单）
  alert_callback_url: "http://ngx_console:8080/api/internal/alerts"
  # DetectionRuleService 注册规则时填入 webhook_url
```

---

## 15. 进程内缓存设计（Ristretto）

### 15.1 选型依据

| 维度 | Ristretto（选用） | Redis | BigCache |
|------|-------------------|-------|----------|
| 运维成本 | 零（纯 Go 库） | 需独立进程 | 零 |
| 跨实例共享 | 否（单进程） | 是 | 否 |
| 内存上限控制 | MaxCost（自动 LRU） | maxmemory | 固定分片 |
| TTL 支持 | 原生 | 原生 | 需自实现 |
| 并发安全 | 是（内置分片锁） | 是 | 是 |
| API 友好度 | 高 | 高 | 中 |

**结论**：ngx_console 单实例部署，无需跨进程共享，Ristretto 零运维、零网络开销，最契合"极致轻量"原则。

### 15.2 缓存层实现

```go
// internal/cache/store.go
package cache

import (
    "encoding/json"
    "time"

    "github.com/dgraph-io/ristretto"
)

type Store struct{ r *ristretto.Cache }

func New() *Store {
    c, _ := ristretto.NewCache(&ristretto.Config{
        NumCounters: 1e7,       // 追踪 10M 个 key 的访问频率（TinyLFU）
        MaxCost:     128 << 20, // 最大 128MB 内存，超出自动 LRU 淘汰
        BufferItems: 64,        // 写入缓冲分片数
    })
    return &Store{r: c}
}

// Set 泛型写缓存（JSON 序列化，cost = 序列化字节数）
func Set[T any](s *Store, key string, val T, ttl time.Duration) {
    b, _ := json.Marshal(val)
    s.r.SetWithTTL(key, b, int64(len(b)), ttl)
}

// Get 泛型读缓存（未命中返回 false）
func Get[T any](s *Store, key string) (T, bool) {
    var zero T
    v, ok := s.r.Get(key)
    if !ok {
        return zero, false
    }
    var result T
    if json.Unmarshal(v.([]byte), &result) != nil {
        return zero, false
    }
    return result, true
}

// Del 主动失效（写操作后调用）
func (s *Store) Del(key string) { s.r.Del(key) }

// DelPrefix 按前缀批量失效（依赖版本戳实现，见 14.4）
func (s *Store) DelPrefix(prefix string) { s.r.Del(prefix + ":ver") }
```

### 15.3 Repository 层集成（透明缓存）

Service 层无感知，缓存逻辑全封装在 Repository：

```go
// internal/repository/alert.go
type AlertRepo struct {
    db    arangodb.Database
    cache *cache.Store
}

func NewAlertRepo(db arangodb.Database, c *cache.Store) *AlertRepo {
    return &AlertRepo{db: db, cache: c}
}

// 单条查询：命中缓存直返，未命中查 ArangoDB 后写缓存
func (r *AlertRepo) FindByID(ctx context.Context, key string) (*model.Alert, error) {
    cacheKey := "alert:" + key
    if hit, ok := cache.Get[model.Alert](r.cache, cacheKey); ok {
        return &hit, nil
    }
    col, _ := r.db.Collection(ctx, "alerts")
    var alert model.Alert
    if _, err := col.ReadDocument(ctx, key, &alert); err != nil {
        return nil, err
    }
    cache.Set(r.cache, cacheKey, alert, 2*time.Minute)
    return &alert, nil
}

// 分页列表：版本戳做 key，写操作时递增版本使旧缓存自然失效
func (r *AlertRepo) FindPaged(ctx context.Context, opts ListOptions) (*PagedResult[model.Alert], error) {
    ver := r.listVersion()
    cacheKey := fmt.Sprintf("alerts:list:v%d:%s", ver, opts.CacheKey())
    if hit, ok := cache.Get[PagedResult[model.Alert]](r.cache, cacheKey); ok {
        return &hit, nil
    }
    result, err := FindPaged[model.Alert](ctx, r.db, opts)
    if err != nil {
        return nil, err
    }
    cache.Set(r.cache, cacheKey, result, 30*time.Second)
    return &result, nil
}

// 写操作后主动失效单条 + 递增列表版本戳
func (r *AlertRepo) UpdateByKey(ctx context.Context, key string, patch map[string]any) error {
    col, _ := r.db.Collection(ctx, "alerts")
    _, err := col.UpdateDocument(ctx, key, patch)
    if err == nil {
        r.cache.Del("alert:" + key)
        r.bumpListVersion()
    }
    return err
}

func (r *AlertRepo) Create(ctx context.Context, alert *model.Alert) error {
    col, _ := r.db.Collection(ctx, "alerts")
    meta, err := col.CreateDocument(ctx, alert)
    if err == nil {
        alert.Key = meta.Key
        r.bumpListVersion() // 新增记录，列表缓存全失效
    }
    return err
}

func (r *AlertRepo) DeleteByKey(ctx context.Context, key string) error {
    col, _ := r.db.Collection(ctx, "alerts")
    _, err := col.DeleteDocument(ctx, key)
    if err == nil {
        r.cache.Del("alert:" + key)
        r.bumpListVersion()
    }
    return err
}
```

### 15.4 列表版本戳（批量失效）

分页列表 key 格式为 `alerts:list:v{N}:page1size20...`，写操作时递增版本号 N，旧版本 key 在 TTL 内自然消失，无需遍历所有 key：

```go
// internal/repository/base.go

import "sync/atomic"

// 每个 collection 一个版本计数器（进程内，重启归零无影响）
type listVersionCounter struct{ v atomic.Int64 }

func (c *listVersionCounter) current() int64 { return c.v.Load() }
func (c *listVersionCounter) bump()          { c.v.Add(1) }

// AlertRepo 嵌入版本计数器
type AlertRepo struct {
    db      arangodb.Database
    cache   *cache.Store
    listVer listVersionCounter
}

func (r *AlertRepo) listVersion() int64 { return r.listVer.current() }
func (r *AlertRepo) bumpListVersion()   { r.listVer.bump() }
```

### 15.5 各模块 TTL 与失效策略

| 数据 | 缓存 Key 格式 | TTL | 主动失效时机 |
|------|--------------|-----|-------------|
| 单条告警 | `alert:{id}` | 2min | Update / Delete 时 |
| 告警列表 | `alerts:list:v{N}:{opts_hash}` | 30s | Create / Update / Delete 时（版本戳 +1） |
| 单条事件 | `incident:{id}` | 2min | Update / Delete 时 |
| 事件列表 | `incidents:list:v{N}:{opts_hash}` | 30s | 同上 |
| Dashboard 统计 | `dashboard:stats:{tenant_id}` | 1min | 告警/事件写入时 |
| 资产列表 | `assets:list:v{N}:{opts_hash}` | 5min | 资产 CRUD 时 |
| IOC 列表 | `iocs:list:v{N}:{opts_hash}` | 10min | IOC CRUD 时 |
| 当前用户信息 | `user:{id}` | 5min | 用户更新时 |
| SmartScore | `smart_score:{incident_id}` | 5min | 告警链接 Incident 时 |
| 检测规则列表 | `rules:list:v{N}:{opts_hash}` | 2min | 规则 CRUD / 状态变更时 |

### 15.6 写路径分类与失效保证

```
① ngx_console 用户操作写（最常见）
───────────────────────────────────────
   HTTP 请求 → Handler → Service → Repository.Write
                                        └─ ArangoDB 写成功后
                                           → cache.Del(单条 key)    即时
                                           → listVer.bump()         即时
   保证：用户刷新页面立即看到新数据

② ngx 规则引擎告警回调（实时性高）
───────────────────────────────────────
   ngx webhook → POST /api/internal/alerts（在 console 进程内）
               → InternalHandler → AlertRepo.Create
                                       └─ listVer.bump()            即时
               → correlationPool.Submit（异步 CAE）
   保证：规则触发的告警下次列表刷新即可见（前端 30s 轮询）

③ ngx_cron 异步写（归档/评分/ITDR flush）
───────────────────────────────────────
   ngx_cron 进程 → ArangoDB 直写（绕过 console Repository 层）
   → console 侧不知道 → 依赖 TTL 自然过期
   影响范围：exposure_scores（5min TTL）、identity_risks（5min TTL）
   可接受：前端不会在 ngx_cron 写完后立刻查这些数据
```

### 15.7 绕过缓存直读 ArangoDB 的场景

```go
// Repository 层提供 Fresh 变体，绕过缓存
func (r *AlertRepo) FindByIDFresh(ctx context.Context, key string) (*model.Alert, error) {
    // 不读缓存，直接查 ArangoDB，但写回缓存
    col, _ := r.db.Collection(ctx, "alerts")
    var alert model.Alert
    if _, err := col.ReadDocument(ctx, key, &alert); err != nil {
        return nil, err
    }
    cache.Set(r.cache, "alert:"+key, alert, 2*time.Minute)
    return &alert, nil
}
```

需要绕过缓存的场景：
- **ITDR L4/L5 限制执行**：安全操作，必须读最新权限状态
- **告警状态变更后的即时重新查询**（Handler 层写后调 FindByIDFresh 返回最新数据给客户端）
- **前端传 `?fresh=true`** 参数（分析师手动强制刷新）

### 15.8 初始化与依赖注入

缓存 Store 在 ngx_console main.go 中初始化，注入所有 Repository：

```go
// cmd/ngx_console/main.go（关键片段）
cacheStore := cache.New()

alertRepo   := repository.NewAlertRepo(database, cacheStore)
incRepo     := repository.NewIncidentRepo(database, cacheStore)
assetRepo   := repository.NewAssetRepo(database, cacheStore)
// ... 其余 repo 同理

// 不需要缓存的 repo（写多读少 / 低频）：
auditRepo   := repository.NewAuditLogRepo(database, nil) // nil = 不缓存
```

### 15.9 go.mod 新增依赖

```
github.com/dgraph-io/ristretto v0.2.0
```

### 15.10 效果预估

| 场景 | 优化前 | 优化后 |
|------|--------|--------|
| 告警详情页刷新 | ArangoDB 查询 ~3ms | 缓存命中 < 0.1ms |
| 告警列表翻页 | ArangoDB 分页 ~10ms | 缓存命中 < 0.1ms |
| Dashboard 统计（多 Aggregation） | ~50ms | 缓存命中 < 0.1ms |
| ArangoDB QPS（高频页面） | 100% 请求打到 DB | 估计降低 70-80% |
| 内存额外占用 | 0 | ≤ 128MB（MaxCost 上限） |

---

*文档结束*
