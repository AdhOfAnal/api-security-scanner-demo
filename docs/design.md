# 设计文档（v1）

## 1. 项目目标
本项目用于实现一个“基于 OpenAPI 的半自动 API 安全测试工具”最小可运行版本，目标是：
- 解析 OpenAPI JSON/YAML 文档并提取接口列表
- 对目标 API 执行基础安全检测
- 输出结构化 JSON 报告，便于后续自动化处理
- 提供本地 FastAPI 靶场用于验证检测规则

当前版本聚焦基础能力验证，不追求高覆盖或低误报。

## 2. 系统整体架构
系统由扫描器与靶场两部分构成。

```text
configs/*.yaml
   │
   ▼
tool/main.py (CLI)
   │
   ▼
tool/engine/runner.py
   ├── tool/parser/openapi_parser.py   (解析 OpenAPI)
   ├── tool/client/http_client.py      (发送 HTTP 请求)
   ├── tool/rules/*                    (执行规则)
   ├── tool/engine/comparator.py       (finding 去重)
   └── tool/report/reporter.py         (写入 JSON 报告)

扫描目标（默认）: testbed/app.py (FastAPI)
```

架构特征：
- 单进程、同步执行
- 规则顺序固定（`no_auth` -> `missing_role_check` -> `bola` -> `sensitive_data`）
- 报告输出为单一 JSON 文件

## 3. 各模块职责
### parser
路径：`tool/parser/openapi_parser.py`
- `OpenAPIParser.load(path)`：读取 `.json/.yaml/.yml` OpenAPI 文件
- 支持 `utf-8-sig`，兼容带 BOM 文件
- `list_endpoints(doc)`：从 `paths` 提取 `{method, path}` 列表

### client
路径：`tool/client/http_client.py`
- `HttpClient.request(...)`：统一发送 HTTP 请求
- 支持可选 Bearer Token 注入
- `HttpClient.login(...)`：调用 `/login` 并提取 `access_token`

### rules
路径：`tool/rules/`
- `no_auth.py`：检测疑似未鉴权访问
- `missing_role_check.py`：检测疑似管理员接口缺少角色校验
- `bola.py`：检测疑似对象级越权访问
- `sensitive_data.py`：检测敏感字段暴露
- 每条规则返回标准化 finding 列表

### engine
路径：`tool/engine/`
- `runner.py`：扫描入口编排
  - 加载配置
  - 解析 OpenAPI
  - 执行规则
  - 去重与组装报告
- `comparator.py`：按 `(rule_id, method, endpoint)` 去重

### report
路径：`tool/report/reporter.py`
- `write_json_report(path, report)`：创建目录并写出 UTF-8 JSON 报告

### testbed
路径：`testbed/`
- `app.py`：本地漏洞靶场 API
- `auth.py`：简化认证逻辑（`token-{username}`）
- `data.py`：内存用户与订单数据
- 用于规则回归验证，不代表生产安全设计

## 4. 扫描执行流程
1. CLI 从 `tool/main.py` 接收 `--config` 参数（默认 `configs/targets.yaml`）。
2. `runner.run_scan` 加载配置：`base_url`、`openapi_path`、`report_path`、`users`。
3. 解析 OpenAPI 并提取 endpoint 列表。
4. 初始化 `HttpClient(base_url)`。
5. 顺序执行规则：
   - `no_auth.run(client, endpoints, users)`
   - `missing_role_check.run(client, endpoints, users)`
   - `bola.run(client, users)`
   - 读取 `configs/sensitive_fields.yaml` 后执行 `sensitive_data.run(...)`
6. 使用 `deduplicate_findings` 去重。
7. 组装报告 `meta + findings`，写入 `report_path`。

## 5. 四条规则的基本检测逻辑
### no_auth
- 输入：OpenAPI 端点列表
- 行为：
  - 遍历所有 `GET` 接口
  - 排除 `/docs`、`/redoc`、`/openapi.json`
  - 不带 token 发起请求；若响应码不是 `401/403`，判定可疑
- 输出：`rule_id=no_auth` finding

### bola
- 输入：`configs/targets.yaml` 中用户列表
- 行为：
  - 使用第一个用户登录获取 token
  - 使用第二个用户的 `expected_user_id`（默认回退 `2`）访问 `/orders/{id}`
  - 若返回 `200`，判定可疑
- 输出：`rule_id=bola` finding

### sensitive_data
- 输入：登录用户 + `configs/sensitive_fields.yaml`
- 行为：
  - 登录后访问 `/profile`
  - 提取响应 JSON 字段，与敏感字段名单比对
  - 若有命中，判定可疑
- 输出：`rule_id=sensitive_data` finding

### missing_role_check
- 输入：OpenAPI 端点列表 + 用户列表
- 行为：
  - 识别 `/admin` 路径的 `GET` 接口
  - 选择一个非 admin 用户（通过 `/profile` 的 `role` 字段推断）
  - 使用该用户 token 访问管理员接口
  - 若返回 `200`，判定可疑
- 输出：`rule_id=missing_role_check` finding

## 6. finding 报告结构说明
当前规则输出遵循统一结构：

```json
{
  "rule_id": "bola",
  "title": "Possible Broken Object Level Authorization",
  "severity": "high",
  "confidence": "medium",
  "endpoint": "/orders/{order_id}",
  "method": "GET",
  "evidence": {
    "actor": {
      "username": "alice",
      "id": 1
    },
    "tested_input": {
      "order_id": 2
    },
    "resource_owner": 2,
    "response_status": 200,
    "response_keys": ["amount", "item", "order_id", "owner_id"]
  },
  "recommendation": "Verify resource ownership before returning object data."
}
```

报告文件顶层结构：
- `meta`：时间、目标地址、OpenAPI 路径、报告路径、发现总数
- `findings`：规则输出列表（去重后）

说明：`evidence` 为规则自定义内容，不同规则字段会有差异，但整体 finding 外层字段保持一致。

## 7. 当前设计上的局限性
- 规则能力基础：仅支持 4 条规则，且策略较简单
- 扫描编排固定：规则执行顺序写死，未插件化
- 缺少并发与速率控制：请求为同步串行
- 误报/漏报控制有限：无重试、基线学习、上下文关联
- 规则与 OpenAPI 关联浅：未利用 security scheme、schema 细粒度语义
- 报告仅 JSON：无 schema 强校验、无历史对比和可视化
- 靶场认证为演示实现，不覆盖 JWT、会话刷新等真实场景
