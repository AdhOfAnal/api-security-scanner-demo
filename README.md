# API Security Scanner Demo Tool

## 1. 项目标题
API Security Scanner Demo Tool

## 2. 项目简介
本项目是一个基于 OpenAPI 的 API 安全扫描器演示工程（Demo Tool）。

项目目标：
- 解析 OpenAPI 文档并提取可测接口
- 按规则自动发起 API 安全测试
- 输出统一结构的 JSON 报告
- 支持漏洞版/修复版结果对比
- 提供本地 Streamlit GUI 用于演示操作

说明：该项目定位为本地演示与规则迭代，不是生产级安全平台。

## 3. 功能概览（Features）
- OpenAPI 解析：支持 JSON/YAML（含 UTF-8 BOM）
- API 自动测试：基于配置和规则自动执行请求
- 规则检测：`no_auth`、`bola`、`sensitive_data`、`missing_role_check`
- 报告生成：标准化 finding JSON 输出
- 修复前后对比：支持 vulnerable/fixed 报告 diff summary
- 轻量 GUI：基于 Streamlit 的本地交互演示界面

## 4. 支持的安全规则
### `no_auth`
- 遍历 OpenAPI 的 `GET` 接口（排除文档路径）
- 比较未鉴权与已鉴权访问结果
- 未鉴权返回非 `401/403` 时判定可疑

### `bola`
- 普通用户登录后访问其他用户资源（`/orders/{order_id}`）
- 返回 `200` 判定可疑
- 若能明确 owner 不一致，提升 confidence

### `sensitive_data`
- 登录后访问 `/profile`
- 将响应字段与 `configs/sensitive_fields.yaml` 比对
- 命中敏感字段即输出 finding

### `missing_role_check`
- 识别 `/admin` 路径
- 使用普通用户 token 请求管理员接口
- 返回 `200` 判定角色校验缺失

## 5. 项目结构
```text
api-security-project/
├── configs/                  # 扫描配置
├── docs/                     # 设计与规划文档
├── samples/
│   ├── openapi/              # 示例 OpenAPI
│   └── reports/              # 报告输出
├── testbed/                  # FastAPI 漏洞靶场
├── tests/                    # pytest 测试
├── tool/
│   ├── client/               # HTTP 客户端
│   ├── engine/               # 扫描编排
│   ├── parser/               # OpenAPI 解析
│   ├── report/               # 报告输出/对比
│   ├── rules/                # 规则实现
│   └── utils/                # 工具函数
├── ui/                       # Streamlit GUI
├── requirements.txt
├── pytest.ini
└── README.md
```

## 6. 安装与运行
### 安装依赖
```bash
python -m pip install -r requirements.txt
```

### 启动靶场（CLI 手动模式）
```bash
python -m uvicorn testbed.app:app --host 127.0.0.1 --port 8000 --reload
```

### 运行扫描（CLI）
```bash
python -m tool.main --config configs/targets.yaml
```

## 7. GUI 启动与使用
### 启动 GUI
```bash
streamlit run ui/app.py
```

### GUI 当前支持能力
- 选择配置文件（或输入自定义配置路径）
- 选择扫描模式（漏洞版 / 修复版）
- 控制修复开关（`FIX_USERS_AUTH`、`FIX_ADMIN_ROLE`）
- 一键执行扫描
- 展示 findings 列表（`rule_id/severity/confidence/endpoint/method`）
- 展示单条 finding 详情（`title/evidence/recommendation`）
- 展示 vulnerable/fixed 报告 diff summary（若两份报告存在）

说明：GUI 会临时启动本地 testbed（`127.0.0.1:8000`）执行扫描；端口被占用时会提示失败。

## 8. 演示流程（漏洞 -> 修复 -> 对比）
### 步骤 1：扫描漏洞版
```powershell
$env:FIX_USERS_AUTH = "0"
$env:FIX_ADMIN_ROLE = "0"
python -m uvicorn testbed.app:app --host 127.0.0.1 --port 8000
```
新开终端：
```powershell
python -m tool.main --config configs/targets_vulnerable.yaml
```

### 步骤 2：扫描修复版
```powershell
$env:FIX_USERS_AUTH = "1"
$env:FIX_ADMIN_ROLE = "1"
python -m uvicorn testbed.app:app --host 127.0.0.1 --port 8000
```
新开终端：
```powershell
python -m tool.main --config configs/targets_fixed.yaml
```

### 步骤 3：查看 diff summary
```powershell
python -m tool.report.compare_reports \
  --vulnerable samples/reports/vulnerable_report.json \
  --fixed samples/reports/fixed_report.json
```

JSON 输出：
```powershell
python -m tool.report.compare_reports \
  --vulnerable samples/reports/vulnerable_report.json \
  --fixed samples/reports/fixed_report.json \
  --format json
```

## 9. 报告示例
```json
{
  "rule_id": "missing_role_check",
  "title": "Possible Missing Role-Based Access Control",
  "severity": "high",
  "confidence": "high",
  "endpoint": "/admin/stats",
  "method": "GET",
  "evidence": {
    "actor": {
      "username": "alice",
      "id": 1,
      "role": "user"
    },
    "required_role": "admin",
    "response_status": 200,
    "response_keys": ["service", "total_orders", "total_users"]
  },
  "recommendation": "Enforce role checks for admin endpoints and return 403 for non-admin users."
}
```

## 10. 项目设计文档
- [docs/design.md](docs/design.md)

## 11. 当前局限
- 规则数量与策略深度有限（演示级）
- 规则编排固定，未插件化
- 缺少并发、速率控制与系统级误报治理
- 报告仅 JSON（未提供 HTML 可视化）
- GUI 为本地演示用途，未做部署与权限管理

## 12. 后续计划
- 提升规则语义与误报控制
- 增强 OpenAPI security schema 利用
- 扩展报告 schema 校验和细粒度差异分析
- 补充更多端到端测试场景

## 13. License
MIT
