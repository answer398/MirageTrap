# MirageTrap

MirageTrap 是一个面向毕业设计与演示场景的 Web 蜜罐与态势感知系统，包含高仿真 Web 诱捕容器、后端控制面、攻击识别链路，以及 Vue 版大屏与管理控制台。

当前仓库保留的是可以直接运行和演示的主链路：

- Web 蜜罐容器
- 攻击请求采集与规则识别
- 攻击事件查询与详情查看
- 单 IP / Session 回放
- JSON / PCAP 证据导出
- 全局态势大屏
- 蜜罐心跳、镜像枚举、实例启停与删除

## 功能概览

### 1. Web 蜜罐

- 提供高仿真企业门户、知识检索、运维后台三种 Web 诱捕画像
- 自动采集请求方法、路径、参数、请求头、请求体、原始请求、响应体
- 支持登录、搜索、后台、上传等典型交互入口，适合承接扫描与攻击流量
- 容器可主动向控制端发送心跳，控制端可感知在线、离线、滞后状态

### 2. 后端控制面

- 基于 Flask + SQLAlchemy + PostgreSQL
- 接收蜜罐上报的攻击事件并完成会话聚合
- 对常见 Web 攻击进行识别，包括 SQL 注入、XSS、路径遍历、命令执行、文件上传、SSRF、SSTI、XXE、恶意扫描
- 提供攻击检索、会话查询、时间线回放、证据导出、系统健康检查和蜜罐管理接口
- 支持通过 Docker 运行时对蜜罐实例进行创建、启动、停止、删除

### 3. 前端界面

- `LoginView`：登录入口
- `ScreenView`：全球态势大屏
- `ConsoleView`：管理控制台，覆盖概览、攻击事件、回放导出、蜜罐管理

## 系统架构

```text
Attacker
   |
   v
Web Honeypot Container
   |
   |  POST /api/ingest/events
   |  POST /api/honeypots/heartbeat
   v
Backend Control Plane
   |
   +--> PostgreSQL
   +--> Docker Runtime
   |
   v
Frontend Screen / Console
```

核心链路如下：

1. 蜜罐容器对外暴露伪装页面。
2. 外部请求进入蜜罐后，被结构化采集并上报至后端。
3. 后端完成规则匹配、风险评级、事件入库和 Session 聚合。
4. 大屏与控制台读取统计数据、攻击详情、回放信息和蜜罐状态。
5. 控制台可向后端发起蜜罐实例启停与删除操作，后端再调用 Docker 运行时执行。

## 技术栈

- Backend: Flask, Flask-JWT-Extended, Flask-Migrate, SQLAlchemy, Gunicorn
- Frontend: Vue 3, Vue Router, Vite
- Database: PostgreSQL 16
- Honeypot Runtime: Docker
- Honeypot Container: Python `http.server` + 自定义高仿真交互逻辑

## 目录结构

```text
MirageTrap/
├── backend/                # Flask 后端
│   ├── app/
│   │   ├── api/            # API 控制器
│   │   ├── models/         # 数据模型
│   │   ├── repositories/   # 数据访问层
│   │   ├── services/       # 业务服务
│   │   └── infrastructure/ # Docker/runtime 等基础设施
│   ├── migrations/         # 数据库迁移
│   ├── manage.py           # 本地启动入口
│   └── Dockerfile
├── frontend-web/           # Vue 前端
│   ├── src/views/          # 登录、大屏、控制台
│   └── public/vendor/      # 地图与图表资源
├── honeypots/
│   └── web/                # Web 蜜罐容器实现
├── docker-compose.yml      # 编排文件
├── web_honeypot_design.md  # 功能设计文稿
└── docker_honeypot_system_design_cn.md
```

## 默认端口

- 后端 API: `15000`
- PostgreSQL: `15432`
- Web 蜜罐: `18080`
- 前端开发服务: `15173`

如果宿主机端口冲突，可通过 `.env` 中的 `HOST_APP_PORT`、`HOST_WEB_HONEYPOT_PORT` 自定义映射端口。

## 快速启动

### 1. 准备环境变量

```bash
cp .env.example .env
```

建议至少修改以下配置：

- `SECRET_KEY`
- `JWT_SECRET_KEY`
- `ADMIN_DEFAULT_PASSWORD`
- `INGEST_TOKEN`
- `HONEYPOT_CONTROL_TOKEN`

### 2. 启动后端、数据库与默认 Web 蜜罐

```bash
docker compose up -d --build postgres backend-api honeypot-web
```

说明：

- `backend-api` 启动时会自动执行数据库迁移
- `honeypot-web` 会自动上报攻击流量和心跳信息
- 后端容器会挂载 `/var/run/docker.sock`，用于启停额外蜜罐实例

### 3. 启动前端

```bash
cd frontend-web
npm install
npm run dev
```

访问地址：

- 登录页：`http://127.0.0.1:15173/login`
- 态势大屏：`http://127.0.0.1:15173/screen`
- 管理控制台：`http://127.0.0.1:15173/console`

### 4. 默认登录账号

- 用户名：`admin`
- 密码：`Admin@123456`

如果你在 `.env` 中修改了 `ADMIN_DEFAULT_USERNAME` 或 `ADMIN_DEFAULT_PASSWORD`，以你自己的配置为准。

## 本地开发

### 后端

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 manage.py
```

### 前端

```bash
cd frontend-web
npm install
npm run dev
```

## 核心接口

### 认证

- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/profile`

### 攻击采集与查询

- `POST /api/ingest/events`
- `GET /api/attacks`
- `GET /api/attacks/{id}`
- `GET /api/attacks/{id}/traffic`
- `GET /api/sessions`
- `GET /api/sessions/{sessionId}`
- `GET /api/sessions/ip/{ip}`

### 态势感知

- `GET /api/dashboard/overview`
- `GET /api/dashboard/global-map`
- `GET /api/dashboard/trends`
- `GET /api/dashboard/top-attackers`
- `GET /api/dashboard/attack-types`
- `GET /api/health`
- `GET /api/health/details`

### 回放与证据

- `GET /api/replay/{ip}`
- `GET /api/replay/{sessionId}/timeline`
- `GET /api/evidence/{sessionId}`
- `POST /api/evidence/{sessionId}/export?format=json|pcap`
- `GET /api/files/{fileId}`
- `GET /api/files/{fileId}/download`
- `GET /api/files/{fileId}/verify`

### 蜜罐管理

- `GET /api/honeypots/catalog`
- `GET /api/honeypots`
- `POST /api/honeypots`
- `GET /api/honeypots/{id}`
- `POST /api/honeypots/{id}/start`
- `POST /api/honeypots/{id}/stop`
- `DELETE /api/honeypots/{id}`
- `POST /api/honeypots/heartbeat`

## Web 蜜罐演示流量

服务启动后，可直接向默认蜜罐端口发送测试请求：

```bash
curl "http://127.0.0.1:18080/admin?id=1%20UNION%20SELECT%201,2--"
curl "http://127.0.0.1:18080/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
curl "http://127.0.0.1:18080/download?file=../../../../etc/passwd"
curl "http://127.0.0.1:18080/api/xml" \
  -H "Content-Type: application/xml" \
  --data '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><root>&xxe;</root>'
```

预期现象：

- 控制台“攻击事件”页出现新记录
- 大屏统计数字、攻击来源和攻击类型分布发生变化
- 攻击详情页可查看结构化请求与命中规则
- 回放页可按 IP 或 Session 查看时间线并导出证据

## 蜜罐管理说明

控制台内置镜像枚举目录，目前提供：

- `web_portal`
- `web_search`
- `web_admin`

每个枚举项会映射到对应的高仿真诱捕画像，控制台可直接完成：

- 创建实例
- 查询实例列表
- 启动实例
- 停止实例
- 删除实例
- 查看运行状态与心跳状态

## 重要环境变量

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `APP_PORT` | 后端容器监听端口 | `15000` |
| `HOST_APP_PORT` | 宿主机映射的后端端口 | `15000` |
| `HOST_WEB_HONEYPOT_PORT` | 宿主机映射的 Web 蜜罐端口 | `18080` |
| `DATABASE_URL` | 数据库连接串 | `postgresql+psycopg2://honeypot:honeypot@localhost:15432/honeypot_db` |
| `CORS_ALLOWED_ORIGINS` | 允许的前端来源 | `http://127.0.0.1:15173,http://localhost:15173` |
| `INGEST_TOKEN` | 蜜罐上报攻击流量令牌 | `dev-ingest-token` |
| `HONEYPOT_CONTROL_TOKEN` | 蜜罐心跳/控制令牌 | 默认跟随 `INGEST_TOKEN` |
| `ADMIN_DEFAULT_USERNAME` | 初始管理员账号 | `admin` |
| `ADMIN_DEFAULT_PASSWORD` | 初始管理员密码 | `Admin@123456` |
| `GEOIP_ENABLED` | 是否启用 GeoLite2 本地 IP 归属地解析 | `false` |
| `GEOIP_CITY_DB_PATH` | GeoLite2 City 数据库路径 | `instance/geoip/GeoLite2-City.mmdb` |
| `GEOIP_ASN_DB_PATH` | GeoLite2 ASN 数据库路径 | `instance/geoip/GeoLite2-ASN.mmdb` |
| `ATTACK_RULESET_PATHS` | 攻击识别规则目录或文件，支持逗号分隔 | `rules` |
| `HONEYPOT_ORCHESTRATION_ENABLED` | 是否启用 Docker 编排控制 | `true` |
| `HONEYPOT_DOCKER_NETWORK` | 蜜罐容器加入的 Docker 网络 | `miragetrap-net` |
| `HONEYPOT_HEARTBEAT_INTERVAL_SECONDS` | 蜜罐心跳发送间隔 | `15` |
| `HONEYPOT_HEARTBEAT_TIMEOUT_SECONDS` | 控制端判定心跳超时阈值 | `45` |

## 攻击规则引擎

- 当前后端会从 `backend/rules/` 加载外部攻击识别规则。
- 规则路径通过 `ATTACK_RULESET_PATHS` 配置，支持目录或文件，多个路径用逗号分隔。
- 默认已提供一组 `OWASP CRS` 思路改写的 Web 攻击规则，覆盖 SQL 注入、XSS、路径遍历、命令执行、恶意上传、SSRF、SSTI、XXE 和扫描探测。
- 若要扩展规则，优先在 `backend/rules/` 中新增规则文件，而不是直接修改 Python 代码。

## GeoLite2 归属地

- 后端支持使用 `GeoLite2 City` 和 `GeoLite2 ASN` 本地数据库解析来源 IP 的国家、地区、城市、经纬度、时区和 ASN 信息。
- 默认数据库路径为 `backend/instance/geoip/GeoLite2-City.mmdb` 和 `backend/instance/geoip/GeoLite2-ASN.mmdb`，也可以通过 `GEOIP_CITY_DB_PATH`、`GEOIP_ASN_DB_PATH` 覆盖。
- 启用方式：将 `GEOIP_ENABLED=true`，并把官方 `.mmdb` 文件放到对应路径后重启后端。
- Docker Compose 已预留 `./backend/instance/geoip:/app/instance/geoip:ro` 挂载，容器内会直接读取宿主机上的数据库文件。
- 如果来源 IP 是内网、回环或保留地址，系统会标记为 `private/local`，不会伪造地理坐标。

## 安全与部署注意事项

- 当前仓库主要面向课程设计、论文答辩、实验室演示与本地部署场景
- 后端容器挂载了 Docker Socket，仅应部署在受信任环境
- 默认账号和密钥仅用于开发环境，公开部署前必须修改
- 蜜罐本身用于诱捕攻击流量，不应与真实业务系统混用

## 当前仓库状态

仓库已经做过一次收口清理，当前仅保留运行主链路代码：

- 无旧版前端目录
- 无测试目录与测试脚本
- 无构建产物与缓存目录
- 适合直接接入 GitHub 做版本管理

## 设计文稿

- `web_honeypot_design.md`


如果你准备继续扩展，可以从以下方向切入：

- 新增更多 Web 画像模板
- 增加更细粒度的攻击规则与风险评分
- 引入消息队列或异步采集链路
- 增加部署文档、演示截图和 API 文档
