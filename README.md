# MirageTrap

MirageTrap 是一个面向 Web 蜜罐的态势感知与控制平台。项目由蜜罐控制层、中文 Web 蜜罐实例和前端展示端组成，支持攻击事件采集、规则识别、地理位置解析、态势大屏、事件检索、回放导出和蜜罐实例管理。

## 核心能力

- 态势大屏：以全球态势图、趋势图、来源热点和事件摘要展示攻击活动。
- 控制台：集中管理攻击事件、回放导出和蜜罐实例。
- 控制层绑定：一个前端服务可绑定多个蜜罐控制层，登录前支持测活。
- 事件采集：中文 Web 蜜罐将请求、响应、会话和心跳上报到控制层。
- 风险识别：基于规则对扫描、注入、敏感路径探测等行为打标并计算风险。
- 地理解析：可接入 MaxMind GeoLite2 City/ASN 数据库展示国家、城市和 ASN。
- 证据留存：支持本地对象存储，保留会话回放和导出文件。

## 项目结构

```text
MirageTrap/
├── backend/                 # Flask 控制层 API、业务服务、数据库模型与迁移
├── frontend-web/            # Vue 3 前端，大屏、控制台和控制层登录入口
├── honeypots/chinese-web/   # 三个中文业务蜜罐镜像与共享运行时
├── deploy/postgres/         # PostgreSQL 访问配置
├── docker-compose.yml       # 控制层、数据库和三个中文蜜罐编排
├── .env.example             # 开发环境变量模板
└── .env.production.example  # 生产环境变量模板
```

## 技术栈

- 后端：Python 3.12、Flask、Flask-SQLAlchemy、Flask-Migrate、Flask-JWT-Extended、Gunicorn
- 前端：Vue 3、Vue Router、Vite
- 数据库：PostgreSQL 16
- 蜜罐运行时：Docker、独立 Web 蜜罐镜像
- 可选能力：MaxMind GeoLite2、MinIO/本地证据存储

## 端口约定

| 服务 | 默认端口 | 说明 |
| --- | ---: | --- |
| 前端开发服务 | `15173` | Vue/Vite 前端入口 |
| 后端控制层 | `15000` | 控制层 API 根地址 |
| PostgreSQL | `15432` | 数据库宿主机映射端口 |
| 中文政务 CMS 蜜罐 | `18080` | 政务信息公开/CMS 后台入口 |
| 中文 OA 办公蜜罐 | `18081` | 协同办公、流程与文档入口 |
| 中文工控网关蜜罐 | `18082` | 设备运维、资产与配置接口入口 |

## 中文蜜罐镜像

系统内置三个独立 Docker 镜像，均复用控制层协议：访问事件上报到 `POST /api/ingest/events`，运行状态心跳上报到 `POST /api/honeypots/heartbeat`。

| 镜像目录 | 镜像名 | 目录 key | 默认端口 | 诱捕场景 |
| --- | --- | --- | ---: | --- |
| `honeypots/chinese-web/cms/` | `miragetrap/cn-cms-honeypot:latest` | `cn_cms_portal` | `18080` | 江海市一体化政务服务门户，包含政务公开、一网通办、后台管理、附件上传和数据目录 |
| `honeypots/chinese-web/oa/` | `miragetrap/cn-oa-honeypot:latest` | `cn_oa_portal` | `18081` | 启明协同办公平台，包含统一身份认证、待办流程、公文、邮件、日程和通讯录 |
| `honeypots/chinese-web/gateway/` | `miragetrap/cn-iot-gateway-honeypot:latest` | `cn_iot_gateway` | `18082` | 蓝盾边缘工业物联网网关，包含设备资产、协议通道、实时告警、审计终端和配置接口 |

这些镜像通过中文页面、常见后台路径、伪 API、下载/上传入口、业务数据表和服务端响应头提升真实性。控制台创建蜜罐实例时会从后端目录自动同步上述三类镜像，并在创建成功后立即启动对应容器。

## 快速启动

### 1. 准备环境

```bash
cp .env.example .env
```

建议至少修改以下配置：

- `SECRET_KEY`：Flask 应用密钥。
- `JWT_SECRET_KEY`：JWT 签名密钥。
- `ADMIN_DEFAULT_USERNAME`：初始管理员用户名。
- `ADMIN_DEFAULT_PASSWORD`：初始管理员密码。
- `CORS_ALLOWED_ORIGINS`：允许访问控制层的前端地址。
- `HONEYPOT_CONTROLLER_PUBLIC_BASE_URL`：蜜罐容器访问控制层的公开地址。

### 2. 使用 Docker Compose 启动后端与蜜罐

```bash
docker compose up -d --build
```

如果只想先构建三张蜜罐镜像，可执行：

```bash
docker compose build honeypot-cms honeypot-oa honeypot-gateway
```

启动后检查控制层：

```bash
curl http://127.0.0.1:15000/api/health
```

如果返回 `success: true`，说明控制层已就绪。

### 3. 启动前端

```bash
cd frontend-web
npm install
npm run dev
```

访问：

- 登录入口：`http://127.0.0.1:15173/login`
- 态势大屏：`http://127.0.0.1:15173/screen`
- 管理控制台：`http://127.0.0.1:15173/console`

## 登录与控制层绑定

前端登录页不是单纯账号表单，而是两步式控制层入口：

1. 填写控制层名称和控制层地址。
2. 点击“测活控制层”。
3. 测活成功后点击“绑定控制层”。
4. 使用管理员账号登录当前控制层。

默认本机控制层地址为：

```text
http://127.0.0.1:15000
```

如果你在另一台电脑浏览器中访问服务器上的前端，不要填写浏览器本机的 `127.0.0.1`。此时控制层地址应使用服务器 IP 或域名，例如：

```text
http://<服务器IP>:15000
```

## 默认账号

开发环境默认账号来自 `.env`：

```text
ADMIN_DEFAULT_USERNAME=admin
ADMIN_DEFAULT_PASSWORD=Admin@123456
```

如果数据库中已存在管理员账号，修改 `.env` 不会自动覆盖旧密码。需要同步默认管理员时执行：

```bash
cd backend
python3.12 -m flask --app manage.py sync-default-admin
```

## 本地后端开发

如需不通过 Docker 直接运行控制层：

```bash
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3.12 manage.py
```

后端默认监听：

```text
http://127.0.0.1:15000
```

## GeoIP 数据

地理位置解析由以下变量控制：

```text
GEOIP_ENABLED=true
GEOIP_CITY_DB_PATH=instance/geoip/GeoLite2-City.mmdb
GEOIP_ASN_DB_PATH=instance/geoip/GeoLite2-ASN.mmdb
```

将 MaxMind 数据库文件放入：

```text
backend/instance/geoip/
```

未启用 GeoIP 时，系统仍可采集事件，但地区、城市和 ASN 信息会降级显示。

## 关键 API

### 认证

- `POST /api/auth/login`：登录并获取访问令牌。
- `POST /api/auth/logout`：退出登录。
- `GET /api/auth/profile`：读取当前用户信息。

### 健康检查

- `GET /api/health`：基础健康状态。
- `GET /api/health/details`：数据库、GeoIP、证据存储和运行时明细。

### 态势与事件

- `GET /api/dashboard/overview`：态势总览。
- `GET /api/dashboard/global-map`：全球地图数据。
- `GET /api/dashboard/trends`：攻击趋势。
- `GET /api/attacks`：攻击事件列表。
- `GET /api/attacks/{id}`：攻击事件详情。
- `DELETE /api/attacks/{id}`：删除单个攻击事件。

### 会话与证据

- `GET /api/replay/{ip}`：按来源 IP 查询回放。
- `GET /api/replay/{sessionId}/timeline`：查询会话时间线。
- `GET /api/evidence/{sessionId}`：查询会话证据。
- `POST /api/evidence/{sessionId}/export`：导出证据文件。

### 蜜罐

- `GET /api/honeypots`：蜜罐实例列表。
- `POST /api/honeypots`：创建蜜罐实例。
- `POST /api/honeypots/{id}/start`：启动蜜罐实例。
- `POST /api/honeypots/{id}/stop`：停止蜜罐实例。
- `POST /api/ingest/events`：蜜罐事件上报。
- `POST /api/honeypots/heartbeat`：蜜罐心跳上报。

## 常见问题

### 前端测活 `127.0.0.1:15000` 失败

`127.0.0.1` 永远指向浏览器所在机器。如果你用自己的电脑浏览器访问远程服务器的前端，控制层地址要填服务器 IP 或域名，而不是本机回环地址。

### 登录提示用户名或密码错误

先确认控制层测活成功，再确认数据库中的管理员密码。必要时执行：

```bash
cd backend
python3.12 -m flask --app manage.py sync-default-admin
```

### Docker 蜜罐无法上报事件

检查以下配置是否能从蜜罐容器访问控制层：

```text
HONEYPOT_CONTROLLER_PUBLIC_BASE_URL
INGEST_TOKEN
HONEYPOT_CONTROL_TOKEN
```

### Docker 后端启动提示 `15000` 端口占用

如果你已经在本机运行了 `python3.12 manage.py`，它会占用 `15000`，此时 Docker 版 `backend-api` 无法绑定同一端口。可先停止本地后端进程，或在 `.env` 中调整 `HOST_APP_PORT` 后再启动 Docker Compose。

## 生产部署建议

- 使用强随机 `SECRET_KEY` 和 `JWT_SECRET_KEY`。
- 修改默认管理员密码。
- 将 `CORS_ALLOWED_ORIGINS` 限定为可信前端域名。
- 仅暴露必要端口，限制数据库端口访问来源。
- 挂载持久化卷保存 PostgreSQL 数据和证据文件。
- 使用反向代理和 HTTPS 暴露前端与控制层。

## 许可证

当前仓库未声明开源许可证。分发、商用或二次开发前请先确认授权范围。
