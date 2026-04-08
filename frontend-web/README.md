# MirageTrap Frontend Web

前端采用 Vue 3 + Vue Router + Vite，当前只保留三类页面：

- 登录页
- 态势感知页
- 管理控制台

## 运行方式

```bash
cd frontend-web
npm install
npm run dev
```

默认地址：

- `http://127.0.0.1:15173/login`
- `http://127.0.0.1:15173/screen`
- `http://127.0.0.1:15173/console`

## 代理策略

开发模式默认通过 Vite 把 `/api/*` 代理到后端：

- 前端地址：`http://127.0.0.1:15173`
- 后端地址：`http://127.0.0.1:15000`

因此登录页推荐保持默认 API Base，不要直接改成后端绝对地址。这样浏览器请求会走同源代理，能避免大多数 CORS 问题。

可配置环境变量：

```bash
cp .env.example .env
```

- `VITE_API_BASE_URL=`
- `VITE_PROXY_TARGET=http://127.0.0.1:15000`
- `VITE_DEFAULT_USERNAME=admin`

## 页面说明

### 登录页

- 支持用户名密码登录
- 支持直接粘贴 JWT Token
- 默认优先走前端代理地址

### 态势页

对接接口：

- `/api/dashboard/overview`
- `/api/dashboard/top-attackers`
- `/api/dashboard/attack-types`
- `/api/dashboard/trends`
- `/api/dashboard/global-map`
- `/api/health/details`

展示内容：

- 今日攻击概览
- 攻击趋势
- 来源排行
- 攻击类型分布
- 来源热点
- 最近攻击事件
- 组件健康

### 控制台

对接接口：

- `/api/attacks`
- `/api/attacks/{id}`
- `/api/replay/{ip}`
- `/api/replay/{sessionId}/timeline`
- `/api/evidence/{sessionId}`
- `/api/evidence/{sessionId}/export`
- `/api/files/{id}/download`

展示内容：

- 攻击事件列表与详情
- 单 IP 回放
- Session 时间线
- JSON / PCAP 导出和下载

## 构建

```bash
cd frontend-web
npm run build
npm run preview
```

`preview` 默认端口为 `14173`。
