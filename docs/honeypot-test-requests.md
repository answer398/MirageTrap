# 三类中文蜜罐 Burp Suite 测试请求集

本文档用于在授权的本地 MirageTrap 环境中，通过 Burp Suite Repeater 验证三类中文 Web 蜜罐的访问上报与规则识别能力。所有请求均基于 `honeypots/chinese-web/server.py` 中已实现的路由，以及 `backend/rules/owasp_crs_like_web.json` 中的检测规则定制。

> 仅限本地或授权环境测试。不要将这些请求发送到任何未授权系统。

## Burp 使用方式

1. 打开 Burp Suite，将请求块粘贴到 `Repeater`。
2. 每次只粘贴一个完整 HTTP 请求，不要粘贴 Markdown 代码块标记。
3. 如果前端创建的蜜罐端口不是默认端口，修改 `Host` 头中的端口。
4. Burp 通常会自动维护 `Content-Length`；如果请求体被修改后无法发送，使用 Burp 的自动更新长度功能或手动补齐。

## 测试目标

| 蜜罐 | 默认 Host | 业务身份 |
| --- | --- | --- |
| CMS | `127.0.0.1:18080` | 江海市一体化政务服务门户 |
| OA | `127.0.0.1:18081` | 启明协同办公平台 |
| Gateway | `127.0.0.1:18082` | 蓝盾边缘工业物联网网关 |

## 覆盖矩阵

| 测试类别 | 目标蜜罐 | 路由 / API | 方法 | 预期识别 |
| --- | --- | --- | --- | --- |
| 普通访问 | CMS / OA / Gateway | `/`, `/login`, `/console` | GET | `web_req` 普通请求 |
| 敏感路径探测 | CMS | `/.env`, `/WEB-INF/web.xml` | GET | `web_scan` 或敏感资源访问记录 |
| SQL 注入特征 | CMS / OA | `/search`, `/api/auth/login` | GET / POST | `web_sqli` |
| XSS 特征 | CMS / OA | `/search`, `/kb/search` | GET / POST | `web_xss` |
| 路径遍历特征 | CMS / Gateway | `/download/notice.doc`, `/logs/export` | GET | `web_path_traversal` |
| 命令执行特征 | Gateway | `/api/device/config`, `/sys/admin` | PUT / POST | `web_cmd_exec` |
| 文件上传特征 | CMS | `/editor/upload.php` | POST multipart | `web_file_upload` |
| SSRF 特征 | Gateway | `/api/device/config` | PUT JSON | `web_ssrf` |
| SSTI 特征 | OA | `/kb/search` | POST form | `web_ssti` |
| XXE 特征 | Gateway | `/service/soap` | POST XML | `web_xxe` |
| 扫描探测特征 | CMS / Gateway / OA | `/.git/config`, `/HNAP1/`, `/manager/html` | GET | `web_scan` |

## 1. 普通访问

用于确认三个蜜罐均能返回页面并上报基础 `web_req` 事件。

### 1.1 CMS 首页

```http
GET / HTTP/1.1
Host: 127.0.0.1:18080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9
Connection: close

```

预期结果：返回政务服务门户首页，仅记录普通 `web_req`。

### 1.2 OA 登录页

```http
GET /login HTTP/1.1
Host: 127.0.0.1:18081
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9
Connection: close

```

预期结果：返回 OA 统一身份认证页，仅记录普通 `web_req`。

### 1.3 Gateway 控制台

```http
GET /console HTTP/1.1
Host: 127.0.0.1:18082
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9
Connection: close

```

预期结果：返回边缘网关运行总览页，仅记录普通 `web_req`。

## 2. 敏感路径探测

CMS 蜜罐显式实现了敏感文件探测响应，适合验证敏感路径与扫描类识别。

### 2.1 环境变量文件探测

```http
GET /.env HTTP/1.1
Host: 127.0.0.1:18080
User-Agent: Mozilla/5.0 (compatible; config-checker/1.0)
Accept: */*
Connection: close

```

预期结果：返回 `403 Forbidden`，并命中 `web_scan` 路径探测规则。

### 2.2 Java Web 配置文件探测

```http
GET /WEB-INF/web.xml HTTP/1.1
Host: 127.0.0.1:18080
User-Agent: Mozilla/5.0 (compatible; asset-review/1.0)
Accept: */*
Connection: close

```

预期结果：返回 `403 Forbidden`，用于验证敏感资源访问上报。

## 3. SQL 注入特征

### 3.1 CMS 全文检索 UNION 注入

`/search` 是 CMS 实现的站内检索入口，参数 `q` 会被解析并上报。

```http
GET /search?q=%E6%94%BF%E7%AD%96%27%20UNION%20SELECT%201,username,password%20FROM%20information_schema.tables-- HTTP/1.1
Host: 127.0.0.1:18080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9
Connection: close

```

预期识别：

- `web_sqli`
- 命中 `UNION SELECT`、`information_schema` 相关规则。

### 3.2 OA 登录 JSON 布尔注入

`/api/auth/login` 是三类蜜罐共用的登录 API，OA 场景下使用域账号字段更贴近业务。

```http
POST /api/auth/login HTTP/1.1
Host: 127.0.0.1:18081
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json
Connection: close

{
  "username": "zhangmin' OR 1=1--",
  "password": "test123",
  "otp": "000000"
}
```

预期识别：

- `web_sqli`
- 命中布尔绕过类规则。

## 4. XSS 特征

### 4.1 CMS 搜索反射点

CMS 搜索页会读取 `q` 参数，适合模拟门户站点检索框 XSS 探测。

```http
GET /search?q=%3Csvg%20onload%3Dalert(1)%3E HTTP/1.1
Host: 127.0.0.1:18080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9
Connection: close

```

预期识别：

- `web_xss`
- 命中 SVG `onload` 与 `alert(` 特征。

### 4.2 OA 知识库 POST 搜索

OA 的 `/kb/search` 支持 POST 表单，适合模拟内部知识库搜索框探测。

```http
POST /kb/search HTTP/1.1
Host: 127.0.0.1:18081
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded
Origin: http://127.0.0.1:18081
Referer: http://127.0.0.1:18081/kb/search
Connection: close

q=%3Cimg%20src%3Dx%20onerror%3Dalert(document.cookie)%3E
```

预期识别：

- `web_xss`
- 命中 `onerror=`、`document.cookie`、`alert(` 特征。

## 5. 路径遍历特征

### 5.1 CMS 附件下载参数探测

`/download/notice.doc` 是 CMS 已实现的通知附件下载路由，使用额外 `file` 参数模拟历史下载接口的路径遍历探测。

```http
GET /download/notice.doc?file=../../../../etc/passwd HTTP/1.1
Host: 127.0.0.1:18080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: */*
Connection: close

```

预期识别：

- `web_path_traversal`
- 命中 `../` 与 `/etc/passwd` 特征。

### 5.2 Gateway 审计日志导出探测

`/logs/export` 是 Gateway 已实现的审计日志导出入口，适合模拟导出文件名参数探测。

```http
GET /logs/export?file=../../../../proc/self/environ HTTP/1.1
Host: 127.0.0.1:18082
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: */*
Connection: close

```

预期识别：

- `web_path_traversal`
- 命中 `../` 与 `/proc/self/environ` 特征。

## 6. 命令执行特征

Gateway 提供设备配置类 API，业务上存在 `diagnostic`、`cmd`、`target` 一类字段最合理。

### 6.1 设备配置诊断字段

```http
PUT /api/device/config HTTP/1.1
Host: 127.0.0.1:18082
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json
Origin: http://127.0.0.1:18082
Referer: http://127.0.0.1:18082/devices
Connection: close

{
  "deviceIp": "10.18.3.21",
  "protocol": "Modbus TCP",
  "diagnostic": "ping 10.18.3.21; id",
  "target": "PLC-01"
}
```

预期识别：

- `web_cmd_exec`
- 命中分号加系统命令特征。

### 6.2 运维后台命令替换特征

```http
POST /sys/admin HTTP/1.1
Host: 127.0.0.1:18082
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/x-www-form-urlencoded
Origin: http://127.0.0.1:18082
Referer: http://127.0.0.1:18082/console
Connection: close

action=healthcheck&cmd=$(whoami)
```

预期识别：

- `web_cmd_exec`
- 命中 `$()` 命令替换特征。

## 7. 文件上传特征

CMS 实现了 `/upload`、`/editor/upload.php`、`/api/file/upload` 三个上传入口，其中 `/editor/upload.php` 更符合旧版编辑器上传组件场景。

```http
POST /editor/upload.php HTTP/1.1
Host: 127.0.0.1:18080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: multipart/form-data; boundary=----MirageTrapBoundary
Origin: http://127.0.0.1:18080
Referer: http://127.0.0.1:18080/editor/upload.php
Connection: close

------MirageTrapBoundary
Content-Disposition: form-data; name="title"

公开目录附件
------MirageTrapBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php /* webshell marker only */ echo shell_exec($_GET["cmd"]); ?>
------MirageTrapBoundary--
```

预期识别：

- `web_file_upload`
- 命中可执行扩展名 `filename="shell.php"`。
- 命中上传内容中的 `webshell` / `shell_exec(` 标记。

## 8. SSRF 特征

Gateway 的设备配置接口适合模拟回调地址、采集端点、远程维护地址等 SSRF 风险字段。

```http
PUT /api/device/config HTTP/1.1
Host: 127.0.0.1:18082
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json
Origin: http://127.0.0.1:18082
Referer: http://127.0.0.1:18082/devices
Connection: close

{
  "deviceIp": "10.18.3.21",
  "callback": "http://127.0.0.1:15000/api/health",
  "endpoint": "http://169.254.169.254/latest/meta-data/",
  "mode": "telemetry-sync"
}
```

预期识别：

- `web_ssrf`
- 命中 `127.0.0.1` 回环地址。
- 命中 `169.254.169.254` 元数据地址。
- 参数名 `callback`、`endpoint` 与内部 URL 组合会触发内部 URL 参数规则。

## 9. SSTI 特征

OA 知识库搜索支持 POST 表单，适合模拟模板表达式被输入到搜索或筛选字段。

```http
POST /kb/search HTTP/1.1
Host: 127.0.0.1:18081
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded
Origin: http://127.0.0.1:18081
Referer: http://127.0.0.1:18081/kb/search
Connection: close

q=%7B%7B7*7%7D%7D&filter=%7B%7Bconfig%5B%27SECRET_KEY%27%5D%7D%7D
```

预期识别：

- `web_ssti`
- 命中 `{{...}}` 模板表达式。
- 命中 `config['...']` 运行时对象访问特征。

## 10. XXE 特征

Gateway 实现了 `/api/xml` 与 `/service/soap`，其中 `/service/soap` 更符合工业网关 SOAP 管理接口特征。

```http
POST /service/soap HTTP/1.1
Host: 127.0.0.1:18082
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36
Accept: application/xml, text/xml, */*
Content-Type: application/xml
Origin: http://127.0.0.1:18082
Referer: http://127.0.0.1:18082/console
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE config [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetDeviceConfig>
      <deviceIp>10.18.3.21</deviceIp>
      <profile>&xxe;</profile>
    </GetDeviceConfig>
  </soap:Body>
</soap:Envelope>
```

预期识别：

- `web_xxe`
- 命中 `DOCTYPE` 与 `ENTITY` 组合。
- 命中 `SYSTEM "file://..."` 外部实体 URI。

## 11. 扫描探测特征

扫描探测类请求通常访问不存在的指纹路径。当前蜜罐会统一记录 404 请求，因此仍可被规则引擎识别。

### 11.1 CMS Git 泄露探测

```http
GET /.git/config HTTP/1.1
Host: 127.0.0.1:18080
User-Agent: nuclei/3.2.0
Accept: */*
Connection: close

```

预期识别：

- `web_scan`
- 命中 `/.git/` 敏感探测路径。
- 命中 `nuclei` 扫描器 User-Agent。

### 11.2 Gateway HNAP 指纹探测

```http
GET /HNAP1/ HTTP/1.1
Host: 127.0.0.1:18082
User-Agent: zgrab/0.x
Accept: */*
Connection: close

```

预期识别：

- `web_scan`
- 命中 `/HNAP1/` 设备指纹路径。
- 命中 `zgrab` 扫描器 User-Agent。

### 11.3 OA 管理后台探测

```http
GET /manager/html HTTP/1.1
Host: 127.0.0.1:18081
User-Agent: Nikto/2.5.0
Accept: */*
Connection: close

```

预期识别：

- `web_scan`
- 命中 `/manager/html` 管理后台探测路径。
- 命中 `nikto` 扫描器 User-Agent。

## 验证建议

1. 先启动后端 API 与三个蜜罐容器，确认前端实例状态为运行中。
2. 在 Burp Repeater 中逐个发送请求，避免并发请求干扰人工核对。
3. 在攻击事件列表中检查 `event_type`、请求路径、查询参数、请求体与响应状态。
4. 如果只看到 `web_req`，先确认后端已加载 `backend/rules/owasp_crs_like_web.json`，再检查 `Host` 端口是否指向正确蜜罐。
