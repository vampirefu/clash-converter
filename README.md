# clash-converter-csharp

代理链接 ⇄ Clash YAML 配置的**双向实时转换**工具，C# / ASP.NET Core 后端实现。
支持 VLESS / VMess / Shadowsocks / ShadowsocksR / Trojan 五种主流协议的解析与反向生成，并提供 AES-256-GCM 加密订阅端点。无数据库、无服务端存储（无状态架构），可任意部署。

> 本仓库是原 Python 版 `clash-converter` 的等价迁移版：功能对齐、API 契约一致，前端页面直接复用。

---

## 功能特性

- **正向转换**：单个代理链接 → 完整 Clash YAML 配置（`proxies` / `proxy-groups` / `rules`）。
- **反向转换**：Clash YAML → 代理链接列表（支持批量多节点）。
- **加密订阅端点**：代理链接经 AES-256-GCM 加密后生成订阅 URL，Clash 订阅管理器可直接拉取；同时兼容旧式明文 `?url=` 端点。
- **五种协议双向**：VLESS / VMess / SS / SSR / Trojan，解析与反向生成对称实现。
- **本地静态托管**：复用原生前端页面（`wwwroot/index.html`），开箱即用。
- **反向代理感知**：通过 `X-Forwarded-Proto` / `X-Forwarded-Host` 正确生成 https 订阅链接（适配 Caddy / Nginx 前置）。

---

## 技术栈

| 层 | 技术 |
|----|------|
| 后端 | .NET 8 (LTS) · ASP.NET Core Minimal API |
| 配置序列化 | YamlDotNet 16.x |
| 加密 | `System.Security.Cryptography.AesGcm` (AES-256-GCM) |
| API 文档 | Swashbuckle.AspNetCore（Swagger / OpenAPI，交互式调试） |
| 前端 | 原生 HTML / CSS / JavaScript（沿用原项目，无需构建） |

---

## 支持的协议与字段

| 协议 | 解析 | 反向生成 | 覆盖参数 |
|------|------|----------|----------|
| **VLESS** | ✅ | ✅ | tcp/ws/grpc/h2、TLS、Reality（pbk/sid/spx）、flow、sni、fp |
| **VMess** | ✅ 标准 base64 + 类 vless 格式 | ✅ | net/tls/sni/alpn/host/path/grpc |
| **Shadowsocks** | ✅ 传统 + SIP002 | ✅ | method/password/plugin |
| **SSR** | ✅ 现代（query 在 base64 外）+ 旧式（整串 base64） | ✅ | protocol/obfs/params（remarks/protoparam/obfsparam） |
| **Trojan** | ✅ | ✅ | sni/alpn/flow/skip-cert-verify |

---

## 目录结构

```
clash-converter-csharp/
├── clash-converter-csharp.csproj   # 主工程（net8.0 Web SDK）
├── Program.cs                      # 入口：3 个 API 端点 + 静态托管 + 转发头
├── Converter.cs                    # 核心：5 协议双向解析/生成 + YAML 序列化
├── Crypto.cs                       # AES-256-GCM 加密（SHA-256 密钥派生）
├── Properties/                     # 运行时配置（自动生成）
├── wwwroot/
│   ├── index.html                  # 前端页面
│   └── static/favicon.ico
├── Dockerfile / docker-compose.yml # 容器化部署
├── clash-converter-csharp.slnx     # 解决方案（含测试工程）
└── README.md

clash-converter-csharp.Tests/       # 单元测试工程（xUnit）
    ├── CryptoTests.cs
    ├── ConverterProtocolTests.cs
    ├── ConverterRoundTripTests.cs
    └── YamlTests.cs
```

---

## API 端点

### `POST /api/convert`
请求体：`{ "url": "<代理链接>" }`

响应：
```json
{
  "protocol": "vless",
  "yaml": "port: 7890\n...",
  "filename": "clash_VLESS-xxxx.yaml",
  "sub_url": "http://host:5000/api/sub?d=<加密串>"
}
```

### `POST /api/to-url`
请求体：`{ "yaml": "<Clash YAML 内容>" }`

响应：
```json
{
  "proxies": [
    { "name": "节点1", "type": "vless", "url": "vless://..." }
  ],
  "total": 1
}
```
> 无法识别的节点会在结果中带 `error` 字段、`url` 为 `null`，不会中断整体转换。

### `GET /api/sub?d=<加密串>`
返回 `proxies-only` 的 YAML（`text/plain`），并附带 `Subscription-Userinfo` 头。
同时支持旧式明文端点 `GET /api/sub?url=<代理链接>`。

---

## API 文档（Swagger UI）

项目已集成 Swagger / OpenAPI。服务启动后，打开浏览器即可访问交互式 API 文档，在线填写请求参数并直接调试三个端点：

- **Swagger UI**：`http://<host>:<port>/swagger`
- **OpenAPI 描述文件**：`http://<host>:<port>/swagger/v1/swagger.json`

> Swagger 默认**始终开启**（含生产环境），方便随时调试。若只需在开发期启用，可在 `Program.cs` 中用 `app.Environment.IsDevelopment()` 包裹 `UseSwagger()` 与 `UseSwaggerUI()` 两行。

---

## 配置

| 环境变量 / 参数 | 默认值 | 说明 |
|----------------|--------|------|
| `PORT` | `5000` | 监听端口（也可用首个命令行参数指定） |
| `ENCRYPTION_KEY` | 未设置则生成临时密钥 | 订阅加密密钥。未设置时每次重启都会生成新密钥，导致**旧订阅链接失效**，生产环境务必设置 |

密钥派生：`SHA-256(ENCRYPTION_KEY)` → 32 字节 AES 密钥。
密文布局：`[12B nonce][16B GCM tag][ciphertext]`，再做 URL-safe base64（无填充）。

---

## 本地运行

前置：安装 [.NET 8 SDK](https://dotnet.microsoft.com/download)。

```powershell
cd clash-converter-csharp
$env:ENCRYPTION_KEY="你的随机字符串"
dotnet run -c Release --urls "http://0.0.0.0:5000"
# 浏览器打开 http://127.0.0.1:5000
# 交互式 API 文档：http://127.0.0.1:5000/swagger
```

---

## 容器部署

```bash
# 构建并启动
docker compose up -d --build

# 或单独 build / run
docker build -t clash-converter .
docker run -d -p 5000:5000 -e ENCRYPTION_KEY="你的随机字符串" clash-converter
```

部署在反向代理（Caddy / Nginx）之后时无需额外配置：程序通过 `UseForwardedHeaders` 识别转发的协议与域名，自动生成 `https://` 订阅链接。

---

## 测试

测试工程 `clash-converter-csharp.Tests` 使用 xUnit，覆盖加密往返、五协议解析、解析→生成往返一致性、YAML 生成与还原等共 29 个用例。

```bash
# 运行全部测试
dotnet test

# 仅运行测试工程
cd clash-converter-csharp.Tests
dotnet test
```

测试发现并修复的两个问题（已并入主代码）：
- **SSR 链接解析**：原实现把 `?` 之后整串当作 base64 解码，无法解析现代客户端生成的「query 在 base64 之外」格式；现兼容两种约定。
- **VMess `port` 为字符串**（如 `"443"`）时正确解析为数字。

---

## 已知局限

- 正向 `/api/convert` 一次只处理单个链接，不支持多链接批量（反向 `/api/to-url` 已支持批量）。
- 无鉴权 / 速率限制：`/api/sub` 为公开端点，任何拿到加密串的人都可拉取。
- 前端输入的 YAML 校验为前端浅校验，不保证字段合法性。

---

## 协议与许可证

MIT 许可证（见 `LICENSE.txt`）。
