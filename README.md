# clash-converter-csharp

代理链接 ⇄ Clash YAML 配置的**双向实时转换**工具，C# / ASP.NET Core 后端实现。
支持 VLESS / VMess / Shadowsocks / ShadowsocksR / Trojan 五种主流协议的解析与反向生成，并提供 AES-256-GCM 加密订阅端点。无数据库、无服务端存储（无状态架构），可任意部署。

> 本仓库是原 Python 版 `clash-converter` 的等价迁移版：功能对齐、API 契约一致，前端页面直接复用。

**Docker 镜像**：[`vampirefu/clashconverter`](https://hub.docker.com/repository/docker/vampirefu/clashconverter/general)（免构建直接部署，见[容器部署](#容器部署)）

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
├── clash-converter/                # 主工程（net8.0 Web SDK）
│   ├── clash-converter-csharp.csproj
│   ├── Program.cs                  # 入口：3 个 API 端点 + 静态托管 + 转发头
│   ├── Converter.cs                # 核心：5 协议双向解析/生成 + YAML 序列化
│   ├── Crypto.cs                   # AES-256-GCM 加密（SHA-256 密钥派生）
│   ├── Properties/                 # launchSettings.json（端口/环境）
│   ├── wwwroot/
│   │   ├── index.html              # 前端页面
│   │   └── static/favicon.ico
│   ├── Dockerfile                  # 多阶段构建（SDK 构建 → ASP.NET 运行时）
│   ├── docker-compose.yml          # compose 编排
│   └── .dockerignore               # 构建上下文排除：bin/ obj/ *.user .vs/
├── clash-converter-csharp.Tests/   # 单元测试工程（xUnit）
│   ├── clash-converter-csharp.Tests.csproj
│   ├── CryptoTests.cs
│   ├── ConverterProtocolTests.cs
│   ├── ConverterRoundTripTests.cs
│   ├── YamlTests.cs
│   └── TestHelpers.cs              # 共享测试辅助
├── clash-converter-csharp.slnx     # 解决方案（含主 + 测试两个工程）
├── LICENSE.txt                     # MIT 许可证
└── README.md
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

### `GET /api/sub` — 订阅拉取

供 **Clash 客户端**周期性拉取的订阅地址（不是给人手动打开的页面）。返回**只含 `proxies`** 的 YAML（`text/plain; charset=utf-8`）——不含 `port` / `proxy-groups` / `rules`，因为订阅只负责提供「节点列表」，规则与分组由客户端本地配置决定。

请求参数（三个均为可选）：

| 参数 | 位置 | 说明 |
|------|------|------|
| `d` | query | AES-256-GCM 加密后的代理链接（URL-safe base64），由 `POST /api/convert` 响应里的 `sub_url` 给出，**推荐方式**——订阅 URL 本身不泄露节点信息 |
| `url` | query | 旧式明文代理链接，向后兼容；仅在未提供 `d` 时生效 |
| `key` | query / 请求头 | 配置了 `ACCESS_KEY` 时必填，也可改用请求头 `X-Access-Key` |

响应状态码：

| 码 | 场景 |
|----|------|
| `200` | 解密成功，返回订阅 YAML |
| `400` | 既没有 `d` 也没有 `url`；或密文非法（长度不足 / GCM 认证失败） |
| `401` | 配置了 `ACCESS_KEY`，但密钥缺失或不匹配 |

响应头：`Cache-Control: no-cache, no-store`（保证客户端每次拿到最新内容）、`Subscription-Userinfo`（订阅协议约定的流量/到期信息，当前为全 0 占位）。

旧版路径格式 `/api/sub/<任意内容>` 会统一返回 `400` 并提示「订阅链接格式已更新，请重新生成」。

> 订阅 URL 本身即凭证：谁知道这个链接，谁就能拿到你的节点，请勿公开分享。
> 该端点无服务端存储，一条订阅只对应一个节点（`d` 内只编码了一条原始链接）。

---

## API 文档（Swagger UI）

项目已集成 Swagger / OpenAPI。服务启动后，打开浏览器即可访问交互式 API 文档，在线填写请求参数并直接调试三个端点：

- **Swagger UI**：`http://<host>:<port>/swagger`
- **OpenAPI 描述文件**：`http://<host>:<port>/swagger/v1/swagger.json`

> Swagger 仅在**开发环境**（`ASPNETCORE_ENVIRONMENT=Development`）开启，生产部署不会暴露 `/swagger`。本地 `dotnet run` 默认即为开发环境，可直接访问。

---

## 配置

| 环境变量 / 参数 | 默认值 | 说明 |
|----------------|--------|------|
| `PORT` | 裸机兜底 `5000`；容器内 `8080` | 监听端口，按下方优先级解析 |
| `ENCRYPTION_KEY` | 未设置则生成临时密钥 | 订阅加密密钥。未设置时每次重启都会生成新密钥，导致**旧订阅链接失效**，生产环境务必设置 |
| `ACCESS_KEY` | 未设置则公开 | `/api/sub` 基础防护：设置后订阅端点要求携带匹配的 `?key=` 或 `X-Access-Key` 头，否则返回 401；`/api/convert` 生成的订阅链接会自动附带该 key |

`PORT` 的解析优先级（`Program.cs`）：

1. `PORT` 环境变量 → `http://0.0.0.0:{PORT}`（**Docker 镜像走这条**，Dockerfile 内置 `ENV PORT=8080`）
2. 首个纯数字命令行参数 → `http://0.0.0.0:{参数值}`（对齐原 Python 版 CLI 行为，如 `dotnet run 8080`）
3. `launchSettings.json` / `ASPNETCORE_URLS` / `--urls` → 原样尊重，不覆盖（保证 VS 调试端口生效）
4. 以上均未指定 → 兜底 `http://0.0.0.0:5000`

`ENCRYPTION_KEY` 的取值优先级：环境变量 `ENCRYPTION_KEY` → 配置项 `EncryptionKey`（仓库未提供 `appsettings.json`，未显式配置时恒为空）→ 生成临时密钥。

密钥派生：`SHA-256(ENCRYPTION_KEY)` → 32 字节 AES 密钥。
密文布局：`[12B nonce][16B GCM tag][ciphertext]`，再做 URL-safe base64（无填充）。

---

## 本地运行

前置：安装 [.NET 8 SDK](https://dotnet.microsoft.com/download)。

```powershell
# 在主工程目录下运行（自动找到 clash-converter-csharp.csproj）
cd clash-converter
$env:ENCRYPTION_KEY="你的随机字符串"

# 直接 run：会读取 Properties/launchSettings.json
# （环境=Development，Swagger 开启，端口取 launchSettings 的 applicationUrl）
dotnet run

# 或显式指定端口（服务器 / 容器场景）
dotnet run --urls "http://0.0.0.0:5000"
```

在 Visual Studio 中按 F5 调试时，会依据 `Properties/launchSettings.json` 启动：环境为 `Development`（Swagger 开启），并**自动打开浏览器到 Swagger 页面**（由该文件的 `launchUrl` 决定），监听端口由 `applicationUrl` 决定。

---

## 容器部署

镜像已发布到 Docker Hub：[`vampirefu/clashconverter`](https://hub.docker.com/repository/docker/vampirefu/clashconverter/general)

### 方式一：直接使用已发布镜像（最快）

```bash
docker run -d \
  --name clash-converter \
  --restart unless-stopped \
  -p 5000:8080 \
  -e ENCRYPTION_KEY="换成你自己的长随机字符串" \
  vampirefu/clashconverter:latest
```

启动后打开 `http://localhost:5000` 即可使用。

### 方式二：本地构建镜像后运行

`Dockerfile`、`docker-compose.yml`、`.dockerignore` 都在 `clash-converter/` 子目录，**构建命令必须在该目录下执行**（从仓库根执行会找不到 Dockerfile）。

```bash
cd clash-converter

docker build -t clash-converter .
docker run -d \
  --name clash-converter \
  --restart unless-stopped \
  -p 5000:8080 \
  -e ENCRYPTION_KEY="换成你自己的长随机字符串" \
  clash-converter
```

### 方式三：docker compose（长期运行推荐）

```bash
cd clash-converter

# 先编辑 docker-compose.yml，把 ENCRYPTION_KEY 改成自己的随机串
docker compose up -d --build

docker compose logs -f      # 跟踪日志
docker compose down         # 停止并移除容器
```

`docker-compose.yml` 已预设：端口映射 `5000:8080`、`ENCRYPTION_KEY` 环境变量、`restart: unless-stopped`（开机/异常退出后自动拉起）。

### 镜像内部结构

| 项 | 值 |
|----|----|
| 运行时基础镜像 | `mcr.microsoft.com/dotnet/aspnet:8.0` |
| 构建基础镜像 | `mcr.microsoft.com/dotnet/sdk:8.0` |
| 容器内监听端口 | `8080` |
| 入口命令 | `dotnet clash-converter.dll` |
| 工作目录 | `/app` |
| 构建方式 | 多阶段（restore → publish → 运行时镜像），镜像内不含 SDK |

### 部署验证

```bash
# 1) 首页：返回 200 且是 HTML 即正常
curl -I http://localhost:5000/

# 2) 转换：代理链接 -> Clash YAML，同时返回加密订阅链接 sub_url
curl -s -X POST http://localhost:5000/api/convert \
  -H "Content-Type: application/json" \
  -d '{"url":"ss://YWVzLTEyOC1nY206dGVzdA==@192.168.100.1:8888#TestNode"}'

# 3) 订阅拉取：把上一步返回的 sub_url 原样请求即可
curl -s "http://localhost:5000/api/sub?d=<上一步返回的加密串>"
```

### 容器相关环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ENCRYPTION_KEY` | 未设置则每次启动生成临时密钥 | **强烈建议设置**。否则容器每次重启都会换密钥，之前生成的订阅链接全部失效 |
| `ACCESS_KEY` | 未设置则公开 | 设置后 `/api/sub` 需带 `?key=` 或 `X-Access-Key` 头 |
| `PORT` | `8080`（Dockerfile 已内置） | 容器内监听端口。**改动后必须同步调整 `-p` 的右侧**，例如改成 `9000` 就要写 `-p 5000:9000` |

### 数据与状态

服务**完全无状态**：不连数据库、不写磁盘、容器内没有任何持久化数据，所以**不需要挂载 volume**。所有信息都编码在订阅 URL 的加密串里，容器可随时删除重建——只要 `ENCRYPTION_KEY` 保持一致，旧订阅链接就继续有效。

### 反向代理

部署在 Caddy / Nginx 之后时**无需额外配置**：程序通过 `UseForwardedHeaders` 读取 `X-Forwarded-Proto` / `X-Forwarded-Host`，自动用对外域名和 `https://` 生成订阅链接，而不是内网地址。

> `/swagger` 仅在 `ASPNETCORE_ENVIRONMENT=Development` 时开放。容器默认按 Production 运行，Swagger 不会暴露。

### 升级与清理

```bash
# 拉取最新镜像后重建容器（ENCRYPTION_KEY 保持不变）
docker pull vampirefu/clashconverter:latest
docker stop clash-converter && docker rm clash-converter
# 再用上面的 docker run 命令重新启动

# 完全清理
docker rm -f clash-converter
docker rmi vampirefu/clashconverter:latest
```

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

---

## 已知局限

- 正向 `/api/convert` 一次只处理单个链接，不支持多链接批量（反向 `/api/to-url` 已支持批量）。
- `/api/sub` 可配置访问密钥（`ACCESS_KEY`）做基础防滥用；未配置时仍保持公开（向后兼容）。`/api/convert`、`/api/to-url` 暂未加任何防护。
- 前端输入的 YAML 校验为前端浅校验，不保证字段合法性。

---

## 协议与许可证

MIT 许可证（见 `LICENSE.txt`）。
