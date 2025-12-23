# 📁 SMMS-WebDav

> 将 [sm.ms](https://sm.ms) 图床伪装成 WebDAV 存储服务 —— 支持 AList、RaiDrive、Windows/macOS 挂载！

[![Go](https://img.shields.io/badge/Go-1.20%2B-blue?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## ✨ 特性

- ✅ **标准 WebDAV 协议支持**（RFC 4918）：`PROPFIND` / `PUT` / `DELETE` / `GET`
- ☁️ **后端使用 sm.ms 图床**：自动上传图片并返回 CDN 加速链接
- 🗃️ **本地 SQLite 索引**：记录文件路径 ↔ sm.ms URL 映射关系
- 🔒 **可选 Basic Auth 认证**：保护你的 WebDAV 服务
- 🔄 **GET 自动 302 重定向**：访问文件时跳转到真实 sm.ms 地址
- 🧪 **兼容主流客户端**：
  - [AList](https://alist.nn.ci/)/OpenList
  - RaiDrive / Cyberduck / Windows 映射网络驱动器
  - macOS Finder “连接服务器”

> ⚠️ 注意：sm.ms 免费用户单文件 ≤ 5MB（API 返回 10MB 限制，实际以网站为准）

---

## 🚀 快速开始

### 1. 编译 & 运行

```bash
# 克隆项目（如有）
git clone https://github.com/yourname/smms-webdav.git
cd smms-webdav

# 构建（需 Go 1.20+）
go build -o smms-webdav .

# 首次运行会生成 config.json
./smms-webdav
```

程序将自动生成 `config.json` 并退出，请编辑后再启动。

### 2. 配置 `config.json`

```json
{
  "smms_token": "your_smms_api_token",
  "port": "8080",
  "username": "admin",
  "password": "123456"
}
```

> 💡 获取 sm.ms Token：登录 [https://sm.ms](https://sm.ms) → 用户中心 → API Token

### 3. 启动服务

```bash
./smms-webdav
```

输出示例：
```
🚀 sm.ms WebDAV server running on :8080
📁 DB: smms.db
⚙️  Config: config.json
🔑 Using sm.ms token from config
```

---

## 🧩 使用方式

### 在 AList 中添加存储

- **驱动类型**：`WebDAV`
- **挂载路径**：`/`
- **地址**：`http://your-server:8080/`
- **用户名/密码**：按 `config.json` 填写（如启用）

### 手动测试

```bash
# 列出所有文件（PROPFIND）
curl -X PROPFIND -u admin:123456 http://localhost:8080/

# 上传图片
curl -X PUT -u admin:123456 --data-binary @photo.jpg http://localhost:8080/photo.jpg

# 访问图片（自动跳转到 sm.ms）
curl -L http://localhost:8080/photo.jpg
```

---

## 🛠️ 部署建议

### Nginx 反向代理（推荐）

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header Depth $http_depth;
    proxy_set_header Destination $http_destination;
    proxy_set_header Overwrite $http_overwrite;
}
```

### Docker（可选）

```Dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o smms-webdav .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/smms-webdav .
COPY --from=builder /app/config.json .
EXPOSE 8080
CMD ["./smms-webdav"]
```

---

## 📂 文件说明

| 文件 | 说明 |
|------|------|
| `smms-webdav` | 主程序 |
| `config.json` | 配置文件（首次运行自动生成） |
| `smms.db` | SQLite 数据库，存储文件元数据 |

---

## 📜 许可证

MIT License — 免费用于个人或商业项目。

---

> Made with ❤️ for developers who love lightweight cloud storage.  
> 如果你觉得有用，欢迎 ⭐ Star 本项目！
