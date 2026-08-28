# TyOpen

> 电信天翼云盘直链分享工具。生成一个链接，别人点开就能下载，完事。

<br>

## 简介

TyOpen 是一个基于电信天翼云盘（cloud.189.cn）的轻量直链分享工具：用云盘账号密码登录后，可以把云盘里的文件/文件夹生成分享链接，对方只能看到你分享的这一个文件，其他啥也看不到（类似于百度网盘的分享页）。

不想暴露完整文件列表，也不想要 Alist、Cloudreve 那样的「个人网盘站」，就一个诉求：发个链接，对方点开就能下载。

<br>

## 为什么做这个

这是 [WoOpen](https://github.com/wp-x/woopen)（联通云盘版）的姊妹项目，核心思路完全一样：换底座，不换产品。

当初做联通云盘版，是因为搞活动一口气买了 11 年联通云盘，不买都对不起那个价格。最近电信云盘要改规则，实体市场（卡商渠道）的价格已经在往下走，目测会出现一波好价——所以先把软件做好放着，等好价来了再入手账号慢慢用。

两个项目的关系：同一套产品逻辑、同一套界面和功能，底层分别对接联通云盘（沃云盘）和电信天翼云盘，互不影响，按需选用。

<br>

## 功能

| 功能 | 说明 |
| --- | --- |
| 直链分享 | 文件/文件夹生成分享链接 |
| 访问控制 | 可以加密码、设过期时间、限制下载次数 |
| 自定义短链 | 比如 `/s/movie` |
| 文件管理 | 浏览、上传、新建目录、重命名、移动、删除 |
| 挂载路径 | 可以把某个子目录设为根目录，只暴露该目录下的内容 |
| 访问统计 | 后台能看访问量 |
| 过期提醒 | 登录态快过期会推送通知，支持 Bark、微信、Telegram 等 |
| 文件上传 | 通过 API 上传文件到云盘 |
| WebDAV | 把云盘挂载成网络驱动器，像本地硬盘一样用 |

<br>

## 预览

**登录页面**

![登录页面](./docs/images/login.png)

**后台管理**

![后台管理](./docs/images/image.png)

**分享页面**

![分享页面](./docs/images/share.png)

<br>

## 部署

### 方式一：本地构建（推荐）

把仓库拉下来构建：

```bash
git clone https://github.com/wp-x/tyopen.git
cd tyopen
```

改一下 `docker-compose.yml` 里的密码，然后：

```bash
docker compose up -d --build
```

浏览器打开 `http://服务器IP:10000`

也可以直接使用预构建镜像（无需本地构建）：

```yaml
services:
  tyopen:
    image: ghcr.io/wp-x/tyopen:latest
    container_name: tyopen
    restart: unless-stopped
    ports:
      - "10000:10000"
    volumes:
      - ./data:/data
    environment:
      - TYOPEN_ADMIN_PASSWORD=改成你的密码
      - TYOPEN_JWT_SECRET=改成至少32位的随机字符串
      - TYOPEN_SITE_URL=http://你的域名或IP:10000
```

<br>

### 方式二：本地开发

需要 Go 和 Node.js 环境，一键启动前后端：

```bash
./start.sh
```

前端开发地址 `http://localhost:3000`，后端 `http://localhost:10000`。

<br>

### 配置云盘账号

登录后台，进「系统设置」，在「云盘配置」里填写：

- **云盘账号**：天翼云盘手机号
- **云盘密码**：云盘登录密码

保存后系统会自动登录 cloud.189.cn 并维护访问令牌（token 自动刷新落库）。如果登录触发电信验证码，请先在官方客户端登录一次后再试。

如果账号触发了电信的**设备安全校验**（首次在新设备登录时可能出现），界面会弹出对话框引导你输入短信验证码；校验通过后设备会被标记为可信，后续登录不再触发。

保存后去「文件管理」看看能不能加载出文件列表，能的话就成了。

### 挂载路径（可选）

默认管理的是云盘根目录。如果只想把某个子目录拿出来用（比如专门建一个「分享」目录），在「云盘配置」的**挂载路径**里填那个目录的 ID，保存后立即生效——文件管理、WebDAV、分享的根就都变成这个子目录，云盘里的其他内容完全不可见。留空则恢复为默认根目录。

### Cookie 登录（备选）

如果账号密码登录频繁触发电信验证码，可以改用 Cookie 登录：在「云盘配置」里展开「Cookie 登录（备选）」，粘贴网页版的 Cookie 后保存。

获取方式：浏览器登录 [cloud.189.cn](https://cloud.189.cn) → `F12` 打开开发者工具 → Network → 刷新页面 → 点开任意 cloud.189.cn 请求 → 复制请求头里的 `Cookie` 整段内容。

注意：设置了 Cookie 后**优先**使用 Cookie 连接云盘；Cookie 失效后系统不会自动续期，会提示"Cookie 已失效，请重新获取"，重新粘贴即可。想回到账号密码方式，点「清除已保存的 Cookie」。

已知上游限制：Cookie 模式下，内容完全相同的文件重复上传可能被天翼的内容安全策略拦截（提示 `file md5 is in black list`），这是服务端行为；账号密码（PC 协议）模式无此限制，需要频繁覆盖上传同内容文件时建议用账号密码模式。

<br>

## 环境变量

| 变量 | 说明 | 默认 |
| --- | --- | --- |
| `TYOPEN_ADMIN_PASSWORD` | 首次启动/数据库尚无管理员哈希时的登录密码（至少 12 位）；已有后台 bcrypt 密码时可留空 | 首次启动必填 |
| `TYOPEN_JWT_SECRET` | JWT 密钥（至少 32 位随机字符） | 必填 |
| `TYOPEN_PORT` | 端口 | 10000 |
| `TYOPEN_DATA_DIR` | 数据目录（SQLite 库 `tyopen.db` 所在目录） | ./data |
| `TYOPEN_SITE_URL` | 站点外部访问地址（用于生成分享链接/二维码；生产环境建议显式设置） | http://localhost:10000 |
| `TYOPEN_TRUSTED_PROXIES` | 可信反向代理 IP/CIDR，逗号分隔（如 `127.0.0.1,10.0.0.0/8`）；直接暴露时留空 | 空（不信任代理头） |

> 密码优先级：在后台「系统设置 → 修改密码」改过的密码持久化在数据库里，**优先于** `TYOPEN_ADMIN_PASSWORD`；环境变量只作为初始/兜底密码。已有 bcrypt 密码时重启不再强制要求设置 `TYOPEN_ADMIN_PASSWORD`。程序会将数据目录收紧为 `0700`、SQLite 文件收紧为 `0600`，请确保运行用户拥有 `data/`（Docker bind mount）权限。

<br>

## Nginx 反代

有域名的话可以配一下：

```nginx
server {
    listen 80;
    server_name pan.example.com;

    location / {
        proxy_pass http://127.0.0.1:10000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
```

> 默认不信任任何 `X-Forwarded-*` 头。反代部署时请配置 `TYOPEN_TRUSTED_PROXIES=127.0.0.1`（或实际代理 IP/CIDR），并建议设置 `TYOPEN_SITE_URL` 固定外部地址。生产环境请使用 HTTPS，不要直接用明文端口暴露公网。管理员登出或修改密码会使已有 JWT（包括 WebDAV Bearer）失效；`forever` 只表示不过期，仍受服务端会话版本撤销。

<br>

## 新功能使用说明

### 文件上传 API

可以通过 API 上传文件到云盘，适合自动化脚本或者第三方工具集成。

**上传文件**

```bash
curl -X POST http://localhost:10000/api/files/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@/path/to/file.txt" \
  -F "parent_id=0"
```

**创建目录**

```bash
curl -X POST http://localhost:10000/api/files/mkdir \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "新文件夹", "parent_id": "0"}'
```

> `parent_id` 填 `0` 表示根目录，填其他 ID 就是在那个目录下创建。

**获取 Token**

登录后台后，按 `F12` 打开开发者工具，在「网络」标签里找到任意请求，看请求头里的 `Authorization` 字段，复制 `Bearer` 后面的内容。

<br>

### WebDAV 挂载

可以把云盘挂载成网络驱动器，直接在文件管理器里操作文件。

**挂载地址**

```
http://你的服务器IP:10000/dav/
```

**认证方式**

WebDAV 使用 **Basic Auth**，账号密码在后台「系统设置 → WebDAV 挂载」中配置（默认账号 `admin`）。

**Windows 挂载**

打开「此电脑」，点击「映射网络驱动器」，输入：

```
\\你的服务器IP@10000\dav
```

或者用命令行：

```cmd
net use Z: http://你的服务器IP:10000/dav/ /user:admin 你的密码
```

**macOS 挂载**

打开 Finder，按 `Command + K`，输入：

```
http://你的服务器IP:10000/dav/
```

输入用户名 `admin` 和你设置的密码。

**Linux 挂载**

安装 davfs2：

```bash
sudo apt install davfs2
```

挂载：

```bash
sudo mount -t davfs http://你的服务器IP:10000/dav/ /mnt/webdav
```

输入用户名 `admin` 和密码。

> **注意**：WebDAV 的写入实现为“写入到临时文件，关闭时一次性上传”。大文件上传会占用磁盘临时空间。

<br>

## FAQ

**登录态多久过期？**

不固定，token 会自动刷新；设置里可以开监控，失效了会推送通知。

**登录时提示需要验证码？**

电信的风控机制，先在官方客户端用同账号登录一次，再回来保存。

**支持其他网盘吗？**

不支持，只支持电信天翼云盘。

<br>

## 参考项目

| 项目 | 说明 |
| --- | --- |
| [Alist](https://github.com/alist-org/alist) | 支持多种网盘的文件列表程序，功能全面 |
| [OpenList](https://github.com/OpenListTeam/OpenList) | Alist 的活跃 Fork，持续维护中 |

<br>

## License

MIT
