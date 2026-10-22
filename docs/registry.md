# 云端发现服务部署

[返回 README](../README.md)

注册服务只提供节点发现，不提供 NAT 穿透或流量中继。两台机器仍需能够直接连接，
例如位于同一局域网、可互通的 VPN，或已有相应的端口转发。


如果两台机器不在同一局域网，或者 IP 经常变动，可以在 VPS 上部署
`kbshare-registry` 作为发现服务。每台 kbshare 启动后会定期把可供对端直连
的本机 IP 报告给注册表，连接前从注册表查询对端 IP。透明代理 TUN 使用的
回环、链路本地和 RFC 2544 基准测试地址不会被上报。

### 编译

**方式一：在 VPS 上直接编译（推荐）**

VPS 上装 Rust 工具链后直接编译，无需交叉编译：

```bash
# 1. 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# 2. 拉代码
git clone https://github.com/li-sky/ununifying_kboard_share.git kbshare
cd kbshare

# 3. 编译（只编译 registry，不需要平台依赖）
cargo build --release --locked -p kbshare-registry

# 4. 二进制在这里
ls -lh target/release/kbshare-registry
# -rwxr-xr-x 2.2M  kbshare-registry
```

**方式二：在 Windows 上交叉编译**

需要安装 musl 工具链和 linker，配置较复杂，不推荐。如果 VPS 架构与
开发机不同（如 ARM），务必用方式一。

### 部署到 VPS

`kbshare-registry` 本身是纯 HTTP，监听 `0.0.0.0:8080`。生产环境应放在
nginx 后面做 TLS 终止。

**1. 安装二进制到系统路径：**

```bash
sudo cp target/release/kbshare-registry /usr/local/bin/
sudo chmod +x /usr/local/bin/kbshare-registry
```

**2. 安装 nginx 并申请证书：**

```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx

# 申请 Let's Encrypt 证书（先确保域名 A 记录已指向 VPS IP）
sudo certbot --nginx -d kbshare-registry.example.com
```

**3. 配置 nginx 反向代理：**

```nginx
# /etc/nginx/sites-available/kbshare-registry
server {
    listen 443 ssl http2;
    server_name kbshare-registry.example.com;

    ssl_certificate     /etc/letsencrypt/live/kbshare-registry.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/kbshare-registry.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

# HTTP 跳转 HTTPS
server {
    listen 80;
    server_name kbshare-registry.example.com;
    return 301 https://$host$request_uri;
}
```

```bash
sudo ln -sf /etc/nginx/sites-available/kbshare-registry /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

**4. 用 systemd 管理进程：**

```ini
# /etc/systemd/system/kbshare-registry.service
[Unit]
Description=kbshare registry
After=network.target

[Service]
ExecStart=/usr/local/bin/kbshare-registry --bind 127.0.0.1:8080
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now kbshare-registry
```

### 验证

```bash
curl https://kbshare-registry.example.com/health
# {"status":"healthy"}
```

### 配置 kbshare 使用注册表

在两台机器的 `config.json` 中填入 `vps_base_url`：

```json
{
  "vps_base_url": "https://kbshare-registry.example.com"
}
```

或在配置编辑器的 **Connection** 页面填写 **Cloud discovery endpoint**。

kbshare 启动时会：
1. 向注册表 `POST /report` 报告本机 `node_id` 和 IP，之后每 30 秒刷新。
2. 连接前 `GET /node/<remote_id>` 查询对端 IP。
3. 如果注册表不可达或对端未注册，回退到 `fallback_remote_ips`。

注册表只做 IP 发现，不参与 TLS 握手或按键转发——所有键盘数据仍然端到端
加密，注册表看不到任何键盘输入。
