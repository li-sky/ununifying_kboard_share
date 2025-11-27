# 非罗技键盘助手

本项目包含一对主机/客户端脚本，根据鼠标活动状态在两台 Windows 机器之间重定向键盘输入。它适用于使用同一罗技优联鼠标在两台电脑间切换、同时保持桌面登录（例如使用 RDP）时的辅助场景。当前实现支持加密传输、基于指纹的“首次信任”（TOFU），以及一个轻量级 VPS 注册表，便于在 IP 变化时自动重连。

> [!CAUTION]
> 本项目几乎全由AI完成，本人不对使用本项目造成的任何后果负责。

## 组件说明

| 文件 | 角色 |
| --- | --- |
| `host.py` | 运行在“发送键盘事件”的机器：挂钩本机低层键盘事件，通过 TLS 发送，并监听来自客户端的 UDP 心跳。 |
| `client.py` | 运行在“接收并注入键盘事件”的机器：托管 TLS 服务器，将鼠标移动作为心跳发给主机，并将收到的按键按压/释放应用到本机。 |
| `config_host.json`、`config_client.json` | 可选配置覆盖。若缺失，脚本会自动生成最小模板并使用默认值。一般只需设置必要字段（节点 ID、备用 IP、VPS 地址等）。 |
| `host_trust.json`、`client_trust.json` | 在你首次信任对端指纹后由脚本创建，保存以 `remote_id` 为键的 SHA-256 指纹。 |
| `vps_registry.py` | 运行在 VPS 上的极简 HTTPS 注册表：各节点上报自身 IP 列表，断链或启动时可向其查询对端最新坐标。 |

## 安全模型

- **双向 TLS**：主机作为 TLS 客户端连接客户端的 TLS 服务端，双方都使用本机证书参与握手。
- **自动生成证书**：如配置的证书/私钥不存在，脚本会调用 `openssl req -x509 -newkey rsa:2048` 在 `certs/` 目录生成一年有效期的自签名证书。仅需确保 `openssl` 在 `PATH` 中；否则可自行提供证书。
- **指纹与 TOFU**：首次连接时，双方会显示对端的 SHA-256 指纹并询问是否信任（`yes`/`no`）。一旦接受，指纹会保存在本地以防止中间人攻击。
- **加密指令通道**：仅在 TLS 会话验证了对端指纹后才发送键盘数据。UDP 心跳包含发送方的 `local_id`，可忽略来自未知节点的心跳。

## 配置

所有选项都有默认值。每台机器通常只需如下最小配置：

```json
// config_host.json
{
  "local_id": "host-alpha",
  "remote_id": "client-alpha",
  "fallback_remote_ips": ["192.168.1.1"],
  "vps_base_url": "https://your-vps.example.com:8443"
}
```

```json
// config_client.json
{
  "local_id": "client-alpha",
  "remote_id": "host-alpha",
  "fallback_remote_ips": ["192.168.1.1"],
  "vps_base_url": "https://your-vps.example.com:8443"
}
```

可选覆盖项（按需设置）：
- `tcp_port` / `udp_port` / `remote_udp_port`：监听与目标端口。
- `window_alpha`：主机控制台透明度。
- `trust_store`：信任库路径。
- `vps_ca_cert` 或 `allow_insecure_vps`：注册表 TLS 校验策略。
- `ip_report_interval`、`remote_refresh_interval`、`heartbeat_interval`：网络上报与刷新频率。

删除配置文件可重新生成带默认值的最小模板。

## VPS 注册表

在具有公网访问能力的 VPS 上运行 `vps_registry.py` 用于 IP 发现与下发：

```powershell
python vps_registry.py --host 0.0.0.0 --port 8443 --cert /path/to/server.pem --key /path/to/server.key
```

接口：
- `POST /report`：节点上报 `{node_id, ips, tcp_port, udp_port, event}`，用于启动、断开或周期性同步。
- `GET /node/<id>`：节点查询对端最新条目，获取可达 IP 列表与端口。

建议 VPS 使用可信证书；否则将其 CA 路径配置为 `vps_ca_cert`，或测试时暂时设置 `allow_insecure_vps: true`。

### 通过 Nginx 反向代理部署

可将 `vps_registry.py` 的 HTTPS 服务置于 Nginx 之后，便于与现有站点或证书共存。下面给出两种常见配置方式：

1) 使用独立子域（推荐）

例如将注册表服务暴露为 `https://registry.example.com`，Nginx 反向到后端 `127.0.0.1:8443`：

```nginx
server {
  listen 443 ssl;
  server_name registry.example.com;

  ssl_certificate     /etc/ssl/example/fullchain.pem;
  ssl_certificate_key /etc/ssl/example/privkey.pem;

  location / {
    proxy_pass          http://127.0.0.1:8443;
    proxy_set_header    Host $host;
    proxy_set_header    X-Real-IP $remote_addr;
    proxy_set_header    X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header    X-Forwarded-Proto $scheme;
  }
}
```

客户端配置中，将 `vps_base_url` 设为：

```json
"vps_base_url": "https://registry.example.com"
```

2) 复用现有主域下的路径（/registry）

如果希望在同一域名下复用路径（例如 `https://example.com/registry`），需要在 Nginx 中配置前缀转发：

```nginx
server {
  listen 443 ssl;
  server_name example.com;

  ssl_certificate     /etc/ssl/example/fullchain.pem;
  ssl_certificate_key /etc/ssl/example/privkey.pem;

  location /registry/ {
    proxy_pass          http://127.0.0.1:8443/;  # 注意末尾斜杠
    proxy_set_header    Host $host;
    proxy_set_header    X-Real-IP $remote_addr;
    proxy_set_header    X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header    X-Forwarded-Proto $scheme;
  }
}
```

同时将客户端/主机的 `vps_base_url` 设置为该路径前缀：

```json
"vps_base_url": "https://example.com/registry"
```

注意事项：
- 如果后端 `vps_registry.py` 已自带 TLS，可在 Nginx 与后端之间改用 `proxy_pass https://127.0.0.1:8443;`，并在 Nginx 上配置 `proxy_ssl_*` 验证；也可让后端仅监听明文 HTTP，由 Nginx 统一做 TLS 终止（更常见）。
- 路径前缀方式下，请确保 `proxy_pass` 末尾带 `/`，避免重复前缀导致 404（例如 `/registry/node/<id>` 能正确映射到后端的 `/node/<id>`）。
- 在程序端将 `vps_base_url` 精确设置为子域或路径前缀，脚本会按此拼接 `POST /report` 与 `GET /node/<id>`。

### 部署方式建议（systemd 等）

注册表服务建议以守护进程方式常驻，推荐使用 Linux 的 `systemd` 管理：

1) 创建服务单元文件 `/etc/systemd/system/kb-registry.service`

```ini
[Unit]
Description=Keyboard Redirector IP Registry
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/kb-registry
ExecStart=/usr/bin/python3 /opt/kb-registry/vps_registry.py --host 127.0.0.1 --port 8443 --cert /opt/kb-registry/server.pem --key /opt/kb-registry/server.key
Restart=always
RestartSec=5
User=www-data
Group=www-data

[Install]
WantedBy=multi-user.target
```

将代码与证书放到 `/opt/kb-registry`（或你的任意目录），确保 `User/Group` 对该目录有读权限。

2) 启用与查看状态：

```bash
sudo systemctl daemon-reload
sudo systemctl enable kb-registry
sudo systemctl start kb-registry
sudo systemctl status kb-registry
```

3) 与 Nginx 配合：

- 若 `ExecStart` 监听 `127.0.0.1:8443`（明文或自签名 HTTPS），在 Nginx 中按前文两种方式做反代。
- 为提升可靠性，可在 Nginx 上启用健康检查或错误页；在 `systemd` 中保留 `Restart=always`，保证异常退出时自动重启。

其它可选部署方式：
- `supervisord`：通过 `supervisord` 管理 Python 进程，适合简单场景。
- `docker`：封装为容器并使用 `docker-compose`/`swarm`/`k8s` 部署；Nginx 反向代理到容器端口。
- Windows 服务器：可以用 `nssm` 或 `sc.exe` 将 Python 脚本注册为服务，或直接放到计划任务中随开机启动。

## 快速开始

1. 安装依赖：`pip install pynput`，并确保系统 `PATH` 中有 OpenSSL。
2. 按需编辑最小配置 JSON（或删除以生成默认模板）。
3. 启动注册表服务（动态 IP 环境建议启用）。
4. 先启动 `client.py`（开始监听与上报）。
5. 再启动 `host.py`。两端会：
  - 在缺失证书时自动生成证书/私钥。
  - 显示自身指纹与期望的对端指纹（如已知）。
  - 首次连接时询问是否信任新指纹。
6. 在客户端机器移动鼠标：其会发送 `MOUSE_ACTIVE:<id>` 心跳，主机提升透明窗口并开始安全发送键盘事件。
7. 在主机本地移动鼠标：恢复本地模式，主机最小化并停止发送按键。

## 运行注意

- 信任库不会被自动覆盖；如证书重置需手动删除相应 `*_trust.json` 条目后重新信任。
- 脚本会向注册表周期上报 `startup`、`connected`、`disconnect`、`shutdown`、`periodic` 事件，便于诊断。
- 若注册表不可达，双方会回退到各自的 `fallback_remote_ips` 列表。
- 心跳含 `local_id`，请确保两端配置的 ID 一致且互指。

## 故障排查

| 现象 | 可能原因 | 处理建议 |
| --- | --- | --- |
| `RuntimeError: 未找到 openssl` | 系统缺少 OpenSSL CLI | 安装 OpenSSL（或使用 Git Bash 的 OpenSSL），重开终端；或手动将证书/私钥放入 `certs/`。 |
| 连接时报“指纹不匹配” | 对端重新生成过证书 | 手动确认新指纹，删除对应 `*_trust.json` 条目，重新连接并信任。 |
| 使用 VPS 时 TLS 握手失败 | 注册表证书不被信任 | 配置 `vps_ca_cert` 指向 CA；或测试时暂设 `allow_insecure_vps: true`。 |
| 收不到键盘事件 | UDP 心跳未到主机 | 检查 `remote_udp_port`/`udp_port`、防火墙规则，并确认客户端能解析主机 IP（通过注册表或备用 IP）。 |

本项目尽量使用内置库（`ssl`、`urllib`）以减少依赖，按需调整配置与注册表以适配你的环境。
