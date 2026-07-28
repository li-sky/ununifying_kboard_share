# kbshare

从零重写的版本。目标与原项目一致：根据鼠标活动状态，把一台机器上的键盘输入安全转发到另一台机器。

## 设计要点

- **语言**：Rust（blocking I/O + std::thread；不引入 tokio 以降低噪声）。
- **分层**：
  - `core` —— 纯逻辑，零 I/O。键码映射、状态机、按键跟踪、协议编解码。
  - `net`  —— TLS + 自签证书 + SHA256 指纹 TOFU + 极简注册表客户端。
  - `platform` —— 键盘捕捉、鼠标监听、键盘注入。Windows / Linux / Mock 三套实现。
  - `app` —— 统一可执行程序 `kbshare`，每台机器运行同一二进制。
  - `registry` —— 节点注册服务可执行程序（可选，用于云端发现）。
  - `tray` —— 可复用的系统托盘库与配置编辑器。
  - `flow` —— Logitech HID++ 探测与 Easy-Switch。
- **协议**：NDJSON。每条消息是一行 JSON，方便日志、抓包、重放、测试。
- **状态机**：`Local ↔ Remote`，纯函数 `transition(state, event) -> (state, action)`，100% 可单测。
- **按键跟踪**：`PressedKeys` 维护“我们当前认为对端按下的键”，断线/切模式时统一 release，杜绝卡键。
- **测试**：
  - `core`：单元测试 + 基于 Mock 平台 + in-memory transport 的集成测试。
  - `net`：rustls 用 `tokio`-free 的 `Stream` 模式，测试走 TcpListener on 127.0.0.1。
  - `platform`：mock 实现覆盖所有 trait，binaries 的集成测试不依赖真实键盘。
  - 真实键盘联调：由使用者在本地人工触发（见 `docs/manual_test.md`）。

## 目录

```
ununifying_kboard_share/
  Cargo.toml                 # workspace 定义与共享依赖
  Cargo.lock                 # workspace 依赖锁定文件
  rust-toolchain.toml        # Rust 工具链版本
  crates/
    core/                    # 协议、状态机与运行时纯逻辑
    net/                     # TLS、证书、信任与注册发现
    platform/                # Windows/Linux/Mock 平台适配
    app/                     # 统一 kbshare 可执行程序
    registry/                # 节点注册服务可执行程序（可选）
    tray/                    # 系统托盘库与配置编辑器
    flow/                    # Logitech HID++ 探测与 Easy-Switch
  docs/
    manual_test.md           # 双机手动联调流程
  examples/                  # 可提交的配置样例
  logs/                      # 运行日志（不提交）
  target/                    # Cargo 构建产物（不提交）
```

`crates/`、`docs/` 和 `examples/` 是项目源码与文档；`logs/`、
`target/` 以及运行时目录下的证书、信任库和实际配置均为本机状态，由 `.gitignore`
排除。新增配置时以 `examples/` 为模板，避免把真实地址或身份材料提交到仓库。

## 构建

```powershell
cargo build
cargo test
```

## 本地运行

每台机器运行同一个 `kbshare` 可执行程序，使用各自的配置文件。两台机器的 `local_id` 和 `remote_id` 必须互换：

```powershell
cargo run -p kbshare -- --config runtime_alpha/config.json
cargo run -p kbshare -- --config runtime_beta/config.json
```

真实键盘捕获与注入的双机验证步骤见 `docs/manual_test.md`。

## 云端发现（可选）

如果两台机器不在同一局域网，或者 IP 经常变动，可以在 VPS 上部署
`kbshare-registry` 作为发现服务。每台 kbshare 启动时把自己的 IP 报告给
注册表，连接前从注册表查询对端 IP。

### 编译

**方式一：在 VPS 上直接编译（推荐）**

VPS 上装 Rust 工具链后直接编译，无需交叉编译：

```bash
# 1. 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# 2. 拉代码
git clone <your-repo-url> kbshare
cd kbshare

# 3. 编译（只编译 registry，不需要平台依赖）
cargo build --release -p kbshare-registry

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
  "vps_base_url": "https://kbshare-registry.example.com",
  ...
}
```

或在配置编辑器的 **Connection** 页面填写 **Cloud discovery endpoint**。

kbshare 启动时会：
1. 向注册表 `POST /report` 报告本机 `node_id` 和 IP。
2. 连接前 `GET /node/<remote_id>` 查询对端 IP。
3. 如果注册表不可达或对端未注册，回退到 `fallback_remote_ips`。

注册表只做 IP 发现，不参与 TLS 握手或按键转发——所有键盘数据仍然端到端
加密，注册表看不到任何键盘输入。

## 配置编辑器

Windows 托盘菜单选择 **Edit configuration…** 会在默认浏览器打开配置界面。
点击 **Setup guide** 后按“本机名称 → 生成/确认 TLS 证书 → 云端发现对端（或手动 IP）→ 鼠标探测与通道 → 设备布局 → 检查应用”完成配置。
证书步骤会显示 SHA-256 指纹；若配置路径已有证书和私钥则只校验并复用，不会覆盖。
鼠标探测不是强制步骤；蓝牙设备或当前切换到另一通道的鼠标可以手动填写。
界面同时保留身份、连接、Flow-lite 和高级 JSON 四个页面；保存时会校验必填字段，
在原配置旁创建 `.json.bak`，随后自动重启使新配置生效。

开发时也可以单独启动编辑器：

```powershell
cargo run -p kbshare-tray --bin kbshare-config -- runtime_alpha/config.json kbshare
```

编辑器仅监听随机的 `127.0.0.1` 端口，并为每次启动生成一次性 URL。

## Flow-lite（Logitech Easy-Switch）

先在连接鼠标的机器上只读探测 HID++ 设备：

```powershell
cargo run -p kbshare-flow -- inspect
```

Windows 和 Linux 都支持 HID++ 探测与切换。Linux 通过 `/dev/hidraw*`
访问设备；当前用户必须对 Logitech hidraw 节点有读写权限。桌面 Linux
可以添加以下 udev 规则：

```udev
# /etc/udev/rules.d/70-kbshare-logitech.rules
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="046d", MODE="0660", GROUP="input", TAG+="uaccess"
```

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=hidraw
sudo usermod -aG input "$USER"
```

重新登录后运行 `cargo run -p kbshare-flow -- collections` 检查设备集合。
WSL 不会自动暴露 Windows USB 设备；接收器需要先通过 USB 透传连接到 WSL，
并确认发行版中出现 `/dev/hidraw*`，之后 Flow-lite 的操作与普通 Linux 相同。

`flow_lite.enabled` 开启后，鼠标从布局中指向当前对端的屏幕边缘切换机器；
默认布局是本机在左、对端在右。host 编号从 0 开始，因此设备 3 的
`host_index` 是 `2`。

配置编辑器的 Flow-lite 页面提供二维设备画布。本机、当前配对端和手动添加的
离线设备都可以拖动重排；节点位置决定鼠标从屏幕左、右、上、下哪条边切向
当前在线对端。每个节点保存稳定 ID、显示名和 Easy-Switch 通道。

两端建立 TLS 会话后会交换完整布局。布局采用版本号与 writer ID 做确定性的
last-write-wins：较新的完整布局覆盖较旧布局，并写回对端配置；离线设备下次
连接时也会收到当前最新版。修改布局后保存并重启任一端即可触发同步。

Bolt/Unifying Host 推荐配置探测到的 receiver `slot`。蓝牙直连或不确定
slot 时可省略，程序会使用 HID++ direct device index `0xff` 或扫描 receiver
slot。也可单独验证切换：

```powershell
cargo run -p kbshare-flow -- switch --host 2 --slot 1
```
