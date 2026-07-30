# kbshare

从零重写的版本。目标与原项目一致：根据鼠标活动状态，把一台机器上的键盘输入安全转发到另一台机器。

## 设计要点

- **语言**：Rust（主体使用 blocking I/O + `std::thread`；Wayland portal
  适配器在独立线程内运行一个单线程异步循环）。
- **分层**：
  - `core` —— 纯逻辑，零 I/O。键码映射、状态机、按键跟踪、协议编解码。
  - `net`  —— TLS + 自签证书 + SHA256 指纹 TOFU + 极简注册表客户端。
  - `platform` —— 键盘捕捉、鼠标监听、键盘注入。Windows / Linux / Mock 三套实现。
  - `app` —— 统一可执行程序 `kbshare`，每台机器运行同一二进制。
  - `registry` —— 节点注册服务可执行程序（可选，用于云端发现）。
  - `tray` —— 可复用的系统托盘库与配置编辑器。
  - `flow` —— Logitech HID++ 探测与 Easy-Switch。
- **协议**：NDJSON。每条消息是一行 JSON，方便日志、抓包、重放、测试。
- **剪贴板**：文本、图片和文件剪贴板使用独立的 TLS 连接和工作线程，默认监听 `5006`；
  大段文本、剪贴板 API 卡顿或剪贴板连接重连都不会占用键盘的 `5005` 通道。
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

Linux 构建需要 udev 和 D-Bus 开发包（包名以 Debian/Ubuntu 为例）：

```bash
sudo apt install pkg-config libudev-dev libdbus-1-dev
```

## 本地运行

每台机器运行同一个 `kbshare` 可执行程序，使用各自的配置文件。两台机器的 `local_id` 和 `remote_id` 必须互换：

```powershell
cargo run -p kbshare -- --config runtime_alpha/config.json
cargo run -p kbshare -- --config runtime_beta/config.json
```

真实键盘捕获与注入的双机验证步骤见 `docs/manual_test.md`。

## 剪贴板共享

剪贴板文本、图片和文件默认双向同步。两端都需要开放并配置相同的独立端口：

```json
{
  "tcp_port": 5005,
  "clipboard_enabled": true,
  "clipboard_port": 5006
}
```

连接建立时不会用一台机器的旧内容覆盖另一台；连接后任意一端发生的下一次
文本、截图或文件复制会通过独立 TLS 会话发送到对端。原生图片剪贴板统一编码为 PNG；
图片和文件内容均按 128 KiB 分块流式传输，
接收完成并通过 SHA-256 校验后先写入临时目录。图片会解码并写回原生图片剪贴板；
文件则把接收端本地路径放进系统剪贴板，所以可以直接在资源管理器或文件管理器中粘贴。
每次最多 32 个普通文件、总计 2 GiB；
单张图片编码后最多 64 MiB，目录暂不共享，单次文本上限为 1 MiB。剪贴板会话复用节点证书和同一份 TOFU
信任库，但拥有独立的 socket、读写循环和系统剪贴板轮询线程，因此断开或传输大文件
不会阻塞键盘输入。

若不需要此功能，将 `clipboard_enabled` 设为 `false`。防火墙只需允许监听方的
`tcp_port` 和 `clipboard_port`；云端注册表仍只负责发现 IP，不接触剪贴板内容。

## 云端发现（可选）

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
1. 向注册表 `POST /report` 报告本机 `node_id` 和 IP，之后每 30 秒刷新。
2. 连接前 `GET /node/<remote_id>` 查询对端 IP。
3. 如果注册表不可达或对端未注册，回退到 `fallback_remote_ips`。

注册表只做 IP 发现，不参与 TLS 握手或按键转发——所有键盘数据仍然端到端
加密，注册表看不到任何键盘输入。

## 配置编辑器

Windows 和 Linux 首次启动遇到空配置时，都会在默认浏览器打开相同的交互式配置向导。
Windows 托盘菜单选择 **Edit configuration…** 也会打开该界面。
Linux 状态栏通过 freedesktop StatusNotifierItem 提供相同的状态、指纹、加载配置、
编辑配置、打开日志/配置目录和退出入口；GNOME 需要启用 AppIndicator/KStatusNotifierItem
扩展，KDE Plasma 原生支持。
Linux 的目录和浏览器入口通过 `xdg-open` 打开；加载配置使用浏览器原生文件选择器，
导入 JSON 后检查并保存即可重启应用。
点击 **Setup guide** 后按“本机名称 → 生成/确认 TLS 证书 → 云端发现对端（或手动 IP）→ 鼠标探测与通道 → 设备布局 → 检查应用”完成配置。
证书步骤会显示 SHA-256 指纹；若配置路径已有证书和私钥则只校验并复用，不会覆盖。
鼠标探测不是强制步骤；蓝牙设备或当前切换到另一通道的鼠标可以手动填写。
界面同时保留身份、连接、Flow-lite 和高级 JSON 四个页面；保存时会校验必填字段，
在原配置旁创建 `.json.bak`，随后自动重启使新配置生效。

开发时也可以单独启动编辑器：

```bash
cargo run -p kbshare-tray --bin kbshare-config -- runtime_alpha/config.json kbshare
```

编辑器仅监听随机的 `127.0.0.1` 端口，并为每次启动生成一次性 URL。
如果系统无法自动唤起浏览器，终端会打印该 URL，可手动复制打开。

## Flow-lite（Logitech Easy-Switch）

先在连接鼠标的机器上只读探测 HID++ 设备：

```powershell
cargo run -p kbshare-flow --bin kbshare-flow -- inspect
```

Windows 和 Linux 都支持 HID++ 探测与切换。Linux 通过 `/dev/hidraw*`
访问设备；当前用户必须对 Logitech hidraw 节点有读写权限。仓库提供了
适用于 USB 接收器、USB 直连和蓝牙设备的 udev 规则：

Linux 配置界面的 Flow-Lite 页面可点击 **Install Linux HID access…**。程序会
通过 Polkit 调起桌面认证窗口；授权后由最小化的特权 helper 原子安装规则、重新
加载 udev 并立即重新探测鼠标。配置服务本身始终以普通用户运行。

```bash
sudo install -Dm644 packaging/udev/70-kbshare-logitech.rules \
  /etc/udev/rules.d/70-kbshare-logitech.rules
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=hidraw
```

发行包还应安装 `packaging/polkit/org.kbshare.install-udev.policy` 到
`/usr/share/polkit-1/actions/`，以显示 kbshare 专用的认证动作；开发目录直接运行
时会回退到 Polkit 的通用 `pkexec` 动作。

重新插拔接收器后运行 `cargo run -p kbshare-flow --bin kbshare-flow -- collections`
检查设备集合，再运行 `cargo run -p kbshare-flow --bin kbshare-flow -- inspect`
探测鼠标。探测时应唤醒或移动无线鼠标；接收器在鼠标休眠时可能暂时返回
`CONNECTION_REQUEST_FAILED`，程序会自动重试。若仍无结果，设置
`KBSHARE_FLOW_DEBUG=1` 可输出 HID++ 请求和响应。
WSL 不会自动暴露 Windows USB 设备；接收器需要先通过 USB 透传连接到 WSL，
并确认发行版中出现 `/dev/hidraw*`，之后 Flow-lite 的操作与普通 Linux 相同。

Linux 的 Flow 边缘判断按桌面协议自动选择实现：

- Wayland 使用 `org.freedesktop.portal.InputCapture` 的 pointer barriers，并通过
  EIS/libei receiver 完成标准会话握手。屏幕区域、多屏外边界、显示器热插拔均由
  compositor 报告，不读取也不推测全局坐标；触发后立即释放捕获并把指针放回本机
  边界内侧。
- X11/XWayland 保留全局光标查询作为兼容回退。

Wayland 桌面必须安装 `xdg-desktop-portal` 及支持 InputCapture 的桌面 portal
后端；首次使用时按桌面提示授权。如果 portal 不提供该接口，日志会明确说明并尝试
X11/XWayland 回退。

Linux 键盘注入同样按会话选择后端。Wayland 优先通过
`org.freedesktop.portal.RemoteDesktop` 授权，并使用 libei sender 把 evdev
keycode 交给 compositor；成功时不访问 `/dev/uinput`。非 Wayland 会话以及 portal
不可用时保留 uinput 回退。若两者均不可用，启动错误会同时列出 portal 和 uinput
失败原因。授权对话框尚未完成时退出应用，会取消等待而不会卡住引擎线程。

键盘捕获与 Flow barrier 共用一个 InputCapture/libei receiver 会话。Wayland
成功授权后不读取 `/dev/input/event*`：越过指向对端的屏幕边缘时 compositor
开始截获键盘，指针向本机方向退回或对端返回时释放。`flow_lite.enabled=false`
时仍可使用这种“仅键盘远程”模式，只跳过 Logitech HID 切换。Portal 不可用时才
回退 evdev；若 evdev 也不可读，错误会同时列出两条捕获路径的失败原因。

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
