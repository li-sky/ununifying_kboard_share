# kbshare

[![CI](https://github.com/li-sky/ununifying_kboard_share/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/li-sky/ununifying_kboard_share/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/li-sky/ununifying_kboard_share)](https://github.com/li-sky/ununifying_kboard_share/releases)

在 Windows 和 Linux 之间共享键盘与剪贴板。两台电脑运行同一个程序，kbshare 根据鼠标活动和设备布局切换键盘输入；搭配支持 Easy-Switch 的 Logitech 鼠标，还可以在越过屏幕边缘时切换鼠标连接的电脑。

kbshare 使用 Rust 编写。键盘与剪贴板通过各自独立的 TLS 连接传输，文件下载不会占用键盘通道。切回本机或连接断开时，程序会释放已跟踪的按键。

## 下载

当前版本：**1.0.1**。从 [GitHub Releases](https://github.com/li-sky/ununifying_kboard_share/releases/latest) 下载，版本变化见 [CHANGELOG](CHANGELOG.md)。

| 系统 | 下载文件 | 要求 |
| --- | --- | --- |
| Windows x64 | `kbshare-v1.0.1-x86_64-pc-windows-msvc.zip` | Windows 桌面环境 |
| Linux x64 | `kbshare-v1.0.1-x86_64-unknown-linux-gnu.tar.gz` | Ubuntu 24.04 或兼容系统，glibc 2.39+ |

每个压缩包包含以下程序，以及配置样例和使用文档：

| 程序 | 用途 |
| --- | --- |
| `kbshare` | 两台电脑都需要运行的主程序 |
| `kbshare-config` | 独立启动浏览器配置编辑器 |
| `kbshare-flow` | 探测 Logitech HID++ 设备、手动切换 Easy-Switch 通道 |
| `kbshare-registry` | 可选的节点发现服务，部署在服务器上 |

Release 提供 `SHA256SUMS`，可用于核对下载文件。Linux 包还包含 udev 和 Polkit 规则；其他架构或较旧发行版可尝试[从源码构建](#从源码构建)。

## 快速开始

1. 在两台电脑上解压对应的压缩包，运行 `kbshare.exe`（Windows）或 `./kbshare`（Linux）。首次启动会创建配置文件并在默认浏览器中打开配置向导。
2. 分别设置本机名称和对端名称，例如 A 机使用 `alpha` / `beta`，B 机使用 `beta` / `alpha`。
3. 按向导生成各自的证书，填写对端 IP；需要自动发现时，再配置可选的注册服务。核对双方显示的证书指纹。
4. 如果使用 Logitech Easy-Switch，探测鼠标、填写通道，并在设备画布上排列电脑位置。不使用此功能时可以跳过鼠标配置。
5. 保存配置，程序会自动重启。允许连接所需的防火墙访问；Wayland 桌面还需按系统对话框授予输入权限。

默认端口为 **TCP 5005（键盘）** 和 **TCP 5006（剪贴板）**。两台机器必须能够直接连接；注册服务只帮助查找地址，不提供流量中继或 NAT 穿透。

托盘菜单可以查看连接状态与指纹、修改或加载配置、打开日志目录和退出。Linux 的 GNOME 桌面需要 AppIndicator / KStatusNotifierItem 扩展才能显示托盘；KDE Plasma 原生支持。

在可捕获按键的情况下，`Ctrl+Alt+Shift+Pause` 可退出程序。不要在同一个桌面会话中同时运行多个 kbshare 实例，以免输入捕获互相干扰。

## 配置

默认读取当前工作目录的 `config.json`，也可以显式指定路径：

```bash
./kbshare --config /path/to/config.json
```

Windows 对应命令为 `.\kbshare.exe --config C:\path\to\config.json`。

以下是 A 机的最小配置示例；B 机需互换两个 ID，并把 IP 改成 A 机的地址：

```json
{
  "local_id": "alpha",
  "remote_id": "beta",
  "fallback_remote_ips": ["192.168.1.42"],
  "tcp_port": 5005,
  "clipboard_enabled": true,
  "clipboard_port": 5006
}
```

更多字段见 [examples/config.json](examples/config.json)。证书和信任库的相对路径以配置文件所在目录为基准。每台机器应生成自己的证书；发行包不携带证书或私钥。

默认使用首次信任（TOFU）：首次见到对端时记录证书指纹，之后拒绝指纹不匹配的连接。`auto_trust_first_seen: false` 会拒绝尚未加入信任库的对端。更换机器或证书后，应先确认身份再更新信任记录。

配置编辑器仅监听本机 `127.0.0.1` 的随机端口，并使用一次性 URL。保存时会校验配置、保留 `.json.bak` 备份并重启程序。如果浏览器未自动打开，可从终端输出中取得 URL。

## 剪贴板共享

连接后，任一端新复制的文本、图片和普通文件都会同步到对端。建立连接时不会用一方已有的剪贴板覆盖另一方；不需要共享时，将 `clipboard_enabled` 设为 `false`。

| 内容 | 传输方式与限制 |
| --- | --- |
| 文本、HTML、RTF | 一起同步，合计不超过 1 MiB |
| 图片 | 编码为 PNG 后立即传输；编码后不超过 64 MiB，解码后不超过约 3355 万像素 |
| 总计小于 10 MiB 的文件组 | 立即传输 |
| 总计大于等于 10 MiB 的文件组 | 先同步文件信息，目标应用读取内容时才开始下载，通常发生在粘贴时 |

一次最多共享 32 个普通文件，总大小不超过 2 GiB，暂不支持目录。图片和文件在接收完成、通过 SHA-256 校验后才交给目标应用。

大文件延迟读取在 Windows 上使用 OLE 虚拟文件，在 Linux 上使用 X11 selection 或 Wayland ext/wlr data-control。使用时需注意：

- 等待粘贴期间，源机器必须保持连接；复制新内容或断开连接会取消未完成的下载。
- 剪贴板历史工具主动读取内容，也可能触发下载。
- Wayland 合成器必须支持相应的 data-control 协议；部分 Linux 文件管理器可能因等待下载过久而超时。
- 文件会完整下载到临时目录后交付，不支持部分文件读取或断点续传。

托盘会显示剪贴板的连接、等待粘贴、传输或失败状态。失败详情可从 **Open log folder** 查看。

**升级到 1.0.0 时，请同时更新并重启两端。剪贴板协议 v5 与旧版 v3/v4 不兼容。**

## Logitech Easy-Switch

Flow-lite 使用 HID++ 探测设备，并在指针越过配置中的屏幕边缘时发送 Easy-Switch 指令。需要鼠标本身支持相应功能；kbshare 不通过网络转发通用鼠标移动。

在配置编辑器的 **Flow-lite** 页面中，填写两台电脑对应的通道并拖动设备位置。通道编号从 0 开始：鼠标上的设备 1、2、3 对应 `0`、`1`、`2`。布局会在两端连接后同步，较新的完整布局覆盖较旧布局。

可以使用命令行检查设备：

```bash
./kbshare-flow collections
./kbshare-flow inspect
```

手动切到设备 3 的示例（会实际切换鼠标连接）：

```bash
./kbshare-flow switch --host 2 --slot 1
```

`slot` 应使用探测得到的接收器编号；蓝牙直连或不确定编号时可省略。探测前先移动鼠标将其唤醒；需要诊断 HID++ 通信时，设置 `KBSHARE_FLOW_DEBUG=1`。

### Linux 权限与桌面支持

Logitech 设备访问需要当前用户对 `/dev/hidraw*` 有相应权限。配置页面的 **Install Linux HID access…** 可通过 Polkit 授权安装规则，也可以手动安装：

```bash
sudo install -Dm644 packaging/udev/70-kbshare-logitech.rules \
  /etc/udev/rules.d/70-kbshare-logitech.rules
sudo install -Dm644 packaging/polkit/org.kbshare.install-udev.policy \
  /usr/share/polkit-1/actions/org.kbshare.install-udev.policy
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=hidraw
```

必要时重新插拔接收器，再运行 `kbshare-flow inspect`。WSL 需要先完成 USB 透传，并能看到对应的 `/dev/hidraw*` 节点。

Wayland 键盘捕获和屏幕边缘检测使用 `InputCapture` portal 与 libei，键盘注入使用 `RemoteDesktop` portal 与 libei。桌面需要安装 `xdg-desktop-portal` 及提供对应接口的后端，并完成系统授权。关闭 Flow-lite 只跳过 Logitech 通道切换，仍可使用 Wayland 的边缘触发键盘远程模式。

Portal 不可用时，程序会尝试 evdev / uinput，以及 X11 / XWayland 边缘检测回退。回退路径需要相应的设备访问权限；纯 Wayland 环境不保证有可用的 X11 回退。具体原因会写入日志。

## 可选的云端发现

`kbshare-registry` 保存节点上报的地址，帮助 IP 经常变化的设备找到对端。它不接触键盘或剪贴板内容；发现地址无法连接时，客户端仍会尝试 `fallback_remote_ips`。

在两台机器的配置编辑器中填写 **Cloud discovery endpoint**，或设置 `vps_base_url`。服务器安装、HTTPS 反向代理和 systemd 配置见[注册服务部署文档](docs/registry.md)。

## 从源码构建

安装 Rust 工具链后，仓库中的 `rust-toolchain.toml` 会选择 stable，并包含 rustfmt 和 Clippy。
Windows 需要 MSVC C++ 构建工具。Debian / Ubuntu 上先安装开发依赖：

```bash
sudo apt install pkg-config libudev-dev libdbus-1-dev
```

克隆并构建：

```bash
git clone https://github.com/li-sky/ununifying_kboard_share.git
cd ununifying_kboard_share
cargo build --workspace --bins --release --locked
```

产物位于 `target/release/`。开发时可以直接运行：

```bash
cargo run -p kbshare -- --config runtime_alpha/config.json
```

### 测试与发布

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked
cargo test --workspace --locked
```

GitHub Actions 在分支推送和 Pull Request 时运行格式检查、Clippy、Linux / Windows 全工作区测试与 release 构建。现有 Clippy warning 会出现在日志中，编译或 lint error 会阻止通过。

发布时更新 workspace 版本、`Cargo.lock`、CHANGELOG 和 `docs/releases/v<版本>.md`，提交后推送对应的 `v<版本>` 标签。CI 会核对标签与包版本，在所有检查通过后发布压缩包及 SHA-256 校验文件。

自动测试覆盖状态机、协议、Mock 输入和本机 TLS 连接；真实键盘、桌面授权、Logitech 设备与跨机器剪贴板需要按[手动联调文档](docs/manual_test.md)验证。

### 代码结构

| 目录 | 职责 |
| --- | --- |
| `crates/app` | 主程序、连接生命周期与剪贴板同步 |
| `crates/core` | 协议、键码映射、状态机与按键跟踪 |
| `crates/net` | TLS、证书、信任库与节点发现 |
| `crates/platform` | Windows、Linux 和 Mock 输入后端 |
| `crates/tray` | 托盘和浏览器配置编辑器 |
| `crates/flow` | Logitech HID++ 与设备布局 |
| `crates/registry` | 可选的节点发现服务 |
| `packaging` | Linux udev / Polkit 规则 |

## 排查问题

| 现象 | 优先检查 |
| --- | --- |
| 两端无法连接 | ID 是否互换、对端 IP 是否可达、防火墙是否允许 TCP 5005 / 5006、证书指纹是否匹配 |
| 键盘可用，剪贴板不通 | 两端版本是否一致、是否启用剪贴板、TCP 5006 是否可达、托盘中的失败状态 |
| 大文件复制后没有立即下载 | 文件组达到 10 MiB 时会等待目标应用读取；在对端粘贴，并保持源端在线 |
| Linux 无法捕获或注入按键 | Portal 接口与授权，或 evdev / uinput 回退的设备权限 |
| Logitech 探测不到鼠标 | 鼠标是否唤醒、当前连接通道、接收器 slot、Linux hidraw 权限 |
| Linux 看不到托盘 | 桌面是否支持 StatusNotifierItem；GNOME 是否启用相应扩展 |

### 日志与保留期限

日志通常位于配置文件旁的 `logs/`；使用 `runtime_*` 配置目录时，日志放在它的上一级目录下。可从托盘打开日志目录。

- 按 **UTC 日期**每天写入一个 `kbshare.YYYY-MM-DD.log` 文件，同一天重启继续追加。
- 保留当天及前 6 天的日志，启动时及运行期间每分钟清理过期文件；程序空闲时也会清理，关闭期间过期的日志在下次启动时删除。
- 旧版 `kbshare.log` 不再写入，最后修改时间满 7 天后自动清理；其他文件、目录和符号链接不参与清理。
- 不记录逐键捕获、转发或注入的键码与动作。`RUST_LOG=debug` / `trace` 仍可用于连接与状态排障，但不会重新开启逐键日志。
