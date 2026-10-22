# Changelog

## 1.0.0 — 2026-10-22

- 首个正式版本，支持 Windows 和 Linux 间的键盘共享、鼠标活动切换和断线按键释放。
- TLS 加密、证书指纹 TOFU、可选云端节点发现。
- 文本、图片和文件剪贴板通过独立 TLS 通道同步；小于 10 MiB 的文件组立即传输，较大文件组在粘贴读取时传输。
- Windows OLE、Linux X11 / Wayland 延迟文件读取；托盘提供剪贴板传输状态。
- Logitech HID++ / Easy-Switch、设备布局同步和浏览器配置向导。
- GitHub Actions 自动执行格式检查、Clippy、Linux / Windows 测试及 release 构建；版本标签自动发布压缩包与 SHA-256 校验文件。

升级时请同时更新并重启两端。剪贴板协议 v5 与旧版 v3/v4 不兼容。
真实硬件、桌面授权和双机剪贴板行为仍需按 `docs/manual_test.md` 联调。
