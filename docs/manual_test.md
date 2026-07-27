# 手动联调：真实键盘捕获 / 注入

纯代码层面的验证由 `cargo test` 覆盖（core 单测 + TLS loopback 集成测试）。
本文档记录 **需要真人参与的最终检查**，确保：

1. Windows LL hook 真的在拦截物理按键。
2. 远程模式下，本机**不会**收到被吞掉的按键。
3. 对端 `SendInput` 注入的按键真的落进了目标应用。
4. 断线 / 鼠标回本机时，没有卡键。

> 这套流程需要两台机器，或一台机器上开两个不同的用户会话。**两个 kbshare
> 进程绝对不要同时跑在同一个桌面会话**——LL hook 会互相干扰。

## 预备

两端都先执行 `cargo build --release`，拿到 `target/release/kbshare.exe`。

分别在项目目录下放配置（参考 `examples/config.json`）：

- A 机：`config.json`，`local_id` 填本机名称，`remote_id` 填对端名称，
  `fallback_remote_ips` 填对端 IP。
- B 机：`config.json`，`local_id` 和 `remote_id` 互换。

`local_id < remote_id`（字典序）的一方负责拨号连接，另一方负责监听——
这是内部建链规则，用户无需关心。

首次启动两端都会在 `certs/` 下生成自签名证书，并把对端指纹写进各自的
`trust.json`。如果你启用了 `auto_trust_first_seen`，第一次连接时会自动记住。

## 步骤 1：冷启动

1. 启动两端（顺序无关）：
   ```
   kbshare.exe --config config.json
   ```
2. 观察日志中出现：
   - `kbshare peer starting ... fingerprint=...`
   - 拨号方：`connecting 10.x.x.x:5005`
   - `peer fingerprint verified` 或 `auto-trusting first seen fingerprint`

两端日志中应看到对应的 `peer verified`。

## 步骤 2：触发远程模式

在 **对端** 移动鼠标。本机应在数百毫秒内进入远程模式。

日志：
```
mode transitioned: Remote
```

## 步骤 3：键盘透传

此时在 **本机** 任意窗口（记事本最合适）按下一些字母、Ctrl+A、方向键。

预期：
- 本机自身的记事本**不会**出现任何字符（被 LL hook 吞掉）。
- 对端前台窗口（记事本）看到完整输入，顺序和节奏都对。

常见失败信号：
- 本机窗口也出现了字符 → 说明 LL hook 没生效或 `forwarding_flag` 没被置位。
- 对端漏字 → 检查是否因为 SendInput extended flag 缺失（参见
  `is_extended_vk` 覆盖列表）。
- 出现乱序 → NDJSON 解码问题，应该不会发生；若复现请把 RUST_LOG=debug
  打开并抓一份 `[Key ...]` 日志 + 对端的 `inject` 日志。

## 步骤 4：卡键回归

1. 在本机按住 `Ctrl`，保持不放。
2. 直接把对端进程 **Ctrl+C 杀掉**，或者拔掉网线。
3. 本机应打印 `session ended`，几秒后重连。
4. 松开 `Ctrl`。
5. 在本机按任意字母 → 应当以普通字符出现在本机（因为你已经在 Local
   模式，所有按键不再被吞）。

再次连上对端后：
- 对端应**不再**处于 Ctrl 被按住的状态（可按方向键验证：方向键不应
  触发滚动或选择）。
- 这是 `PressedKeys` 在断线时对对端做 release-all 的效果。

## 步骤 5：Panic 恢复

此处留一个未接的 UI 线索：`HostDriver::on_panic_hotkey()` 已经实现并在单元
测试里证明能 flush。下一步可以把“连按 5 次 Esc”之类的组合键识别接进
capture 回调，调用 `on_panic_hotkey`。目前请用**杀进程**来模拟。

## 步骤 6：本机鼠标抢回

1. 处于远程模式 + 正在打字。
2. 在本机动一下本机鼠标。
3. 预期：模式切 Local；此后按键立刻回本机；对端前台应用里没有残留的
   按下键。

如果出现残留（极少数场景下 SendInput 的 release 还没到），再打一下就该
消失。

## 回归矩阵（建议每次改完 `core/runtime.rs` 过一遍）

| 场景                             | 预期                       |
| -------------------------------- | -------------------------- |
| Ctrl+A 顺序                      | 精确到达                   |
| 按住 Ctrl 断线                   | client 无残留              |
| 远程模式下本机鼠标动             | 立刻回本机                 |
| 远程模式下松手（PeerInactive）   | 自动 flush，client 无残留  |
| 重复 press 同一个键（OS 自动键） | client 只注入一次          |
| 证书被替换                       | 连接被 trust store 拒绝    |
| 未知对端 + auto_trust_first_seen | 自动学习并继续             |
| 未知对端 + 严格模式              | 拒绝并报 `unknown`         |
