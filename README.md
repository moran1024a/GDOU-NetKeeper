# GDOU NetKeeper

Linux SRUN 校园网认证服务，目标平台 Ubuntu 24.04，支持有线、Wi-Fi 和网卡绑定。
提供终端菜单、认证参数识别、主动注销、快速连通性探测和自动恢复，由 systemd 管理后台进程。

## 安装与使用

从 [Releases](https://github.com/moran1024a/GDOU-NetKeeper/releases) 下载 `.deb` 和 `.deb.sha256`，放在同一目录校验并安装：

```bash
sha256sum -c gdou-netkeeper_0.3.3-1_amd64.deb.sha256
sudo apt install ./gdou-netkeeper_0.3.3-1_amd64.deb
sudo netkeeper
```

首次运行或配置无效时自动进入设置，保存后启动。填写账号、密码、Portal 根地址和 `ac_id`；
网卡通过列表选择，显示连接状态和 IPv4，也可选择跟随系统路由。
菜单使用 ↑↓ / Tab 选择、Enter 确认、Esc 返回；输入支持左右移动、删除、粘贴和 Ctrl+U 清空。
所有输入均明文显示，包括密码。

认证参数缺失时，选择网卡后会尝试自动识别；也可在设置中选择“自动识别 Portal / ac_id”。
探测绑定所选网卡，优先读取已填写的 Portal，然后尝试 HTTP 连通性页面的认证跳转；
支持 HTTP 重定向、常见 HTML / JavaScript 跳转文字和页面内的 `ac_id`，不执行页面脚本。
最多读取 6 个页面、等待 10 秒，Esc 可取消；不会登录或注销，失败保留原参数。
也可选择“从认证页面链接导入”，粘贴含 `ac_id` 的完整地址，自动拆分根地址和编号。
识别或导入后先确认回填，再保存配置。已经在线且没有已知 Portal 时，可能无法自动识别，仍可手动填写。

| 命令 | 行为 |
| --- | --- |
| `sudo netkeeper start` | 缺少有效配置时先设置；等待确认在线，成功后退出前台，后台继续巡检 |
| `sudo netkeeper stop` | 停止后台及正在执行的请求，不再巡检或重试；不会注销校园网 |
| `sudo netkeeper logout` | 停止服务，主动注销当前校园网登录并确认下线；不自动重连 |
| `netkeeper status` | 显示进程、网卡、最近检查结果和记录时间，不发起网络请求 |
| `sudo netkeeper settings` | 修改配置；服务运行时可选择立即重启应用或下次启动生效 |

启动最多等待 30 秒。首次认证失败、超时或取消会显示原因并停止本次新启动的服务。
服务正常时，重复 `start` 会立即重新确认在线，不重复创建进程；失败或取消时保留原有服务。
退出菜单不会停止已启动的后台服务。

TUI 的“注销校园网”需要确认，命令行 `logout` 直接执行；需要已有有效配置，不会自动进入设置或启动。
注销通过所选网卡操作当前登录，只发送一次注销请求，随后最多查询 3 次确认下线。
服务未能停止时不发送注销请求；注销失败或结果无法确认时，服务仍保持停止，显示具体原因。
网络不通不代表注销成功；如有其他自动登录工具，应先暂停它们。依赖该校园网出口的远程 SSH 可能断开。

正常时每 **2 秒**开始一轮 ICMP 探测，单目标超时 **1 秒**。先检测主目标，失败后并行检查备用；
任意目标成功就清零失败计数。连续 **3 轮全部失败**提前触发 Portal 检查，正常时仍每 **300 秒**巡检 Portal。
探测和认证串行执行，超时不堆积补跑。Portal 在线但公网探测失败时仅复查，不重复登录。

| 默认目标 | 地址 |
| --- | --- |
| 主目标：阿里公共 DNS | `223.5.5.5` |
| 备用：腾讯 DNSPod、百度公共 DNS、阿里公共 DNS | `119.29.29.29`、`180.76.76.76`、`223.6.6.6` |

恢复阶段统一按 **5 秒 × 3 次 → 15 秒 × 3 次 → 持续 30 秒**重试；等待从本轮结束后计算。
期间暂停普通轮询，重复 `start` 也不会绕过等待；恢复时确认公网探测通过后重置计数。
明确识别的凭据错误会暂停自动请求，修改配置并重启后恢复；未知错误仍按退避重试。
服务运行时，普通用户可用 `status` 查看最近探测、连续失败轮数、恢复尝试次数和下次重试时间。
停止后自动清理运行状态文件；历史记录通过 `journalctl -u netkeeper` 查看。

在设置中可修改各项间隔、超时、失败门槛，切换 ICMP / TCP，编辑主目标及最多三个可选备用目标。
目标使用 IPv4 地址；TCP 模式的所有目标使用同一可配置端口，默认 53。全部探测绑定所选网卡。
默认目标尚未在目标校园网验证；这些地址仅用于探测，不修改系统 DNS。

配置保存在 `/etc/netkeeper/config.toml`，权限为 `0600`；取消设置不覆盖原配置。
首次安装不自动启动，也不启用开机自启。升级保留配置，并重启正在运行的服务。
旧配置可继续使用，缺少的字段采用默认值；已有 `online_interval_secs` 值保留。
旧 `retry_interval_secs` 忽略，保存后移除，改用 `retry_intervals_secs = [5, 15, 30]`。
已有开机自启设置会保留，可用 `sudo systemctl disable netkeeper` 关闭。
非交互环境支持 `start`、`stop`、`status`、`logout`；配置无效时提示先在终端完成设置。

仅支持 IPv4，网络连接、Wi-Fi 接入和 DNS 由系统管理，不修改网络拓扑。
绑定网卡不可用时报告错误，不切换出口；请求禁用环境代理，域名由系统 DNS 解析。
查看日志使用 `journalctl -u netkeeper`。卸载使用 `sudo apt remove gdou-netkeeper`，
删除配置及运行记录使用 `sudo apt purge gdou-netkeeper`。

## 构建

需要 Rust stable、Python 3.11+、C 链接器、`dpkg-dev` 和 `iputils-ping`，在 Ubuntu 24.04 原生构建。

```bash
cargo build --locked
python3 packaging/build-deb.py
```

安装包和 SHA-256 文件输出到 `dist/`，运行时无需 Rust 工具链；安装 deb 会自动安装 `iputils-ping` 依赖。
依赖已缓存时可用 `python3 packaging/build-deb.py --offline` 打包。

本项目采用 [MIT License](LICENSE)，第三方依赖保留各自许可证。
