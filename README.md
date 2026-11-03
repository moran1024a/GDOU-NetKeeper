# GDOU NetKeeper

Linux SRUN 校园网认证服务，目标平台 Ubuntu 24.04，支持有线、Wi-Fi 和网卡绑定。
v0.2.0 提供终端菜单和四个管理命令，由 systemd 管理后台进程。

## 安装与使用

将构建得到的 `.deb` 和 `.deb.sha256` 放在同一目录，校验并安装：

```bash
sha256sum -c gdou-netkeeper_0.2.0-1_amd64.deb.sha256
sudo apt install ./gdou-netkeeper_0.2.0-1_amd64.deb
sudo netkeeper
```

首次运行或配置无效时自动进入设置，保存后启动。填写账号、密码、Portal 根地址和 `ac_id`；
网卡通过列表选择，显示连接状态和 IPv4，也可选择跟随系统路由。
菜单使用 ↑↓ / Tab 选择、Enter 确认、Esc 返回；输入支持左右移动、删除、粘贴和 Ctrl+U 清空。
所有输入均明文显示，包括密码。

| 命令 | 行为 |
| --- | --- |
| `sudo netkeeper start` | 缺少有效配置时先设置；等待确认在线，成功后退出前台，后台继续巡检 |
| `sudo netkeeper stop` | 停止后台及正在执行的请求，不再巡检或重试；不会注销校园网 |
| `netkeeper status` | 显示进程、网卡、最近检查结果和记录时间，不发起网络请求 |
| `sudo netkeeper settings` | 修改配置；服务运行时可选择立即重启应用或下次启动生效 |

启动最多等待 30 秒。首次认证失败、超时或取消会显示原因并停止本次新启动的服务。
重复 `start` 会立即重新确认在线，不重复创建进程；失败或取消时保留原有服务。
首次成功后，默认每 60 秒巡检，掉线或认证失败每 15 秒重试；间隔可在设置中修改。
退出菜单不会停止已启动的后台服务。

配置保存在 `/etc/netkeeper/config.toml`，权限为 `0600`；取消设置不覆盖原配置。
首次安装不自动启动，也不启用开机自启。升级保留配置，并重启正在运行的服务。
从 0.1.0 升级可直接安装新版包，原配置仍可使用；旧的 `--once` / `--check` 已移除。
已有开机自启设置会保留，可用 `sudo systemctl disable netkeeper` 关闭。
非交互环境支持 `start`、`stop`、`status`；配置无效时提示先在终端完成设置。

仅支持 IPv4，网络连接、Wi-Fi 接入和 DNS 由系统管理，不修改网络拓扑。
绑定网卡不可用时报告错误，不切换出口；请求禁用环境代理，域名由系统 DNS 解析。
查看日志使用 `journalctl -u netkeeper`。卸载使用 `sudo apt remove gdou-netkeeper`，
删除配置及运行记录使用 `sudo apt purge gdou-netkeeper`。

## 构建与测试

需要 Rust stable、Python 3.11+、C 链接器和 `dpkg-dev`，在 Ubuntu 24.04 原生构建。

```bash
cargo build --locked
cargo test --locked
python3 tests/behavior.py
python3 packaging/build-deb.py
```

安装包和 SHA-256 文件输出到 `dist/`，运行时无需 Rust 工具链。
依赖已缓存时可用 `python3 packaging/build-deb.py --offline` 打包。
测试使用本机模拟 Portal 和伪终端，覆盖首次认证、失败清理、恢复、停止以及菜单交互；
不连接校园网，也不安装或启动本机 systemd 服务。新管理流程尚未在校园网实机验证。

本项目采用 [MIT License](LICENSE)，第三方依赖保留各自许可证。
