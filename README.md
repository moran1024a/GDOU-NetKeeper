# GDOU NetKeeper

Linux SRUN 校园网自动认证服务，目标平台为 Ubuntu 24.04，支持有线、Wi-Fi 和可选网卡绑定。
启动即检查网络，离线自动认证；默认在线每 60 秒检查，失败每 15 秒重试。
目前仅完成编译和离线模拟验证，尚未验证真实校园网认证。

## 安装

从 [Releases](https://github.com/moran1024a/GDOU-NetKeeper/releases) 下载 `.deb` 和对应的 `.deb.sha256` 到同一目录。
在 Ubuntu 24.04 amd64 上校验并安装，填写配置后启用服务：

```bash
sha256sum -c gdou-netkeeper_0.1.0-1_amd64.deb.sha256
sudo apt install ./gdou-netkeeper_0.1.0-1_amd64.deb
sudoedit /etc/netkeeper/config.toml
sudo netkeeper --check
sudo systemctl enable --now netkeeper
```

配置中填写完整账号、密码、Portal 根地址和 `ac_id`，按需指定 `interface`。
首次安装不会自动启用服务。升级保留配置，并重启正在运行的服务。

```bash
systemctl status netkeeper
journalctl -u netkeeper -f
sudo systemctl restart netkeeper  # 修改配置后重启
sudo systemctl stop netkeeper
```

`active` 仅表示进程运行，认证结果以日志中的“已确认在线”为准。
`--check` 不请求网络；`sudo netkeeper --once` 执行一轮认证，确认在线才返回 0，请先停止后台服务再使用。

仅支持 IPv4，网络连接和 DNS 由系统管理。绑定网卡不可用时等待重试，不切换出口。
HTTP 请求禁用环境代理，域名仍由系统 DNS 解析。停止服务不会注销校园网。

卸载保留配置，彻底清除则删除配置：

```bash
sudo apt remove gdou-netkeeper
sudo apt purge gdou-netkeeper
```

## 构建

需要 Rust stable、Python 3.11+、C 链接器和 `dpkg-dev`，在 Ubuntu 24.04 原生构建。

```bash
python3 packaging/build-deb.py
cargo test --locked
```

安装包和 SHA-256 校验文件输出到 `dist/`，运行时无需 Rust 工具链。
依赖已缓存时可使用 `--offline` 打包；测试仅使用本机模拟 Portal。

## 许可证

本项目采用 [MIT License](LICENSE)，第三方依赖保留各自许可证。
