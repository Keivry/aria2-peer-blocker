# Aria2 Peer Blocker

[中文](README_zh.md) | [English](README.md)

`Aria2 Peer Blocker`
一个在 Linux 上设计用于阻止 Aria2 中不受欢迎的 BitTorrent 节点的简单工具。

## 功能

- **对等节点阻止**：根据预定义规则阻止不需要的对等节点。
- **基于 Iptables & Ipset**: 使用 iptables 和 ipset 阻止节点。

## 入门指南

### 安装

#### 下载预构建二进制文件

您可以从 [发布页面](https://github.com/Keivry/aria2-peer-blocker/releases) 下载最新版本

#### 手动构建

要手动构建项目，请确保您的系统上已安装 [Rust](https://www.rust-lang.org/tools/install)。

1. 安装依赖项（例如 Ubuntu）：

   ```bash
   sudo apt install libipset-dev libclang-dev
   ```

1. 克隆仓库：

   ```bash
   git clone https://github.com/Keivry/aria2-peer-blocker.git
   cd aria2-peer-blocker
   ```

1. 构建项目：

   ```bash
   cargo build --release
   ```

### 配置

请参阅 [`config.toml`](config.toml)

### 使用方法

#### 手动运行程序

```bash
/path/to/aria2-peer-blocker -c /path/to/config.toml

```

#### 使用 systemd 服务

在 `/etc/systemd/system/aria2-peer-blocker.service` 创建 systemd 服务文件：

```bash
[Unit]
Description=Aria2 Peer Blocker
After=network.target aria2.service

[Service]
Type=simple
ExecStart=/path/to/aria2-peer-blocker -c /path/to/config.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

启用并启动服务：

```bash
sudo systemctl enable aria2-peer-blocker.service
sudo systemctl start aria2-peer-blocker.service
```

#### 创建防火墙规则

##### 使用 iptables

```bash
sudo iptables -t raw -A PREROUTING \
        -m set --match-set aria2-peer-blocker-set_v4 src -j DROP
sudo ip6tables -t raw -A PREROUTING \
        -m set --match-set aria2-peer-blocker-set_v6 src -j DROP
```

## 贡献

欢迎贡献！
请提交 issue 或 pull request 来帮助改进这个项目。

## 许可证

本项目基于 [Apache License 2.0](LICENSE) 许可。
