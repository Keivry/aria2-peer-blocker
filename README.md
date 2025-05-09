# Aria2 Peer Blocker

[中文](README_zh.md) | [English](README.md)

`Aria2 Peer Blocker`
A simple tool on Linux designed to block unwelcome BitTorrent peers for Aria2.

## Features

- **Peer Blocking**: Block BT peers based on predefined rules.
- **Iptables & Ipset based**: Uses iptables and ipset for blocking.

## Getting Started

### Installation

#### Download Prebuilt Binaries

You can download the latest release from the [Releases page](https://github.com/Keivry/aria2-peer-blocker/releases)

#### Manual Build

To build the project manually, ensure you have [Rust](https://www.rust-lang.org/tools/install) installed on your system.

1. Install dependencies (e.g. for Ubuntu):

   ```bash
   sudo apt install libipset-dev libclang-dev
   ```

1. Clone the repository:

   ```bash
   git clone https://github.com/Keivry/aria2-peer-blocker.git
   cd aria2-peer-blocker
   ```

1. Build the project:

   ```bash
   cargo build --release
   ```

### Configuration

See [`config.toml`](config.toml)

### Usage

#### Manually run the program

```bash
/path/to/aria2-peer-blocker -c /path/to/config.toml

```

#### Using systemd service

Create a systemd service file at `/etc/systemd/system/aria2-peer-blocker.service`:

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

Enable and start the service:

```bash
sudo systemctl enable aria2-peer-blocker.service
sudo systemctl start aria2-peer-blocker.service
```

#### Create firewall rules

##### Using iptables

```bash
sudo iptables -t raw -A PREROUTING -m set --match-set PeerBlock src -j DROP
sudo ip6tables -t raw -A PREROUTING -m set --match-set PeerBlockv6 src -j DROP
```

## Contributing

Contributions are welcome!
Please open an issue or submit a pull request to help improve this project.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
