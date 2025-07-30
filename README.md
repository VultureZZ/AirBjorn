# <img src="https://github.com/user-attachments/assets/c5eb4cc1-0c3d-497d-9422-1614651a84ab" alt="thumbnail_IMG_0546" width="33"> Bjorn

![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)
![Status](https://img.shields.io/badge/Status-Development-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Reddit](https://img.shields.io/badge/Reddit-Bjorn__CyberViking-orange?style=for-the-badge&logo=reddit)](https://www.reddit.com/r/Bjorn_CyberViking)
[![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289DA?style=for-the-badge&logo=discord)](https://discord.com/invite/B3ZH9taVfT)

<p align="center">
  <img src="https://github.com/user-attachments/assets/c5eb4cc1-0c3d-497d-9422-1614651a84ab" alt="thumbnail_IMG_0546" width="150">
  <img src="https://github.com/user-attachments/assets/1b490f07-f28e-4418-8d41-14f1492890c6" alt="bjorn_epd-removebg-preview" width="150">
</p>

Bjorn is a « Tamagotchi like » sophisticated, autonomous network scanning, vulnerability assessment, and offensive security tool designed to run on a Raspberry Pi equipped with a 2.13-inch e-Paper HAT. This document provides a detailed explanation of the project.


## 📚 Table of Contents

- [Introduction](#-introduction)
- [Features](#-features)
- [Getting Started](#-getting-started)
  - [Prerequisites](#-prerequisites)
  - [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Example](#-usage-example)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

## 📄 Introduction

Bjorn is a powerful tool designed to perform comprehensive network scanning, vulnerability assessment, and data ex-filtration. Its modular design and extensive configuration options allow for flexible and targeted operations. By combining different actions and orchestrating them intelligently, Bjorn can provide valuable insights into network security and help identify and mitigate potential risks.

The e-Paper HAT display and web interface make it easy to monitor and interact with Bjorn, providing real-time updates and status information. With its extensible architecture and customizable actions, Bjorn can be adapted to suit a wide range of security testing and monitoring needs.

## 🌟 Features

- **Network Scanning**: Identifies live hosts and open ports on the network.
- **Vulnerability Assessment**: Performs vulnerability scans using Nmap and other tools.
- **System Attacks**: Conducts brute-force attacks on various services (FTP, SSH, SMB, RDP, Telnet, SQL).
- **Wireless Network Attacks**: Performs wireless network scanning and attacks using wifite2 with external wifi adapter support.
- **File Stealing**: Extracts data from vulnerable services.
- **User Interface**: Real-time display on the e-Paper HAT and web interface for monitoring and interaction.

![Bjorn Display](https://github.com/infinition/Bjorn/assets/37984399/bcad830d-77d6-4f3e-833d-473eadd33921)

## 🚀 Getting Started

## 📌 Prerequisites

### 📋 Prerequisites for RPI zero W (32bits)

![image](https://github.com/user-attachments/assets/3980ec5f-a8fc-4848-ab25-4356e0529639)

- Raspberry Pi OS installed.
    - Stable:
      - System: 32-bit
      - Kernel version: 6.6
      - Debian version: 12 (bookworm) '2024-10-22-raspios-bookworm-armhf-lite'
- Username and hostname set to `bjorn`.
- 2.13-inch e-Paper HAT connected to GPIO pins.

### 📋 Prerequisites for RPI zero W2 (64bits)

![image](https://github.com/user-attachments/assets/e8d276be-4cb2-474d-a74d-b5b6704d22f5)

I did not develop Bjorn for the raspberry pi zero w2 64bits, but several feedbacks have attested that the installation worked perfectly.

- Raspberry Pi OS installed.
    - Stable:
      - System: 64-bit
      - Kernel version: 6.6
      - Debian version: 12 (bookworm) '2024-10-22-raspios-bookworm-arm64-lite'
- Username and hostname set to `bjorn`.
- 2.13-inch e-Paper HAT connected to GPIO pins.


At the moment the paper screen v2  v4 have been tested and implemented.
I juste hope the V1 & V3 will work the same.

### 📡 Wireless Network Support (Wifite2)

Bjorn includes comprehensive wireless network attack capabilities using wifite2 with external wifi adapter support:

#### **External WiFi Adapter Requirements**
- **Compatible Adapters**: Supports USB wifi adapters with monitor mode capabilities
- **Recommended Adapters**:
  - Alfa AWUS036ACH (802.11ac)
  - Alfa AWUS036NHA (802.11n)
  - TP-Link TL-WN722N v1 (802.11n)
  - Panda PAU09 (802.11n)
- **Driver Support**: Most adapters work with standard Linux drivers
- **Monitor Mode**: Adapter must support monitor mode for packet injection
- **Automatic Detection**: Bjorn automatically detects Alfa USB wifi adapters and only activates wireless attacks when one is connected

#### **Wifite2 Features**
- **Network Discovery**: Automatic scanning for available wireless networks
- **Attack Methods**:
  - WPS Pixie-Dust attacks
  - WPA handshake capture and cracking
  - PMKID attacks
- **Smart Targeting**: Prioritizes WPS-enabled networks when configured
- **Automatic Connection**: Connects to successfully cracked networks
- **IDLE Network Scanning**: Automatically connects to unsecured networks during IDLE state for additional reconnaissance
- **Results Storage**: Saves cracked networks and discovered networks to JSON files

#### **Configuration**
Wireless scanning can be configured via `config/shared_config.json`:
```json
{
  "wireless_scan_enabled": true,
  "wireless_require_alfa_adapter": true,
  "wireless_idle_scanning_enabled": true,
  "wireless_attack_timeout": 300,
  "wireless_scan_interval": 600,
  "wireless_wps_priority": true,
  "wireless_pmkid_enabled": true,
  "wireless_handshake_enabled": true
}
```

**Adapter Detection**: By default, Bjorn requires an Alfa USB wifi adapter to be connected before performing wireless attacks. This can be disabled by setting `"wireless_require_alfa_adapter": false` in the configuration.

**IDLE Network Scanning**: When Bjorn is in IDLE state, it can automatically connect to unsecured wifi networks for scanning, then reconnect to the primary network. Enable with `"wireless_idle_scanning_enabled": true`.

#### **Automatic Triggering**
Wireless scanning is automatically triggered when:
- No alive hosts are found on the network
- No wireless-related activity is detected (ports 80, 443, 8080, 8443)
- Wireless scanning is enabled in configuration

⚠️ **Legal Notice**: Only perform wireless attacks on networks you own or have explicit permission to test.

### 📱 E-Ink Display Interface

Bjorn features a sophisticated 2.13-inch e-Paper HAT display that provides real-time status information and visual feedback. The interface is designed to be both functional and visually appealing, with various icons representing different system states and activities.

#### **Connection Status Icons**
- **🌐 WiFi Icon**: Indicates when WiFi is connected and active
- **🔌 USB Icon**: Shows when USB devices are connected and active
- **🔗 Connected Icon**: Displays when PAN (Personal Area Network) is connected
- **📡 Bluetooth Icon**: Indicates Bluetooth connectivity (currently disabled in code)

#### **Statistics Icons**
The display shows various statistics with corresponding icons:
- **🎯 Target Icon**: Number of discovered targets/hosts
- **🔌 Port Icon**: Number of open ports found
- **⚠️ Vulnerability Icon**: Number of vulnerabilities discovered
- **🔑 Credentials Icon**: Number of cracked credentials
- **💰 Money Icon**: Current coin balance (earned from successful attacks)
- **📊 Level Icon**: Current level (progress indicator)
- **🧟 Zombie Icon**: Number of compromised systems
- **📡 Network KB Icon**: Network data transferred (in KB)
- **💾 Data Icon**: Amount of data stolen/exfiltrated
- **⚔️ Attacks Icon**: Number of attacks performed

#### **Status Animation Icons**
Bjorn displays animated status icons that change based on current activities:
- **IDLE**: Default state when no active operations
- **NetworkScanner**: Scanning for network hosts and ports
- **NmapVulnScanner**: Performing vulnerability assessments
- **SSHBruteforce**: Attempting SSH brute force attacks
- **SMBBruteforce**: Attempting SMB brute force attacks
- **RDPBruteforce**: Attempting RDP brute force attacks
- **FTPBruteforce**: Attempting FTP brute force attacks
- **SQLBruteforce**: Attempting SQL brute force attacks
- **TelnetBruteforce**: Attempting Telnet brute force attacks
- **Wifite2Connector**: Performing wireless network attacks
- **Wifite2IdleScan**: Scanning networks while connected to unsecured wifi during IDLE state
- **StealFilesSSH**: Stealing files via SSH
- **StealFilesSMB**: Stealing files via SMB
- **StealFilesRDP**: Stealing files via RDP
- **StealFilesFTP**: Stealing files via FTP
- **StealFilesTelnet**: Stealing files via Telnet
- **StealDataSQL**: Stealing data from SQL databases
- **LogStandalone**: Standalone logging operations
- **LogStandalone2**: Secondary logging operations

#### **Display Layout**
The e-Paper display is organized into several sections:
- **Header**: Shows "BJORN" title and connection status icons
- **Statistics Row 1**: Target, Port, and Vulnerability counts
- **Statistics Row 2**: Credentials, Zombie, and Data counts
- **Status Area**: Current activity status with animated icon
- **Bottom Section**: Coin balance, level, and attack count
- **Comment Area**: AI-generated comments and status messages
- **Decorative Elements**: Viking-themed decorative elements (frise)

#### **Real-Time Updates**
The display updates automatically to show:
- Current system status and activities
- Live statistics as they change
- Connection status indicators
- AI-generated commentary on Bjorn's activities
- Progress indicators for ongoing operations

### 🔨 Installation

The fastest way to install Bjorn is using the automatic installation script :

```bash
# Download and run the installer
wget https://raw.githubusercontent.com/infinition/Bjorn/refs/heads/main/install_bjorn.sh
sudo chmod +x install_bjorn.sh && sudo ./install_bjorn.sh
# Choose the choice 1 for automatic installation. It may take a while as a lot of packages and modules will be installed. You must reboot at the end.
```

For **detailed information** about **installation** process go to [Install Guide](INSTALL.md)

## ⚡ Quick Start

**Need help ? You struggle to find Bjorn's IP after the installation ?**
Use my Bjorn Detector & SSH Launcher :

[https://github.com/infinition/bjorn-detector](https://github.com/infinition/bjorn-detector)

![ezgif-1-a310f5fe8f](https://github.com/user-attachments/assets/182f82f0-5c3a-48a9-a75e-37b9cfa2263a)

**Hmm, You still need help ?**
For **detailed information** about **troubleshooting** go to [Troubleshooting](TROUBLESHOOTING.md)

**Quick Installation**: you can use the fastest way to install **Bjorn** [Getting Started](#-getting-started)

## 💡 Usage Example

Here's a demonstration of how Bjorn autonomously hunts through your network like a Viking raider (fake demo for illustration):

```bash
# Reconnaissance Phase
[NetworkScanner] Discovering alive hosts...
[+] Host found: 192.168.1.100
    ├── Ports: 22,80,445,3306
    └── MAC: 00:11:22:33:44:55

# Wireless Network Discovery
[Wifite2Connector] Scanning for wireless networks...
[+] Networks found: 5
    ├── SSID: HomeNetwork (WPA2)
    ├── SSID: Office_WiFi (WPS Enabled)
    └── SSID: GuestNetwork (Open)

# Wireless Attack Sequence
[Wifite2Connector] Attacking Office_WiFi...
[+] WPS Pixie-Dust attack successful!
[+] Password: office123456
[+] Connected to network successfully

# Attack Sequence
[NmapVulnScanner] Found vulnerabilities on 192.168.1.100
    ├── MySQL 5.5 < 5.7 - User Enumeration
    └── SMB - EternalBlue Candidate

[SSHBruteforce] Cracking credentials...
[+] Success! user:password123
[StealFilesSSH] Extracting sensitive data...

# Automated Data Exfiltration
[SQLBruteforce] Database accessed!
[StealDataSQL] Dumping tables...
[SMBBruteforce] Share accessible
[+] Found config files, credentials, backups...
```

This is just a demo output - actual results will vary based on your network and target configuration.

All discovered data is automatically organized in the data/output/ directory, viewable through both the e-Paper display (as indicators) and web interface. Wireless network results are stored in data/output/wireless_results/ with cracked networks and discovered networks saved as JSON files.
Bjorn works tirelessly, expanding its network knowledge base and growing stronger with each discovery.

No constant monitoring needed - just deploy and let Bjorn do what it does best: hunt for vulnerabilities.

🔧 Expand Bjorn's Arsenal!
Bjorn is designed to be a community-driven weapon forge. Create and share your own attack modules!

⚠️ **For educational and authorized testing purposes only** ⚠️

## 🤝 Contributing

The project welcomes contributions in:

- New attack modules.
- Bug fixes.
- Documentation.
- Feature improvements.

For **detailed information** about **contributing** process go to [Contributing Docs](CONTRIBUTING.md), [Code Of Conduct](CODE_OF_CONDUCT.md) and [Development Guide](DEVELOPMENT.md).

## 📫 Contact

- **Report Issues**: Via GitHub.
- **Guidelines**:
  - Follow ethical guidelines.
  - Document reproduction steps.
  - Provide logs and context.

- **Author**: __infinition__
- **GitHub**: [infinition/Bjorn](https://github.com/infinition/Bjorn)

## 🌠 Stargazers

[![Star History Chart](https://api.star-history.com/svg?repos=infinition/bjorn&type=Date)](https://star-history.com/#infinition/bjorn&Date)

---

## 📜 License

2024 - Bjorn is distributed under the MIT License. For more details, please refer to the [LICENSE](LICENSE) file included in this repository.
