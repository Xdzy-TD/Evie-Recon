# 🔎 EVIE-Recon

### `Network Reconnaissance • Information Gathering • Security Testing`

<p align="center">
  <img src="https://img.shields.io/badge/EVIE-v4.0-blueviolet?style=for-the-badge" alt="EVIE Version">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-success?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/License-GPL--3.0-orange?style=for-the-badge" alt="License">
</p>

<p align="center">
  <b>A practical Python-based reconnaissance toolkit for network discovery and security testing.</b>
</p>

---

## ⚡ What is EVIE?

**EVIE** is a Python-based network reconnaissance tool designed to bring several common information-gathering tasks together in one place.

Instead of switching between different commands and tools for basic reconnaissance, EVIE gives you a single interface for scanning, enumeration, service discovery, and reporting.

You can use it interactively through the terminal or run scans directly from the command line.

```text
        ███████╗██╗   ██╗██╗███████╗
        ██╔════╝██║   ██║██║██╔════╝
        █████╗  ██║   ██║██║█████╗
        ██╔══╝  ╚██╗ ██╔╝██║██╔══╝
        ███████╗ ╚████╔╝ ██║███████╗
        ╚══════╝  ╚═══╝  ╚═╝╚══════╝

       Network Reconnaissance Toolkit
                   v4.0
```

---

## 🧰 Features

| Feature                      | Description                              |
| :--------------------------- | :--------------------------------------- |
| 🔌 **TCP Scanner**           | Discover open TCP ports                  |
| 📡 **UDP Scanner**           | Check common UDP services                |
| 🏷️ **Banner Grabbing**      | Identify service banners                 |
| 🌐 **DNS Enumeration**       | Collect DNS information                  |
| 🔍 **Subdomain Enumeration** | Discover available subdomains            |
| 🌍 **GeoIP Lookup**          | Get geographic and ISP information       |
| 🧠 **Technology Detection**  | Detect technologies used by websites     |
| 🔐 **SSL/TLS Analysis**      | Inspect SSL/TLS certificates             |
| 📋 **HTTP Headers**          | Inspect HTTP/S response headers          |
| 👤 **WHOIS Lookup**          | Retrieve domain registration information |
| 💻 **OS Detection**          | Basic operating system detection         |
| 🛰️ **Traceroute**           | Trace the network path to a target       |
| 🛡️ **Vulnerability Lookup** | Search for CVE information               |
| 🕵️ **Passive Sniffing**     | Capture network traffic using Scapy      |
| 📊 **HTML Reports**          | Generate readable scan reports           |
| 🕘 **Scan History**          | Review previous scans                    |

---

## 🚀 Installation

### Clone the repository

```bash
git clone https://github.com/Xdzy-TD/Evie-Recon.git
cd Evie-Recon
```

### Install dependencies

```bash
pip install -r requirements.txt
```

Once the dependencies are installed, EVIE is ready to run.

---

## 🎮 Interactive Mode

The easiest way to start EVIE is without any arguments:

```bash
python3 evie.py
```

This launches the interactive interface where you can choose the reconnaissance options you want to run.

---

## 💻 Command-Line Mode

You can also run EVIE directly from the terminal.

### Scan a single target

```bash
python3 evie.py --targets 192.168.1.1
```

### Scan multiple targets

```bash
python3 evie.py \
  --targets 192.168.1.1,192.168.1.10,example.com
```

### Load targets from a file

```bash
python3 evie.py --target-file targets.txt
```

---

## 🔥 Full Recon

If you want to run the available reconnaissance modules together, use:

```bash
python3 evie.py --targets example.com --full
```

This is useful when you want a broader overview of a target instead of manually selecting each module.

---

## 🎯 Port Scanning

Specify the ports you want EVIE to scan:

```bash
python3 evie.py \
  --targets 192.168.1.1 \
  --ports 22,80,443,8080
```

You can also use the built-in top-port presets:

```bash
python3 evie.py \
  --targets 192.168.1.1 \
  --top-ports 100
```

Available presets:

```text
16
100
1000
```

### ⚙️ Adjust scan settings

Threads and timeout can be customized:

```bash
python3 evie.py \
  --targets 192.168.1.1 \
  --threads 20 \
  --timeout 3
```

---

## 🔬 Recon Modules

Individual reconnaissance modules can be enabled when needed.

Example:

```bash
python3 evie.py \
  --targets example.com \
  --banner \
  --dns \
  --headers \
  --whois \
  --ssl
```

Available modules include:

```text
--banner
--dns
--headers
--whois
--ssl
--os-detect
--subdomain
--geoip
--techdetect
--traceroute
--vuln
--udp
```

---

## 📊 HTML Reports

EVIE can generate an HTML report from a scan:

```bash
python3 evie.py \
  --targets example.com \
  --report
```

This makes it easier to review and share the results of a reconnaissance session.

---

## 🕵️ Passive Mode

EVIE also supports passive packet capture using **Scapy**.

Example:

```bash
sudo python3 evie.py \
  --passive \
  --interface eth0 \
  --duration 60
```

Another example:

```bash
sudo python3 evie.py \
  --passive \
  --interface wlan0 \
  --duration 120
```

> ⚠️ Passive packet capture may require root or administrator privileges depending on your operating system.

---

## 🕘 Scan History

Previous scans can be viewed using:

```bash
python3 evie.py --history
```

This is useful when working with multiple targets or reviewing previous reconnaissance sessions.

---

## 🆘 Help

To see all available commands:

```bash
python3 evie.py --help
```

Check the current version:

```bash
python3 evie.py --version
```

---

## 🗂️ Project Structure

```text
Evie-Recon/
│
├── core/
│   ├── ...
│
├── evie.py
├── requirements.txt
├── README.md
└── LICENSE
```

The `evie.py` file is the main entry point for EVIE.

The `core` directory contains the supporting components used by the reconnaissance framework, interface, configuration, reporting, and scan history.

---

## 🖥️ Quick Start

```bash
# Clone the project
git clone https://github.com/Xdzy-TD/Evie-Recon.git

# Enter the directory
cd Evie-Recon

# Install dependencies
pip install -r requirements.txt

# Start EVIE
python3 evie.py
```

Or start a full reconnaissance scan:

```bash
python3 evie.py \
  --targets example.com \
  --full \
  --report
```

---

## 🧪 Requirements

* 🐍 Python 3
* 📦 Dependencies listed in `requirements.txt`
* 🌐 Network access for online reconnaissance features
* 🔑 Appropriate privileges for operations such as packet capture

Install the required packages with:

```bash
pip install -r requirements.txt
```

---

## ⚠️ Responsible Use

EVIE is intended for legitimate security testing, research, network administration, CTFs, and educational purposes.

Only scan systems and networks that you own or have explicit permission to test.

Unauthorized reconnaissance may generate alerts, violate security policies, or potentially cause unwanted network traffic.

**Use EVIE responsibly.**

---

## 🤝 Contributing

Found a bug or have an idea?

You can contribute by:

* 🐛 Reporting bugs
* 💡 Suggesting features
* 🔧 Improving existing modules
* 📖 Improving documentation
* 🔀 Opening a pull request

Every useful contribution is appreciated.

---

## 📜 License

EVIE-Recon is released under the **GNU General Public License v3.0**.

See the [`LICENSE`](LICENSE) file for the complete license.

---

## ⭐ Support

If you find **EVIE-Recon** useful, consider giving the repository a ⭐ on GitHub.

It helps the project get more visibility and motivates further development.

---

<p align="center">

### 🔎 EVIE-Recon

**Scan. Discover. Understand.**

Made with 🐍 Python

</p>
