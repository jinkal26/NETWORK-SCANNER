# NETWORK-SCANNER USING PYTHON 
# Network Scanner Using Python

**By Inlighn Tech**

---

## Overview

A simple, educational network scanner written in Python. It uses Scapy to send ARP requests across a CIDR subnet (e.g. `192.168.1.0/24`) to discover active hosts, collect IP and MAC addresses, and attempt hostname resolution. The scanner supports multithreading to improve performance on larger subnets.

This project is intended for learning purposes — understanding ARP, raw packet manipulation (via Scapy), socket programming, and Python multithreading.

---

## Features

* Discover active hosts in a CIDR range using ARP
* Retrieve IP and MAC addresses of responding devices
* Attempt reverse DNS hostname resolution
* Multi-threaded scanning for faster results
* Clear, minimal CLI usage

---

## Requirements

* Python 3.8+
* `scapy` Python package
* `netaddr` (optional, but helpful for CIDR handling) — fallback implementation can be included in script

> **Important:** ARP scanning requires access to raw packets. On most systems you must run the script with elevated privileges (e.g., `sudo` on Linux/Mac). Do **not** scan networks you do not own or have explicit authorization to test.

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
```

2. Create a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate  # Linux / macOS
venv\\Scripts\\activate  # Windows (PowerShell)
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

`requirements.txt` example:

---

## Usage

Basic usage (run with elevated privileges):

```bash
sudo python3 scanner.py 192.168.1.0/24
```

If your script accepts options, examples:

```bash
sudo python3 scanner.py --network 192.168.1.0/24 --threads 50 --timeout 2
```


