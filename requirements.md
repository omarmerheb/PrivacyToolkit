# PrivacyToolkit - Requirements & Setup

PrivacyToolkit is a Linux privacy and hardening toolkit. To run seamlessly, ensure the following dependencies are installed.

---

## 1. Python

- **Python 3.8+** (tested up to 3.12)  
- Standard library only; no additional pip packages required for core features.

---

## 2. Core Linux Utilities

| Utility | Purpose |
|---------|--------|
| `proxychains` | Route traffic through Tor |
| `tor` | Tor daemon & SOCKS proxy |
| `systemctl` | Manage system services (stop/disable) |
| `ss` or `netstat` | Check open/listening ports |
| `curl` | Optional, for Tor connectivity testing |
| `ufw` | Firewall setup and hardening |
| `shred` or `srm` | Securely delete files |

> Note: Most of these utilities require root/sudo to fully operate.

---

## 3. Metadata Cleaning (Optional but Recommended)

- **`mat2`** — preferred for metadata removal  
- **`exiftool`** — alternative if mat2 is not installed

---

## 4. Supported Package Managers (for updates)

- `apt` (Debian/Ubuntu)  
- `dnf` / `yum` (Fedora/RHEL/CentOS)  
- `pacman` (Arch/Manjaro)  
- `zypper` (openSUSE)

---

## 5. Installation Examples

### Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-pip proxychains tor curl ufw mat2 exiftool shred
