# PrivacyToolkit 🛡️

**PrivacyToolkit** is a Linux-focused privacy and security utility designed for users who want to operate safely, anonymously, and securely. It combines multiple privacy-hardening features in one single Python tool.

[GitHub Repository](https://github.com/omarmerheb)  
BTC Donation: `15o7Md2HJrQU2rSNyf5Azt8SPu9aBCCLi9`

---

## Features

PrivacyToolkit provides a suite of tools to enhance user privacy and harden Linux systems:

1. **Proxychains + Tor integration**  
   - Automatically configures `proxychains` to route traffic through Tor.
   - Detects SOCKS5 port and updates proxychains configuration safely.
   - Optional connectivity test to validate Tor routing.

2. **Open port audit & service management**  
   - Detects listening ports on your system.
   - Maps common ports to associated services.
   - Offers the ability to safely stop or disable unnecessary services.

3. **Linux distro detection & update reminders**  
   - Detects your Linux distribution and package manager.
   - Checks if your system is up to date.
   - Optionally runs upgrades in live mode after confirmation.

4. **Firewall & service hardening**  
   - Checks UFW status and suggests/automates recommended firewall settings.
   - Audits common services (like Avahi, Bluetooth, CUPS) and allows safe disabling.

5. **SSH security audit**  
   - Scans `sshd_config` for risky settings (PermitRootLogin, PasswordAuthentication).
   - Provides guided fixes with backups and safe reloads.

6. **Wipe your trail & evidence**  
   - **Anonymity profile:** review identifiable information on your system.
   - **Log clearing:** securely backup and truncate logs and shell history.
   - **Metadata cleaning:** integrates with `mat2` or `exiftool` to remove sensitive metadata from files.
   - **Secure file deletion:** irreversibly overwrite and delete files using `shred` or `srm`.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/omarmerheb/privacytoolkit.git
cd privacytoolkit
# PrivacyToolkit 🛡️

**PrivacyToolkit** is a Linux-focused privacy and security utility designed for users who want to operate safely, anonymously, and securely. It combines multiple privacy-hardening features in one single Python tool.

[GitHub Repository](https://github.com/omarmerheb)  
BTC Donation: `15o7Md2HJrQU2rSNyf5Azt8SPu9aBCCLi9`

---

## Features

PrivacyToolkit provides a suite of tools to enhance user privacy and harden Linux systems:

1. **Proxychains + Tor integration**  
   - Automatically configures `proxychains` to route traffic through Tor.
   - Detects SOCKS5 port and updates proxychains configuration safely.
   - Optional connectivity test to validate Tor routing.

2. **Open port audit & service management**  
   - Detects listening ports on your system.
   - Maps common ports to associated services.
   - Offers the ability to safely stop or disable unnecessary services.

3. **Linux distro detection & update reminders**  
   - Detects your Linux distribution and package manager.
   - Checks if your system is up to date.
   - Optionally runs upgrades in live mode after confirmation.

4. **Firewall & service hardening**  
   - Checks UFW status and suggests/automates recommended firewall settings.
   - Audits common services (like Avahi, Bluetooth, CUPS) and allows safe disabling.

5. **SSH security audit**  
   - Scans `sshd_config` for risky settings (PermitRootLogin, PasswordAuthentication).
   - Provides guided fixes with backups and safe reloads.

6. **Wipe your trail & evidence**  
   - **Anonymity profile:** review identifiable information on your system.
   - **Log clearing:** securely backup and truncate logs and shell history.
   - **Metadata cleaning:** integrates with `mat2` or `exiftool` to remove sensitive metadata from files.
   - **Secure file deletion:** irreversibly overwrite and delete files using `shred` or `srm`.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/omarmerheb/privacytoolkit.git
cd privacytoolkit
