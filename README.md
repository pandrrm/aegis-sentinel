# Aegis Sentinel - Network Protection System 🛡️

**Real-time Network Threat Detection and Response System**

Aegis Sentinel is a Python-based network security monitoring tool that provides real-time threat detection, automatic IP blocking, and Discord notifications for suspicious network activities.

## 🚀 Features

- **Real-time Packet Analysis**: Monitor network traffic using Scapy
- **Automatic Threat Detection**: Identify port scans, exploit attempts, and suspicious activities
- **IP Blocking**: Automatically block malicious IPs using iptables
- **Discord Integration**: Instant threat notifications via Discord webhooks
- **Cloud Provider Recognition**: Identify and classify traffic from major cloud providers
- **Geolocation Lookup**: Get location and organization info for suspicious IPs
- **Whitelist Support**: Protect legitimate services from being blocked
- **Smart Filtering**: Avoid blocking local networks and trusted IPs

## 🔧 Requirements

### System Requirements
- Linux operating system (Ubuntu/Debian/CentOS)
- Python 3.6+
- Root/sudo privileges (for iptables management)
- Network interface access

### Python Dependencies
```bash
pip install scapy requests ipaddress netifaces
```

### System Dependencies
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3-pip iptables

# CentOS/RHEL
sudo yum install python3-pip iptables
```

## 📋 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/aegis-sentinel.git
   cd aegis-sentinel
   ```

2. **Install Python dependencies**
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Configure the system**
   - Edit `aegis_sentinel.py`
   - Set your Discord webhook URL
   - Configure your local network ranges
   - Adjust interface settings

## ⚙️ Configuration

### Basic Configuration
```python
# Discord Webhook (Required)
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE"

# Local Networks (Adjust to your network)
LOCAL_NETS = [
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("192.168.1.0/24")  # Your local network
]

# Your Server IP
LOCAL_IPS = [
    ipaddress.IPv4Address("192.168.1.100")  # Your server IP
]
```

### Network Interface
```python
# In the main execution section, change "eth0" to your interface
sniff(prn=detect_packet, store=0, iface="eth0")  # Change to your interface
```

## 🚀 Usage

### Basic Usage
```bash
# Run with sudo (required for packet capture and iptables)
sudo python3 aegis_sentinel.py
```

### Advanced Usage
```bash
# Run in background
sudo nohup python3 aegis_sentinel.py &

# Run with systemd (recommended for production)
sudo systemctl start aegis-sentinel
sudo systemctl enable aegis-sentinel
```

## 🔍 Detection Capabilities

### Threat Types Detected
- **Port Scanning**: SYN scans, stealth scans
- **Network Reconnaissance**: Nmap, Masscan, Zmap
- **Exploitation Attempts**: Metasploit, SQLMap, Hydra
- **Web Attacks**: Directory brute-forcing, admin panel attacks
- **IP Spoofing**: Invalid or spoofed source addresses

### Automatic Responses
- **IP Blocking**: Immediate iptables DROP rules
- **Discord Alerts**: Real-time notifications with threat details
- **Geolocation**: Automatic IP location and ISP identification
- **Cloud Detection**: Identify traffic from AWS, Google Cloud, etc.

## 📊 Monitoring & Alerts

### Discord Notifications Include:
- Timestamp of the threat
- Source IP address
- Threat type and severity
- Network payload samples
- Geolocation data
- Cloud provider information
- Hostname resolution

### Command Line Monitoring
```bash
# View blocked IPs
sudo iptables -L INPUT -n | grep DROP

# Unblock specific IP
sudo iptables -D INPUT -s 1.2.3.4 -j DROP
```

## 🛡️ Security Features

### Whitelist Protection
Pre-configured whitelists for:
- Discord CDN
- GitHub
- Cloudflare
- Google DNS
- Common VPN providers

### Smart Filtering
- Avoids blocking legitimate cloud services
- Protects local network traffic
- Prevents self-blocking scenarios

## 📝 Logging

All activities are logged with:
- Timestamp
- Source IP
- Action taken
- Threat classification
- Network payload (if applicable)

## 🚨 Important Notes

### Security Considerations
- Run only on networks you own or have permission to monitor
- Be careful with whitelist configurations
- Monitor Discord notifications to avoid false positives
- Regular review of blocked IPs is recommended

### Performance Impact
- Minimal CPU usage during normal operation
- Memory usage scales with network traffic
- Designed for 24/7 operation

## 🤝 Contributing

We welcome contributions! Please feel free to submit pull requests, report bugs, or suggest new features.

### Development Setup
```bash
git clone https://github.com/yourusername/aegis-sentinel.git
cd aegis-sentinel
pip3 install -r requirements.txt
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and legitimate network security purposes only. Users are responsible for compliance with local laws and regulations. Always obtain proper authorization before monitoring network traffic.

## 🔧 Troubleshooting

### Common Issues
1. **Permission Denied**: Run with sudo
2. **Interface Not Found**: Check available interfaces with `ip link show`
3. **Discord Not Working**: Verify webhook URL and network connectivity
4. **High False Positives**: Adjust whitelist and detection thresholds

### Support
For issues and questions:
- Create a GitHub issue
- Check the documentation
- Review the configuration settings

---

**Made with ❤️ for network security professionals**
