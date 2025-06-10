#!/usr/bin/env python3
"""
Advanced Network Security Monitor - Production Ready
ระบบตรวจจับและป้องกันภัยคุกคามเครือข่ายแบบครบครัน
"""

import os
import re
import time
import json
import socket
import threading
import requests
import ipaddress
import subprocess
import signal
import sys
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path

# ตรวจสอบและติดตั้ง dependencies
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
    print("[✓] Scapy ready")
except ImportError:
    print("[!] Please install: pip install scapy")
    sys.exit(1)

# === การตั้งค่า ===
class Config:
    # Discord webhook สำหรับแจ้งเตือน
    DISCORD_WEBHOOK = ""  # ใส่ webhook URL ของคุณ
    
    # ไฟล์การตั้งค่า
    CONFIG_FILE = "security_config.json"
    BLOCKED_IPS_FILE = "blocked_ips.json"
    LOGS_DIR = Path("security_logs")
    
    # เครือข่ายที่ยกเว้น (ไม่บล็อก)
    TRUSTED_NETWORKS = [
        "127.0.0.0/8",      # localhost
        "192.168.0.0/16",   # เครือข่ายบ้าน
        "10.0.0.0/8",       # private network
        "172.16.0.0/12"     # private network
    ]
    
    # Whitelist - IP/Network ที่ไม่ควรบล็อก
    WHITELIST = [
        # Cloudflare
        "103.21.244.0/22", "103.22.200.0/22", "104.16.0.0/13",
        "108.162.192.0/18", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        
        # Google
        "8.8.8.8/32", "8.8.4.4/32", "172.217.0.0/16",
        "74.125.0.0/16", "142.250.0.0/15",
        
        # GitHub
        "140.82.112.0/20", "192.30.252.0/22", "185.199.108.0/22",
        
        # Discord
        "162.159.128.0/17", "104.16.0.0/12"
    ]
    
    # การตั้งค่าการตรวจจับ
    PORT_SCAN_THRESHOLD = 10      # จำนวน port ที่สแกนก่อนถือว่าเป็น port scan
    CONNECTION_RATE_LIMIT = 50    # จำนวน connection ต่อนาทีที่อนุญาต
    AUTO_UNBLOCK_HOURS = 24       # ยกเลิกการบล็อกอัตโนมัติหลังจาก x ชั่วโมง
    
    # โหมดการทำงาน
    BLOCK_MODE = True            # เปิด/ปิด การบล็อก IP
    MONITOR_MODE = True          # เปิด/ปิด การตรวจจับ
    ALERT_MODE = True           # เปิด/ปิด การแจ้งเตือน

# === คลาสจัดการ IP ที่ถูกบล็อก ===
class BlockedIPManager:
    def __init__(self):
        self.blocked_ips = {}
        self.load_blocked_ips()
        
    def load_blocked_ips(self):
        """โหลดรายการ IP ที่ถูกบล็อกจากไฟล์"""
        try:
            if Path(Config.BLOCKED_IPS_FILE).exists():
                with open(Config.BLOCKED_IPS_FILE, 'r') as f:
                    data = json.load(f)
                    # แปลง string datetime กลับเป็น datetime object
                    for ip, info in data.items():
                        info['blocked_at'] = datetime.fromisoformat(info['blocked_at'])
                    self.blocked_ips = data
                print(f"[✓] โหลด {len(self.blocked_ips)} IP ที่ถูกบล็อก")
        except Exception as e:
            print(f"[!] ไม่สามารถโหลดไฟล์ blocked IPs: {e}")
            self.blocked_ips = {}
    
    def save_blocked_ips(self):
        """บันทึกรายการ IP ที่ถูกบล็อกลงไฟล์"""
        try:
            # แปลง datetime เป็น string สำหรับ JSON
            data = {}
            for ip, info in self.blocked_ips.items():
                data[ip] = {
                    'reason': info['reason'],
                    'blocked_at': info['blocked_at'].isoformat(),
                    'auto_unblock': info.get('auto_unblock', True)
                }
            
            with open(Config.BLOCKED_IPS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[!] ไม่สามารถบันทึกไฟล์ blocked IPs: {e}")
    
    def is_blocked(self, ip):
        """ตรวจสอบว่า IP ถูกบล็อกหรือไม่"""
        return ip in self.blocked_ips
    
    def block_ip(self, ip, reason="Suspicious Activity"):
        """บล็อก IP"""
        if self.is_blocked(ip):
            return False
            
        # เพิ่มใน iptables
        cmd = f"iptables -C INPUT -s {ip} -j DROP 2>/dev/null || iptables -I INPUT -s {ip} -j DROP"
        result = subprocess.run(cmd, shell=True, capture_output=True)
        
        if result.returncode == 0:
            self.blocked_ips[ip] = {
                'reason': reason,
                'blocked_at': datetime.now(),
                'auto_unblock': True
            }
            self.save_blocked_ips()
            print(f"[🔴] บล็อก IP: {ip} - {reason}")
            return True
        else:
            print(f"[!] ไม่สามารถบล็อก IP: {ip}")
            return False
    
    def unblock_ip(self, ip):
        """ยกเลิกการบล็อก IP"""
        if not self.is_blocked(ip):
            return False
            
        # ลบจาก iptables
        cmd = f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null"
        result = subprocess.run(cmd, shell=True, capture_output=True)
        
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            self.save_blocked_ips()
        
        print(f"[🟢] ยกเลิกบล็อก IP: {ip}")
        return True
    
    def auto_unblock_expired(self):
        """ยกเลิกการบล็อก IP ที่หมดเวลาแล้ว"""
        expired_ips = []
        now = datetime.now()
        
        for ip, info in self.blocked_ips.items():
            if info.get('auto_unblock', True):
                blocked_time = info['blocked_at']
                if now - blocked_time > timedelta(hours=Config.AUTO_UNBLOCK_HOURS):
                    expired_ips.append(ip)
        
        for ip in expired_ips:
            self.unblock_ip(ip)
            print(f"[⏰] ยกเลิกบล็อก IP หมดเวลา: {ip}")
        
        return len(expired_ips)
    
    def list_blocked_ips(self):
        """แสดงรายการ IP ที่ถูกบล็อก"""
        if not self.blocked_ips:
            print("[ℹ️] ไม่มี IP ที่ถูกบล็อก")
            return
            
        print(f"\n--- รายการ IP ที่ถูกบล็อก ({len(self.blocked_ips)} รายการ) ---")
        for ip, info in self.blocked_ips.items():
            blocked_time = info['blocked_at'].strftime("%Y-%m-%d %H:%M:%S")
            auto_unblock = "✓" if info.get('auto_unblock', True) else "✗"
            print(f"📍 {ip:15} | {info['reason']:30} | {blocked_time} | Auto: {auto_unblock}")
        print("--- สิ้นสุดรายการ ---\n")

# === คลาสตรวจจับภัยคุกคาม ===
class ThreatDetector:
    def __init__(self, blocked_ip_manager):
        self.blocked_ips = blocked_ip_manager
        self.connection_tracker = defaultdict(lambda: deque(maxlen=100))
        self.port_scan_tracker = defaultdict(set)
        self.stats = {
            'packets_analyzed': 0,
            'threats_detected': 0,
            'ips_blocked': 0,
            'start_time': datetime.now()
        }
        
        # สร้างโฟลเดอร์ logs
        Config.LOGS_DIR.mkdir(exist_ok=True)
    
    def is_trusted_ip(self, ip):
        """ตรวจสอบว่า IP อยู่ในรายการที่เชื่อถือได้หรือไม่"""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            
            # ตรวจสอบ trusted networks
            for network in Config.TRUSTED_NETWORKS:
                if ip_obj in ipaddress.IPv4Network(network):
                    return True
            
            # ตรวจสอบ whitelist
            for network in Config.WHITELIST:
                if ip_obj in ipaddress.IPv4Network(network):
                    return True
                    
            return False
        except:
            return True  # ถ้า parse ไม่ได้ให้ถือว่าเชื่อถือได้
    
    def log_threat(self, ip, threat_type, details=""):
        """บันทึก log ภัยคุกคาม"""
        timestamp = datetime.now().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'ip': ip,
            'threat_type': threat_type,
            'details': details,
            'action': 'blocked' if Config.BLOCK_MODE else 'detected'
        }
        
        # บันทึกลงไฟล์ log รายวัน
        date_str = datetime.now().strftime("%Y-%m-%d")
        log_file = Config.LOGS_DIR / f"threats_{date_str}.json"
        
        try:
            # อ่านไฟล์เดิม (ถ้ามี)
            if log_file.exists():
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
            
            # เพิ่ม log ใหม่
            logs.append(log_entry)
            
            # บันทึกกลับ
            with open(log_file, 'w') as f:
                json.dump(logs, f, indent=2)
                
        except Exception as e:
            print(f"[!] ไม่สามารถบันทึก log: {e}")
    
    def send_alert(self, ip, threat_type, details=""):
        """ส่งการแจ้งเตือน"""
        if not Config.ALERT_MODE or not Config.DISCORD_WEBHOOK:
            return
            
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        hostname = self.get_hostname(ip)
        
        message = f"""🚨 **SECURITY ALERT** 🚨
⏰ **Time:** `{timestamp}`
🌐 **IP:** `{ip}`
🏠 **Host:** `{hostname}`
⚠️ **Threat:** **{threat_type}**
📝 **Details:** {details}
🛡️ **Action:** {'Blocked' if Config.BLOCK_MODE else 'Detected'}"""
        
        def send():
            try:
                response = requests.post(
                    Config.DISCORD_WEBHOOK,
                    json={"content": message},
                    timeout=5
                )
                if response.status_code == 200:
                    print(f"[✓] Alert sent to Discord")
                elif response.status_code == 429:
                    retry_after = response.json().get("retry_after", 1)
                    time.sleep(retry_after)
                    requests.post(Config.DISCORD_WEBHOOK, json={"content": message}, timeout=5)
            except Exception as e:
                print(f"[!] Discord alert failed: {e}")
        
        threading.Thread(target=send, daemon=True).start()
    
    def get_hostname(self, ip):
        """แปลง IP เป็น hostname"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "unknown"
    
    def detect_port_scan(self, src_ip, dst_port):
        """ตรวจจับ port scan"""
        self.port_scan_tracker[src_ip].add(dst_port)
        
        if len(self.port_scan_tracker[src_ip]) >= Config.PORT_SCAN_THRESHOLD:
            ports_list = sorted(list(self.port_scan_tracker[src_ip]))
            details = f"Scanned {len(ports_list)} ports: {ports_list[:10]}..."
            self.handle_threat(src_ip, "Port Scan", details)
            
            # Clear tracker หลังจากตรวจพบแล้ว
            self.port_scan_tracker[src_ip].clear()
    
    def detect_connection_flood(self, src_ip):
        """ตรวจจับ connection flooding"""
        now = datetime.now()
        self.connection_tracker[src_ip].append(now)
        
        # นับ connection ในช่วง 1 นาทีที่ผ่านมา
        recent_connections = [
            conn_time for conn_time in self.connection_tracker[src_ip]
            if now - conn_time < timedelta(minutes=1)
        ]
        
        if len(recent_connections) > Config.CONNECTION_RATE_LIMIT:
            details = f"{len(recent_connections)} connections in 1 minute"
            self.handle_threat(src_ip, "Connection Flood", details)
    
    def detect_malicious_payload(self, packet, src_ip):
        """ตรวจจับ payload ที่เป็นอันตราย"""
        if not packet.haslayer(Raw):
            return
            
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
            
            # เครื่องมือสแกน
            scan_tools = ['nmap', 'masscan', 'zmap', 'unicornscan']
            exploit_tools = ['metasploit', 'msfconsole', 'sqlmap', 'nikto', 'hydra', 'medusa']
            
            for tool in scan_tools + exploit_tools:
                if tool in payload:
                    tool_type = "Scanner" if tool in scan_tools else "Exploit Tool"
                    self.handle_threat(src_ip, f"{tool_type} Detected", f"Tool: {tool}")
                    break
                    
            # SQL Injection patterns
            sql_patterns = [
                r"union.*select", r"drop.*table", r"insert.*into",
                r"delete.*from", r"update.*set", r"exec.*xp_"
            ]
            
            for pattern in sql_patterns:
                if re.search(pattern, payload):
                    self.handle_threat(src_ip, "SQL Injection Attempt", f"Pattern: {pattern}")
                    break
                    
        except Exception:
            pass
    
    def handle_threat(self, ip, threat_type, details=""):
        """จัดการกับภัยคุกคามที่ตรวจพบ"""
        self.stats['threats_detected'] += 1
        
        print(f"[⚠️] THREAT DETECTED: {ip} - {threat_type}")
        if details:
            print(f"    Details: {details}")
        
        # บันทึก log
        self.log_threat(ip, threat_type, details)
        
        # ส่งการแจ้งเตือน
        self.send_alert(ip, threat_type, details)
        
        # บล็อก IP (ถ้าเปิดใช้งาน)
        if Config.BLOCK_MODE and not self.blocked_ips.is_blocked(ip):
            if self.blocked_ips.block_ip(ip, threat_type):
                self.stats['ips_blocked'] += 1
    
    def analyze_packet(self, packet):
        """วิเคราะห์ packet"""
        self.stats['packets_analyzed'] += 1
        
        if not packet.haslayer(IP):
            return
            
        src_ip = packet[IP].src
        
        # ข้าม IP ที่เชื่อถือได้
        if self.is_trusted_ip(src_ip):
            return
            
        # ข้าม IP ที่ถูกบล็อกแล้ว
        if self.blocked_ips.is_blocked(src_ip):
            return
        
        # ตรวจจับ TCP packets
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            
            # ตรวจจับ port scan
            if tcp.flags == 2:  # SYN
                self.detect_port_scan(src_ip, tcp.dport)
            
            # ตรวจจับ connection flood
            self.detect_connection_flood(src_ip)
        
        # ตรวจจับ payload ที่เป็นอันตราย
        self.detect_malicious_payload(packet, src_ip)
    
    def get_stats(self):
        """ดึงสถิติการทำงาน"""
        uptime = datetime.now() - self.stats['start_time']
        return {
            **self.stats,
            'uptime': str(uptime),
            'blocked_ips_count': len(self.blocked_ips.blocked_ips)
        }

# === คลาสหลัก ===
class NetworkSecurityMonitor:
    def __init__(self):
        self.blocked_ip_manager = BlockedIPManager()
        self.threat_detector = ThreatDetector(self.blocked_ip_manager)
        self.running = False
        
    def start_monitoring(self, interface=None):
        """เริ่มการตรวจจับ"""
        print(f"[*] เริ่มระบบรักษาความปลอดภัยเครือข่าย...")
        print(f"[*] Block Mode: {'ON' if Config.BLOCK_MODE else 'OFF'}")
        print(f"[*] Monitor Mode: {'ON' if Config.MONITOR_MODE else 'OFF'}")
        print(f"[*] Alert Mode: {'ON' if Config.ALERT_MODE else 'OFF'}")
        
        if interface:
            print(f"[*] Interface: {interface}")
        
        self.running = True
        
        # เริ่ม thread สำหรับ auto unblock
        auto_unblock_thread = threading.Thread(target=self.auto_unblock_loop, daemon=True)
        auto_unblock_thread.start()
        
        # เริ่ม thread สำหรับแสดงสถิติ
        stats_thread = threading.Thread(target=self.stats_loop, daemon=True)
        stats_thread.start()
        
        try:
            if Config.MONITOR_MODE:
                sniff(
                    prn=self.threat_detector.analyze_packet,
                    store=0,
                    iface=interface,
                    stop_filter=lambda x: not self.running
                )
            else:
                print("[*] Monitor mode ปิดอยู่ - รอคำสั่ง...")
                while self.running:
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            print(f"\n[*] กำลังปิดระบบ...")
            self.shutdown()
        except Exception as e:
            print(f"[!] Error: {e}")
            self.shutdown()
    
    def auto_unblock_loop(self):
        """ลูปสำหรับยกเลิกการบล็อกอัตโนมัติ"""
        while self.running:
            time.sleep(3600)  # ตรวจสอบทุกชั่วโมง
            if self.running:
                self.blocked_ip_manager.auto_unblock_expired()
    
    def stats_loop(self):
        """ลูปแสดงสถิติ"""
        while self.running:
            time.sleep(60)  # แสดงทุกนาที
            if self.running:
                self.print_stats()
    
    def print_stats(self):
        """แสดงสถิติ"""
        stats = self.threat_detector.get_stats()
        print(f"\n--- Security Monitor Stats ---")
        print(f"📊 Packets analyzed: {stats['packets_analyzed']}")
        print(f"⚠️ Threats detected: {stats['threats_detected']}")
        print(f"🔴 IPs blocked: {stats['ips_blocked']}")
        print(f"📋 Currently blocked: {stats['blocked_ips_count']}")
        print(f"⏱️ Uptime: {stats['uptime']}")
        print(f"--- End Stats ---\n")
    
    def shutdown(self):
        """ปิดระบบ"""
        self.running = False
        print("[*] ระบบปิดแล้ว")

# === Management Interface ===
def management_interface():
    """อินเตอร์เฟซสำหรับจัดการระบบ"""
    blocked_ip_manager = BlockedIPManager()
    
    while True:
        print(f"\n--- Network Security Management ---")
        print(f"1. แสดงรายการ IP ที่ถูกบล็อก")
        print(f"2. ยกเลิกการบล็อก IP")
        print(f"3. บล็อก IP แบบ manual")
        print(f"4. ยกเลิกการบล็อก IP ที่หมดเวลา")
        print(f"5. ดู logs")
        print(f"0. ออก")
        
        choice = input("👉 เลือก: ").strip()
        
        if choice == "1":
            blocked_ip_manager.list_blocked_ips()
            
        elif choice == "2":
            ip = input("IP ที่ต้องการยกเลิกการบล็อก: ").strip()
            if ip:
                blocked_ip_manager.unblock_ip(ip)
                
        elif choice == "3":
            ip = input("IP ที่ต้องการบล็อก: ").strip()
            reason = input("เหตุผล: ").strip() or "Manual Block"
            if ip:
                blocked_ip_manager.block_ip(ip, reason)
                
        elif choice == "4":
            count = blocked_ip_manager.auto_unblock_expired()
            print(f"[✓] ยกเลิกการบล็อก {count} IP")
            
        elif choice == "5":
            print(f"📁 Log files อยู่ใน: {Config.LOGS_DIR}")
            for log_file in Config.LOGS_DIR.glob("*.json"):
                print(f"  - {log_file.name}")
                
        elif choice == "0":
            break
        else:
            print("[!] เลือกไม่ถูกต้อง")

# === ฟังก์ชันหลัก ===
def main():
    print("=" * 60)
    print("🛡️  Advanced Network Security Monitor v2.0")
    print("=" * 60)
    
    # ตรวจสอบสิทธิ์ root
    if os.geteuid() != 0:
        print("❌ ต้องใช้สิทธิ์ root เพื่อจับ packet และจัดการ iptables")
        print("   ลอง: sudo python3 security_monitor.py")
        sys.exit(1)
    
    # ตัวเลือกการทำงาน
    print(f"เลือกโหมดการทำงาน:")
    print(f"1. เริ่มการตรวจจับ (Monitor)")
    print(f"2. จัดการ IP ที่ถูกบล็อก (Management)")
    print(f"3. ดู Help")
    
    choice = input("👉 เลือก (1-3): ").strip()
    
    if choice == "1":
        # เริ่มการตรวจจับ
        interfaces = get_if_list()
        active_interfaces = [iface for iface in interfaces if not iface.startswith('lo')]
        
        print(f"\n📡 Interfaces: {', '.join(active_interfaces)}")
        print(f"เลือก interface (หรือกด Enter เพื่อใช้ทั้งหมด):")
        
        for i, iface in enumerate(active_interfaces, 1):
            print(f"  {i}. {iface}")
        
        iface_choice = input("👉 เลือก: ").strip()
        selected_interface = None
        
        if iface_choice.isdigit() and 1 <= int(iface_choice) <= len(active_interfaces):
            selected_interface = active_interfaces[int(iface_choice) - 1]
        
        # เริ่มระบบ
        monitor = NetworkSecurityMonitor()
        monitor.start_monitoring(selected_interface)
        
    elif choice == "2":
        # จัดการระบบ
        management_interface()
        
    elif choice == "3":
        # Help
        print(f"""
🛡️ Network Security Monitor Help

📋 คุณสมบัติ:
- ตรวจจับและบล็อก port scan
- ตรวจจับเครื่องมือโจมตี (nmap, metasploit, etc.)
- ตรวจจับ SQL injection
- ตรวจจับ connection flooding
- ยกเลิกการบล็อกอัตโนมัติ (24 ชั่วโมง)
- แจ้งเตือนผ่าน Discord
- บันทึก logs แยกตามวัน

⚙️ การตั้งค่า:
- แก้ไข DISCORD_WEBHOOK ในโค้ด
- ปรับ TRUSTED_NETWORKS และ WHITELIST
- เปลี่ยน threshold ต่างๆ ตามต้องการ

📁 ไฟล์ที่สร้าง:
- blocked_ips.json - รายการ IP ที่ถูกบล็อก
- security_logs/ - โฟลเดอร์ logs
- security_config.json - การตั้งค่า (จะสร้างในอนาคต)

⚠️ ข้อควรระวัง:
- ใช้สิทธิ์ root เท่านั้น
- ตรวจสอบ whitelist ก่อนใช้งาน
- สำรองข้อมูล iptables ก่อนใช้งาน
        """)
    else:
        print("[!] เลือกไม่ถูกต้อง")

if __name__ == "__main__":
    main()
