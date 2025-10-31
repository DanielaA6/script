#!/usr/bin/env python3
"""
Basic Port Scanner - Cybersecurity Tool
Author: Daniela
Usage: Educational purposes only
"""

import socket
import sys
from datetime import datetime

def scan_ports(target, ports=[21, 22, 23, 25, 53, 80, 110, 443, 3389]):
    print(f"\n🔍 Scanning {target}...")
    print(f"⏰ Started: {datetime.now()}\n")
    
    open_ports = []
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        result = sock.connect_ex((target, port))
        if result == 0:
            service = get_service_name(port)
            print(f"✅ Port {port} OPEN - {service}")
            open_ports.append(port)
        
        sock.close()
    
    return open_ports

def get_service_name(port):
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 443: "HTTPS", 3389: "RDP"
    }
    return services.get(port, "Unknown")

def main():
    print("🚀 Basic Port Scanner")
    print("⚠️  For authorized testing only!\n")
    
    if len(sys.argv) != 2:
        print("Usage: python3 scanner.py <ip/hostname>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    try:
        open_ports = scan_ports(target)
        
        print(f"\n📊 Scan Complete!")
        print(f"📍 Target: {target}")
        print(f"🔓 Open ports: {len(open_ports)}")
        print(f"🕒 Finished: {datetime.now()}")
        
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()