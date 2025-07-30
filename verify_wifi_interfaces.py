#!/usr/bin/env python3
"""
Script to verify wifi interfaces and their capabilities.
This helps verify that the Alfa adapter detection is working correctly.
"""

import subprocess
import sys

def check_wifi_interfaces():
    """Check all wifi interfaces and their capabilities."""
    print("=== WiFi Interface Verification ===\n")

    # Check USB devices
    print("1. USB Devices:")
    try:
        result = subprocess.run(['lsusb'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(result.stdout)
        else:
            print("Failed to get USB devices")
    except Exception as e:
        print(f"Error checking USB devices: {e}")

    print("\n2. WiFi Interfaces:")
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(result.stdout)
        else:
            print("Failed to get wifi interfaces")
    except Exception as e:
        print(f"Error checking wifi interfaces: {e}")

    print("\n3. Network Interfaces:")
    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            # Filter for wireless interfaces
            lines = result.stdout.split('\n')
            for line in lines:
                if 'wlan' in line or 'wifi' in line:
                    print(line.strip())
        else:
            print("Failed to get network interfaces")
    except Exception as e:
        print(f"Error checking network interfaces: {e}")

    print("\n4. Interface Details (if any wlan interfaces found):")
    try:
        # Get list of wifi interfaces
        iw_result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=10)
        if iw_result.returncode == 0:
            interfaces = []
            for line in iw_result.stdout.split('\n'):
                if 'Interface' in line:
                    interface = line.split()[1]
                    interfaces.append(interface)

            for interface in interfaces:
                print(f"\n--- {interface} ---")
                try:
                    # Get interface info
                    info_result = subprocess.run(['iw', interface, 'info'],
                                              capture_output=True, text=True, timeout=5)
                    if info_result.returncode == 0:
                        print(info_result.stdout)
                    else:
                        print(f"Failed to get info for {interface}")
                except Exception as e:
                    print(f"Error getting info for {interface}: {e}")
        else:
            print("No wifi interfaces found")
    except Exception as e:
        print(f"Error checking interface details: {e}")

if __name__ == "__main__":
    check_wifi_interfaces()