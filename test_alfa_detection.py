#!/usr/bin/env python3
"""
Test script for Alfa USB wifi adapter detection.
This script tests the detect_alfa_wifi_adapter function from wifite2_connector.py
"""

import sys
import os

# Add the current directory to the path so we can import the wifite2_connector
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from actions.wifite2_connector import Wifite2Connector
from shared import SharedData

def test_alfa_detection():
    """Test the Alfa adapter detection functionality."""
    print("Testing Alfa USB wifi adapter detection...")

    # Initialize shared data
    shared_data = SharedData()

    # Create wifite2 connector instance
    wifite2_connector = Wifite2Connector(shared_data)

    # Test adapter detection
    print("\nChecking for Alfa USB wifi adapter...")
    adapter_detected = wifite2_connector.detect_alfa_wifi_adapter()

    if adapter_detected:
        print("✅ Alfa USB wifi adapter detected!")
        print(f"Interface: {wifite2_connector.alfa_interface}")
        print("Wireless attacks will be enabled.")

        # Test monitor mode functionality
        print("\nTesting monitor mode functionality...")
        if wifite2_connector._ensure_monitor_mode():
            print("✅ Successfully set adapter to monitor mode")

            # Test restore functionality
            if wifite2_connector._restore_managed_mode():
                print("✅ Successfully restored adapter to managed mode")
            else:
                print("❌ Failed to restore adapter to managed mode")
        else:
            print("❌ Failed to set adapter to monitor mode")
    else:
        print("❌ No Alfa USB wifi adapter detected.")
        print("Wireless attacks will be disabled.")

    # Test configuration
    print(f"\nConfiguration:")
    print(f"  wireless_require_alfa_adapter: {getattr(shared_data, 'wireless_require_alfa_adapter', True)}")
    print(f"  wireless_scan_enabled: {getattr(shared_data, 'wireless_scan_enabled', True)}")

    # Test full execution
    print("\nTesting full wireless attack execution...")
    try:
        success = wifite2_connector.execute_wireless_attack()
        if success:
            print("✅ Wireless attack executed successfully!")
        else:
            print("❌ Wireless attack failed or was skipped.")
    except Exception as e:
        print(f"❌ Error during wireless attack: {e}")

    return adapter_detected

if __name__ == "__main__":
    test_alfa_detection()