#!/usr/bin/env python3
"""
Test script for IDLE network scanning functionality.
This script tests the perform_idle_network_scanning function from wifite2_connector.py
"""

import sys
import os

# Add the current directory to the path so we can import the wifite2_connector
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from actions.wifite2_connector import Wifite2Connector
from shared import SharedData

def test_idle_scanning():
    """Test the IDLE network scanning functionality."""
    print("Testing IDLE network scanning functionality...")

    # Initialize shared data
    shared_data = SharedData()

    # Create wifite2 connector instance
    wifite2_connector = Wifite2Connector(shared_data)

    # Test configuration
    print(f"\nConfiguration:")
    print(f"  wireless_scan_enabled: {getattr(shared_data, 'wireless_scan_enabled', True)}")
    print(f"  wireless_require_alfa_adapter: {getattr(shared_data, 'wireless_require_alfa_adapter', True)}")
    print(f"  wireless_idle_scanning_enabled: {getattr(shared_data, 'wireless_idle_scanning_enabled', True)}")

    # Test adapter detection
    print("\nChecking for Alfa USB wifi adapter...")
    adapter_detected = wifite2_connector.detect_alfa_wifi_adapter()

    if adapter_detected:
        print("✅ Alfa USB wifi adapter detected!")
        print(f"Interface: {wifite2_connector.alfa_interface}")

        # Test primary network detection
        print("\nTesting primary network detection...")
        primary_network = wifite2_connector.get_primary_network_info()
        if primary_network:
            print(f"✅ Primary network detected: {primary_network}")
        else:
            print("❌ No primary network detected")

        # Test current connection saving
        print("\nTesting current connection saving...")
        if wifite2_connector.save_current_connection():
            print(f"✅ Current connection saved: {wifite2_connector.primary_connection}")
        else:
            print("❌ Failed to save current connection")

        # Test unsecured network scanning
        print("\nTesting unsecured network scanning...")
        unsecured_networks = wifite2_connector.scan_for_unsecured_networks()
        if unsecured_networks:
            print(f"✅ Found {len(unsecured_networks)} unsecured networks:")
            for i, network in enumerate(unsecured_networks[:3]):  # Show first 3
                print(f"  {i+1}. {network.get('ssid', 'Unknown')} ({network.get('encryption', 'Unknown')})")
        else:
            print("❌ No unsecured networks found")

        # Test full IDLE scanning (with confirmation)
        print("\nTesting full IDLE network scanning...")
        print("⚠️  This will attempt to connect to unsecured networks!")
        response = input("Do you want to proceed? (y/N): ")

        if response.lower() == 'y':
            try:
                success = wifite2_connector.perform_idle_network_scanning()
                if success:
                    print("✅ IDLE network scanning completed successfully!")
                else:
                    print("❌ IDLE network scanning failed or was skipped.")
            except Exception as e:
                print(f"❌ Error during IDLE network scanning: {e}")
        else:
            print("Skipping IDLE network scanning test.")
    else:
        print("❌ No Alfa USB wifi adapter detected.")
        print("IDLE network scanning requires an Alfa adapter.")

    return adapter_detected

if __name__ == "__main__":
    test_idle_scanning()