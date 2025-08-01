# orchestrator.py
# Description:
# This file, orchestrator.py, is the heuristic Bjorn brain, and it is responsible for coordinating and executing various network scanning and offensive security actions
# It manages the loading and execution of actions, handles retries for failed and successful actions,
# and updates the status of the orchestrator.
#
# Key functionalities include:
# - Initializing and loading actions from a configuration file, including network and vulnerability scanners.
# - Managing the execution of actions on network targets, checking for open ports and handling retries based on success or failure.
# - Coordinating the execution of parent and child actions, ensuring actions are executed in a logical order.
# - Running the orchestrator cycle to continuously check for and execute actions on available network targets.
# - Handling and updating the status of the orchestrator, including scanning for new targets and performing vulnerability scans.
# - Implementing threading to manage concurrent execution of actions with a semaphore to limit active threads.
# - Logging events and errors to ensure maintainability and ease of debugging.
# - Handling graceful degradation by managing retries and idle states when no new targets are found.

import json
import importlib
import time
import logging
import sys
import threading
from datetime import datetime, timedelta
from actions.nmap_vuln_scanner import NmapVulnScanner
from init_shared import shared_data
from logger import Logger

logger = Logger(name="orchestrator.py", level=logging.DEBUG)

class Orchestrator:
    def __init__(self):
        """Initialise the orchestrator"""
        self.shared_data = shared_data
        self.actions = []  # List of actions to be executed
        self.standalone_actions = []  # List of standalone actions to be executed
        self.failed_scans_count = 0  # Count the number of failed scans
        self.network_scanner = None
        self.last_vuln_scan_time = datetime.min  # Set the last vulnerability scan time to the minimum datetime value

        # Dynamic thread management
        self.max_threads = getattr(self.shared_data, 'max_concurrent_actions', 10)
        self.semaphore = threading.Semaphore(self.max_threads)
        self.active_threads = 0
        self.thread_lock = threading.Lock()

        # Metrics collection
        self.metrics = {
            'actions_executed': 0,
            'successful_attacks': 0,
            'failed_attacks': 0,
            'scan_duration': 0,
            'targets_discovered': 0,
            'last_scan_time': None
        }

        self.load_actions()  # Load all actions from the actions file
        actions_loaded = [action.__class__.__name__ for action in self.actions + self.standalone_actions]  # Get the names of the loaded actions
        logger.info(f"Actions loaded: {actions_loaded}")
        logger.info(f"Max concurrent threads: {self.max_threads}")

    def get_thread_stats(self):
        """
        Get current threading statistics.

        Returns:
            dict: Current thread statistics
        """
        with self.thread_lock:
            return {
                'active_threads': self.active_threads,
                'max_threads': self.max_threads,
                'available_slots': self.max_threads - self.active_threads
            }

    def acquire_thread_slot(self):
        """
        Acquire a thread slot with timeout.

        Returns:
            bool: True if slot acquired, False if timeout
        """
        try:
            acquired = self.semaphore.acquire(timeout=30)  # 30 second timeout
            if acquired:
                with self.thread_lock:
                    self.active_threads += 1
                    logger.debug(f"Thread slot acquired. Active: {self.active_threads}/{self.max_threads}")
            return acquired
        except Exception as e:
            logger.error(f"Error acquiring thread slot: {e}")
            return False

    def release_thread_slot(self):
        """Release a thread slot."""
        try:
            with self.thread_lock:
                if self.active_threads > 0:
                    self.active_threads -= 1
                    logger.debug(f"Thread slot released. Active: {self.active_threads}/{self.max_threads}")
            self.semaphore.release()
        except Exception as e:
            logger.error(f"Error releasing thread slot: {e}")

    def update_metrics(self, metric_type, value=1):
        """
        Update metrics counters.

        Args:
            metric_type: Type of metric to update
            value: Value to add (default 1)
        """
        try:
            if metric_type in self.metrics:
                if isinstance(self.metrics[metric_type], (int, float)):
                    self.metrics[metric_type] += value
                elif metric_type == 'last_scan_time':
                    self.metrics[metric_type] = datetime.now()
        except Exception as e:
            logger.error(f"Error updating metrics: {e}")

    def get_metrics(self):
        """
        Get current metrics.

        Returns:
            dict: Current metrics
        """
        return self.metrics.copy()

    def load_actions(self):
        """Load all actions from the actions file"""
        self.actions_dir = self.shared_data.actions_dir
        with open(self.shared_data.actions_file, 'r') as file:
            actions_config = json.load(file)
        for action in actions_config:
            module_name = action["b_module"]
            if module_name == 'scanning':
                self.load_scanner(module_name)
            elif module_name == 'nmap_vuln_scanner':
                self.load_nmap_vuln_scanner(module_name)
            else:
                self.load_action(module_name, action)

    def load_scanner(self, module_name):
        """Load the network scanner"""
        module = importlib.import_module(f'actions.{module_name}')
        b_class = getattr(module, 'b_class')
        self.network_scanner = getattr(module, b_class)(self.shared_data)

    def load_nmap_vuln_scanner(self, module_name):
        """Load the nmap vulnerability scanner"""
        self.nmap_vuln_scanner = NmapVulnScanner(self.shared_data)

    def load_action(self, module_name, action):
        """Load an action from the actions file"""
        module = importlib.import_module(f'actions.{module_name}')
        try:
            b_class = action["b_class"]
            action_instance = getattr(module, b_class)(self.shared_data)
            action_instance.action_name = b_class
            action_instance.port = action.get("b_port")
            action_instance.b_parent_action = action.get("b_parent")
            if action_instance.port == 0:
                self.standalone_actions.append(action_instance)
            else:
                self.actions.append(action_instance)
        except AttributeError as e:
            logger.error(f"Module {module_name} is missing required attributes: {e}")

    def process_alive_ips(self, current_data):
        """Process all IPs with alive status set to 1"""
        any_action_executed = False
        action_executed_status = None

        for action in self.actions:
            for row in current_data:
                if row["Alive"] != '1':
                    continue
                ip, ports = row["IPs"], row["Ports"].split(';')
                action_key = action.action_name

                if action.b_parent_action is None:
                    with self.semaphore:
                        if self.execute_action(action, ip, ports, row, action_key, current_data):
                            action_executed_status = action_key
                            any_action_executed = True
                            self.shared_data.bjornorch_status = action_executed_status

                            for child_action in self.actions:
                                if child_action.b_parent_action == action_key:
                                    with self.semaphore:
                                        if self.execute_action(child_action, ip, ports, row, child_action.action_name, current_data):
                                            action_executed_status = child_action.action_name
                                            self.shared_data.bjornorch_status = action_executed_status
                                            break
                            break

        for child_action in self.actions:
            if child_action.b_parent_action:
                action_key = child_action.action_name
                for row in current_data:
                    ip, ports = row["IPs"], row["Ports"].split(';')
                    with self.semaphore:
                        if self.execute_action(child_action, ip, ports, row, action_key, current_data):
                            action_executed_status = child_action.action_name
                            any_action_executed = True
                            self.shared_data.bjornorch_status = action_executed_status
                            break

        return any_action_executed


    def execute_action(self, action, ip, ports, row, action_key, current_data):
        """
        Execute an action on a target with improved error handling and metrics.

        Args:
            action: Action instance to execute
            ip: Target IP address
            ports: List of open ports
            row: Current data row
            action_key: Action identifier
            current_data: All current data

        Returns:
            bool: True if action executed successfully, False otherwise
        """
        try:
            # Validate inputs
            if not action or not ip or not ports:
                logger.warning(f"Invalid inputs for action execution: action={action}, ip={ip}, ports={ports}")
                return False

            # Check if port is required and available
            if hasattr(action, 'port') and str(action.port) not in ports:
                return False

            # Check parent action status
            if action.b_parent_action:
                parent_status = row.get(action.b_parent_action, "")
                if 'success' not in parent_status:
                    return False  # Skip child action if parent action has not succeeded

            # Check if the action is already successful and if retries are disabled for successful actions
            if 'success' in row.get(action_key, ""):
                if not self.shared_data.retry_success_actions:
                    return False  # Skip if retries are disabled for successful actions

            # Check if the action has failed and if retries are disabled for failed actions
            if 'failed' in row.get(action_key, ""):
                if not self.shared_data.retry_failed_actions:
                    return False  # Skip if retries are disabled for failed actions

            # Acquire thread slot
            if not self.acquire_thread_slot():
                logger.warning(f"Could not acquire thread slot for action {action_key} on {ip}")
                return False

            try:
                # Execute the action
                logger.info(f"Executing {action_key} on {ip}")
                self.update_metrics('actions_executed')

                start_time = time.time()
                result = action.execute(ip, action.port, row, action_key)
                execution_time = time.time() - start_time

                # Update metrics based on result
                if result == 'success':
                    self.update_metrics('successful_attacks')
                    logger.info(f"Action {action_key} on {ip} completed successfully in {execution_time:.2f}s")

                    # Check achievements after successful action
                    try:
                        from achievement_manager import AchievementManager
                        achievement_manager = AchievementManager(self.shared_data)
                        achievement_manager.check_achievements()
                    except Exception as e:
                        logger.error(f"Error checking achievements: {e}")
                else:
                    self.update_metrics('failed_attacks')
                    logger.info(f"Action {action_key} on {ip} failed in {execution_time:.2f}s")

                # Update the row with the result
                row[action_key] = result

                return result == 'success'

            finally:
                # Always release the thread slot
                self.release_thread_slot()

        except Exception as e:
            logger.error(f"Error executing action {action_key} on {ip}: {e}")
            self.update_metrics('failed_attacks')
            return False

    def execute_standalone_action(self, action, current_data):
        """Execute a standalone action"""
        row = next((r for r in current_data if r["MAC Address"] == "STANDALONE"), None)
        if not row:
            row = {
                "MAC Address": "STANDALONE",
                "IPs": "STANDALONE",
                "Hostnames": "STANDALONE",
                "Ports": "0",
                "Alive": "0"
            }
            current_data.append(row)

        action_key = action.action_name
        if action_key not in row:
            row[action_key] = ""

        # Check if the action is already successful and if retries are disabled for successful actions
        if 'success' in row[action_key]:
            if not self.shared_data.retry_success_actions:
                return False
            else:
                try:
                    last_success_time = datetime.strptime(row[action_key].split('_')[1] + "_" + row[action_key].split('_')[2], "%Y%m%d_%H%M%S")
                    if datetime.now() < last_success_time + timedelta(seconds=self.shared_data.success_retry_delay):
                        retry_in_seconds = (last_success_time + timedelta(seconds=self.shared_data.success_retry_delay) - datetime.now()).seconds
                        formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                        logger.warning(f"Skipping standalone action {action.action_name} due to success retry delay, retry possible in: {formatted_retry_in}")
                        return False  # Skip if the success retry delay has not passed
                except ValueError as ve:
                    logger.error(f"Error parsing last success time for {action.action_name}: {ve}")

        last_failed_time_str = row.get(action_key, "")
        if 'failed' in last_failed_time_str:
            try:
                last_failed_time = datetime.strptime(last_failed_time_str.split('_')[1] + "_" + last_failed_time_str.split('_')[2], "%Y%m%d_%H%M%S")
                if datetime.now() < last_failed_time + timedelta(seconds=self.shared_data.failed_retry_delay):
                    retry_in_seconds = (last_failed_time + timedelta(seconds=self.shared_data.failed_retry_delay) - datetime.now()).seconds
                    formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                    logger.warning(f"Skipping standalone action {action.action_name} due to failed retry delay, retry possible in: {formatted_retry_in}")
                    return False  # Skip if the retry delay has not passed
            except ValueError as ve:
                logger.error(f"Error parsing last failed time for {action.action_name}: {ve}")

        try:
            logger.info(f"Executing standalone action {action.action_name}")
            result = action.execute()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if result == 'success':
                row[action_key] = f'success_{timestamp}'
                logger.info(f"Standalone action {action.action_name} executed successfully")
            else:
                row[action_key] = f'failed_{timestamp}'
                logger.error(f"Standalone action {action.action_name} failed")
            self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Standalone action {action.action_name} failed: {e}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            row[action_key] = f'failed_{timestamp}'
            self.shared_data.write_data(current_data)
            return False

    def run(self):
        """Run the orchestrator cycle to execute actions"""
        #Run the scanner a first time to get the initial data
        self.shared_data.bjornorch_status = "NetworkScanner"
        self.shared_data.bjornstatustext2 = "First scan..."
        self.network_scanner.scan()
        self.shared_data.bjornstatustext2 = ""
        while not self.shared_data.orchestrator_should_exit:
            current_data = self.shared_data.read_data()
            any_action_executed = False
            action_executed_status = None
            action_retry_pending = False
            any_action_executed = self.process_alive_ips(current_data)

            for action in self.actions:
                for row in current_data:
                    if row["Alive"] != '1':
                        continue
                    ip, ports = row["IPs"], row["Ports"].split(';')
                    action_key = action.action_name

                    if action.b_parent_action is None:
                        with self.semaphore:
                            if self.execute_action(action, ip, ports, row, action_key, current_data):
                                action_executed_status = action_key
                                any_action_executed = True
                                self.shared_data.bjornorch_status = action_executed_status

                                for child_action in self.actions:
                                    if child_action.b_parent_action == action_key:
                                        with self.semaphore:
                                            if self.execute_action(child_action, ip, ports, row, child_action.action_name, current_data):
                                                action_executed_status = child_action.action_name
                                                self.shared_data.bjornorch_status = action_executed_status
                                                break
                                break

            for child_action in self.actions:
                if child_action.b_parent_action:
                    action_key = child_action.action_name
                    for row in current_data:
                        ip, ports = row["IPs"], row["Ports"].split(';')
                        with self.semaphore:
                            if self.execute_action(child_action, ip, ports, row, action_key, current_data):
                                action_executed_status = child_action.action_name
                                any_action_executed = True
                                self.shared_data.bjornorch_status = action_executed_status
                                break

            self.shared_data.write_data(current_data)

            if not any_action_executed:
                self.shared_data.bjornorch_status = "IDLE"
                self.shared_data.bjornstatustext2 = ""
                logger.info("No available targets. Running network scan...")
                if self.network_scanner:
                    self.shared_data.bjornorch_status = "NetworkScanner"
                    self.network_scanner.scan()
                     # Relire les données mises à jour après le scan
                    current_data = self.shared_data.read_data()
                    any_action_executed = self.process_alive_ips(current_data)
                    if self.shared_data.scan_vuln_running:
                        current_time = datetime.now()
                        if current_time >= self.last_vuln_scan_time + timedelta(seconds=self.shared_data.scan_vuln_interval):
                            try:
                                logger.info("Starting vulnerability scans...")
                                for row in current_data:
                                    if row["Alive"] == '1':
                                        ip = row["IPs"]
                                        scan_status = row.get("NmapVulnScanner", "")

                                        # Check success retry delay
                                        if 'success' in scan_status:
                                            last_success_time = datetime.strptime(scan_status.split('_')[1] + "_" + scan_status.split('_')[2], "%Y%m%d_%H%M%S")
                                            if not self.shared_data.retry_success_actions:
                                                logger.warning(f"Skipping vulnerability scan for {ip} because retry on success is disabled.")
                                                continue  # Skip if retry on success is disabled
                                            if datetime.now() < last_success_time + timedelta(seconds=self.shared_data.success_retry_delay):
                                                retry_in_seconds = (last_success_time + timedelta(seconds=self.shared_data.success_retry_delay) - datetime.now()).seconds
                                                formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                                                logger.warning(f"Skipping vulnerability scan for {ip} due to success retry delay, retry possible in: {formatted_retry_in}")
                                                # Skip if the retry delay has not passed
                                                continue

                                        # Check failed retry delay
                                        if 'failed' in scan_status:
                                            last_failed_time = datetime.strptime(scan_status.split('_')[1] + "_" + scan_status.split('_')[2], "%Y%m%d_%H%M%S")
                                            if datetime.now() < last_failed_time + timedelta(seconds=self.shared_data.failed_retry_delay):
                                                retry_in_seconds = (last_failed_time + timedelta(seconds=self.shared_data.failed_retry_delay) - datetime.now()).seconds
                                                formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                                                logger.warning(f"Skipping vulnerability scan for {ip} due to failed retry delay, retry possible in: {formatted_retry_in}")
                                                continue

                                        with self.semaphore:
                                            result = self.nmap_vuln_scanner.execute(ip, row, "NmapVulnScanner")
                                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                            if result == 'success':
                                                row["NmapVulnScanner"] = f'success_{timestamp}'
                                            else:
                                                row["NmapVulnScanner"] = f'failed_{timestamp}'
                                            self.shared_data.write_data(current_data)
                                self.last_vuln_scan_time = current_time
                            except Exception as e:
                                logger.error(f"Error during vulnerability scan: {e}")


                else:
                    logger.warning("No network scanner available.")
                self.failed_scans_count += 1
                if self.failed_scans_count >= 1:
                    for action in self.standalone_actions:
                        with self.semaphore:
                            if self.execute_standalone_action(action, current_data):
                                self.failed_scans_count = 0
                                break
                    idle_start_time = datetime.now()
                    idle_end_time = idle_start_time + timedelta(seconds=self.shared_data.scan_interval)

                    # Perform IDLE network scanning if wifite2 is available and Alfa adapter is detected
                    try:
                        from actions.wifite2_connector import Wifite2Connector
                        wifite2_connector = Wifite2Connector(self.shared_data)

                        # Check if Alfa adapter is detected and wireless scanning is enabled
                        if (getattr(self.shared_data, 'wireless_scan_enabled', True) and
                            getattr(self.shared_data, 'wireless_require_alfa_adapter', True) and
                            getattr(self.shared_data, 'wireless_idle_scanning_enabled', True) and
                            wifite2_connector.detect_alfa_wifi_adapter()):

                            logger.info("Starting IDLE network scanning with wifite2...")
                            self.shared_data.bjornorch_status = "Wifite2IdleScan"
                            wifite2_connector.perform_idle_network_scanning()
                            logger.info("IDLE network scanning completed")
                        else:
                            logger.info("Skipping IDLE network scanning - no Alfa adapter or wireless scanning disabled")
                    except ImportError as e:
                        logger.debug(f"Wifite2 connector not available for IDLE scanning: {e}")
                    except Exception as e:
                        logger.error(f"Error during IDLE network scanning: {e}")

                    while datetime.now() < idle_end_time:
                        if self.shared_data.orchestrator_should_exit:
                            break
                        remaining_time = (idle_end_time - datetime.now()).seconds
                        self.shared_data.bjornorch_status = "IDLE"
                        self.shared_data.bjornstatustext2 = ""
                        sys.stdout.write('\x1b[1A\x1b[2K')
                        logger.warning(f"Scanner did not find any new targets. Next scan in: {remaining_time} seconds")
                        time.sleep(1)
                    self.failed_scans_count = 0
                    continue
            else:
                self.failed_scans_count = 0
                action_retry_pending = True

            if action_retry_pending:
                self.failed_scans_count = 0

if __name__ == "__main__":
    orchestrator = Orchestrator()
    orchestrator.run()
