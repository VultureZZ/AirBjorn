#bjorn.py
# This script defines the main execution flow for the Bjorn application. It initializes and starts
# various components such as network scanning, display, and web server functionalities. The Bjorn
# class manages the primary operations, including initiating network scans and orchestrating tasks.
# The script handles startup delays, checks for Wi-Fi connectivity, and coordinates the execution of
# scanning and orchestrator tasks using semaphores to limit concurrent threads. It also sets up
# signal handlers to ensure a clean exit when the application is terminated.

# Functions:
# - handle_exit:  handles the termination of the main and display threads.
# - handle_exit_webserver:  handles the termination of the web server thread.
# - is_wifi_connected: Checks for Wi-Fi connectivity using the nmcli command.

# The script starts by loading shared data configurations, then initializes and sta
# bjorn.py


import threading
import signal
import logging
import time
import sys
import subprocess
from typing import Optional
from init_shared import shared_data
from display import Display, handle_exit_display
from comment import Commentaireia
from webapp import web_thread, handle_exit_web
from orchestrator import Orchestrator
from achievement_manager import AchievementManager
from logger import Logger

logger = Logger(name="Bjorn.py", level=logging.DEBUG)

class Bjorn:
    """
    Main class for Bjorn. Manages the primary operations of the application.

    Attributes:
        shared_data: Centralized configuration and state management
        commentaire_ia: AI-powered comment generation
        orchestrator_thread: Thread running the attack orchestrator
        orchestrator: Orchestrator instance
        wifi_connected: Current WiFi connection status
        health_monitor: System health monitoring instance
    """

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.commentaire_ia = Commentaireia()
        self.orchestrator_thread: Optional[threading.Thread] = None
        self.orchestrator: Optional[Orchestrator] = None
        self.wifi_connected = False
        self.health_monitor = HealthMonitor(shared_data)
        self.achievement_manager = AchievementManager(shared_data)

        # Validate configuration on startup
        if not self.shared_data.validate_config():
            logger.error("Configuration validation failed. Exiting.")
            sys.exit(1)

    def run(self):
        """
        Main loop for Bjorn. Waits for Wi-Fi connection and starts Orchestrator.

        Continuously monitors WiFi connectivity and manages the orchestrator
        thread based on network availability and manual mode settings.
        """
        try:
            # Wait for startup delay if configured in shared data
            if hasattr(self.shared_data, 'startup_delay') and self.shared_data.startup_delay > 0:
                logger.info(f"Waiting for startup delay: {self.shared_data.startup_delay} seconds")
                time.sleep(self.shared_data.startup_delay)

            # Main loop to keep Bjorn running
            while not self.shared_data.should_exit:
                try:
                    if not self.shared_data.manual_mode:
                        self.check_and_start_orchestrator()

                    # Perform health check
                    self.health_monitor.check_system_health()

                    # Check achievements
                    self.achievement_manager.check_achievements()

                    time.sleep(10)  # Main loop idle waiting

                except Exception as e:
                    logger.error(f"Error in main loop iteration: {e}")
                    time.sleep(30)  # Wait longer on error

        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, shutting down gracefully...")
        except Exception as e:
            logger.error(f"Critical error in main run loop: {e}")
            raise

    def check_and_start_orchestrator(self):
        """
        Check Wi-Fi and start the orchestrator if connected.

        Returns:
            bool: True if orchestrator was started or is running, False otherwise
        """
        try:
            if self.is_wifi_connected():
                self.wifi_connected = True
                if self.orchestrator_thread is None or not self.orchestrator_thread.is_alive():
                    return self.start_orchestrator()
                return True
            else:
                self.wifi_connected = False
                logger.info("Waiting for Wi-Fi connection to start Orchestrator...")
                return False
        except Exception as e:
            logger.error(f"Error checking and starting orchestrator: {e}")
            return False

    def start_orchestrator(self):
        """
        Start the orchestrator thread.

        Returns:
            bool: True if orchestrator was started successfully, False otherwise
        """
        try:
            # Re-check if Wi-Fi is connected before starting the orchestrator
            if not self.is_wifi_connected():
                logger.warning("Cannot start Orchestrator: Wi-Fi is not connected.")
                return False

            if self.orchestrator_thread is None or not self.orchestrator_thread.is_alive():
                logger.info("Starting Orchestrator thread...")
                self.shared_data.orchestrator_should_exit = False
                self.shared_data.manual_mode = False

                self.orchestrator = Orchestrator()
                self.orchestrator_thread = threading.Thread(
                    target=self.orchestrator.run,
                    name="OrchestratorThread"
                )
                self.orchestrator_thread.daemon = True
                self.orchestrator_thread.start()

                logger.info("Orchestrator thread started, automatic mode activated.")
                return True
            else:
                logger.info("Orchestrator thread is already running.")
                return True

        except Exception as e:
            logger.error(f"Error starting orchestrator: {e}")
            return False

    def stop_orchestrator(self):
        """
        Stop the orchestrator thread gracefully.

        Returns:
            bool: True if orchestrator was stopped successfully, False otherwise
        """
        try:
            self.shared_data.manual_mode = True
            logger.info("Stop button pressed. Manual mode activated & Stopping Orchestrator...")

            if self.orchestrator_thread is not None and self.orchestrator_thread.is_alive():
                logger.info("Stopping Orchestrator thread...")
                self.shared_data.orchestrator_should_exit = True

                # Wait for orchestrator to stop with timeout
                self.orchestrator_thread.join(timeout=30)

                if self.orchestrator_thread.is_alive():
                    logger.warning("Orchestrator thread did not stop gracefully within timeout")
                    return False
                else:
                    logger.info("Orchestrator thread stopped successfully.")
                    self.shared_data.bjornorch_status = "IDLE"
                    self.shared_data.bjornstatustext2 = ""
                    self.shared_data.manual_mode = True
                    return True
            else:
                logger.info("Orchestrator thread is not running.")
                return True

        except Exception as e:
            logger.error(f"Error stopping orchestrator: {e}")
            return False

    def is_wifi_connected(self):
        """
        Checks for Wi-Fi connectivity using the nmcli command.

        Returns:
            bool: True if WiFi is connected, False otherwise
        """
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'active', 'dev', 'wifi'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0:
                logger.warning(f"nmcli command failed with return code {result.returncode}")
                self.wifi_connected = False
                return False

            self.wifi_connected = 'yes' in result.stdout
            return self.wifi_connected

        except subprocess.TimeoutExpired:
            logger.warning("WiFi connection check timed out")
            self.wifi_connected = False
            return False
        except FileNotFoundError:
            logger.error("nmcli command not found. Is NetworkManager installed?")
            self.wifi_connected = False
            return False
        except subprocess.SubprocessError as e:
            logger.error(f"Subprocess error checking WiFi: {e}")
            self.wifi_connected = False
            return False
        except Exception as e:
            logger.error(f"Unexpected error checking WiFi connection: {e}")
            self.wifi_connected = False
            return False

    @staticmethod
    def start_display():
        """
        Start the display thread.

        Returns:
            threading.Thread: The display thread instance
        """
        try:
            display = Display(shared_data)
            display_thread = threading.Thread(target=display.run, name="DisplayThread")
            display_thread.daemon = True
            display_thread.start()
            return display_thread
        except Exception as e:
            logger.error(f"Error starting display thread: {e}")
            raise


class HealthMonitor:
    """
    System health monitoring for Bjorn.

    Monitors system resources and performance metrics to ensure
    optimal operation of the penetration testing tool.
    """

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.health_metrics = {}
        self.last_check = 0
        self.check_interval = 300  # Check every 5 minutes

    def check_system_health(self):
        """
        Monitor system resources and performance.

        Returns:
            dict: Current health metrics
        """
        current_time = time.time()
        if current_time - self.last_check < self.check_interval:
            return self.health_metrics

        try:
            import psutil

            self.health_metrics = {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'timestamp': current_time
            }

            # Log warnings for high resource usage
            if self.health_metrics['cpu_percent'] > 80:
                logger.warning(f"High CPU usage: {self.health_metrics['cpu_percent']}%")
            if self.health_metrics['memory_percent'] > 85:
                logger.warning(f"High memory usage: {self.health_metrics['memory_percent']}%")
            if self.health_metrics['disk_percent'] > 90:
                logger.warning(f"High disk usage: {self.health_metrics['disk_percent']}%")

            self.last_check = current_time

        except ImportError:
            logger.warning("psutil not available, skipping health check")
        except Exception as e:
            logger.error(f"Error during health check: {e}")

        return self.health_metrics


def handle_exit(sig, frame, display_thread, bjorn_thread, web_thread):
    """
    Handles the termination of the main, display, and web threads.

    Args:
        sig: Signal number
        frame: Current stack frame
        display_thread: Display thread instance
        bjorn_thread: Main Bjorn thread instance
        web_thread: Web server thread instance
    """
    try:
        logger.info("Received exit signal, shutting down gracefully...")

        shared_data.should_exit = True
        shared_data.orchestrator_should_exit = True  # Ensure orchestrator stops
        shared_data.display_should_exit = True  # Ensure display stops
        shared_data.webapp_should_exit = True  # Ensure web server stops

        # Stop orchestrator if running
        if hasattr(shared_data, 'bjorn_instance') and shared_data.bjorn_instance:
            shared_data.bjorn_instance.stop_orchestrator()

        # Handle display exit
        handle_exit_display(sig, frame, display_thread)

        # Wait for threads to finish with timeout
        timeout = 30
        if display_thread.is_alive():
            display_thread.join(timeout=timeout)
        if bjorn_thread.is_alive():
            bjorn_thread.join(timeout=timeout)
        if web_thread.is_alive():
            web_thread.join(timeout=timeout)

        logger.info("Main loop finished. Clean exit.")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Error during shutdown: {e}")
        sys.exit(1)


if __name__ == "__main__":
    logger.info("Starting Bjorn threads")

    try:
        logger.info("Loading shared data config...")
        shared_data.load_config()

        logger.info("Starting display thread...")
        shared_data.display_should_exit = False  # Initialize display should_exit
        display_thread = Bjorn.start_display()

        logger.info("Starting Bjorn thread...")
        bjorn = Bjorn(shared_data)
        shared_data.bjorn_instance = bjorn  # Assign Bjorn instance to shared_data
        bjorn_thread = threading.Thread(target=bjorn.run, name="MainBjornThread")
        bjorn_thread.daemon = True
        bjorn_thread.start()

        if shared_data.config.get("websrv", True):
            logger.info("Starting the web server...")
            web_thread.start()

        # Set up signal handlers
        signal.signal(signal.SIGINT, lambda sig, frame: handle_exit(sig, frame, display_thread, bjorn_thread, web_thread))
        signal.signal(signal.SIGTERM, lambda sig, frame: handle_exit(sig, frame, display_thread, bjorn_thread, web_thread))

        logger.info("All threads started successfully")

    except Exception as e:
        logger.error(f"An exception occurred during thread start: {e}")
        try:
            handle_exit_display(signal.SIGINT, None)
        except:
            pass
        sys.exit(1)
