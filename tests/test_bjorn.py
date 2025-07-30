#!/usr/bin/env python3
"""
Test suite for Bjorn penetration testing tool.

This module contains unit tests for the main Bjorn components including
the main Bjorn class, orchestrator, configuration validation, and web interface.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import tempfile
import json
import time

# Add the parent directory to the path to import Bjorn modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Bjorn import Bjorn, HealthMonitor
from shared import SharedData


class TestBjorn(unittest.TestCase):
    """Test cases for the main Bjorn class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_shared_data = Mock()
        self.mock_shared_data.should_exit = False
        self.mock_shared_data.manual_mode = False
        self.mock_shared_data.startup_delay = 0
        self.mock_shared_data.validate_config.return_value = True

        # Mock the Commentaireia class
        with patch('Bjorn.Commentaireia'):
            self.bjorn = Bjorn(self.mock_shared_data)

    def test_bjorn_initialization(self):
        """Test Bjorn class initialization."""
        self.assertIsNotNone(self.bjorn)
        self.assertEqual(self.bjorn.shared_data, self.mock_shared_data)
        self.assertFalse(self.bjorn.wifi_connected)
        self.assertIsNone(self.bjorn.orchestrator_thread)
        self.assertIsNone(self.bjorn.orchestrator)

    @patch('Bjorn.subprocess.run')
    def test_wifi_connected_success(self, mock_run):
        """Test WiFi connection check when connected."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "yes\n"

        result = self.bjorn.is_wifi_connected()

        self.assertTrue(result)
        self.assertTrue(self.bjorn.wifi_connected)
        mock_run.assert_called_once()

    @patch('Bjorn.subprocess.run')
    def test_wifi_connected_failure(self, mock_run):
        """Test WiFi connection check when not connected."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "no\n"

        result = self.bjorn.is_wifi_connected()

        self.assertFalse(result)
        self.assertFalse(self.bjorn.wifi_connected)

    @patch('Bjorn.subprocess.run')
    def test_wifi_connected_timeout(self, mock_run):
        """Test WiFi connection check with timeout."""
        mock_run.side_effect = TimeoutError("Command timed out")

        result = self.bjorn.is_wifi_connected()

        self.assertFalse(result)
        self.assertFalse(self.bjorn.wifi_connected)

    @patch('Bjorn.subprocess.run')
    def test_wifi_connected_command_not_found(self, mock_run):
        """Test WiFi connection check when nmcli is not found."""
        mock_run.side_effect = FileNotFoundError("Command not found")

        result = self.bjorn.is_wifi_connected()

        self.assertFalse(result)
        self.assertFalse(self.bjorn.wifi_connected)

    def test_start_orchestrator_no_wifi(self):
        """Test starting orchestrator when WiFi is not connected."""
        with patch.object(self.bjorn, 'is_wifi_connected', return_value=False):
            result = self.bjorn.start_orchestrator()

            self.assertFalse(result)

    def test_stop_orchestrator_not_running(self):
        """Test stopping orchestrator when not running."""
        result = self.bjorn.stop_orchestrator()

        self.assertTrue(result)  # Should return True when not running


class TestHealthMonitor(unittest.TestCase):
    """Test cases for the HealthMonitor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_shared_data = Mock()
        self.health_monitor = HealthMonitor(self.mock_shared_data)

    def test_health_monitor_initialization(self):
        """Test HealthMonitor initialization."""
        self.assertIsNotNone(self.health_monitor)
        self.assertEqual(self.health_monitor.shared_data, self.mock_shared_data)
        self.assertEqual(self.health_monitor.check_interval, 300)
        self.assertEqual(self.health_monitor.last_check, 0)

    @patch('Bjorn.psutil')
    def test_check_system_health_success(self, mock_psutil):
        """Test system health check with psutil available."""
        mock_psutil.cpu_percent.return_value = 25.5
        mock_psutil.virtual_memory.return_value.percent = 60.0
        mock_psutil.disk_usage.return_value.percent = 45.0

        # Mock time to control the check interval
        with patch('time.time', return_value=1000):
            result = self.health_monitor.check_system_health()

        self.assertIsInstance(result, dict)
        self.assertEqual(result['cpu_percent'], 25.5)
        self.assertEqual(result['memory_percent'], 60.0)
        self.assertEqual(result['disk_percent'], 45.0)
        self.assertEqual(result['timestamp'], 1000)

    @patch('Bjorn.psutil')
    def test_check_system_health_high_usage(self, mock_psutil):
        """Test system health check with high resource usage."""
        mock_psutil.cpu_percent.return_value = 85.0
        mock_psutil.virtual_memory.return_value.percent = 90.0
        mock_psutil.disk_usage.return_value.percent = 95.0

        with patch('time.time', return_value=1000):
            with patch('Bjorn.logger') as mock_logger:
                result = self.health_monitor.check_system_health()

        # Should log warnings for high usage
        self.assertEqual(mock_logger.warning.call_count, 3)

    def test_check_system_health_no_psutil(self):
        """Test system health check when psutil is not available."""
        with patch('time.time', return_value=1000):
            with patch('Bjorn.logger') as mock_logger:
                result = self.health_monitor.check_system_health()

        # Should log warning about psutil not available
        mock_logger.warning.assert_called_with("psutil not available, skipping health check")

    def test_check_system_health_interval(self):
        """Test that health check respects the interval."""
        # First check
        with patch('time.time', return_value=1000):
            result1 = self.health_monitor.check_system_health()

        # Second check within interval (should return cached result)
        with patch('time.time', return_value=1100):  # 100 seconds later, within 300s interval
            result2 = self.health_monitor.check_system_health()

        # Should return the same result without checking again
        self.assertEqual(result1, result2)


class TestSharedData(unittest.TestCase):
    """Test cases for the SharedData class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'test_config.json')

        # Create a minimal SharedData instance for testing
        with patch('shared.SharedData.initialize_paths'):
            with patch('shared.SharedData.setup_environment'):
                with patch('shared.SharedData.initialize_variables'):
                    with patch('shared.SharedData.create_livestatusfile'):
                        with patch('shared.SharedData.load_fonts'):
                            with patch('shared.SharedData.load_images'):
                                self.shared_data = SharedData()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_validate_config_success(self):
        """Test configuration validation with valid config."""
        # Set up valid configuration
        self.shared_data.startup_delay = 10
        self.shared_data.scan_interval = 180
        self.shared_data.web_delay = 2
        self.shared_data.screen_delay = 1
        self.shared_data.portstart = 1
        self.shared_data.portend = 100

        result = self.shared_data.validate_config()

        self.assertTrue(result)

    def test_validate_config_missing_settings(self):
        """Test configuration validation with missing settings."""
        # Don't set any configuration values

        result = self.shared_data.validate_config()

        self.assertFalse(result)

    def test_validate_config_invalid_port_range(self):
        """Test configuration validation with invalid port range."""
        self.shared_data.startup_delay = 10
        self.shared_data.scan_interval = 180
        self.shared_data.web_delay = 2
        self.shared_data.screen_delay = 1
        self.shared_data.portstart = 100  # Start > end
        self.shared_data.portend = 1

        result = self.shared_data.validate_config()

        self.assertFalse(result)

    def test_validate_wireless_config_success(self):
        """Test wireless configuration validation with valid config."""
        # Set up valid wireless configuration
        self.shared_data.wireless_scan_enabled = True
        self.shared_data.wireless_attack_timeout = 300
        self.shared_data.wireless_scan_interval = 600
        self.shared_data.wireless_retry_failed = True
        self.shared_data.wireless_wps_priority = True
        self.shared_data.wireless_pmkid_enabled = True
        self.shared_data.wireless_handshake_enabled = True

        result = self.shared_data.validate_wireless_config()

        self.assertTrue(result)

    def test_validate_wireless_config_missing_settings(self):
        """Test wireless configuration validation with missing settings."""
        # Don't set wireless configuration values

        result = self.shared_data.validate_wireless_config()

        # Should set defaults and return True
        self.assertTrue(result)
        self.assertTrue(hasattr(self.shared_data, 'wireless_scan_enabled'))
        self.assertTrue(hasattr(self.shared_data, 'wireless_attack_timeout'))


class TestWebInterface(unittest.TestCase):
    """Test cases for the web interface components."""

    def setUp(self):
        """Set up test fixtures."""
        from webapp import InputValidator, RateLimiter

        self.validator = InputValidator()
        self.rate_limiter = RateLimiter()

    def test_sanitize_input_normal(self):
        """Test input sanitization with normal input."""
        test_input = "normal text"
        result = self.validator.sanitize_input(test_input)

        self.assertEqual(result, "normal text")

    def test_sanitize_input_html_injection(self):
        """Test input sanitization with HTML injection attempt."""
        test_input = "<script>alert('xss')</script>"
        result = self.validator.sanitize_input(test_input)

        self.assertNotIn("<script>", result)
        self.assertNotIn("</script>", result)

    def test_sanitize_input_none(self):
        """Test input sanitization with None input."""
        result = self.validator.sanitize_input(None)

        self.assertEqual(result, "")

    def test_validate_ip_address_valid(self):
        """Test IP address validation with valid IPs."""
        valid_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"]

        for ip in valid_ips:
            result = self.validator.validate_ip_address(ip)
            self.assertTrue(result, f"IP {ip} should be valid")

    def test_validate_ip_address_invalid(self):
        """Test IP address validation with invalid IPs."""
        invalid_ips = ["256.1.2.3", "1.2.3.256", "192.168.1", "not.an.ip", ""]

        for ip in invalid_ips:
            result = self.validator.validate_ip_address(ip)
            self.assertFalse(result, f"IP {ip} should be invalid")

    def test_validate_port_valid(self):
        """Test port validation with valid ports."""
        valid_ports = [1, 80, 443, 8080, 65535]

        for port in valid_ports:
            result = self.validator.validate_port(port)
            self.assertTrue(result, f"Port {port} should be valid")

    def test_validate_port_invalid(self):
        """Test port validation with invalid ports."""
        invalid_ports = [0, 65536, -1, "not_a_port", ""]

        for port in invalid_ports:
            result = self.validator.validate_port(port)
            self.assertFalse(result, f"Port {port} should be invalid")

    def test_validate_ssid_valid(self):
        """Test SSID validation with valid SSIDs."""
        valid_ssids = ["MyWiFi", "WiFi_Network", "a" * 32]  # Max length

        for ssid in valid_ssids:
            result = self.validator.validate_ssid(ssid)
            self.assertTrue(result, f"SSID {ssid} should be valid")

    def test_validate_ssid_invalid(self):
        """Test SSID validation with invalid SSIDs."""
        invalid_ssids = ["", "a" * 33, "WiFi\x00Network"]  # Too long, control char

        for ssid in invalid_ssids:
            result = self.validator.validate_ssid(ssid)
            self.assertFalse(result, f"SSID {ssid} should be invalid")

    def test_rate_limiter_initial(self):
        """Test rate limiter with initial requests."""
        client_ip = "192.168.1.1"

        # First request should be allowed
        result = self.rate_limiter.is_allowed(client_ip)
        self.assertTrue(result)

    def test_rate_limiter_limit_exceeded(self):
        """Test rate limiter when limit is exceeded."""
        client_ip = "192.168.1.1"

        # Make max_requests + 1 requests
        for _ in range(self.rate_limiter.max_requests + 1):
            result = self.rate_limiter.is_allowed(client_ip)

        # Last request should be denied
        self.assertFalse(result)


def run_tests():
    """Run all tests and return results."""
    # Create test suite
    test_suite = unittest.TestSuite()

    # Add test cases
    test_classes = [
        TestBjorn,
        TestHealthMonitor,
        TestSharedData,
        TestWebInterface
    ]

    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)