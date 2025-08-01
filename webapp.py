#webapp.py
import json
import threading
import http.server
import socketserver
import logging
import sys
import signal
import os
import gzip
import io
import re
import html
from urllib.parse import parse_qs, urlparse
from logger import Logger
from init_shared import shared_data
from utils import WebUtils
import time

# Initialize the logger
logger = Logger(name="webapp.py", level=logging.DEBUG)

# Set the path to the favicon
favicon_path = os.path.join(shared_data.webdir, '/images/favicon.ico')

class InputValidator:
    """
    Input validation and sanitization for web requests.
    """

    @staticmethod
    def sanitize_input(data):
        """
        Sanitize user input to prevent injection attacks.

        Args:
            data: Input data to sanitize

        Returns:
            str: Sanitized data
        """
        if data is None:
            return ""

        # Convert to string and escape HTML
        sanitized = html.escape(str(data))

        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', sanitized)

        return sanitized.strip()

    @staticmethod
    def validate_ip_address(ip):
        """
        Validate IP address format.

        Args:
            ip: IP address to validate

        Returns:
            bool: True if valid IP, False otherwise
        """
        if not ip:
            return False

        # Basic IP validation regex
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ip_pattern, ip))

    @staticmethod
    def validate_port(port):
        """
        Validate port number.

        Args:
            port: Port number to validate

        Returns:
            bool: True if valid port, False otherwise
        """
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False

    @staticmethod
    def validate_ssid(ssid):
        """
        Validate WiFi SSID.

        Args:
            ssid: SSID to validate

        Returns:
            bool: True if valid SSID, False otherwise
        """
        if not ssid:
            return False

        # SSID should be 1-32 characters, no control characters
        return 1 <= len(ssid) <= 32 and not re.search(r'[\x00-\x1f\x7f]', ssid)

class RateLimiter:
    """
    Rate limiting for web requests.
    """

    def __init__(self, max_requests=100, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}

    def is_allowed(self, client_ip):
        """
        Check if request is allowed for client IP.

        Args:
            client_ip: Client IP address

        Returns:
            bool: True if request is allowed, False otherwise
        """
        current_time = time.time()

        # Clean old entries
        self.requests = {
            ip: times for ip, times in self.requests.items()
            if any(current_time - t < self.window_seconds for t in times)
        }

        # Get current requests for this IP
        if client_ip not in self.requests:
            self.requests[client_ip] = []

        # Remove old requests outside window
        self.requests[client_ip] = [
            t for t in self.requests[client_ip]
            if current_time - t < self.window_seconds
        ]

        # Check if under limit
        if len(self.requests[client_ip]) >= self.max_requests:
            return False

        # Add current request
        self.requests[client_ip].append(current_time)
        return True

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.shared_data = shared_data
        self.web_utils = WebUtils(shared_data, logger)
        self.validator = InputValidator()
        self.rate_limiter = RateLimiter()
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        # Override to suppress logging of GET requests.
        if 'GET' not in format % args:
            logger.info("%s - - [%s] %s\n" %
                        (self.client_address[0],
                         self.log_date_time_string(),
                         format % args))

    def gzip_encode(self, content):
        """Gzip compress the given content."""
        out = io.BytesIO()
        with gzip.GzipFile(fileobj=out, mode="w") as f:
            f.write(content)
        return out.getvalue()

    def send_gzipped_response(self, content, content_type):
        """Send a gzipped HTTP response."""
        gzipped_content = self.gzip_encode(content)
        self.send_response(200)
        self.send_header("Content-type", content_type)
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(gzipped_content)))
        self.end_headers()
        self.wfile.write(gzipped_content)

    def serve_file_gzipped(self, file_path, content_type):
        """Serve a file with gzip compression."""
        with open(file_path, 'rb') as file:
            content = file.read()
        self.send_gzipped_response(content, content_type)

    def check_rate_limit(self):
        """
        Check rate limiting for current request.

        Returns:
            bool: True if request is allowed, False if rate limited
        """
        client_ip = self.client_address[0]
        if not self.rate_limiter.is_allowed(client_ip):
            self.send_error(429, "Too Many Requests")
            return False
        return True

    def parse_post_data(self):
        """
        Parse and validate POST data.

        Returns:
            dict: Parsed and validated POST data
        """
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 1024 * 1024:  # 1MB limit
                raise ValueError("Request too large")

            post_data = self.rfile.read(content_length).decode('utf-8')
            parsed_data = parse_qs(post_data)

            # Sanitize all input values
            sanitized_data = {}
            for key, values in parsed_data.items():
                sanitized_key = self.validator.sanitize_input(key)
                sanitized_values = [self.validator.sanitize_input(v) for v in values]
                sanitized_data[sanitized_key] = sanitized_values

            return sanitized_data

        except Exception as e:
            logger.error(f"Error parsing POST data: {e}")
            return {}

    def do_GET(self):
        """Handle GET requests with input validation."""
        # Check rate limiting
        if not self.check_rate_limit():
            return

        try:
            # Parse and validate URL
            parsed_url = urlparse(self.path)
            path = self.validator.sanitize_input(parsed_url.path)

            # Handle GET requests. Serve the HTML interface and the EPD image.
            if path == '/index.html' or path == '/':
                self.serve_file_gzipped(os.path.join(self.shared_data.webdir, 'index.html'), 'text/html')
            elif path == '/config.html':
                self.serve_file_gzipped(os.path.join(self.shared_data.webdir, 'config.html'), 'text/html')
            elif path == '/actions.html':
                self.serve_file_gzipped(os.path.join(self.shared_data.webdir, 'actions.html'), 'text/html')
            elif path == '/network.html':
                self.serve_file_gzipped(os.path.join(self.shared_data.webdir, 'network.html'), 'text/html')
            elif path == '/netkb.html':
                self.serve_file_gzipped(os.path.join(self.shared_data.webdir, 'netkb.html'), 'text/html')
            elif path == '/bjorn.html':
                self.serve_file_gzipped(os.path.join(self.shared_data.webdir, 'bjorn.html'), 'text/html')
            elif path == '/loot.html':
                self.serve_file_gzipped(os.path.join(self.shared_data.webdir, 'loot.html'), 'text/html')
            elif path == '/credentials.html':
                self.serve_file_gzipped(os.path.join(self.shared_data.webdir, 'credentials.html'), 'text/html')
            elif path == '/achievements.html':
                self.serve_file_gzipped(os.path.join(self.shared_data.webdir, 'achievements.html'), 'text/html')
            elif path == '/manual.html':
                self.serve_file_gzipped(os.path.join(self.shared_data.webdir, 'manual.html'), 'text/html')
            elif path == '/load_config':
                self.web_utils.serve_current_config(self)
            elif path == '/restore_default_config':
                self.web_utils.restore_default_config(self)
            elif path == '/get_web_delay':
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                response = json.dumps({"web_delay": self.shared_data.web_delay})
                self.wfile.write(response.encode('utf-8'))
            elif path == '/scan_wifi':
                self.web_utils.scan_wifi(self)
            elif path == '/network_data':
                self.web_utils.serve_network_data(self)
            elif path == '/netkb_data':
                self.web_utils.serve_netkb_data(self)
            elif path == '/netkb_data_json':
                self.web_utils.serve_netkb_data_json(self)
            elif path.startswith('/screen.png'):
                self.web_utils.serve_image(self)
            elif path == '/favicon.ico':
                self.web_utils.serve_favicon(self)
            elif path == '/manifest.json':
                self.web_utils.serve_manifest(self)
            elif path == '/apple-touch-icon':
                self.web_utils.serve_apple_touch_icon(self)
            elif path == '/get_logs':
                self.web_utils.serve_logs(self)
            elif path == '/list_credentials':
                self.web_utils.serve_credentials_data(self)
            elif path == '/achievements_data':
                self.web_utils.serve_achievements_data(self)
            elif path.startswith('/list_files'):
                self.web_utils.list_files_endpoint(self)
            elif path.startswith('/download_file'):
                self.web_utils.download_file(self)
            elif path.startswith('/download_backup'):
                self.web_utils.download_backup(self)
            else:
                self.send_error(404, "File not found")

        except Exception as e:
            logger.error(f"Error handling GET request: {e}")
            self.send_error(500, "Internal server error")

    def do_POST(self):
        """
        Handle POST requests with input validation and sanitization.

        Handles requests for saving configuration, connecting to Wi-Fi,
        clearing files, rebooting, and shutting down.
        """
        # Check rate limiting
        if not self.check_rate_limit():
            return

        try:
            # Parse and validate POST data
            post_data = self.parse_post_data()
            if not post_data:
                self.send_error(400, "Invalid POST data")
                return

            # Parse and validate URL
            parsed_url = urlparse(self.path)
            path = self.validator.sanitize_input(parsed_url.path)

            if path == '/save_config':
                self.handle_save_config(post_data)
            elif path == '/connect_wifi':
                self.handle_connect_wifi(post_data)
            elif path == '/clear_files':
                self.handle_clear_files(post_data)
            elif path == '/reboot':
                self.handle_reboot()
            elif path == '/shutdown':
                self.handle_shutdown()
            else:
                self.send_error(404, "Endpoint not found")

        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            self.send_error(500, "Internal server error")

    def handle_save_config(self, post_data):
        """Handle configuration save with validation."""
        try:
            # Validate configuration data
            if 'config' not in post_data:
                self.send_error(400, "Missing configuration data")
                return

            config_str = post_data['config'][0] if post_data['config'] else '{}'

            # Validate JSON format
            try:
                config = json.loads(config_str)
            except json.JSONDecodeError:
                self.send_error(400, "Invalid JSON format")
                return

            # Save configuration
            self.shared_data.config.update(config)
            self.shared_data.save_config()

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = json.dumps({"status": "success", "message": "Configuration saved"})
            self.wfile.write(response.encode('utf-8'))

        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            self.send_error(500, "Error saving configuration")

    def handle_connect_wifi(self, post_data):
        """Handle WiFi connection with validation."""
        try:
            # Validate required fields
            required_fields = ['ssid', 'password']
            for field in required_fields:
                if field not in post_data or not post_data[field]:
                    self.send_error(400, f"Missing required field: {field}")
                    return

            ssid = post_data['ssid'][0]
            password = post_data['password'][0]

            # Validate SSID
            if not self.validator.validate_ssid(ssid):
                self.send_error(400, "Invalid SSID format")
                return

            # Connect to WiFi (implement actual connection logic)
            logger.info(f"Attempting to connect to WiFi: {ssid}")

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = json.dumps({"status": "success", "message": f"Connecting to {ssid}"})
            self.wfile.write(response.encode('utf-8'))

        except Exception as e:
            logger.error(f"Error connecting to WiFi: {e}")
            self.send_error(500, "Error connecting to WiFi")

    def handle_clear_files(self, post_data):
        """Handle file clearing with validation."""
        try:
            # Validate file type
            if 'file_type' not in post_data:
                self.send_error(400, "Missing file type")
                return

            file_type = post_data['file_type'][0]

            # Validate file type (whitelist approach)
            allowed_types = ['logs', 'scan_results', 'credentials', 'all']
            if file_type not in allowed_types:
                self.send_error(400, f"Invalid file type. Allowed: {allowed_types}")
                return

            # Clear files (implement actual clearing logic)
            logger.info(f"Clearing files of type: {file_type}")

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = json.dumps({"status": "success", "message": f"Cleared {file_type} files"})
            self.wfile.write(response.encode('utf-8'))

        except Exception as e:
            logger.error(f"Error clearing files: {e}")
            self.send_error(500, "Error clearing files")

    def handle_reboot(self):
        """Handle system reboot."""
        try:
            logger.info("System reboot requested")

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = json.dumps({"status": "success", "message": "System rebooting"})
            self.wfile.write(response.encode('utf-8'))

            # Schedule reboot after response is sent
            import threading
            def delayed_reboot():
                time.sleep(2)
                os.system("sudo reboot")

            reboot_thread = threading.Thread(target=delayed_reboot)
            reboot_thread.daemon = True
            reboot_thread.start()

        except Exception as e:
            logger.error(f"Error handling reboot: {e}")
            self.send_error(500, "Error rebooting system")

    def handle_shutdown(self):
        """Handle system shutdown."""
        try:
            logger.info("System shutdown requested")

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = json.dumps({"status": "success", "message": "System shutting down"})
            self.wfile.write(response.encode('utf-8'))

            # Schedule shutdown after response is sent
            import threading
            def delayed_shutdown():
                time.sleep(2)
                os.system("sudo shutdown -h now")

            shutdown_thread = threading.Thread(target=delayed_shutdown)
            shutdown_thread.daemon = True
            shutdown_thread.start()

        except Exception as e:
            logger.error(f"Error handling shutdown: {e}")
            self.send_error(500, "Error shutting down system")

class WebThread(threading.Thread):
    """
    Thread to run the web server serving the EPD display interface.
    """
    def __init__(self, handler_class=CustomHandler, port=8000):
        super().__init__()
        self.shared_data = shared_data
        self.port = port
        self.handler_class = handler_class
        self.httpd = None

    def run(self):
        """
        Run the web server in a separate thread.
        """
        while not self.shared_data.webapp_should_exit:
            try:
                with socketserver.TCPServer(("", self.port), self.handler_class) as httpd:
                    self.httpd = httpd
                    logger.info(f"Serving at port {self.port}")
                    while not self.shared_data.webapp_should_exit:
                        httpd.handle_request()
            except OSError as e:
                if e.errno == 98:  # Address already in use error
                    logger.warning(f"Port {self.port} is in use, trying the next port...")
                    self.port += 1
                else:
                    logger.error(f"Error in web server: {e}")
                    break
            finally:
                if self.httpd:
                    self.httpd.server_close()
                    logger.info("Web server closed.")

    def shutdown(self):
        """
        Shutdown the web server gracefully.
        """
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            logger.info("Web server shutdown initiated.")

def handle_exit_web(signum, frame):
    """
    Handle exit signals to shutdown the web server cleanly.
    """
    shared_data.webapp_should_exit = True
    if web_thread.is_alive():
        web_thread.shutdown()
        web_thread.join()  # Wait until the web_thread is finished
    logger.info("Server shutting down...")
    sys.exit(0)

# Initialize the web thread
web_thread = WebThread(port=8000)

# Set up signal handling for graceful shutdown
signal.signal(signal.SIGINT, handle_exit_web)
signal.signal(signal.SIGTERM, handle_exit_web)

if __name__ == "__main__":
    try:
        # Start the web server thread
        web_thread.start()
        logger.info("Web server thread started.")
    except Exception as e:
        logger.error(f"An exception occurred during web server start: {e}")
        handle_exit_web(signal.SIGINT, None)
        sys.exit(1)
