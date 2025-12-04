#!/usr/bin/env python3
"""
DNS Tunnel Detection Service - Interactive Installer
Guides users through configuration and installation
"""

import os
import sys
import platform
import subprocess
import getpass
from pathlib import Path
from typing import Dict, Any

try:
    import yaml
except ImportError:
    print("Installing required package: pyyaml")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml"])
    import yaml


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


class DNSTunnelInstaller:
    """Interactive installer for DNS Tunnel Detection Service."""

    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.install_dir = Path.cwd()
        self.is_windows = platform.system() == 'Windows'
        self.is_linux = platform.system() == 'Linux'

    def print_header(self, text: str):
        """Print formatted header."""
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 70}{Colors.END}")
        print(f"{Colors.HEADER}{Colors.BOLD}{text:^70}{Colors.END}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 70}{Colors.END}\n")

    def print_step(self, step: int, total: int, text: str):
        """Print step indicator."""
        print(f"{Colors.CYAN}[Step {step}/{total}]{Colors.END} {Colors.BOLD}{text}{Colors.END}\n")

    def print_success(self, text: str):
        """Print success message."""
        print(f"{Colors.GREEN}✓ {text}{Colors.END}")

    def print_error(self, text: str):
        """Print error message."""
        print(f"{Colors.RED}✗ {text}{Colors.END}")

    def print_warning(self, text: str):
        """Print warning message."""
        print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")

    def prompt(self, question: str, default: str = "") -> str:
        """Prompt user for input."""
        if default:
            prompt_text = f"{Colors.BLUE}? {question} [{default}]:{Colors.END} "
        else:
            prompt_text = f"{Colors.BLUE}? {question}:{Colors.END} "

        response = input(prompt_text).strip()
        return response if response else default

    def prompt_password(self, question: str) -> str:
        """Prompt for password (hidden input)."""
        return getpass.getpass(f"{Colors.BLUE}? {question}:{Colors.END} ")

    def prompt_yes_no(self, question: str, default: bool = False) -> bool:
        """Prompt for yes/no answer."""
        default_str = "Y/n" if default else "y/N"
        response = self.prompt(f"{question} ({default_str})", "y" if default else "n")
        return response.lower() in ['y', 'yes', '1', 'true']

    def welcome(self):
        """Display welcome message."""
        self.print_header("DNS Tunnel Detection Service - Installer")

        print("This installer will guide you through setting up the DNS Tunnel")
        print("Detection Service on your system.\n")
        print("The service will be configured to:")
        print("  • Monitor DNS queries for tunneling activity")
        print("  • Alert your team via Slack, Email, or JIRA")
        print("  • Optionally block malicious traffic automatically")
        print("  • Run as a system service on startup\n")

        input(f"{Colors.GREEN}Press Enter to begin...{Colors.END}")

    def configure_detection(self):
        """Configure detection settings."""
        self.print_step(1, 6, "Detection Configuration")

        print("Detection thresholds determine when alerts are triggered:")
        print("  • SUSPICIOUS: 0.60-0.84 (Warning alerts)")
        print("  • HIGH: 0.85+ (Critical alerts)\n")

        threshold_suspicious = float(self.prompt(
            "Suspicious threshold",
            "0.70"
        ))

        threshold_high = float(self.prompt(
            "High severity threshold",
            "0.85"
        ))

        window_size = int(self.prompt(
            "Analysis window size (seconds)",
            "60"
        ))

        self.config['detection'] = {
            'threshold_suspicious': threshold_suspicious,
            'threshold_high': threshold_high,
            'window_size': window_size,
            'model_path': 'models/isolation_forest.pkl'
        }

        self.print_success("Detection settings configured")

    def configure_database(self):
        """Configure database settings."""
        self.print_step(2, 6, "Database Configuration")

        print("Choose your database option:")
        print("  1. SQLite (embedded, no setup required) - Recommended for small deployments")
        print("  2. PostgreSQL (external, more scalable) - Recommended for enterprise\n")

        db_choice = self.prompt("Select option (1 or 2)", "1")

        if db_choice == "1":
            self.config['database'] = {
                'type': 'sqlite',
                'path': 'data/dns_tunnel.db'
            }
            self.print_success("Using embedded SQLite database")
        else:
            print("\nPostgreSQL Configuration:")
            self.config['database'] = {
                'type': 'postgresql',
                'host': self.prompt("PostgreSQL host", "localhost"),
                'port': int(self.prompt("PostgreSQL port", "5432")),
                'database': self.prompt("Database name", "dns_tunnel_db"),
                'username': self.prompt("Username", "dnsadmin"),
                'password': self.prompt_password("Password")
            }
            self.print_success("PostgreSQL configured")

    def configure_alerting(self):
        """Configure alerting channels."""
        self.print_step(3, 6, "Alerting Configuration")

        print("Configure how you want to receive alerts.\n")

        self.config['alerting'] = {
            'throttle_seconds': 300
        }

        # Slack
        if self.prompt_yes_no("Enable Slack notifications?", False):
            webhook = self.prompt("Slack webhook URL")
            self.config['alerting']['slack'] = {
                'enabled': True,
                'webhook_url': webhook
            }
            self.print_success("Slack configured")
        else:
            self.config['alerting']['slack'] = {'enabled': False}

        # Email
        if self.prompt_yes_no("Enable email notifications?", True):
            print("\nEmail SMTP Configuration:")
            self.config['alerting']['email'] = {
                'enabled': True,
                'smtp_host': self.prompt("SMTP host", "smtp.gmail.com"),
                'smtp_port': int(self.prompt("SMTP port", "587")),
                'from_address': self.prompt("From address", "alerts@company.com"),
                'to_addresses': self.prompt("To addresses (comma-separated)", "security@company.com"),
                'username': self.prompt("SMTP username"),
                'password': self.prompt_password("SMTP password")
            }
            self.print_success("Email configured")
        else:
            self.config['alerting']['email'] = {'enabled': False}

        # JIRA
        if self.prompt_yes_no("Enable JIRA ticket creation?", False):
            print("\nJIRA Configuration:")
            self.config['alerting']['jira'] = {
                'enabled': True,
                'url': self.prompt("JIRA URL (e.g., https://company.atlassian.net)"),
                'username': self.prompt("JIRA username/email"),
                'api_token': self.prompt_password("JIRA API token"),
                'project_key': self.prompt("Project key", "SEC")
            }
            self.print_success("JIRA configured")
        else:
            self.config['alerting']['jira'] = {'enabled': False}

    def configure_response(self):
        """Configure automated response."""
        self.print_step(4, 6, "Automated Response Configuration")

        print("Automated response can block malicious traffic automatically.")
        self.print_warning("Use with caution - may cause false positive blocks\n")

        auto_block = self.prompt_yes_no("Enable automated blocking?", False)

        self.config['response'] = {
            'auto_block': auto_block,
            'require_manual_approval': True if auto_block else False
        }

        if auto_block:
            self.print_warning("Automated blocking enabled with manual approval")
        else:
            self.print_success("Automated blocking disabled (manual only)")

    def configure_collector(self):
        """Configure log collection."""
        self.print_step(5, 6, "Log Collection Configuration")

        print("Configure where DNS logs are collected from.\n")

        enable_collector = self.prompt_yes_no("Enable automatic log collection?", True)

        if enable_collector:
            print("\nLog source options:")
            print("  1. File (Zeek/Bind9 logs)")
            print("  2. Network capture (requires root/admin)")
            print("  3. API only (external systems push to API)\n")

            source_type = self.prompt("Select option (1-3)", "1")

            sources = []
            if source_type == "1":
                log_path = self.prompt("Log file path", "/var/log/zeek/dns.log")
                sources.append({
                    'type': 'file',
                    'path': log_path,
                    'format': 'zeek'
                })
            elif source_type == "2":
                interface = self.prompt("Network interface", "eth0")
                sources.append({
                    'type': 'pcap',
                    'interface': interface
                })

            self.config['collector'] = {
                'enabled': True,
                'sources': sources
            }
            self.print_success("Log collector configured")
        else:
            self.config['collector'] = {
                'enabled': False,
                'sources': []
            }
            self.print_success("Using API-only mode")

    def configure_api(self):
        """Configure API settings."""
        self.print_step(6, 6, "API Configuration")

        print("Configure the REST API endpoint.\n")

        host = self.prompt("API host", "0.0.0.0")
        port = int(self.prompt("API port", "8000"))

        self.config['api'] = {
            'host': host,
            'port': port
        }

        self.print_success(f"API will be accessible at http://{host}:{port}")

    def save_configuration(self):
        """Save configuration to file."""
        config_path = self.install_dir / "config.yaml"

        with open(config_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)

        self.print_success(f"Configuration saved to {config_path}")

    def install_dependencies(self):
        """Install Python dependencies."""
        self.print_header("Installing Dependencies")

        requirements_file = self.install_dir / "requirements.txt"

        if not requirements_file.exists():
            self.print_error(f"requirements.txt not found at {requirements_file}")
            return False

        print("Installing Python packages...")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
            ])
            self.print_success("Dependencies installed")
            return True
        except subprocess.CalledProcessError as e:
            self.print_error(f"Failed to install dependencies: {e}")
            return False

    def create_directories(self):
        """Create necessary directories."""
        dirs = ['models', 'data', 'logs', 'reports']

        for dir_name in dirs:
            dir_path = self.install_dir / dir_name
            dir_path.mkdir(exist_ok=True)

        self.print_success("Directories created")

    def train_initial_model(self):
        """Train initial ML model."""
        self.print_header("Training ML Model")

        print("Training initial detection model with sample data...")
        print("This may take 30-60 seconds...\n")

        try:
            subprocess.check_call([
                sys.executable,
                str(self.install_dir / "scripts" / "train_model.py"),
                "--format", "sample",
                "--num-samples", "5000"
            ])
            self.print_success("Model trained successfully")
            return True
        except subprocess.CalledProcessError as e:
            self.print_error(f"Failed to train model: {e}")
            return False

    def install_windows_service(self):
        """Install as Windows service."""
        self.print_header("Installing Windows Service")

        print("To install as a Windows Service, you need administrator privileges.")
        print("We'll use NSSM (Non-Sucking Service Manager) to create the service.\n")

        if not self.prompt_yes_no("Install as Windows Service?", True):
            self.print_warning("Skipping service installation")
            self.print_warning("You can run manually with: python service/dns_tunnel_service.py")
            return

        # Create service installer script
        service_script = self.install_dir / "install_service_windows.bat"

        service_script_content = f"""@echo off
REM DNS Tunnel Detection Service - Windows Service Installer

echo Installing DNS Tunnel Detection Service...

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Administrator privileges required
    echo Right-click this script and select "Run as administrator"
    pause
    exit /b 1
)

REM Download NSSM if not present
if not exist nssm.exe (
    echo Downloading NSSM...
    powershell -Command "Invoke-WebRequest -Uri https://nssm.cc/release/nssm-2.24.zip -OutFile nssm.zip"
    powershell -Command "Expand-Archive -Path nssm.zip -DestinationPath ."
    copy nssm-2.24\\win64\\nssm.exe .
    del nssm.zip
    rmdir /s /q nssm-2.24
)

REM Install service
nssm install DNSTunnelDetection "{sys.executable}" "{self.install_dir / 'service' / 'dns_tunnel_service.py'}"
nssm set DNSTunnelDetection AppDirectory "{self.install_dir}"
nssm set DNSTunnelDetection DisplayName "DNS Tunnel Detection Service"
nssm set DNSTunnelDetection Description "Enterprise DNS tunneling detection and alerting system"
nssm set DNSTunnelDetection Start SERVICE_AUTO_START

echo Service installed successfully!
echo.
echo To start the service:
echo   net start DNSTunnelDetection
echo.
echo To stop the service:
echo   net stop DNSTunnelDetection
echo.
pause
"""

        with open(service_script, 'w') as f:
            f.write(service_script_content)

        self.print_success("Service installer created: install_service_windows.bat")
        self.print_warning("Run install_service_windows.bat as Administrator to install the service")

    def install_linux_service(self):
        """Install as Linux systemd service."""
        self.print_header("Installing Linux Service")

        print("Creating systemd service configuration...\n")

        if not self.prompt_yes_no("Install as systemd service?", True):
            self.print_warning("Skipping service installation")
            self.print_warning("You can run manually with: python3 service/dns_tunnel_service.py")
            return

        # Create systemd service file
        service_content = f"""[Unit]
Description=DNS Tunnel Detection Service
After=network.target

[Service]
Type=simple
User={os.getenv('USER', 'root')}
WorkingDirectory={self.install_dir}
ExecStart={sys.executable} {self.install_dir / 'service' / 'dns_tunnel_service.py'}
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

        service_file = self.install_dir / "dns-tunnel-detection.service"
        with open(service_file, 'w') as f:
            f.write(service_content)

        # Create install script
        install_script = self.install_dir / "install_service_linux.sh"
        install_script_content = f"""#!/bin/bash
# DNS Tunnel Detection Service - Linux Service Installer

echo "Installing DNS Tunnel Detection Service..."

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root (sudo)"
    exit 1
fi

# Copy service file
cp {service_file} /etc/systemd/system/

# Reload systemd
systemctl daemon-reload

# Enable service
systemctl enable dns-tunnel-detection.service

echo "Service installed successfully!"
echo ""
echo "To start the service:"
echo "  sudo systemctl start dns-tunnel-detection"
echo ""
echo "To check status:"
echo "  sudo systemctl status dns-tunnel-detection"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u dns-tunnel-detection -f"
"""

        with open(install_script, 'w') as f:
            f.write(install_script_content)

        install_script.chmod(0o755)

        self.print_success(f"Service configuration created: {service_file}")
        self.print_success(f"Install script created: {install_script}")
        self.print_warning(f"Run with sudo: sudo {install_script}")

    def run(self):
        """Run the installer."""
        try:
            # Welcome
            self.welcome()

            # Configuration steps
            self.configure_detection()
            self.configure_database()
            self.configure_alerting()
            self.configure_response()
            self.configure_collector()
            self.configure_api()

            # Save configuration
            self.print_header("Saving Configuration")
            self.save_configuration()

            # Install dependencies
            if not self.install_dependencies():
                return

            # Create directories
            self.create_directories()

            # Train model
            if not self.train_initial_model():
                self.print_warning("Model training failed - you can train manually later")

            # Install service
            if self.is_windows:
                self.install_windows_service()
            elif self.is_linux:
                self.install_linux_service()

            # Final message
            self.print_header("Installation Complete!")

            print(f"{Colors.GREEN}The DNS Tunnel Detection Service has been installed successfully!{Colors.END}\n")

            print("Next steps:")
            print(f"  1. Review configuration: {self.install_dir / 'config.yaml'}")

            if self.is_windows:
                print("  2. Install service: Run install_service_windows.bat as Administrator")
                print("  3. Start service: net start DNSTunnelDetection")
            elif self.is_linux:
                print("  2. Install service: sudo ./install_service_linux.sh")
                print("  3. Start service: sudo systemctl start dns-tunnel-detection")
            else:
                print("  2. Start manually: python service/dns_tunnel_service.py")

            print(f"  4. Access API: http://{self.config['api']['host']}:{self.config['api']['port']}")
            print(f"  5. View logs: {self.install_dir / 'logs'}\n")

            print(f"{Colors.CYAN}Documentation: README.md{Colors.END}")
            print(f"{Colors.CYAN}Support: https://github.com/SandyK43/DnsTunnel/issues{Colors.END}\n")

        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}Installation cancelled by user{Colors.END}")
            sys.exit(1)
        except Exception as e:
            self.print_error(f"Installation failed: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


def main():
    """Main entry point."""
    installer = DNSTunnelInstaller()
    installer.run()


if __name__ == "__main__":
    main()
