#!/bin/bash
# DNS Tunnel Detection Service - Linux Setup Launcher

set -e

echo "========================================"
echo "DNS Tunnel Detection Service"
echo "Interactive Installation Wizard"
echo "========================================"
echo ""

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo ""
    echo "Install Python 3.11+ using:"
    echo "  Ubuntu/Debian: sudo apt install python3.11 python3-pip"
    echo "  CentOS/RHEL:   sudo yum install python3.11 python3-pip"
    echo "  macOS:         brew install python@3.11"
    exit 1
fi

echo "Python found:"
python3 --version
echo ""

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
REQUIRED_VERSION="3.11"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null; then
    echo "ERROR: Python 3.11 or higher is required"
    echo ""
    echo "Current version: $PYTHON_VERSION"
    echo "Required version: $REQUIRED_VERSION+"
    echo ""
    echo "Please upgrade Python"
    exit 1
fi

echo "Starting installer..."
echo ""

# Run installer
python3 install.py

if [ $? -eq 0 ]; then
    echo ""
    echo "========================================"
    echo "Installation Complete!"
    echo "========================================"
    echo ""
    echo "To install as a systemd service:"
    echo "  sudo ./install_service_linux.sh"
    echo ""
    echo "To start manually:"
    echo "  python3 service/dns_tunnel_service.py"
    echo ""
else
    echo ""
    echo "Installation failed. Check the error messages above."
    echo ""
    exit 1
fi
