#!/usr/bin/env bash
# ==============================================================================
# Project Aethelgard - Production Linux Service Installer
# Installs Aethelgard as a systemd service that automatically starts on reboot.
# ==============================================================================

set -euo pipefail

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "[-] ERROR: Please run this installation script as root (e.g. sudo bash install-service.sh)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR_SOURCE="${SCRIPT_DIR}/../target/aethelgard.jar"

if [ ! -f "$JAR_SOURCE" ] && [ -f "${SCRIPT_DIR}/aethelgard.jar" ]; then
  JAR_SOURCE="${SCRIPT_DIR}/aethelgard.jar"
fi

if [ ! -f "$JAR_SOURCE" ]; then
  echo "[-] ERROR: aethelgard.jar not found at '${JAR_SOURCE}'"
  echo "    Please place aethelgard.jar in the deploy/ folder or build it with: mvn clean package"
  exit 1
fi

echo "[+] Checking for Java 21..."
if ! command -v java &> /dev/null; then
  echo "[!] Java is not installed. Attempting installation..."
  if command -v apt-get &> /dev/null; then
    apt-get update -y && apt-get install -y openjdk-21-jre-headless
  elif command -v dnf &> /dev/null; then
    dnf install -y java-21-openjdk-headless
  else
    echo "[-] Could not automatically install Java. Please install Java 21 manually."
    exit 1
  fi
fi

JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d'.' -f1)
if [ "$JAVA_VERSION" -lt 21 ]; then
  echo "[-] ERROR: Java 21 or higher is required. Found version: $JAVA_VERSION"
  exit 1
fi
echo "[+] Java 21 detected: $(java -version 2>&1 | head -n 1)"

# Create system user & group if not exists
if ! id "aethelgard" &>/dev/null; then
  echo "[+] Creating dedicated system user 'aethelgard'..."
  useradd --system --no-create-home --user-group --shell /usr/sbin/nologin aethelgard
fi

# Set up installation directory
INSTALL_DIR="/opt/aethelgard"
echo "[+] Installing binary to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
cp -f "${JAR_SOURCE}" "${INSTALL_DIR}/aethelgard.jar"
chown -R aethelgard:aethelgard "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}"
chmod 640 "${INSTALL_DIR}/aethelgard.jar"

# Set up default configuration file
CONFIG_FILE="/etc/default/aethelgard"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "[+] Installing default configuration to ${CONFIG_FILE}..."
  cp "${SCRIPT_DIR}/aethelgard.env" "$CONFIG_FILE"
  chmod 644 "$CONFIG_FILE"
else
  echo "[*] Existing configuration at ${CONFIG_FILE} preserved."
fi

# Install systemd service
SERVICE_FILE="/etc/systemd/system/aethelgard.service"
echo "[+] Installing systemd service unit to ${SERVICE_FILE}..."
cp -f "${SCRIPT_DIR}/aethelgard.service" "$SERVICE_FILE"
chmod 644 "$SERVICE_FILE"

# Reload systemd and enable service
echo "[+] Enabling and starting aethelgard service..."
systemctl daemon-reload
systemctl enable aethelgard.service
systemctl restart aethelgard.service

echo ""
echo "=========================================================================="
echo " [SUCCESS] Project Aethelgard service is active and enabled on reboot!"
echo "=========================================================================="
echo " - View live logs:      journalctl -u aethelgard -f"
echo " - Check status:        systemctl status aethelgard"
echo " - Restart node:        sudo systemctl restart aethelgard"
echo " - Edit configuration:  sudo nano /etc/default/aethelgard"
echo "=========================================================================="
