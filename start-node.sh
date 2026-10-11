#!/usr/bin/env bash
# ==============================================================================
# Project Aethelgard - Swarm Node Consumer Launcher (macOS / Linux)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=============================================================================="
echo "                 PROJECT AETHELGARD - AUTONOMOUS MESH NODE"
echo "=============================================================================="
echo ""

# 1. Check for Java 21
HAS_JAVA=true
if ! command -v java &>/dev/null; then
    HAS_JAVA=false
else
    JAVA_MAJOR=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d'.' -f1)
    if [ "$JAVA_MAJOR" -lt 21 ]; then
        HAS_JAVA=false
    fi
fi

if [ "$HAS_JAVA" = false ]; then
    echo "=============================================================================="
    echo "                  AUTOMATIC SETUP REQUIRED: JAVA 21 LTS"
    echo "=============================================================================="
    echo "Project Aethelgard requires Java 21 LTS to run with quantum-safe cryptography"
    echo "and virtual threads."
    echo ""
    read -p "Would you like to automatically install Java 21 now? (y/n): " INSTALL_REPLY
    case "$INSTALL_REPLY" in
        [yY][eE][sS]|[yY])
            echo "[*] Detecting package manager..."
            if command -v apt-get &>/dev/null; then
                sudo apt-get update && sudo apt-get install -y openjdk-21-jre-headless
            elif command -v dnf &>/dev/null; then
                sudo dnf install -y java-21-openjdk-headless
            elif command -v brew &>/dev/null; then
                brew install openjdk@21
                sudo ln -sfn "$(brew --prefix)/opt/openjdk@21/libexec/openjdk.jdk" /Library/Java/JavaVirtualMachines/openjdk-21.jdk || true
            else
                echo "[!] Could not detect supported package manager."
                echo "Please install Java 21 from https://adoptium.net/temurin/releases/?version=21"
                exit 1
            fi
            echo "[OK] Java 21 successfully installed!"
            ;;
        *)
            echo "Cancelled. Please install Java 21 manually from https://adoptium.net"
            exit 1
            ;;
    esac
fi

echo "[OK] Java 21+ detected: $(java -version 2>&1 | head -n 1)"

# 2. Locate JAR
JAR_PATH=""
if [ -f "${SCRIPT_DIR}/aethelgard.jar" ]; then
    JAR_PATH="${SCRIPT_DIR}/aethelgard.jar"
elif [ -f "${SCRIPT_DIR}/target/aethelgard.jar" ]; then
    JAR_PATH="${SCRIPT_DIR}/target/aethelgard.jar"
fi

if [ -z "$JAR_PATH" ]; then
    echo "[ERROR] Could not find aethelgard.jar in this directory or target/."
    exit 1
fi

echo ""
echo "------------------------------------------------------------------------------"
echo "                        NODE CONFIGURATION"
echo "------------------------------------------------------------------------------"
read -p "Enter port to listen on [Default: 8001]: " INPUT_PORT
PORT="${INPUT_PORT:-8001}"

read -p "Connect to an existing peer IP:port (e.g. 192.168.1.50:8001, or Enter for standalone): " INPUT_PEER
CONNECT_ARG=""
if [ -n "$INPUT_PEER" ]; then
    CONNECT_ARG="--connect=${INPUT_PEER}"
fi

echo ""
echo "[*] Starting Aethelgard Node on port ${PORT}..."
if [ -n "$CONNECT_ARG" ]; then
    echo "[*] Connecting to peer: ${INPUT_PEER}"
fi
echo ""

# 3. Launch with preview features enabled
exec java --enable-preview -jar "$JAR_PATH" --port="$PORT" $CONNECT_ARG
