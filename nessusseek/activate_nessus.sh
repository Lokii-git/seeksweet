#!/bin/bash
#
# activate_nessus.sh - Automated Nessus activation for fresh vRPAs
#
# Usage:
#   ./activate_nessus.sh XXXX-XXXX-XXXX-XXXX          # Activate with code
#   ./activate_nessus.sh --import nessus_backup.tar   # Import from backup
#   ./activate_nessus.sh                              # Will prompt for activation code
#
# This script handles:
# - Starting Nessus service
# - Waiting for Nessus to initialize
# - Automated activation with provided code
# - OR importing settings from previous instance
# - Creating admin user
# - Generating API keys
#
# Perfect for disposable vRPAs that need quick Nessus deployment!

set -e

# Colors
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
CYAN='\033[96m'
RESET='\033[0m'
BOLD='\033[1m'

# Nessus defaults
NESSUS_URL="https://localhost:8834"
NESSUS_USER="admin"
NESSUS_PASS="changeme123!"  # Change this to your preferred default
IMPORT_MODE=false
IMPORT_FILE=""

echo -e "${CYAN}${BOLD}"
echo "=========================================================================="
echo "Nessus Activation Script - vRPA Quick Deploy"
echo "=========================================================================="
echo -e "${RESET}"

# Parse arguments
if [ "$1" == "--import" ]; then
    IMPORT_MODE=true
    IMPORT_FILE="$2"
    
    if [ -z "$IMPORT_FILE" ] || [ ! -f "$IMPORT_FILE" ]; then
        echo -e "${RED}[!] Import file not found: $IMPORT_FILE${RESET}"
        echo -e "${YELLOW}Usage: $0 --import /path/to/nessus_backup.tar${RESET}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] Import mode - will restore from: $IMPORT_FILE${RESET}"
else
    # Get activation code
    ACTIVATION_CODE="$1"
    if [ -z "$ACTIVATION_CODE" ]; then
        echo -e "${YELLOW}[*] Enter your Nessus Essentials activation code${RESET}"
        echo -e "${YELLOW}[*] Get one free at: https://www.tenable.com/products/nessus/nessus-essentials${RESET}"
        echo -e "${YELLOW}[*] Or use --import to restore from backup${RESET}"
        read -p "Activation Code: " ACTIVATION_CODE
    fi

    if [ -z "$ACTIVATION_CODE" ]; then
        echo -e "${RED}[!] Activation code is required${RESET}"
        exit 1
    fi
fi

# Check if Nessus is installed
if ! command -v nessusd &> /dev/null && [ ! -f /opt/nessus/sbin/nessusd ] && [ ! -f /usr/local/nessus/sbin/nessusd ]; then
    echo -e "${RED}[!] Nessus is not installed${RESET}"
    echo -e "${YELLOW}[*] Install from: https://www.tenable.com/downloads/nessus${RESET}"
    exit 1
fi

# Detect Nessus installation path
if [ -f /opt/nessus/sbin/nessusd ]; then
    NESSUS_BIN="/opt/nessus/sbin/nessusd"
elif [ -f /usr/local/nessus/sbin/nessusd ]; then
    NESSUS_BIN="/usr/local/nessus/sbin/nessusd"
else
    NESSUS_BIN="nessusd"
fi

echo -e "${BLUE}[*] Found Nessus: $NESSUS_BIN${RESET}"

# Start Nessus service
echo -e "${BLUE}[*] Starting Nessus service...${RESET}"
if command -v systemctl &> /dev/null; then
    sudo systemctl start nessusd 2>/dev/null || sudo /bin/systemctl start nessusd
elif command -v service &> /dev/null; then
    sudo service nessusd start
else
    # Try direct binary start
    sudo $NESSUS_BIN -D
fi

echo -e "${CYAN}[*] Waiting for Nessus to initialize (this may take 60-90 seconds)...${RESET}"
sleep 10

# Wait for Nessus web interface to be ready
MAX_WAIT=180
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if curl -k -s "$NESSUS_URL" > /dev/null 2>&1; then
        echo -e "${GREEN}[+] Nessus web interface is ready!${RESET}"
        break
    fi
    echo -ne "${YELLOW}[*] Waiting... ${WAITED}s / ${MAX_WAIT}s\r${RESET}"
    sleep 5
    WAITED=$((WAITED + 5))
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo -e "${RED}[!] Timeout waiting for Nessus to start${RESET}"
    exit 1
fi

# Handle import mode
if [ "$IMPORT_MODE" = true ]; then
    echo -e "${CYAN}${BOLD}"
    echo "=========================================================================="
    echo "IMPORT MODE - Restoring Nessus Configuration"
    echo "==========================================================================${RESET}"
    
    # Stop Nessus before importing
    echo -e "${BLUE}[*] Stopping Nessus for import...${RESET}"
    if command -v systemctl &> /dev/null; then
        sudo systemctl stop nessusd
    elif command -v service &> /dev/null; then
        sudo service nessusd stop
    fi
    sleep 5
    
    # Extract and restore backup
    echo -e "${BLUE}[*] Extracting backup: $IMPORT_FILE${RESET}"
    TEMP_DIR=$(mktemp -d)
    tar -xf "$IMPORT_FILE" -C "$TEMP_DIR"
    
    # Determine Nessus data directory
    if [ -d /opt/nessus/var/nessus ]; then
        NESSUS_DATA="/opt/nessus/var/nessus"
    elif [ -d /usr/local/nessus/var/nessus ]; then
        NESSUS_DATA="/usr/local/nessus/var/nessus"
    else
        echo -e "${RED}[!] Could not find Nessus data directory${RESET}"
        exit 1
    fi
    
    # Backup current data (just in case)
    echo -e "${BLUE}[*] Backing up current Nessus data...${RESET}"
    sudo mv "$NESSUS_DATA" "${NESSUS_DATA}.backup.$(date +%s)" 2>/dev/null || true
    
    # Restore from backup
    echo -e "${BLUE}[*] Restoring configuration to: $NESSUS_DATA${RESET}"
    sudo cp -r "$TEMP_DIR/nessus" "$(dirname $NESSUS_DATA)/"
    
    # Fix permissions
    sudo chown -R root:root "$NESSUS_DATA"
    
    # Cleanup
    rm -rf "$TEMP_DIR"
    
    # Restart Nessus
    echo -e "${BLUE}[*] Restarting Nessus...${RESET}"
    if command -v systemctl &> /dev/null; then
        sudo systemctl start nessusd
    elif command -v service &> /dev/null; then
        sudo service nessusd start
    fi
    
    echo -e "${CYAN}[*] Waiting for Nessus to reload...${RESET}"
    sleep 30
    
    # Wait for web interface
    WAITED=0
    while [ $WAITED -lt $MAX_WAIT ]; do
        if curl -k -s "$NESSUS_URL" > /dev/null 2>&1; then
            echo -e "${GREEN}[+] Nessus restored and ready!${RESET}"
            break
        fi
        sleep 5
        WAITED=$((WAITED + 5))
    done
    
    echo -e "${GREEN}${BOLD}"
    echo "=========================================================================="
    echo "Import Complete!"
    echo "==========================================================================${RESET}"
    echo -e "${CYAN}Nessus URL:${RESET} $NESSUS_URL"
    echo -e "${YELLOW}[*] Your previous settings, license, and plugins have been restored${RESET}"
    echo -e "${YELLOW}[*] Login with your original admin credentials${RESET}"
    echo ""
    
    # Try to generate API keys with default credentials
    echo -e "${BLUE}[*] Attempting to generate API keys...${RESET}"
    read -sp "Enter admin password from backup: " USER_PASS
    echo ""
    
    AUTH_RESPONSE=$(curl -k -s -X POST "$NESSUS_URL/session" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$NESSUS_USER\",\"password\":\"$USER_PASS\"}")
    
    TOKEN=$(echo "$AUTH_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    
    if [ -n "$TOKEN" ]; then
        echo -e "${GREEN}[+] Authenticated successfully${RESET}"
        
        # Generate API keys
        API_RESPONSE=$(curl -k -s -X PUT "$NESSUS_URL/session/keys" \
            -H "X-Cookie: token=$TOKEN" \
            -H "Content-Type: application/json")
        
        ACCESS_KEY=$(echo "$API_RESPONSE" | grep -o '"accessKey":"[^"]*"' | cut -d'"' -f4)
        SECRET_KEY=$(echo "$API_RESPONSE" | grep -o '"secretKey":"[^"]*"' | cut -d'"' -f4)
        
        if [ -n "$ACCESS_KEY" ] && [ -n "$SECRET_KEY" ]; then
            cat > ~/.nessus_keys << EOF
# Nessus API Keys (Imported Configuration)
# Generated: $(date)
export NESSUS_ACCESS_KEY="$ACCESS_KEY"
export NESSUS_SECRET_KEY="$SECRET_KEY"
export NESSUS_URL="$NESSUS_URL"
EOF
            chmod 600 ~/.nessus_keys
            
            echo -e "${GREEN}[+] API keys saved to ~/.nessus_keys${RESET}"
            echo -e "${YELLOW}[*] Load with: source ~/.nessus_keys${RESET}"
        fi
    fi
    
    exit 0
fi


# Check if already initialized
echo -e "${BLUE}[*] Checking Nessus status...${RESET}"
SERVER_STATUS=$(curl -k -s "$NESSUS_URL/server/status" 2>/dev/null || echo "")

# Check if we need to go through initial setup wizard
if echo "$SERVER_STATUS" | grep -q '"code":401'; then
    echo -e "${YELLOW}[!] Nessus needs initial setup via Web UI${RESET}"
    echo -e "${CYAN}[*] Opening browser to complete setup...${RESET}"
    echo ""
    echo -e "${BOLD}=========================================================================="
    echo "MANUAL SETUP REQUIRED (First Time Only)"
    echo "==========================================================================${RESET}"
    echo ""
    echo -e "${YELLOW}1. Open browser to: ${GREEN}$NESSUS_URL${RESET}"
    echo -e "${YELLOW}2. Click 'Register for Nessus Essentials'${RESET}"
    echo -e "${YELLOW}3. Enter activation code: ${GREEN}$ACTIVATION_CODE${RESET}"
    echo -e "${YELLOW}4. Create admin user:${RESET}"
    echo -e "   ${CYAN}Username: admin${RESET}"
    echo -e "   ${CYAN}Password: changeme123! ${YELLOW}(or your preferred password)${RESET}"
    echo -e "${YELLOW}5. Wait for plugin download to complete (30-60 min)${RESET}"
    echo ""
    echo -e "${YELLOW}Then run this script again to generate API keys!${RESET}"
    echo ""
    exit 0
fi

if echo "$SERVER_STATUS" | grep -q '"status":"ready"'; then
    echo -e "${GREEN}[+] Nessus is ready!${RESET}"
else
    echo -e "${YELLOW}[*] Nessus is initializing...${RESET}"
fi

# Try to authenticate
echo -e "${BLUE}[*] Attempting authentication...${RESET}"

# Prompt for password if using default
read -sp "Enter Nessus admin password (default: changeme123!): " USER_PASS
echo ""
if [ -z "$USER_PASS" ]; then
    USER_PASS="$NESSUS_PASS"
fi
# Try to authenticate
echo -e "${BLUE}[*] Attempting authentication...${RESET}"

# Prompt for password if using default
read -sp "Enter Nessus admin password (default: changeme123!): " USER_PASS
echo ""
if [ -z "$USER_PASS" ]; then
    USER_PASS="$NESSUS_PASS"
fi

AUTH_RESPONSE=$(curl -k -s -X POST "$NESSUS_URL/session" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$NESSUS_USER\",\"password\":\"$USER_PASS\"}")

TOKEN=$(echo "$AUTH_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo -e "${RED}[!] Authentication failed${RESET}"
    echo -e "${YELLOW}[*] This usually means:${RESET}"
    echo -e "${YELLOW}   1. Wrong username/password${RESET}"
    echo -e "${YELLOW}   2. Nessus needs initial setup via Web UI: $NESSUS_URL${RESET}"
    echo -e "${YELLOW}   3. User account doesn't exist yet${RESET}"
    echo ""
    echo -e "${CYAN}To complete setup manually:${RESET}"
    echo -e "${BLUE}  1. Browse to: $NESSUS_URL${RESET}"
    echo -e "${BLUE}  2. Complete initial setup wizard${RESET}"
    echo -e "${BLUE}  3. Create admin account${RESET}"
    echo -e "${BLUE}  4. Enter activation code: $ACTIVATION_CODE${RESET}"
    echo -e "${BLUE}  5. Run this script again to generate API keys${RESET}"
    exit 1
fi

echo -e "${GREEN}[+] Authenticated successfully${RESET}"

# Check if already registered
LICENSE_INFO=$(curl -k -s "$NESSUS_URL/server/properties" \
    -H "X-Cookie: token=$TOKEN")

if echo "$LICENSE_INFO" | grep -q '"type":"PV"\|"type":"VS"\|"type":"SC"'; then
    LICENSE_TYPE=$(echo "$LICENSE_INFO" | grep -o '"type":"[^"]*"' | head -1 | cut -d'"' -f4)
    echo -e "${GREEN}[+] Nessus already registered with license type: $LICENSE_TYPE${RESET}"
else
    # Register Nessus with activation code
    echo -e "${BLUE}[*] Registering Nessus with activation code...${RESET}"
    REGISTER_RESPONSE=$(curl -k -s -X POST "$NESSUS_URL/plugins/plugin-sets/register" \
        -H "X-Cookie: token=$TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"code\":\"$ACTIVATION_CODE\"}")

    if echo "$REGISTER_RESPONSE" | grep -q '"code"'; then
        echo -e "${GREEN}[+] Nessus registered successfully!${RESET}"
    else
        echo -e "${YELLOW}[*] Registration response: $REGISTER_RESPONSE${RESET}"
        if echo "$REGISTER_RESPONSE" | grep -qi "already"; then
            echo -e "${GREEN}[+] Nessus is already registered${RESET}"
        else
            echo -e "${YELLOW}[!] Registration may have failed - check response above${RESET}"
        fi
    fi
fi

# Generate API keys
echo -e "${BLUE}[*] Generating API keys...${RESET}"
API_RESPONSE=$(curl -k -s -X PUT "$NESSUS_URL/session/keys" \
    -H "X-Cookie: token=$TOKEN" \
    -H "Content-Type: application/json")

ACCESS_KEY=$(echo "$API_RESPONSE" | grep -o '"accessKey":"[^"]*"' | cut -d'"' -f4)
SECRET_KEY=$(echo "$API_RESPONSE" | grep -o '"secretKey":"[^"]*"' | cut -d'"' -f4)

if [ -n "$ACCESS_KEY" ] && [ -n "$SECRET_KEY" ]; then
    echo -e "${GREEN}[+] API keys generated successfully!${RESET}"
    echo ""
    echo -e "${CYAN}${BOLD}=========================================================================="
    echo "Nessus API Credentials - Save These!"
    echo "==========================================================================${RESET}"
    echo -e "${YELLOW}Access Key: ${GREEN}$ACCESS_KEY${RESET}"
    echo -e "${YELLOW}Secret Key: ${GREEN}$SECRET_KEY${RESET}"
    echo ""
    echo -e "${CYAN}Save these to use with NessusSeek:${RESET}"
    echo -e "${BLUE}  export NESSUS_ACCESS_KEY='$ACCESS_KEY'${RESET}"
    echo -e "${BLUE}  export NESSUS_SECRET_KEY='$SECRET_KEY'${RESET}"
    echo ""
    echo -e "${CYAN}Or create ~/.nessus_keys:${RESET}"
    
    # Create credentials file
    cat > ~/.nessus_keys << EOF
# Nessus API Keys
# Generated: $(date)
export NESSUS_ACCESS_KEY="$ACCESS_KEY"
export NESSUS_SECRET_KEY="$SECRET_KEY"
export NESSUS_URL="$NESSUS_URL"
EOF
    chmod 600 ~/.nessus_keys
    
    echo -e "${GREEN}[+] Saved to ~/.nessus_keys${RESET}"
    echo -e "${YELLOW}[*] Load with: source ~/.nessus_keys${RESET}"
else
    echo -e "${RED}[!] Failed to generate API keys${RESET}"
    echo -e "${YELLOW}[*] You can generate them manually in: Settings → API Keys${RESET}"
fi

echo ""
echo -e "${CYAN}[*] Checking plugin feed status...${RESET}"
sleep 2
FEED_INFO=$(curl -k -s "$NESSUS_URL/feed" -H "X-Cookie: token=$TOKEN")
echo -e "${BLUE}[*] Plugin download will begin automatically${RESET}"
echo -e "${YELLOW}[*] This can take 30-60 minutes on first run${RESET}"

echo ""
echo -e "${GREEN}${BOLD}=========================================================================="
echo "Setup Complete!"
echo "==========================================================================${RESET}"
echo -e "${CYAN}Nessus URL:${RESET} $NESSUS_URL"
echo -e "${CYAN}Username:${RESET} $NESSUS_USER"
echo -e "${CYAN}Password:${RESET} $NESSUS_PASS"
echo ""
echo -e "${YELLOW}[*] Run NessusSeek:${RESET}"
echo -e "${BLUE}  source ~/.nessus_keys${RESET}"
echo -e "${BLUE}  python3 nessusseek.py -t iplist.txt${RESET}"
echo ""
echo -e "${YELLOW}[*] Or use with environment variables:${RESET}"
echo -e "${BLUE}  export NESSUS_ACCESS_KEY='$ACCESS_KEY'${RESET}"
echo -e "${BLUE}  export NESSUS_SECRET_KEY='$SECRET_KEY'${RESET}"
echo ""
