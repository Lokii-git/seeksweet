#!/bin/bash
#
# activate_nessus.sh - Automated Nessus activation for fresh vRPAs
#
# Usage:
#   ./activate_nessus.sh XXXX-XXXX-XXXX-XXXX
#   ./activate_nessus.sh  # Will prompt for activation code
#
# This script handles:
# - Starting Nessus service
# - Waiting for Nessus to initialize
# - Automated activation with provided code
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

echo -e "${CYAN}${BOLD}"
echo "=========================================================================="
echo "Nessus Activation Script - vRPA Quick Deploy"
echo "=========================================================================="
echo -e "${RESET}"

# Get activation code
ACTIVATION_CODE="$1"
if [ -z "$ACTIVATION_CODE" ]; then
    echo -e "${YELLOW}[*] Enter your Nessus Essentials activation code${RESET}"
    echo -e "${YELLOW}[*] Get one free at: https://www.tenable.com/products/nessus/nessus-essentials${RESET}"
    read -p "Activation Code: " ACTIVATION_CODE
fi

if [ -z "$ACTIVATION_CODE" ]; then
    echo -e "${RED}[!] Activation code is required${RESET}"
    exit 1
fi

# Check if Nessus is installed
if ! command -v nessusd &> /dev/null; then
    echo -e "${RED}[!] Nessus is not installed${RESET}"
    echo -e "${YELLOW}[*] Install from: https://www.tenable.com/downloads/nessus${RESET}"
    exit 1
fi

# Start Nessus service
echo -e "${BLUE}[*] Starting Nessus service...${RESET}"
sudo systemctl start nessusd || {
    echo -e "${YELLOW}[*] Trying service command...${RESET}"
    sudo service nessusd start
}

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

# Check if already initialized
echo -e "${BLUE}[*] Checking Nessus status...${RESET}"
FEED_STATUS=$(curl -k -s "$NESSUS_URL/server/status" 2>/dev/null || echo "")

if echo "$FEED_STATUS" | grep -q '"status":"ready"'; then
    echo -e "${GREEN}[+] Nessus is already initialized!${RESET}"
else
    echo -e "${CYAN}[*] Initializing Nessus (this happens once)...${RESET}"
    
    # Create initial user account
    echo -e "${BLUE}[*] Creating admin user: $NESSUS_USER${RESET}"
    
    curl -k -X POST "$NESSUS_URL/users" \
        -H "Content-Type: application/json" \
        -d "{
            \"username\": \"$NESSUS_USER\",
            \"password\": \"$NESSUS_PASS\",
            \"permissions\": 128,
            \"name\": \"SeekSweet Admin\",
            \"email\": \"admin@seeksweet.local\",
            \"type\": \"local\"
        }" 2>/dev/null && echo -e "${GREEN}[+] Admin user created${RESET}" || echo -e "${YELLOW}[*] User may already exist${RESET}"
    
    sleep 2
fi

# Authenticate and get session token
echo -e "${BLUE}[*] Authenticating...${RESET}"
AUTH_RESPONSE=$(curl -k -s -X POST "$NESSUS_URL/session" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$NESSUS_USER\",\"password\":\"$NESSUS_PASS\"}")

TOKEN=$(echo "$AUTH_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo -e "${RED}[!] Authentication failed${RESET}"
    echo -e "${YELLOW}[*] You may need to complete initial setup via Web UI: $NESSUS_URL${RESET}"
    exit 1
fi

echo -e "${GREEN}[+] Authenticated successfully${RESET}"

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
        echo -e "${RED}[!] Registration may have failed${RESET}"
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
