#!/bin/bash
#
# export_nessus.sh - Export Nessus configuration for backup/transfer
#
# Usage:
#   ./export_nessus.sh                    # Export to nessus_backup_YYYYMMDD.tar
#   ./export_nessus.sh /path/backup.tar   # Export to specific file
#
# This exports:
# - License/activation
# - User accounts
# - Scan configurations
# - Policies
# - Plugin database
# - All settings
#
# Perfect for moving Nessus between disposable vRPAs!

set -e

# Colors
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
CYAN='\033[96m'
RESET='\033[0m'
BOLD='\033[1m'

echo -e "${CYAN}${BOLD}"
echo "=========================================================================="
echo "Nessus Export Script - Backup Configuration"
echo "=========================================================================="
echo -e "${RESET}"

# Determine output file
OUTPUT_FILE="$1"
if [ -z "$OUTPUT_FILE" ]; then
    OUTPUT_FILE="nessus_backup_$(date +%Y%m%d_%H%M%S).tar"
fi

# Check if Nessus is installed
if [ -d /opt/nessus/var/nessus ]; then
    NESSUS_DATA="/opt/nessus/var/nessus"
elif [ -d /usr/local/nessus/var/nessus ]; then
    NESSUS_DATA="/usr/local/nessus/var/nessus"
else
    echo -e "${RED}[!] Could not find Nessus data directory${RESET}"
    exit 1
fi

echo -e "${BLUE}[*] Found Nessus data: $NESSUS_DATA${RESET}"

# Check if we should stop Nessus first
echo -e "${YELLOW}[*] For best results, Nessus should be stopped during export${RESET}"
read -p "Stop Nessus service? (y/n): " STOP_SERVICE

if [ "$STOP_SERVICE" = "y" ] || [ "$STOP_SERVICE" = "Y" ]; then
    echo -e "${BLUE}[*] Stopping Nessus...${RESET}"
    if command -v systemctl &> /dev/null; then
        sudo systemctl stop nessusd
    elif command -v service &> /dev/null; then
        sudo service nessusd stop
    fi
    sleep 5
    RESTART_NEEDED=true
else
    RESTART_NEEDED=false
fi

# Create temporary directory for export
TEMP_DIR=$(mktemp -d)
echo -e "${BLUE}[*] Creating backup in temporary directory...${RESET}"

# Copy Nessus data
sudo cp -r "$NESSUS_DATA" "$TEMP_DIR/"

# Fix permissions so we can tar it
sudo chown -R $USER:$USER "$TEMP_DIR"

# Create tarball
echo -e "${BLUE}[*] Creating archive: $OUTPUT_FILE${RESET}"
cd "$TEMP_DIR"
tar -czf "$OUTPUT_FILE" nessus/
mv "$OUTPUT_FILE" "$OLDPWD/"
cd "$OLDPWD"

# Cleanup
rm -rf "$TEMP_DIR"

# Get file size
FILE_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)

echo -e "${GREEN}${BOLD}"
echo "=========================================================================="
echo "Export Complete!"
echo "==========================================================================${RESET}"
echo -e "${CYAN}Backup file:${RESET} $OUTPUT_FILE"
echo -e "${CYAN}File size:${RESET} $FILE_SIZE"
echo ""
echo -e "${YELLOW}What's included:${RESET}"
echo -e "  ${GREEN}✓${RESET} License activation"
echo -e "  ${GREEN}✓${RESET} User accounts and passwords"
echo -e "  ${GREEN}✓${RESET} All scan configurations"
echo -e "  ${GREEN}✓${RESET} Custom policies"
echo -e "  ${GREEN}✓${RESET} Plugin database"
echo -e "  ${GREEN}✓${RESET} All settings"
echo ""
echo -e "${CYAN}To restore on new vRPA:${RESET}"
echo -e "${BLUE}  scp $OUTPUT_FILE user@new-vrpa:/opt/seeksweet/nessusseek/${RESET}"
echo -e "${BLUE}  ssh user@new-vrpa${RESET}"
echo -e "${BLUE}  cd /opt/seeksweet/nessusseek${RESET}"
echo -e "${BLUE}  ./activate_nessus.sh --import $OUTPUT_FILE${RESET}"
echo ""

# Restart Nessus if we stopped it
if [ "$RESTART_NEEDED" = true ]; then
    echo -e "${BLUE}[*] Restarting Nessus...${RESET}"
    if command -v systemctl &> /dev/null; then
        sudo systemctl start nessusd
    elif command -v service &> /dev/null; then
        sudo service nessusd start
    fi
    echo -e "${GREEN}[+] Nessus restarted${RESET}"
fi

echo -e "${YELLOW}[!] Keep this backup secure - it contains your license and credentials!${RESET}"
echo ""
