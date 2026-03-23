#!/bin/bash

###############################################################################
# AWS Policy Explorer - One-Command Demo Launcher
#
# Usage: ./test-scripts/demo.sh
###############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

clear

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║           AWS Policy Explorer - Demo Launcher                   ║"
echo "║           Shadow Admin Detection for AWS IAM Policies           ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

echo -e "${BLUE}Checking prerequisites...${NC}"

if ! command -v aws &> /dev/null; then
    echo -e "${RED}✗ AWS CLI not found${NC}"
    echo -e "${YELLOW}  Install: https://aws.amazon.com/cli/${NC}"
    exit 1
fi
echo -e "${GREEN}✓ AWS CLI found${NC}"

if ! command -v jq &> /dev/null; then
    echo -e "${RED}✗ jq not found${NC}"
    echo -e "${YELLOW}  Install: brew install jq (macOS) or sudo apt-get install jq (Linux)${NC}"
    exit 1
fi
echo -e "${GREEN}✓ jq found${NC}"

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 not found${NC}"
    echo -e "${YELLOW}  Install: https://www.python.org/downloads/${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python 3 found${NC}"

echo ""

while true; do
    echo -e "${BOLD}What would you like to do?${NC}"
    echo ""
    echo "  1) Quick Demo (Setup test accounts + Launch app)"
    echo "  2) Setup test accounts only"
    echo "  3) Launch app only (use your own credentials)"
    echo "  4) Cleanup test accounts"
    echo "  5) Exit"
    echo ""
    read -p "Enter your choice (1-5): " choice
    echo ""

    case $choice in
        1)
            echo -e "${GREEN}Starting Quick Demo...${NC}"
            echo ""
            echo -e "${BLUE}Step 1/2: Creating test accounts...${NC}"
            "$SCRIPT_DIR/setup-test-accounts.sh"
            echo ""
            echo -e "${BLUE}Step 2/2: Starting web server...${NC}"
            echo ""
            echo -e "${CYAN}Open your browser to:${NC}"
            echo -e "${BOLD}  http://localhost:8000${NC}"
            echo ""
            echo -e "${YELLOW}Use the test account credentials displayed above${NC}"
            echo -e "${YELLOW}Press Ctrl+C to stop the server when done${NC}"
            echo ""
            cd "$PROJECT_ROOT"
            python3 -m http.server 8000
            break
            ;;
        2)
            "$SCRIPT_DIR/setup-test-accounts.sh"
            echo ""
            read -p "Press Enter to continue..."
            echo ""
            ;;
        3)
            echo -e "${CYAN}Open your browser to:${NC}"
            echo -e "${BOLD}  http://localhost:8000${NC}"
            echo ""
            echo -e "${YELLOW}Press Ctrl+C to stop the server when done${NC}"
            echo ""
            cd "$PROJECT_ROOT"
            python3 -m http.server 8000
            break
            ;;
        4)
            "$SCRIPT_DIR/cleanup-test-accounts.sh"
            echo ""
            read -p "Press Enter to continue..."
            echo ""
            ;;
        5)
            echo -e "${BLUE}Thanks for using AWS Policy Explorer!${NC}"
            echo ""
            echo -e "${YELLOW}Remember to cleanup test accounts:${NC}"
            echo -e "  ${BOLD}./test-scripts/cleanup-test-accounts.sh${NC}"
            echo ""
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Please enter 1-5.${NC}"
            echo ""
            ;;
    esac
done
