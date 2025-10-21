#!/bin/bash

###############################################################################
# AWS Policy Explorer - One-Command Demo Launcher
# 
# Usage: ./demo.sh
###############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

clear

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                                                                  ║"
echo "║           AWS Policy Explorer - Demo Launcher                   ║"
echo "║                                                                  ║"
echo "║           Shadow Admin Detection for AWS IAM Policies           ║"
echo "║                                                                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

# Check prerequisites
echo -e "${BLUE}Checking prerequisites...${NC}"

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo -e "${RED}✗ AWS CLI not found${NC}"
    echo -e "${YELLOW}  Install: https://aws.amazon.com/cli/${NC}"
    exit 1
fi
echo -e "${GREEN}✓ AWS CLI found${NC}"

# Check jq
if ! command -v jq &> /dev/null; then
    echo -e "${RED}✗ jq not found${NC}"
    echo -e "${YELLOW}  Install: brew install jq (macOS) or sudo apt-get install jq (Linux)${NC}"
    exit 1
fi
echo -e "${GREEN}✓ jq found${NC}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 not found${NC}"
    echo -e "${YELLOW}  Install: https://www.python.org/downloads/${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python 3 found${NC}"

echo ""

# Main menu
while true; do
    echo -e "${BOLD}What would you like to do?${NC}"
    echo ""
    echo "  1) 🚀 Quick Demo (Setup test accounts + Launch app)"
    echo "  2) 🔧 Setup test accounts only"
    echo "  3) 🌐 Launch app only (use your own credentials)"
    echo "  4) 🧹 Cleanup test accounts"
    echo "  5) 📚 View documentation"
    echo "  6) ❌ Exit"
    echo ""
    read -p "Enter your choice (1-6): " choice
    echo ""

    case $choice in
        1)
            echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}Starting Quick Demo...${NC}"
            echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
            echo ""
            
            # Setup test accounts
            echo -e "${BLUE}Step 1/2: Creating test accounts...${NC}"
            ./setup-test-accounts.sh
            
            echo ""
            echo -e "${BLUE}Step 2/2: Starting web server...${NC}"
            echo ""
            echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}✓ Ready!${NC}"
            echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
            echo ""
            echo -e "${CYAN}Open your browser to:${NC}"
            echo -e "${BOLD}  👉 http://localhost:8000${NC}"
            echo ""
            echo -e "${YELLOW}Use the test account credentials displayed above to log in${NC}"
            echo ""
            echo -e "${YELLOW}Press Ctrl+C to stop the server when done${NC}"
            echo ""
            
            python3 -m http.server 8000
            break
            ;;
            
        2)
            echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}Setting up test accounts...${NC}"
            echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
            echo ""
            
            ./setup-test-accounts.sh
            
            echo ""
            echo -e "${GREEN}✓ Test accounts created!${NC}"
            echo ""
            echo -e "${CYAN}Next steps:${NC}"
            echo -e "  1. Start the app: ${BOLD}./demo.sh${NC} (choose option 3)"
            echo -e "  2. Open browser to http://localhost:8000"
            echo -e "  3. Use test credentials to log in"
            echo ""
            read -p "Press Enter to continue..."
            echo ""
            ;;
            
        3)
            echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}Starting web server...${NC}"
            echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
            echo ""
            echo -e "${CYAN}Open your browser to:${NC}"
            echo -e "${BOLD}  👉 http://localhost:8000${NC}"
            echo ""
            echo -e "${YELLOW}Enter your AWS credentials to explore policies${NC}"
            echo ""
            echo -e "${YELLOW}Press Ctrl+C to stop the server when done${NC}"
            echo ""
            
            python3 -m http.server 8000
            break
            ;;
            
        4)
            echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}Cleaning up test accounts...${NC}"
            echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
            echo ""
            
            ./cleanup-test-accounts.sh
            
            echo ""
            echo -e "${GREEN}✓ Cleanup complete!${NC}"
            echo ""
            read -p "Press Enter to continue..."
            echo ""
            ;;
            
        5)
            echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}Documentation Files${NC}"
            echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
            echo ""
            echo -e "${CYAN}Quick Start:${NC}"
            echo -e "  📄 ${BOLD}START-HERE.md${NC}          - Fastest way to get started"
            echo ""
            echo -e "${CYAN}User Documentation:${NC}"
            echo -e "  📄 ${BOLD}README.md${NC}              - Complete user guide"
            echo -e "  📄 ${BOLD}TESTING-GUIDE.md${NC}       - Detailed testing scenarios (589 lines)"
            echo -e "  📄 ${BOLD}DEMO-WALKTHROUGH.md${NC}    - Presentation guide for demos"
            echo ""
            echo -e "${CYAN}Technical Documentation:${NC}"
            echo -e "  📄 ${BOLD}shadow-admin-logic.md${NC}  - Detection methodology (401 lines)"
            echo -e "  📄 ${BOLD}IMPLEMENTATION-SUMMARY.md${NC} - Technical implementation details"
            echo -e "  📄 ${BOLD}PROJECT-STATUS.md${NC}      - Current project status"
            echo ""
            echo -e "${CYAN}Design:${NC}"
            echo -e "  📄 ${BOLD}brandguideline.md${NC}      - Cyfinoid branding specifications"
            echo ""
            read -p "Press Enter to continue..."
            echo ""
            ;;
            
        6)
            echo -e "${BLUE}Thanks for using AWS Policy Explorer!${NC}"
            echo ""
            echo -e "${YELLOW}Remember to cleanup test accounts if you created them:${NC}"
            echo -e "  ${BOLD}./cleanup-test-accounts.sh${NC}"
            echo ""
            exit 0
            ;;
            
        *)
            echo -e "${RED}Invalid choice. Please enter 1-6.${NC}"
            echo ""
            ;;
    esac
done

