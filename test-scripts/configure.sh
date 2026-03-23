#!/bin/bash

###############################################################################
# AWS Policy Explorer - Quick Configuration Wizard
#
# Helps set up AWS CLI and credentials quickly.
###############################################################################

set -e

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
echo "╔══════════════════════════════════════════════════════════╗"
echo "║         AWS Policy Explorer - Configuration              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

if [ -f "$PROJECT_ROOT/.env" ]; then
    echo -e "${YELLOW}⚠️  .env file already exists${NC}"
    echo ""
    read -p "Do you want to reconfigure? (yes/no): " RECONFIG
    if [ "$RECONFIG" != "yes" ]; then
        echo -e "${GREEN}Using existing configuration${NC}"
        exit 0
    fi
    mv "$PROJECT_ROOT/.env" "$PROJECT_ROOT/.env.backup"
    echo -e "${GREEN}Backed up existing .env to .env.backup${NC}"
    echo ""
fi

echo -e "${BOLD}Step 1: AWS CLI Installation${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ -f "$PROJECT_ROOT/.venv/bin/aws" ]; then
    echo -e "${GREEN}✓ AWS CLI already installed in .venv/${NC}"
    USE_VENV=true
elif command -v aws &> /dev/null; then
    echo -e "${GREEN}✓ System AWS CLI found${NC}"
    echo ""
    read -p "Install local AWS CLI with uv for isolation? (yes/no): " INSTALL_LOCAL
    if [ "$INSTALL_LOCAL" = "yes" ]; then
        "$SCRIPT_DIR/setup-aws-cli.sh"
        USE_VENV=true
    else
        USE_VENV=false
    fi
else
    echo -e "${YELLOW}AWS CLI not found${NC}"
    echo ""
    read -p "Install AWS CLI with uv? (yes/no): " INSTALL_UV
    if [ "$INSTALL_UV" = "yes" ]; then
        "$SCRIPT_DIR/setup-aws-cli.sh"
        USE_VENV=true
    else
        echo -e "${YELLOW}Please install AWS CLI manually:${NC}"
        echo "  https://aws.amazon.com/cli/"
        exit 1
    fi
fi

echo ""

echo -e "${BOLD}Step 2: Choose Credential Method${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  1) AWS Profile (Recommended)"
echo "  2) Direct Credentials (Quick - temporary testing)"
echo "  3) Use existing environment variables"
echo ""
read -p "Choose (1-3): " CRED_METHOD

cat > "$PROJECT_ROOT/.env" << EOF
# AWS Policy Explorer Configuration
# Generated: $(date)

EOF

case $CRED_METHOD in
    1)
        echo ""
        echo "Available AWS profiles:"
        if [ "$USE_VENV" = "true" ]; then
            "$PROJECT_ROOT/.venv/bin/aws" configure list-profiles 2>/dev/null || echo "  (No profiles found)"
        else
            aws configure list-profiles 2>/dev/null || echo "  (No profiles found)"
        fi
        echo ""
        read -p "Enter AWS profile name (or press Enter to create new): " PROFILE_NAME
        if [ -z "$PROFILE_NAME" ]; then
            read -p "Enter name for new profile: " PROFILE_NAME
            if [ "$USE_VENV" = "true" ]; then
                "$PROJECT_ROOT/.venv/bin/aws" configure --profile "$PROFILE_NAME"
            else
                aws configure --profile "$PROFILE_NAME"
            fi
        fi
        echo "AWS_PROFILE=$PROFILE_NAME" >> "$PROJECT_ROOT/.env"
        echo -e "${GREEN}✓ Configured to use profile: $PROFILE_NAME${NC}"
        ;;
    2)
        echo ""
        echo -e "${YELLOW}⚠️  Credentials will be stored in .env (gitignored)${NC}"
        echo ""
        read -p "AWS Access Key ID: " ACCESS_KEY
        read -sp "AWS Secret Access Key: " SECRET_KEY
        echo ""
        read -p "AWS Session Token (optional, press Enter to skip): " SESSION_TOKEN
        read -p "AWS Region (default: us-east-1): " REGION
        REGION=${REGION:-us-east-1}
        echo "AWS_ACCESS_KEY_ID=$ACCESS_KEY" >> "$PROJECT_ROOT/.env"
        echo "AWS_SECRET_ACCESS_KEY=$SECRET_KEY" >> "$PROJECT_ROOT/.env"
        if [ -n "$SESSION_TOKEN" ]; then
            echo "AWS_SESSION_TOKEN=$SESSION_TOKEN" >> "$PROJECT_ROOT/.env"
        fi
        echo "AWS_DEFAULT_REGION=$REGION" >> "$PROJECT_ROOT/.env"
        echo -e "${GREEN}✓ Direct credentials configured${NC}"
        ;;
    3)
        echo "" >> "$PROJECT_ROOT/.env"
        echo "# Using environment variables" >> "$PROJECT_ROOT/.env"
        echo -e "${GREEN}✓ Will use existing environment variables${NC}"
        ;;
    *)
        echo -e "${YELLOW}Invalid choice, using environment variables${NC}"
        ;;
esac

echo "" >> "$PROJECT_ROOT/.env"
echo "USE_UV_VENV=$USE_VENV" >> "$PROJECT_ROOT/.env"
echo "" >> "$PROJECT_ROOT/.env"
echo "# TEST_PREFIX=test-shadow-admin" >> "$PROJECT_ROOT/.env"

echo ""
echo -e "${BOLD}Step 3: Verify Configuration${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

source "$SCRIPT_DIR/aws-config.sh"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              ✓ Configuration Complete!                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Next Steps:${NC}"
echo "  1. Run the demo:            ./test-scripts/demo.sh"
echo "  2. Setup test accounts:     ./test-scripts/setup-test-accounts.sh"
echo "  3. Start the application:   ./start-server.sh"
echo ""
