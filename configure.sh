#!/bin/bash

###############################################################################
# AWS Policy Explorer - Quick Configuration Wizard
# 
# This script helps you set up AWS CLI and credentials quickly
###############################################################################

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

clear

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                                                          ║"
echo "║         AWS Policy Explorer - Configuration              ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

# Check if .env already exists
if [ -f .env ]; then
    echo -e "${YELLOW}⚠️  .env file already exists${NC}"
    echo ""
    read -p "Do you want to reconfigure? (yes/no): " RECONFIG
    if [ "$RECONFIG" != "yes" ]; then
        echo -e "${GREEN}Using existing configuration${NC}"
        exit 0
    fi
    mv .env .env.backup
    echo -e "${GREEN}Backed up existing .env to .env.backup${NC}"
    echo ""
fi

# Step 1: AWS CLI
echo -e "${BOLD}Step 1: AWS CLI Installation${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ -f .venv/bin/aws ]; then
    echo -e "${GREEN}✓ AWS CLI already installed in .venv/${NC}"
    USE_VENV=true
elif command -v aws &> /dev/null; then
    echo -e "${GREEN}✓ System AWS CLI found${NC}"
    echo ""
    read -p "Install local AWS CLI with uv for isolation? (yes/no): " INSTALL_LOCAL
    if [ "$INSTALL_LOCAL" = "yes" ]; then
        ./setup-aws-cli.sh
        USE_VENV=true
    else
        USE_VENV=false
    fi
else
    echo -e "${YELLOW}AWS CLI not found${NC}"
    echo ""
    read -p "Install AWS CLI with uv? (yes/no): " INSTALL_UV
    if [ "$INSTALL_UV" = "yes" ]; then
        ./setup-aws-cli.sh
        USE_VENV=true
    else
        echo -e "${YELLOW}Please install AWS CLI manually:${NC}"
        echo "  https://aws.amazon.com/cli/"
        exit 1
    fi
fi

echo ""

# Step 2: Credentials Method
echo -e "${BOLD}Step 2: Choose Credential Method${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "How would you like to configure AWS credentials?"
echo ""
echo "  1) AWS Profile (Recommended - secure, reusable)"
echo "  2) Direct Credentials (Quick - for temporary testing)"
echo "  3) Use existing environment variables"
echo ""
read -p "Choose (1-3): " CRED_METHOD

# Create .env file
cat > .env << EOF
# AWS Policy Explorer Configuration
# Generated: $(date)

EOF

case $CRED_METHOD in
    1)
        echo ""
        echo "Available AWS profiles:"
        if [ "$USE_VENV" = "true" ]; then
            .venv/bin/aws configure list-profiles 2>/dev/null || echo "  (No profiles found)"
        else
            aws configure list-profiles 2>/dev/null || echo "  (No profiles found)"
        fi
        echo ""
        read -p "Enter AWS profile name (or press Enter to create new): " PROFILE_NAME
        
        if [ -z "$PROFILE_NAME" ]; then
            read -p "Enter name for new profile: " PROFILE_NAME
            if [ "$USE_VENV" = "true" ]; then
                .venv/bin/aws configure --profile "$PROFILE_NAME"
            else
                aws configure --profile "$PROFILE_NAME"
            fi
        fi
        
        echo "AWS_PROFILE=$PROFILE_NAME" >> .env
        echo -e "${GREEN}✓ Configured to use profile: $PROFILE_NAME${NC}"
        ;;
        
    2)
        echo ""
        echo -e "${YELLOW}⚠️  Direct credentials will be stored in .env file${NC}"
        echo -e "${YELLOW}⚠️  This file is gitignored but use with caution${NC}"
        echo ""
        read -p "AWS Access Key ID: " ACCESS_KEY
        read -sp "AWS Secret Access Key: " SECRET_KEY
        echo ""
        read -p "AWS Session Token (optional, press Enter to skip): " SESSION_TOKEN
        read -p "AWS Region (default: us-east-1): " REGION
        REGION=${REGION:-us-east-1}
        
        echo "AWS_ACCESS_KEY_ID=$ACCESS_KEY" >> .env
        echo "AWS_SECRET_ACCESS_KEY=$SECRET_KEY" >> .env
        if [ -n "$SESSION_TOKEN" ]; then
            echo "AWS_SESSION_TOKEN=$SESSION_TOKEN" >> .env
        fi
        echo "AWS_DEFAULT_REGION=$REGION" >> .env
        
        echo -e "${GREEN}✓ Direct credentials configured${NC}"
        ;;
        
    3)
        echo ""
        echo "Using environment variables..."
        echo "# Using environment variables" >> .env
        echo -e "${GREEN}✓ Will use existing environment variables${NC}"
        ;;
        
    *)
        echo -e "${YELLOW}Invalid choice, using environment variables${NC}"
        ;;
esac

# Step 3: Additional Options
echo "" >> .env
echo "# Use uv virtual environment for AWS CLI" >> .env
if [ "$USE_VENV" = "true" ]; then
    echo "USE_UV_VENV=true" >> .env
else
    echo "USE_UV_VENV=false" >> .env
fi

echo "" >> .env
echo "# Test account prefix (optional)" >> .env
echo "# TEST_PREFIX=test-shadow-admin" >> .env

echo ""
echo -e "${BOLD}Step 3: Verify Configuration${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Test AWS access
echo "Testing AWS access..."
source aws-config.sh

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}║              ✓ Configuration Complete!                  ║${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Next Steps:${NC}"
echo ""
echo "  1. Run the demo:"
echo -e "     ${BOLD}./demo.sh${NC}"
echo ""
echo "  2. Or setup test accounts:"
echo -e "     ${BOLD}./setup-test-accounts.sh${NC}"
echo ""
echo "  3. Start the application:"
echo -e "     ${BOLD}python3 -m http.server 8000${NC}"
echo ""
echo -e "${YELLOW}Your configuration is saved in .env${NC}"
echo -e "${YELLOW}This file is gitignored and safe${NC}"
echo ""

