#!/bin/bash

###############################################################################
# AWS CLI Setup with uv
# 
# This script installs AWS CLI using uv in the project directory,
# keeping your base Python installation clean.
###############################################################################

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}Setting up AWS CLI with uv...${NC}"
echo ""

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo -e "${RED}Error: uv is not installed${NC}"
    echo ""
    echo "Install uv with:"
    echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"
    echo ""
    echo "Or on macOS:"
    echo "  brew install uv"
    echo ""
    exit 1
fi

echo -e "${GREEN}✓ uv found${NC}"

# Create virtual environment with uv if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    uv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment already exists${NC}"
fi

# Install AWS CLI via uv
echo "Installing AWS CLI..."
uv pip install awscli

echo ""
echo -e "${GREEN}✓ AWS CLI installed successfully!${NC}"
echo ""
echo "To use AWS CLI, activate the virtual environment:"
echo -e "${YELLOW}  source .venv/bin/activate${NC}"
echo ""
echo "Or use it directly:"
echo -e "${YELLOW}  .venv/bin/aws --version${NC}"
echo ""

