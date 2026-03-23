#!/bin/bash

###############################################################################
# AWS CLI Setup with uv
#
# Installs AWS CLI using uv in the project .venv directory.
###############################################################################

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo -e "${GREEN}Setting up AWS CLI with uv...${NC}"
echo ""

if ! command -v uv &> /dev/null; then
    echo -e "${RED}Error: uv is not installed${NC}"
    echo ""
    echo "Install uv with:"
    echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"
    echo "  Or: brew install uv"
    exit 1
fi

echo -e "${GREEN}✓ uv found${NC}"

cd "$PROJECT_ROOT"

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    uv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment already exists${NC}"
fi

echo "Installing AWS CLI..."
uv pip install awscli

echo ""
echo -e "${GREEN}✓ AWS CLI installed successfully!${NC}"
echo ""
echo "Activate: source .venv/bin/activate"
echo "Or use:   .venv/bin/aws --version"
echo ""
