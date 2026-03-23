#!/bin/bash

###############################################################################
# AWS Configuration Loader
#
# Loads AWS config from .env (project root) or environment variables and
# exposes aws_run() for other scripts to call.
#
# Usage: source aws-config.sh [--profile PROFILE_NAME]
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)
            CLI_AWS_PROFILE="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [ -f "$PROJECT_ROOT/.env" ]; then
    echo -e "${BLUE}Loading configuration from .env...${NC}"
    export $(grep -v '^#' "$PROJECT_ROOT/.env" | grep -v '^$' | xargs)
    echo -e "${GREEN}✓ Configuration loaded${NC}"
else
    echo -e "${YELLOW}No .env file found, using environment variables${NC}"
fi

if [ -n "$CLI_AWS_PROFILE" ]; then
    export AWS_PROFILE="$CLI_AWS_PROFILE"
    echo -e "${BLUE}Using AWS profile from command line: ${AWS_PROFILE}${NC}"
elif [ -n "$AWS_PROFILE" ]; then
    echo -e "${BLUE}Using AWS profile: ${AWS_PROFILE}${NC}"
fi

if [ "$USE_UV_VENV" = "true" ] && [ -f "$PROJECT_ROOT/.venv/bin/aws" ]; then
    AWS_CMD="$PROJECT_ROOT/.venv/bin/aws"
    echo -e "${GREEN}✓ Using AWS CLI from uv virtual environment${NC}"
elif [ -f "$PROJECT_ROOT/.venv/bin/aws" ]; then
    AWS_CMD="$PROJECT_ROOT/.venv/bin/aws"
    echo -e "${GREEN}✓ Using AWS CLI from virtual environment${NC}"
elif command -v aws &> /dev/null; then
    AWS_CMD="aws"
    echo -e "${GREEN}✓ Using system AWS CLI${NC}"
else
    echo -e "${RED}✗ AWS CLI not found!${NC}"
    echo ""
    echo "Please install AWS CLI:"
    echo "  Option 1: Run ./test-scripts/setup-aws-cli.sh (uses uv)"
    echo "  Option 2: Install system-wide from https://aws.amazon.com/cli/"
    echo ""
    return 1
fi

echo ""
echo -e "${BLUE}Verifying AWS credentials...${NC}"

if ! $AWS_CMD sts get-caller-identity &> /dev/null; then
    echo -e "${RED}✗ Failed to verify AWS credentials${NC}"
    echo ""
    if [ -n "$AWS_PROFILE" ]; then
        echo "  Current profile: $AWS_PROFILE"
        echo "  Try: $AWS_CMD configure --profile $AWS_PROFILE"
    else
        echo "  Try: $AWS_CMD configure"
    fi
    echo "  Or create a .env file (see .env.example)"
    echo ""
    return 1
fi

CALLER_IDENTITY=$($AWS_CMD sts get-caller-identity --output json)
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | grep -o '"Account": "[^"]*' | sed 's/"Account": "//')
USER_ARN=$(echo "$CALLER_IDENTITY" | grep -o '"Arn": "[^"]*' | sed 's/"Arn": "//')

echo -e "${GREEN}✓ AWS credentials verified${NC}"
echo -e "${BLUE}Account ID: ${ACCOUNT_ID}${NC}"
echo -e "${BLUE}Identity: ${USER_ARN}${NC}"
echo ""

export AWS_CMD
export AWS_ACCOUNT_ID="$ACCOUNT_ID"

aws_run() {
    $AWS_CMD "$@"
}

export -f aws_run
