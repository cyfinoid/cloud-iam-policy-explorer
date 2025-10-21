#!/bin/bash

###############################################################################
# AWS Configuration Loader
# 
# This script loads AWS configuration from .env file or environment variables
# and sets up the AWS CLI command to use.
#
# Usage: source aws-config.sh [--profile PROFILE_NAME]
###############################################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Parse command line arguments
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

# Load .env file if it exists
if [ -f .env ]; then
    echo -e "${BLUE}Loading configuration from .env...${NC}"
    export $(grep -v '^#' .env | grep -v '^$' | xargs)
    echo -e "${GREEN}✓ Configuration loaded${NC}"
else
    echo -e "${YELLOW}No .env file found, using environment variables${NC}"
fi

# Override with command line profile if provided
if [ -n "$CLI_AWS_PROFILE" ]; then
    export AWS_PROFILE="$CLI_AWS_PROFILE"
    echo -e "${BLUE}Using AWS profile from command line: ${AWS_PROFILE}${NC}"
elif [ -n "$AWS_PROFILE" ]; then
    echo -e "${BLUE}Using AWS profile: ${AWS_PROFILE}${NC}"
fi

# Determine which AWS CLI to use
if [ "$USE_UV_VENV" = "true" ] && [ -f ".venv/bin/aws" ]; then
    AWS_CMD=".venv/bin/aws"
    echo -e "${GREEN}✓ Using AWS CLI from uv virtual environment${NC}"
elif [ -f ".venv/bin/aws" ]; then
    AWS_CMD=".venv/bin/aws"
    echo -e "${GREEN}✓ Using AWS CLI from virtual environment${NC}"
elif command -v aws &> /dev/null; then
    AWS_CMD="aws"
    echo -e "${GREEN}✓ Using system AWS CLI${NC}"
else
    echo -e "${RED}✗ AWS CLI not found!${NC}"
    echo ""
    echo "Please install AWS CLI:"
    echo "  Option 1: Run ./setup-aws-cli.sh (uses uv)"
    echo "  Option 2: Install system-wide from https://aws.amazon.com/cli/"
    echo ""
    return 1
fi

# Verify AWS credentials are available
echo ""
echo -e "${BLUE}Verifying AWS credentials...${NC}"

if ! $AWS_CMD sts get-caller-identity &> /dev/null; then
    echo -e "${RED}✗ Failed to verify AWS credentials${NC}"
    echo ""
    echo "Please configure your AWS credentials:"
    echo ""
    if [ -n "$AWS_PROFILE" ]; then
        echo "  Current profile: $AWS_PROFILE"
        echo ""
        echo "  Options:"
        echo "    1. Configure the profile:"
        echo "       $AWS_CMD configure --profile $AWS_PROFILE"
        echo ""
        echo "    2. Use a different profile:"
        echo "       export AWS_PROFILE=your-profile-name"
        echo ""
        echo "    3. Create a .env file with credentials (see .env.example)"
    else
        echo "  Options:"
        echo "    1. Configure default profile:"
        echo "       $AWS_CMD configure"
        echo ""
        echo "    2. Use a named profile:"
        echo "       export AWS_PROFILE=your-profile-name"
        echo ""
        echo "    3. Create a .env file with credentials (see .env.example)"
    fi
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

# Export AWS_CMD for use in other scripts
export AWS_CMD
export AWS_ACCOUNT_ID="$ACCOUNT_ID"

# Helper function to run AWS commands
aws_run() {
    $AWS_CMD "$@"
}

export -f aws_run

