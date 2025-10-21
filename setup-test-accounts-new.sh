#!/bin/bash

###############################################################################
# AWS Policy Explorer - Test Account Setup Script
# 
# This script creates test IAM users and policies to demonstrate various
# privilege escalation scenarios for testing the shadow admin detection feature.
#
# WARNING: This creates potentially dangerous IAM configurations for testing.
#          Only run in a dedicated test/sandbox AWS account.
#          DO NOT run in production environments.
#
# Usage:
#   ./setup-test-accounts.sh                    # Use default/env config
#   ./setup-test-accounts.sh --profile PROFILE  # Use specific AWS profile
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PREFIX="${TEST_PREFIX:-test-shadow-admin}"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  AWS Policy Explorer - Test Account Setup                ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Load AWS configuration
source "$(dirname "$0")/aws-config.sh" "$@" || exit 1

REGION="${AWS_DEFAULT_REGION:-us-east-1}"

echo -e "${YELLOW}⚠️  WARNING: This creates privileged test accounts${NC}"
echo -e "${YELLOW}⚠️  Only run in a test/sandbox AWS account${NC}"
echo ""

# Confirmation
read -p "Are you sure you want to continue? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo -e "${RED}Aborted.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Starting setup...${NC}"
echo ""

###############################################################################
# Function to create a user and generate access keys
###############################################################################
create_user_with_keys() {
    local username=$1
    echo -e "${BLUE}Creating user: ${username}${NC}"
    
    # Create user
    aws_run iam create-user --user-name "$username" 2>/dev/null || echo "  User already exists"
    
    # Delete any existing access keys
    existing_keys=$(aws_run iam list-access-keys --user-name "$username" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null)
    for key in $existing_keys; do
        aws_run iam delete-access-key --user-name "$username" --access-key-id "$key" 2>/dev/null
    done
    
    # Create new access key
    local key_output=$(aws_run iam create-access-key --user-name "$username" --output json)
    local access_key=$(echo "$key_output" | jq -r '.AccessKey.AccessKeyId')
    local secret_key=$(echo "$key_output" | jq -r '.AccessKey.SecretAccessKey')
    
    echo "  ✓ User created"
    echo "  Access Key: $access_key"
    echo "  Secret Key: $secret_key"
    echo ""
}

###############################################################################
# 1. MULTI-VERSION POLICY TEST (SetExistingDefaultPolicyVersion)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}1. Multi-Version Policy Test${NC}"
echo -e "${GREEN}   (SetExistingDefaultPolicyVersion Escalation)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

POLICY_NAME="${PREFIX}-multiversion-policy"
USER_MULTIVERSION="${PREFIX}-multiversion-user"

# Create the policy with v1 (includes SecretsManager access)
echo "Creating policy: $POLICY_NAME (v1 with SecretsManager access)..."
POLICY_ARN=$(aws_run iam create-policy \
    --policy-name "$POLICY_NAME" \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadOnlyAccess",
                "Effect": "Allow",
                "Action": [
                    "iam:GetPolicy",
                    "iam:GetPolicyVersion",
                    "iam:ListPolicies",
                    "iam:ListPolicyVersions"
                ],
                "Resource": "*"
            },
            {
                "Sid": "SecretsManagerAccess",
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:ListSecrets"
                ],
                "Resource": "*"
            }
        ]
    }' \
    --description "Test policy with multiple versions for privilege escalation testing" \
    --query 'Policy.Arn' \
    --output text 2>/dev/null || aws_run iam get-policy --policy-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/$POLICY_NAME" --query 'Policy.Arn' --output text)

echo "  ✓ Policy created: $POLICY_ARN"

# Create v2 (removes SecretsManager access)
echo "Creating policy version v2 (without SecretsManager access)..."
aws_run iam create-policy-version \
    --policy-arn "$POLICY_ARN" \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadOnlyAccess",
                "Effect": "Allow",
                "Action": [
                    "iam:GetPolicy",
                    "iam:GetPolicyVersion",
                    "iam:ListPolicies",
                    "iam:ListPolicyVersions"
                ],
                "Resource": "*"
            }
        ]
    }' \
    --set-as-default 2>/dev/null || echo "  Version already exists"

echo "  ✓ Policy version v2 created and set as default (no SecretsManager access)"

# Create user with ability to change policy version
create_user_with_keys "$USER_MULTIVERSION"

# Attach the multi-version policy
aws_run iam attach-user-policy --user-name "$USER_MULTIVERSION" --policy-arn "$POLICY_ARN"

# Create and attach a policy that allows changing policy versions
ESCALATION_POLICY_NAME="${PREFIX}-set-policy-version"
ESCALATION_POLICY_ARN=$(aws_run iam create-policy \
    --policy-name "$ESCALATION_POLICY_NAME" \
    --policy-document "{
        \"Version\": \"2012-10-17\",
        \"Statement\": [
            {
                \"Effect\": \"Allow\",
                \"Action\": [
                    \"iam:SetDefaultPolicyVersion\",
                    \"iam:ListAttachedUserPolicies\",
                    \"iam:ListUserPolicies\"
                ],
                \"Resource\": \"*\"
            }
        ]
    }" \
    --description "Allows setting default policy version - PRIVILEGE ESCALATION" \
    --query 'Policy.Arn' \
    --output text 2>/dev/null || aws_run iam get-policy --policy-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/$ESCALATION_POLICY_NAME" --query 'Policy.Arn' --output text)

aws_run iam attach-user-policy --user-name "$USER_MULTIVERSION" --policy-arn "$ESCALATION_POLICY_ARN"

echo -e "${GREEN}✓ Multi-version test setup complete!${NC}"
echo -e "${YELLOW}  This user can escalate by running:${NC}"
echo -e "${YELLOW}  aws iam set-default-policy-version --policy-arn $POLICY_ARN --version-id v1${NC}"
echo ""

###############################################################################
# Continue with other test scenarios...
# (The rest of the script follows the same pattern, replacing 'aws' with 'aws_run')
###############################################################################

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Setup Complete - Test Users Summary                     ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Test users have been created successfully!${NC}"
echo ""
echo -e "${YELLOW}AWS Configuration Used:${NC}"
if [ -n "$AWS_PROFILE" ]; then
    echo "  Profile: $AWS_PROFILE"
fi
echo "  Account: $AWS_ACCOUNT_ID"
echo "  Region: $REGION"
echo ""
echo -e "${GREEN}Next Steps:${NC}"
echo "1. Start the application: python3 -m http.server 8000"
echo "2. Open: http://localhost:8000"
echo "3. Use the test credentials shown above"
echo ""
echo -e "${RED}⚠️  Remember to cleanup:${NC}"
echo -e "${RED}⚠️  ./cleanup-test-accounts.sh${NC}"
if [ -n "$AWS_PROFILE" ]; then
    echo -e "${RED}⚠️  ./cleanup-test-accounts.sh --profile $AWS_PROFILE${NC}"
fi
echo ""

