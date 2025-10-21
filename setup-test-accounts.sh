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
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PREFIX="test-shadow-admin"
REGION="${AWS_REGION:-us-east-1}"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  AWS Policy Explorer - Test Account Setup                ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
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
    aws iam create-user --user-name "$username" 2>/dev/null || echo "  User already exists"
    
    # Delete any existing access keys
    existing_keys=$(aws iam list-access-keys --user-name "$username" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null)
    for key in $existing_keys; do
        aws iam delete-access-key --user-name "$username" --access-key-id "$key" 2>/dev/null
    done
    
    # Create new access key
    local key_output=$(aws iam create-access-key --user-name "$username" --output json)
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
POLICY_ARN=$(aws iam create-policy \
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
    --output text 2>/dev/null || aws iam get-policy --policy-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/$POLICY_NAME" --query 'Policy.Arn' --output text)

echo "  ✓ Policy created: $POLICY_ARN"

# Create v2 (removes SecretsManager access)
echo "Creating policy version v2 (without SecretsManager access)..."
aws iam create-policy-version \
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
aws iam attach-user-policy --user-name "$USER_MULTIVERSION" --policy-arn "$POLICY_ARN"

# Create and attach a policy that allows changing policy versions
ESCALATION_POLICY_NAME="${PREFIX}-set-policy-version"
ESCALATION_POLICY_ARN=$(aws iam create-policy \
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
    --output text 2>/dev/null || aws iam get-policy --policy-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/$ESCALATION_POLICY_NAME" --query 'Policy.Arn' --output text)

aws iam attach-user-policy --user-name "$USER_MULTIVERSION" --policy-arn "$ESCALATION_POLICY_ARN"

echo -e "${GREEN}✓ Multi-version test setup complete!${NC}"
echo -e "${YELLOW}  This user can escalate by running:${NC}"
echo -e "${YELLOW}  aws iam set-default-policy-version --policy-arn $POLICY_ARN --version-id v1${NC}"
echo ""

###############################################################################
# 2. ATTACH USER POLICY TEST (AttachUserPolicy Escalation)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}2. Attach User Policy Test${NC}"
echo -e "${GREEN}   (AttachUserPolicy Escalation - CRITICAL)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_ATTACH="${PREFIX}-attach-policy-user"
create_user_with_keys "$USER_ATTACH"

ATTACH_POLICY_NAME="${PREFIX}-attach-user-policy"
ATTACH_POLICY_ARN=$(aws iam create-policy \
    --policy-name "$ATTACH_POLICY_NAME" \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:AttachUserPolicy",
                    "iam:ListPolicies",
                    "iam:ListAttachedUserPolicies"
                ],
                "Resource": "*"
            }
        ]
    }' \
    --description "Allows attaching policies to users - PRIVILEGE ESCALATION" \
    --query 'Policy.Arn' \
    --output text 2>/dev/null || aws iam get-policy --policy-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/$ATTACH_POLICY_NAME" --query 'Policy.Arn' --output text)

aws iam attach-user-policy --user-name "$USER_ATTACH" --policy-arn "$ATTACH_POLICY_ARN"

echo -e "${GREEN}✓ AttachUserPolicy test setup complete!${NC}"
echo -e "${YELLOW}  This user can escalate by running:${NC}"
echo -e "${YELLOW}  aws iam attach-user-policy --user-name $USER_ATTACH --policy-arn arn:aws:iam::aws:policy/AdministratorAccess${NC}"
echo ""

###############################################################################
# 3. PUT USER POLICY TEST (PutUserPolicy Escalation)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}3. Put User Policy Test${NC}"
echo -e "${GREEN}   (PutUserPolicy Escalation - CRITICAL)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_PUT="${PREFIX}-put-policy-user"
create_user_with_keys "$USER_PUT"

PUT_POLICY_NAME="${PREFIX}-put-user-policy"
PUT_POLICY_ARN=$(aws iam create-policy \
    --policy-name "$PUT_POLICY_NAME" \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:PutUserPolicy",
                    "iam:ListUserPolicies"
                ],
                "Resource": "*"
            }
        ]
    }' \
    --description "Allows creating inline policies on users - PRIVILEGE ESCALATION" \
    --query 'Policy.Arn' \
    --output text 2>/dev/null || aws iam get-policy --policy-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/$PUT_POLICY_NAME" --query 'Policy.Arn' --output text)

aws iam attach-user-policy --user-name "$USER_PUT" --policy-arn "$PUT_POLICY_ARN"

echo -e "${GREEN}✓ PutUserPolicy test setup complete!${NC}"
echo -e "${YELLOW}  This user can escalate by running:${NC}"
echo -e "${YELLOW}  aws iam put-user-policy --user-name $USER_PUT --policy-name AdminPolicy --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}'${NC}"
echo ""

###############################################################################
# 4. CREATE ACCESS KEY TEST (CreateAccessKey Escalation)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}4. Create Access Key Test${NC}"
echo -e "${GREEN}   (CreateAccessKey Escalation - CRITICAL)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_CREATE_KEY="${PREFIX}-create-key-user"
USER_PRIVILEGED="${PREFIX}-privileged-target-user"

create_user_with_keys "$USER_CREATE_KEY"

# Create a privileged target user (with admin access)
echo "Creating privileged target user: $USER_PRIVILEGED"
aws iam create-user --user-name "$USER_PRIVILEGED" 2>/dev/null || echo "  User already exists"
aws iam attach-user-policy --user-name "$USER_PRIVILEGED" --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
echo "  ✓ Privileged target user created with admin access"

CREATE_KEY_POLICY_NAME="${PREFIX}-create-access-key"
CREATE_KEY_POLICY_ARN=$(aws iam create-policy \
    --policy-name "$CREATE_KEY_POLICY_NAME" \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:CreateAccessKey",
                    "iam:ListUsers"
                ],
                "Resource": "*"
            }
        ]
    }' \
    --description "Allows creating access keys for other users - PRIVILEGE ESCALATION" \
    --query 'Policy.Arn' \
    --output text 2>/dev/null || aws iam get-policy --policy-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/$CREATE_KEY_POLICY_NAME" --query 'Policy.Arn' --output text)

aws iam attach-user-policy --user-name "$USER_CREATE_KEY" --policy-arn "$CREATE_KEY_POLICY_ARN"

echo -e "${GREEN}✓ CreateAccessKey test setup complete!${NC}"
echo -e "${YELLOW}  This user can escalate by running:${NC}"
echo -e "${YELLOW}  aws iam create-access-key --user-name $USER_PRIVILEGED${NC}"
echo ""

###############################################################################
# 5. PASSROLE + LAMBDA TEST (PassRoleToLambda Escalation)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}5. PassRole + Lambda Test${NC}"
echo -e "${GREEN}   (PassRoleToLambda Escalation - CRITICAL)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_LAMBDA="${PREFIX}-lambda-user"
create_user_with_keys "$USER_LAMBDA"

# Create a privileged role that Lambda can assume
LAMBDA_ROLE_NAME="${PREFIX}-privileged-lambda-role"
echo "Creating privileged Lambda role: $LAMBDA_ROLE_NAME"
LAMBDA_ROLE_ARN=$(aws iam create-role \
    --role-name "$LAMBDA_ROLE_NAME" \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }' \
    --description "Privileged role for Lambda testing" \
    --query 'Role.Arn' \
    --output text 2>/dev/null || aws iam get-role --role-name "$LAMBDA_ROLE_NAME" --query 'Role.Arn' --output text)

# Attach admin policy to the Lambda role
aws iam attach-role-policy --role-name "$LAMBDA_ROLE_NAME" --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
echo "  ✓ Privileged Lambda role created: $LAMBDA_ROLE_ARN"

LAMBDA_POLICY_NAME="${PREFIX}-passrole-lambda"
LAMBDA_POLICY_ARN=$(aws iam create-policy \
    --policy-name "$LAMBDA_POLICY_NAME" \
    --policy-document "{
        \"Version\": \"2012-10-17\",
        \"Statement\": [
            {
                \"Effect\": \"Allow\",
                \"Action\": [
                    \"iam:PassRole\",
                    \"iam:ListRoles\"
                ],
                \"Resource\": \"*\"
            },
            {
                \"Effect\": \"Allow\",
                \"Action\": [
                    \"lambda:CreateFunction\",
                    \"lambda:InvokeFunction\",
                    \"lambda:ListFunctions\"
                ],
                \"Resource\": \"*\"
            }
        ]
    }" \
    --description "Allows PassRole + Lambda operations - PRIVILEGE ESCALATION" \
    --query 'Policy.Arn' \
    --output text 2>/dev/null || aws iam get-policy --policy-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/$LAMBDA_POLICY_NAME" --query 'Policy.Arn' --output text)

aws iam attach-user-policy --user-name "$USER_LAMBDA" --policy-arn "$LAMBDA_POLICY_ARN"

echo -e "${GREEN}✓ PassRole+Lambda test setup complete!${NC}"
echo -e "${YELLOW}  This user can escalate by creating a Lambda with the privileged role${NC}"
echo ""

###############################################################################
# 6. WILDCARD TEST (Full Admin Wildcard)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}6. Wildcard Test${NC}"
echo -e "${GREEN}   (Full Admin - CRITICAL)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_WILDCARD="${PREFIX}-wildcard-admin"
create_user_with_keys "$USER_WILDCARD"

WILDCARD_POLICY_NAME="${PREFIX}-wildcard-admin-policy"
WILDCARD_POLICY_ARN=$(aws iam create-policy \
    --policy-name "$WILDCARD_POLICY_NAME" \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }' \
    --description "Full admin wildcard policy - CRITICAL" \
    --query 'Policy.Arn' \
    --output text 2>/dev/null || aws iam get-policy --policy-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/$WILDCARD_POLICY_NAME" --query 'Policy.Arn' --output text)

aws iam attach-user-policy --user-name "$USER_WILDCARD" --policy-arn "$WILDCARD_POLICY_ARN"

echo -e "${GREEN}✓ Wildcard admin test setup complete!${NC}"
echo -e "${YELLOW}  This user has full admin access (Action: *, Resource: *)${NC}"
echo ""

###############################################################################
# 7. IAM WILDCARD TEST (IAM Full Access)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}7. IAM Wildcard Test${NC}"
echo -e "${GREEN}   (IAM:* Escalation - CRITICAL)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_IAM_WILDCARD="${PREFIX}-iam-wildcard-user"
create_user_with_keys "$USER_IAM_WILDCARD"

IAM_WILDCARD_POLICY_NAME="${PREFIX}-iam-wildcard-policy"
IAM_WILDCARD_POLICY_ARN=$(aws iam create-policy \
    --policy-name "$IAM_WILDCARD_POLICY_NAME" \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": "*"
            }
        ]
    }' \
    --description "Full IAM access - multiple escalation paths" \
    --query 'Policy.Arn' \
    --output text 2>/dev/null || aws iam get-policy --policy-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/$IAM_WILDCARD_POLICY_NAME" --query 'Policy.Arn' --output text)

aws iam attach-user-policy --user-name "$USER_IAM_WILDCARD" --policy-arn "$IAM_WILDCARD_POLICY_ARN"

echo -e "${GREEN}✓ IAM wildcard test setup complete!${NC}"
echo -e "${YELLOW}  This user has full IAM access (iam:*) - multiple escalation paths${NC}"
echo ""

###############################################################################
# SUMMARY
###############################################################################
echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Setup Complete - Test Users Summary                     ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}The following test users have been created:${NC}"
echo ""
echo -e "${YELLOW}1. $USER_MULTIVERSION${NC}"
echo "   - Can set default policy version (v1 has SecretsManager, v2 doesn't)"
echo "   - Demonstrates: SetExistingDefaultPolicyVersion escalation"
echo "   - Risk Level: CRITICAL (10/10)"
echo ""
echo -e "${YELLOW}2. $USER_ATTACH${NC}"
echo "   - Can attach policies to own user"
echo "   - Demonstrates: AttachUserPolicy escalation"
echo "   - Risk Level: CRITICAL (10/10)"
echo ""
echo -e "${YELLOW}3. $USER_PUT${NC}"
echo "   - Can create inline policies on own user"
echo "   - Demonstrates: PutUserPolicy escalation"
echo "   - Risk Level: CRITICAL (10/10)"
echo ""
echo -e "${YELLOW}4. $USER_CREATE_KEY${NC}"
echo "   - Can create access keys for privileged users"
echo "   - Target: $USER_PRIVILEGED (has admin access)"
echo "   - Demonstrates: CreateAccessKey escalation"
echo "   - Risk Level: CRITICAL (9/10)"
echo ""
echo -e "${YELLOW}5. $USER_LAMBDA${NC}"
echo "   - Can pass privileged role to Lambda and invoke"
echo "   - Privileged Role: $LAMBDA_ROLE_NAME"
echo "   - Demonstrates: PassRoleToLambda escalation"
echo "   - Risk Level: CRITICAL (10/10)"
echo ""
echo -e "${YELLOW}6. $USER_WILDCARD${NC}"
echo "   - Has full admin access (Action: *, Resource: *)"
echo "   - Demonstrates: Full administrator detection"
echo "   - Risk Level: CRITICAL (10/10)"
echo ""
echo -e "${YELLOW}7. $USER_IAM_WILDCARD${NC}"
echo "   - Has full IAM access (iam:*)"
echo "   - Demonstrates: Multiple IAM-based escalations"
echo "   - Risk Level: CRITICAL (10/10)"
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo "1. Open the AWS Policy Explorer in your browser"
echo "2. Use any of the test user credentials to log in"
echo "3. Browse policies and view the Security Analysis tab"
echo "4. Observe the detected privilege escalation methods"
echo ""
echo -e "${RED}⚠️  IMPORTANT: Remember to clean up these test accounts!${NC}"
echo -e "${RED}⚠️  Run: ./cleanup-test-accounts.sh${NC}"
echo ""

