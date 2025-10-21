#!/bin/bash

###############################################################################
# AWS Policy Explorer - Test Account Cleanup Script
# 
# This script removes all test IAM users, roles, and policies created by
# the setup-test-accounts.sh script.
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PREFIX="test-shadow-admin"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  AWS Policy Explorer - Test Account Cleanup              ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Confirmation
read -p "Are you sure you want to delete all test accounts? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo -e "${RED}Aborted.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Starting cleanup...${NC}"
echo ""

###############################################################################
# Function to delete a user and all associated resources
###############################################################################
delete_user() {
    local username=$1
    echo -e "${BLUE}Deleting user: ${username}${NC}"
    
    # Check if user exists
    if ! aws iam get-user --user-name "$username" &>/dev/null; then
        echo "  User does not exist, skipping"
        return
    fi
    
    # Delete access keys
    local access_keys=$(aws iam list-access-keys --user-name "$username" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null)
    for key in $access_keys; do
        echo "  Deleting access key: $key"
        aws iam delete-access-key --user-name "$username" --access-key-id "$key" 2>/dev/null || true
    done
    
    # Detach managed policies
    local attached_policies=$(aws iam list-attached-user-policies --user-name "$username" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)
    for policy_arn in $attached_policies; do
        echo "  Detaching policy: $policy_arn"
        aws iam detach-user-policy --user-name "$username" --policy-arn "$policy_arn" 2>/dev/null || true
    done
    
    # Delete inline policies
    local inline_policies=$(aws iam list-user-policies --user-name "$username" --query 'PolicyNames[]' --output text 2>/dev/null)
    for policy_name in $inline_policies; do
        echo "  Deleting inline policy: $policy_name"
        aws iam delete-user-policy --user-name "$username" --policy-name "$policy_name" 2>/dev/null || true
    done
    
    # Delete user
    echo "  Deleting user..."
    aws iam delete-user --user-name "$username" 2>/dev/null || true
    echo "  ✓ User deleted"
    echo ""
}

###############################################################################
# Function to delete a policy and all its versions
###############################################################################
delete_policy() {
    local policy_name=$1
    local account_id=$(aws sts get-caller-identity --query Account --output text)
    local policy_arn="arn:aws:iam::${account_id}:policy/${policy_name}"
    
    echo -e "${BLUE}Deleting policy: ${policy_name}${NC}"
    
    # Check if policy exists
    if ! aws iam get-policy --policy-arn "$policy_arn" &>/dev/null; then
        echo "  Policy does not exist, skipping"
        return
    fi
    
    # List all policy versions
    local versions=$(aws iam list-policy-versions --policy-arn "$policy_arn" --query 'Versions[?!IsDefaultVersion].VersionId' --output text 2>/dev/null)
    
    # Delete non-default versions
    for version in $versions; do
        echo "  Deleting version: $version"
        aws iam delete-policy-version --policy-arn "$policy_arn" --version-id "$version" 2>/dev/null || true
    done
    
    # Delete policy
    echo "  Deleting policy..."
    aws iam delete-policy --policy-arn "$policy_arn" 2>/dev/null || true
    echo "  ✓ Policy deleted"
    echo ""
}

###############################################################################
# Function to delete a role and all associated resources
###############################################################################
delete_role() {
    local role_name=$1
    echo -e "${BLUE}Deleting role: ${role_name}${NC}"
    
    # Check if role exists
    if ! aws iam get-role --role-name "$role_name" &>/dev/null; then
        echo "  Role does not exist, skipping"
        return
    fi
    
    # Detach managed policies
    local attached_policies=$(aws iam list-attached-role-policies --role-name "$role_name" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)
    for policy_arn in $attached_policies; do
        echo "  Detaching policy: $policy_arn"
        aws iam detach-role-policy --role-name "$role_name" --policy-arn "$policy_arn" 2>/dev/null || true
    done
    
    # Delete inline policies
    local inline_policies=$(aws iam list-role-policies --role-name "$role_name" --query 'PolicyNames[]' --output text 2>/dev/null)
    for policy_name in $inline_policies; do
        echo "  Deleting inline policy: $policy_name"
        aws iam delete-role-policy --role-name "$role_name" --policy-name "$policy_name" 2>/dev/null || true
    done
    
    # Delete role
    echo "  Deleting role..."
    aws iam delete-role --role-name "$role_name" 2>/dev/null || true
    echo "  ✓ Role deleted"
    echo ""
}

###############################################################################
# Delete all test users
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Deleting Test Users${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

delete_user "${PREFIX}-multiversion-user"
delete_user "${PREFIX}-attach-policy-user"
delete_user "${PREFIX}-put-policy-user"
delete_user "${PREFIX}-create-key-user"
delete_user "${PREFIX}-privileged-target-user"
delete_user "${PREFIX}-lambda-user"
delete_user "${PREFIX}-wildcard-admin"
delete_user "${PREFIX}-iam-wildcard-user"

###############################################################################
# Delete all test roles
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Deleting Test Roles${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

delete_role "${PREFIX}-privileged-lambda-role"

###############################################################################
# Delete all test policies
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Deleting Test Policies${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

delete_policy "${PREFIX}-multiversion-policy"
delete_policy "${PREFIX}-set-policy-version"
delete_policy "${PREFIX}-attach-user-policy"
delete_policy "${PREFIX}-put-user-policy"
delete_policy "${PREFIX}-create-access-key"
delete_policy "${PREFIX}-passrole-lambda"
delete_policy "${PREFIX}-wildcard-admin-policy"
delete_policy "${PREFIX}-iam-wildcard-policy"

###############################################################################
# Summary
###############################################################################
echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Cleanup Complete                                        ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}All test accounts, roles, and policies have been removed.${NC}"
echo ""

