#!/bin/bash

###############################################################################
# AWS Policy Explorer - Test Account Cleanup Script
#
# Removes all test IAM users, roles, and policies created by
# setup-test-accounts.sh (all 16 scenarios).
#
# Usage:
#   ./cleanup-test-accounts.sh                    # Use default / env config
#   ./cleanup-test-accounts.sh --profile PROFILE  # Use specific AWS profile
###############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PREFIX="${TEST_PREFIX:-test-shadow-admin}"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  AWS Policy Explorer - Test Account Cleanup              ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/aws-config.sh" "$@" || exit 1

read -p "Delete ALL test accounts with prefix '${PREFIX}'? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo -e "${RED}Aborted.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Starting cleanup...${NC}"
echo ""

###############################################################################
# Helpers
###############################################################################
delete_user() {
    local username=$1
    echo -e "${BLUE}Deleting user: ${username}${NC}"

    if ! aws_run iam get-user --user-name "$username" &>/dev/null; then
        echo "  Skipped (does not exist)"
        return
    fi

    local access_keys
    access_keys=$(aws_run iam list-access-keys --user-name "$username" \
        --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null)
    for key in $access_keys; do
        aws_run iam delete-access-key --user-name "$username" --access-key-id "$key" 2>/dev/null || true
    done

    local attached
    attached=$(aws_run iam list-attached-user-policies --user-name "$username" \
        --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)
    for arn in $attached; do
        aws_run iam detach-user-policy --user-name "$username" --policy-arn "$arn" 2>/dev/null || true
    done

    local inline
    inline=$(aws_run iam list-user-policies --user-name "$username" \
        --query 'PolicyNames[]' --output text 2>/dev/null)
    for name in $inline; do
        aws_run iam delete-user-policy --user-name "$username" --policy-name "$name" 2>/dev/null || true
    done

    aws_run iam delete-user --user-name "$username" 2>/dev/null || true
    echo "  ✓ Deleted"
}

delete_role() {
    local role_name=$1
    echo -e "${BLUE}Deleting role: ${role_name}${NC}"

    if ! aws_run iam get-role --role-name "$role_name" &>/dev/null; then
        echo "  Skipped (does not exist)"
        return
    fi

    local attached
    attached=$(aws_run iam list-attached-role-policies --role-name "$role_name" \
        --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)
    for arn in $attached; do
        aws_run iam detach-role-policy --role-name "$role_name" --policy-arn "$arn" 2>/dev/null || true
    done

    local inline
    inline=$(aws_run iam list-role-policies --role-name "$role_name" \
        --query 'PolicyNames[]' --output text 2>/dev/null)
    for name in $inline; do
        aws_run iam delete-role-policy --role-name "$role_name" --policy-name "$name" 2>/dev/null || true
    done

    aws_run iam delete-role --role-name "$role_name" 2>/dev/null || true
    echo "  ✓ Deleted"
}

delete_policy() {
    local policy_name=$1
    local policy_arn="arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${policy_name}"
    echo -e "${BLUE}Deleting policy: ${policy_name}${NC}"

    if ! aws_run iam get-policy --policy-arn "$policy_arn" &>/dev/null; then
        echo "  Skipped (does not exist)"
        return
    fi

    local versions
    versions=$(aws_run iam list-policy-versions --policy-arn "$policy_arn" \
        --query 'Versions[?!IsDefaultVersion].VersionId' --output text 2>/dev/null)
    for v in $versions; do
        aws_run iam delete-policy-version --policy-arn "$policy_arn" --version-id "$v" 2>/dev/null || true
    done

    aws_run iam delete-policy --policy-arn "$policy_arn" 2>/dev/null || true
    echo "  ✓ Deleted"
}

###############################################################################
# Delete users (all 16 scenarios + privileged target)
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
delete_user "${PREFIX}-ecs-user"
delete_user "${PREFIX}-codebuild-user"
delete_user "${PREFIX}-ssm-user"
delete_user "${PREFIX}-cfn-user"
delete_user "${PREFIX}-ec2-user"
delete_user "${PREFIX}-sagemaker-user"
delete_user "${PREFIX}-glue-user"
delete_user "${PREFIX}-iam-chain-user"
delete_user "${PREFIX}-notaction-user"

###############################################################################
# Delete roles
###############################################################################
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Deleting Test Roles${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

delete_role "${PREFIX}-privileged-lambda-role"

###############################################################################
# Delete policies (all 16 scenarios)
###############################################################################
echo ""
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
delete_policy "${PREFIX}-ecs-passrole"
delete_policy "${PREFIX}-codebuild-passrole"
delete_policy "${PREFIX}-ssm-access"
delete_policy "${PREFIX}-cfn-changeset"
delete_policy "${PREFIX}-ec2-modify"
delete_policy "${PREFIX}-sagemaker-passrole"
delete_policy "${PREFIX}-glue-passrole"
delete_policy "${PREFIX}-iam-chain"
delete_policy "${PREFIX}-notaction-demo"

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
