#!/bin/bash

###############################################################################
# AWS Policy Explorer - Test Account Setup Script
#
# Creates test IAM users and policies that demonstrate insecure permission
# patterns.  When examined through the explorer, these policies trigger
# shadow-admin / privilege-escalation detections across many services.
#
# WARNING: This creates intentionally dangerous IAM configurations.
#          Only run in a dedicated sandbox / test AWS account.
#          DO NOT run in production environments.
#
# Usage:
#   ./setup-test-accounts.sh                    # Use default / env config
#   ./setup-test-accounts.sh --profile PROFILE  # Use specific AWS profile
###############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PREFIX="${TEST_PREFIX:-test-shadow-admin}"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  AWS Policy Explorer - Test Account Setup                ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/aws-config.sh" "$@" || exit 1

REGION="${AWS_DEFAULT_REGION:-us-east-1}"

echo -e "${YELLOW}⚠️  WARNING: This creates privileged test accounts${NC}"
echo -e "${YELLOW}⚠️  Only run in a test/sandbox AWS account${NC}"
echo ""

read -p "Are you sure you want to continue? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo -e "${RED}Aborted.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Starting setup...${NC}"
echo ""

###############################################################################
# Helpers
###############################################################################
create_user_with_keys() {
    local username=$1
    echo -e "${BLUE}Creating user: ${username}${NC}"
    aws_run iam create-user --user-name "$username" 2>/dev/null || echo "  User already exists"

    existing_keys=$(aws_run iam list-access-keys --user-name "$username" \
        --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null)
    for key in $existing_keys; do
        aws_run iam delete-access-key --user-name "$username" --access-key-id "$key" 2>/dev/null
    done

    local key_output
    key_output=$(aws_run iam create-access-key --user-name "$username" --output json)
    local access_key secret_key
    access_key=$(echo "$key_output" | jq -r '.AccessKey.AccessKeyId')
    secret_key=$(echo "$key_output" | jq -r '.AccessKey.SecretAccessKey')

    echo "  ✓ User created"
    echo "  Access Key: $access_key"
    echo "  Secret Key: $secret_key"
    echo ""
}

create_and_attach_policy() {
    local policy_name=$1
    local username=$2
    local description=$3
    local policy_doc=$4

    local policy_arn
    policy_arn=$(aws_run iam create-policy \
        --policy-name "$policy_name" \
        --policy-document "$policy_doc" \
        --description "$description" \
        --query 'Policy.Arn' --output text 2>/dev/null \
    || aws_run iam get-policy \
        --policy-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/$policy_name" \
        --query 'Policy.Arn' --output text)

    aws_run iam attach-user-policy --user-name "$username" --policy-arn "$policy_arn"
    echo "  ✓ Attached $policy_name"
}

###############################################################################
# 1.  SetDefaultPolicyVersion (multi-version)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}1. Multi-Version Policy (SetDefaultPolicyVersion)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

POLICY_NAME="${PREFIX}-multiversion-policy"
USER_MULTIVERSION="${PREFIX}-multiversion-user"

POLICY_ARN=$(aws_run iam create-policy \
    --policy-name "$POLICY_NAME" \
    --policy-document '{
        "Version":"2012-10-17","Statement":[
            {"Sid":"ReadOnly","Effect":"Allow","Action":["iam:GetPolicy","iam:GetPolicyVersion","iam:ListPolicies","iam:ListPolicyVersions"],"Resource":"*"},
            {"Sid":"SecretsManager","Effect":"Allow","Action":["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret","secretsmanager:ListSecrets"],"Resource":"*"}
        ]
    }' \
    --description "v1 has SecretsManager access; v2 removes it" \
    --query 'Policy.Arn' --output text 2>/dev/null \
|| aws_run iam get-policy --policy-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/$POLICY_NAME" --query 'Policy.Arn' --output text)

aws_run iam create-policy-version --policy-arn "$POLICY_ARN" --set-as-default \
    --policy-document '{
        "Version":"2012-10-17","Statement":[
            {"Sid":"ReadOnly","Effect":"Allow","Action":["iam:GetPolicy","iam:GetPolicyVersion","iam:ListPolicies","iam:ListPolicyVersions"],"Resource":"*"}
        ]
    }' 2>/dev/null || echo "  Version already exists"

create_user_with_keys "$USER_MULTIVERSION"
aws_run iam attach-user-policy --user-name "$USER_MULTIVERSION" --policy-arn "$POLICY_ARN"

create_and_attach_policy "${PREFIX}-set-policy-version" "$USER_MULTIVERSION" \
    "SetDefaultPolicyVersion escalation" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:SetDefaultPolicyVersion","iam:ListAttachedUserPolicies","iam:ListUserPolicies"],"Resource":"*"}]}'

echo -e "${GREEN}✓ #1 complete${NC}"
echo ""

###############################################################################
# 2.  AttachUserPolicy
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}2. AttachUserPolicy escalation${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_ATTACH="${PREFIX}-attach-policy-user"
create_user_with_keys "$USER_ATTACH"

create_and_attach_policy "${PREFIX}-attach-user-policy" "$USER_ATTACH" \
    "AttachUserPolicy escalation" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:AttachUserPolicy","iam:ListPolicies","iam:ListAttachedUserPolicies"],"Resource":"*"}]}'

echo -e "${GREEN}✓ #2 complete${NC}"
echo ""

###############################################################################
# 3.  PutUserPolicy
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}3. PutUserPolicy escalation${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_PUT="${PREFIX}-put-policy-user"
create_user_with_keys "$USER_PUT"

create_and_attach_policy "${PREFIX}-put-user-policy" "$USER_PUT" \
    "PutUserPolicy escalation" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:PutUserPolicy","iam:ListUserPolicies"],"Resource":"*"}]}'

echo -e "${GREEN}✓ #3 complete${NC}"
echo ""

###############################################################################
# 4.  CreateAccessKey (target a privileged user)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}4. CreateAccessKey escalation${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_CREATE_KEY="${PREFIX}-create-key-user"
USER_PRIVILEGED="${PREFIX}-privileged-target-user"

create_user_with_keys "$USER_CREATE_KEY"

echo "Creating privileged target user: $USER_PRIVILEGED"
aws_run iam create-user --user-name "$USER_PRIVILEGED" 2>/dev/null || echo "  User already exists"
aws_run iam attach-user-policy --user-name "$USER_PRIVILEGED" \
    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
echo "  ✓ Privileged target user created"

create_and_attach_policy "${PREFIX}-create-access-key" "$USER_CREATE_KEY" \
    "CreateAccessKey escalation" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateAccessKey","iam:ListUsers"],"Resource":"*"}]}'

echo -e "${GREEN}✓ #4 complete${NC}"
echo ""

###############################################################################
# 5.  PassRole + Lambda
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}5. PassRole + Lambda (create + invoke)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_LAMBDA="${PREFIX}-lambda-user"
LAMBDA_ROLE="${PREFIX}-privileged-lambda-role"

create_user_with_keys "$USER_LAMBDA"

LAMBDA_ROLE_ARN=$(aws_run iam create-role \
    --role-name "$LAMBDA_ROLE" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
    --description "Privileged Lambda role" \
    --query 'Role.Arn' --output text 2>/dev/null \
|| aws_run iam get-role --role-name "$LAMBDA_ROLE" --query 'Role.Arn' --output text)

aws_run iam attach-role-policy --role-name "$LAMBDA_ROLE" \
    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

create_and_attach_policy "${PREFIX}-passrole-lambda" "$USER_LAMBDA" \
    "PassRole + Lambda escalation" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:PassRole","iam:ListRoles"],"Resource":"*"},{"Effect":"Allow","Action":["lambda:CreateFunction","lambda:InvokeFunction","lambda:ListFunctions"],"Resource":"*"}]}'

echo -e "${GREEN}✓ #5 complete${NC}"
echo ""

###############################################################################
# 6.  Wildcard admin (Action: *, Resource: *)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}6. Full wildcard admin${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_WILDCARD="${PREFIX}-wildcard-admin"
create_user_with_keys "$USER_WILDCARD"

create_and_attach_policy "${PREFIX}-wildcard-admin-policy" "$USER_WILDCARD" \
    "Full admin wildcard" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'

echo -e "${GREEN}✓ #6 complete${NC}"
echo ""

###############################################################################
# 7.  IAM wildcard (iam:*)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}7. IAM wildcard (iam:*)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_IAM_WILDCARD="${PREFIX}-iam-wildcard-user"
create_user_with_keys "$USER_IAM_WILDCARD"

create_and_attach_policy "${PREFIX}-iam-wildcard-policy" "$USER_IAM_WILDCARD" \
    "Full IAM access" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}'

echo -e "${GREEN}✓ #7 complete${NC}"
echo ""

###############################################################################
# 8.  PassRole + ECS (register task + run task)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}8. PassRole + ECS escalation${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_ECS="${PREFIX}-ecs-user"
create_user_with_keys "$USER_ECS"

create_and_attach_policy "${PREFIX}-ecs-passrole" "$USER_ECS" \
    "PassRole + ECS task escalation" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:PassRole","iam:ListRoles"],"Resource":"*"},{"Effect":"Allow","Action":["ecs:RegisterTaskDefinition","ecs:RunTask","ecs:CreateCluster","ecs:CreateService","ecs:ListClusters"],"Resource":"*"}]}'

echo -e "${GREEN}✓ #8 complete${NC}"
echo ""

###############################################################################
# 9.  PassRole + CodeBuild (create project + start build)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}9. PassRole + CodeBuild escalation${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_CODEBUILD="${PREFIX}-codebuild-user"
create_user_with_keys "$USER_CODEBUILD"

create_and_attach_policy "${PREFIX}-codebuild-passrole" "$USER_CODEBUILD" \
    "PassRole + CodeBuild escalation" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:PassRole","iam:ListRoles"],"Resource":"*"},{"Effect":"Allow","Action":["codebuild:CreateProject","codebuild:StartBuild","codebuild:StartBuildBatch","codebuild:ListProjects"],"Resource":"*"}]}'

echo -e "${GREEN}✓ #9 complete${NC}"
echo ""

###############################################################################
# 10. SSM escalation (SendCommand + StartSession)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}10. SSM escalation (SendCommand / StartSession)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_SSM="${PREFIX}-ssm-user"
create_user_with_keys "$USER_SSM"

create_and_attach_policy "${PREFIX}-ssm-access" "$USER_SSM" \
    "SSM escalation" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:SendCommand","ssm:StartSession","ssm:DescribeInstanceInformation","ec2:DescribeInstances"],"Resource":"*"}]}'

echo -e "${GREEN}✓ #10 complete${NC}"
echo ""

###############################################################################
# 11. CloudFormation escalation (CreateChangeSet + ExecuteChangeSet)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}11. CloudFormation escalation${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_CFN="${PREFIX}-cfn-user"
create_user_with_keys "$USER_CFN"

create_and_attach_policy "${PREFIX}-cfn-changeset" "$USER_CFN" \
    "CloudFormation ChangeSet + StackSet escalation" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:PassRole","iam:ListRoles"],"Resource":"*"},{"Effect":"Allow","Action":["cloudformation:CreateStack","cloudformation:UpdateStack","cloudformation:CreateChangeSet","cloudformation:ExecuteChangeSet","cloudformation:CreateStackSet","cloudformation:CreateStackInstances","cloudformation:UpdateStackSet","cloudformation:DescribeStacks","cloudformation:DescribeChangeSet","cloudformation:DescribeStackSet","cloudformation:GetTemplate"],"Resource":"*"}]}'

echo -e "${GREEN}✓ #11 complete${NC}"
echo ""

###############################################################################
# 12. EC2 escalation (ModifyInstanceAttribute + Stop/Start)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}12. EC2 escalation (ModifyInstanceAttribute + user data)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_EC2="${PREFIX}-ec2-user"
create_user_with_keys "$USER_EC2"

create_and_attach_policy "${PREFIX}-ec2-modify" "$USER_EC2" \
    "EC2 ModifyInstanceAttribute + RunInstances + Spot + LaunchTemplate" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:PassRole","iam:ListRoles","iam:ListInstanceProfiles"],"Resource":"*"},{"Effect":"Allow","Action":["ec2:ModifyInstanceAttribute","ec2:StopInstances","ec2:StartInstances","ec2:RunInstances","ec2:RequestSpotInstances","ec2:CreateLaunchTemplateVersion","ec2:ModifyLaunchTemplate","ec2:DescribeLaunchTemplates","ec2:DescribeLaunchTemplateVersions","ec2:DescribeInstances"],"Resource":"*"}]}'

echo -e "${GREEN}✓ #12 complete${NC}"
echo ""

###############################################################################
# 13. SageMaker escalation (PassRole + CreateNotebookInstance)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}13. SageMaker escalation${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_SAGEMAKER="${PREFIX}-sagemaker-user"
create_user_with_keys "$USER_SAGEMAKER"

create_and_attach_policy "${PREFIX}-sagemaker-passrole" "$USER_SAGEMAKER" \
    "PassRole + SageMaker notebook/training/processing + lifecycle" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:PassRole","iam:ListRoles"],"Resource":"*"},{"Effect":"Allow","Action":["sagemaker:CreateNotebookInstance","sagemaker:CreateTrainingJob","sagemaker:CreateProcessingJob","sagemaker:CreatePresignedNotebookInstanceUrl","sagemaker:CreateNotebookInstanceLifecycleConfig","sagemaker:StopNotebookInstance","sagemaker:UpdateNotebookInstance","sagemaker:StartNotebookInstance","sagemaker:DescribeNotebookInstance","sagemaker:ListNotebookInstances"],"Resource":"*"}]}'

echo -e "${GREEN}✓ #13 complete${NC}"
echo ""

###############################################################################
# 14. Glue escalation (PassRole + CreateDevEndpoint + CreateJob)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}14. Glue escalation${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_GLUE="${PREFIX}-glue-user"
create_user_with_keys "$USER_GLUE"

create_and_attach_policy "${PREFIX}-glue-passrole" "$USER_GLUE" \
    "PassRole + Glue DevEndpoint / Job escalation" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:PassRole","iam:ListRoles"],"Resource":"*"},{"Effect":"Allow","Action":["glue:CreateDevEndpoint","glue:UpdateDevEndpoint","glue:GetDevEndpoint","glue:GetDevEndpoints","glue:CreateJob","glue:UpdateJob","glue:StartJobRun","glue:CreateTrigger","glue:GetJob"],"Resource":"*"}]}'

echo -e "${GREEN}✓ #14 complete${NC}"
echo ""

###############################################################################
# 15. Multi-step IAM chain (AttachRolePolicy + UpdateAssumeRolePolicy + AssumeRole)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}15. Multi-step IAM chain${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_CHAIN="${PREFIX}-iam-chain-user"
create_user_with_keys "$USER_CHAIN"

create_and_attach_policy "${PREFIX}-iam-chain" "$USER_CHAIN" \
    "AttachRolePolicy + UpdateAssumeRolePolicy + AssumeRole chain" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:AttachRolePolicy","iam:UpdateAssumeRolePolicy","iam:PutRolePolicy","iam:CreatePolicyVersion","iam:ListRoles","iam:GetRole","iam:GetPolicy","iam:GetPolicyVersion","iam:ListRolePolicies"],"Resource":"*"},{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}'

echo -e "${GREEN}✓ #15 complete${NC}"
echo ""

###############################################################################
# 16. NotAction demo (Allow everything EXCEPT IAM)
###############################################################################
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}16. NotAction demo (Allow NotAction: iam:*)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

USER_NOTACTION="${PREFIX}-notaction-user"
create_user_with_keys "$USER_NOTACTION"

create_and_attach_policy "${PREFIX}-notaction-demo" "$USER_NOTACTION" \
    "NotAction demo: everything except IAM" \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}'

echo -e "${GREEN}✓ #16 complete${NC}"
echo ""

###############################################################################
# SUMMARY
###############################################################################
echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Setup Complete - Test Users Summary                     ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Users created (all prefixed ${PREFIX}-):${NC}"
echo ""
echo -e "${YELLOW} #  User                    Escalation Paths Triggered${NC}"
echo "────────────────────────────────────────────────────────────────"
echo " 1  multiversion-user       SetDefaultPolicyVersion"
echo " 2  attach-policy-user      AttachUserPolicy"
echo " 3  put-policy-user         PutUserPolicy"
echo " 4  create-key-user         CreateAccessKey"
echo " 5  lambda-user             PassRole+Lambda (create+invoke)"
echo " 6  wildcard-admin          Full admin (*)"
echo " 7  iam-wildcard-user       iam:* (many IAM escalations)"
echo " 8  ecs-user                PassRole+ECS (register+run task)"
echo " 9  codebuild-user          PassRole+CodeBuild (create+build)"
echo "10  ssm-user                SSM SendCommand / StartSession"
echo "11  cfn-user                CloudFormation stack/changeset/stackset"
echo "12  ec2-user                EC2 ModifyInstanceAttr / RunInstances / Spot"
echo "13  sagemaker-user          PassRole+SageMaker notebook/training"
echo "14  glue-user               PassRole+Glue DevEndpoint/Job"
echo "15  iam-chain-user          Multi-step: AttachRolePolicy+AssumeRole chain"
echo "16  notaction-user          NotAction demo (everything except iam:*)"
echo ""
echo -e "${YELLOW}Roles:${NC}"
echo "  ${PREFIX}-privileged-lambda-role  (AdminAccess, assumed by Lambda)"
echo ""
echo -e "${YELLOW}AWS Configuration Used:${NC}"
if [ -n "$AWS_PROFILE" ]; then
    echo "  Profile: $AWS_PROFILE"
fi
echo "  Account: $AWS_ACCOUNT_ID"
echo "  Region:  $REGION"
echo ""
echo -e "${GREEN}Next Steps:${NC}"
echo "1. Start the application: ./start-server.sh  (from project root)"
echo "2. Open: http://localhost:8000"
echo "3. Use any of the test credentials above to log in"
echo "4. Browse policies → Security Analysis → Expansion tabs"
echo ""
echo -e "${RED}⚠️  Remember to cleanup when done:${NC}"
echo -e "${RED}⚠️  ./test-scripts/cleanup-test-accounts.sh${NC}"
if [ -n "$AWS_PROFILE" ]; then
    echo -e "${RED}⚠️  ./test-scripts/cleanup-test-accounts.sh --profile $AWS_PROFILE${NC}"
fi
echo ""
