/**
 * AWS Handler Module
 * Manages AWS SDK interactions for IAM policy operations
 */

import { 
    IAMClient, 
    ListPoliciesCommand,
    GetPolicyCommand,
    GetPolicyVersionCommand,
    ListPolicyVersionsCommand,
    SetDefaultPolicyVersionCommand
} from '@aws-sdk/client-iam';

class AWSHandler {
    constructor() {
        this.iamClient = null;
        this.credentials = null;
    }

    /**
     * Initialize AWS clients with provided credentials
     */
    initialize(accessKeyId, secretAccessKey, sessionToken, region) {
        this.credentials = {
            accessKeyId,
            secretAccessKey,
            ...(sessionToken && { sessionToken })
        };

        this.iamClient = new IAMClient({
            region: region || 'us-east-1',
            credentials: this.credentials
        });

        return true;
    }

    /**
     * Test connection by making a simple API call
     */
    async testConnection() {
        try {
            const command = new ListPoliciesCommand({
                MaxItems: 1
            });
            await this.iamClient.send(command);
            return { success: true };
        } catch (error) {
            return { 
                success: false, 
                error: error.message || 'Failed to connect to AWS'
            };
        }
    }

    /**
     * List all managed policies (AWS and Customer managed)
     * Handles pagination automatically
     */
    async listAllPolicies() {
        try {
            const allPolicies = {
                awsManaged: [],
                customerManaged: []
            };

            // Get AWS Managed Policies
            let marker = null;
            do {
                const command = new ListPoliciesCommand({
                    Scope: 'AWS',
                    MaxItems: 100,
                    ...(marker && { Marker: marker })
                });
                
                const response = await this.iamClient.send(command);
                
                if (response.Policies) {
                    allPolicies.awsManaged.push(...response.Policies);
                }
                
                marker = response.IsTruncated ? response.Marker : null;
            } while (marker);

            // Get Customer Managed Policies
            marker = null;
            do {
                const command = new ListPoliciesCommand({
                    Scope: 'Local',
                    MaxItems: 100,
                    ...(marker && { Marker: marker })
                });
                
                const response = await this.iamClient.send(command);
                
                if (response.Policies) {
                    allPolicies.customerManaged.push(...response.Policies);
                }
                
                marker = response.IsTruncated ? response.Marker : null;
            } while (marker);

            return {
                success: true,
                data: allPolicies
            };
        } catch (error) {
            console.error('Error listing policies:', error);
            return {
                success: false,
                error: error.message || 'Failed to list policies'
            };
        }
    }

    /**
     * Get detailed information about a specific policy
     */
    async getPolicyDetails(policyArn) {
        try {
            const command = new GetPolicyCommand({
                PolicyArn: policyArn
            });
            
            const response = await this.iamClient.send(command);
            
            return {
                success: true,
                data: response.Policy
            };
        } catch (error) {
            console.error('Error getting policy details:', error);
            return {
                success: false,
                error: error.message || 'Failed to get policy details'
            };
        }
    }

    /**
     * Get the policy document for a specific version
     */
    async getPolicyVersion(policyArn, versionId) {
        try {
            const command = new GetPolicyVersionCommand({
                PolicyArn: policyArn,
                VersionId: versionId
            });
            
            const response = await this.iamClient.send(command);
            
            // Decode the policy document
            let policyDocument = response.PolicyVersion.Document;
            if (typeof policyDocument === 'string') {
                policyDocument = JSON.parse(decodeURIComponent(policyDocument));
            }
            
            return {
                success: true,
                data: {
                    ...response.PolicyVersion,
                    Document: policyDocument
                }
            };
        } catch (error) {
            console.error('Error getting policy version:', error);
            return {
                success: false,
                error: error.message || 'Failed to get policy version'
            };
        }
    }

    /**
     * List all versions of a policy
     */
    async listPolicyVersions(policyArn) {
        try {
            const command = new ListPolicyVersionsCommand({
                PolicyArn: policyArn,
                MaxItems: 100
            });
            
            const response = await this.iamClient.send(command);
            
            return {
                success: true,
                data: response.Versions || []
            };
        } catch (error) {
            console.error('Error listing policy versions:', error);
            return {
                success: false,
                error: error.message || 'Failed to list policy versions'
            };
        }
    }

    /**
     * Set a specific version as the default policy version
     * Note: This requires iam:SetDefaultPolicyVersion permission
     */
    async setDefaultPolicyVersion(policyArn, versionId) {
        try {
            const command = new SetDefaultPolicyVersionCommand({
                PolicyArn: policyArn,
                VersionId: versionId
            });
            
            await this.iamClient.send(command);
            
            return {
                success: true,
                message: `Successfully set ${versionId} as default version`
            };
        } catch (error) {
            console.error('Error setting default policy version:', error);
            return {
                success: false,
                error: error.message || 'Failed to set default policy version'
            };
        }
    }

    /**
     * Get complete policy information including document
     */
    async getCompletePolicyInfo(policyArn, versionId = null) {
        try {
            // Get policy details
            const detailsResult = await this.getPolicyDetails(policyArn);
            if (!detailsResult.success) {
                return detailsResult;
            }

            const policy = detailsResult.data;
            
            // If no version specified, use default version
            const targetVersion = versionId || policy.DefaultVersionId;
            
            // Get policy document
            const versionResult = await this.getPolicyVersion(policyArn, targetVersion);
            if (!versionResult.success) {
                return versionResult;
            }

            // Get all versions
            const versionsResult = await this.listPolicyVersions(policyArn);
            
            return {
                success: true,
                data: {
                    policy,
                    currentVersion: versionResult.data,
                    allVersions: versionsResult.success ? versionsResult.data : []
                }
            };
        } catch (error) {
            console.error('Error getting complete policy info:', error);
            return {
                success: false,
                error: error.message || 'Failed to get complete policy information'
            };
        }
    }

    /**
     * Clear credentials from memory
     */
    disconnect() {
        this.iamClient = null;
        this.credentials = null;
    }

    /**
     * Check if handler is initialized
     */
    isInitialized() {
        return this.iamClient !== null;
    }
}

// Export singleton instance
export const awsHandler = new AWSHandler();

/**
 * Shadow Admin Detection - Privilege Escalation Methods
 * Based on research from Rhino Security Labs Pacu framework
 */

const ESCALATION_METHODS = {
    // IAM Policy Manipulation
    'CreateNewPolicyVersion': {
        permissions: ['iam:createpolicyversion'],
        optional: ['iam:listattachedgrouppolicies', 'iam:listattachedrolepolicies', 'iam:listattacheduserpolicies'],
        riskLevel: 10,
        category: 'IAM Policy Manipulation',
        description: 'Can create new policy version with admin permissions and set as default'
    },
    'SetExistingDefaultPolicyVersion': {
        permissions: ['iam:setdefaultpolicyversion'],
        optional: ['iam:listpolicyversions', 'iam:listattacheduserpolicies'],
        riskLevel: 10,
        category: 'IAM Policy Manipulation',
        description: 'Can revert to previous policy version with higher privileges'
    },
    'AttachUserPolicy': {
        permissions: ['iam:attachuserpolicy'],
        optional: ['iam:listusers'],
        riskLevel: 10,
        category: 'IAM Policy Manipulation',
        description: 'Can attach AdministratorAccess policy to own user'
    },
    'AttachGroupPolicy': {
        permissions: ['iam:attachgrouppolicy'],
        optional: ['iam:listgroupsforuser'],
        riskLevel: 10,
        category: 'IAM Policy Manipulation',
        description: 'Can attach admin policy to a group user belongs to'
    },
    'AttachRolePolicy': {
        permissions: ['iam:attachrolepolicy', 'sts:assumerole'],
        optional: ['iam:listroles'],
        riskLevel: 10,
        category: 'IAM Policy Manipulation',
        description: 'Can attach admin policy to an assumable role'
    },
    'PutUserPolicy': {
        permissions: ['iam:putuserpolicy'],
        optional: ['iam:listuserpolicies'],
        riskLevel: 10,
        category: 'IAM Policy Manipulation',
        description: 'Can create inline policy with admin permissions on own user'
    },
    'PutGroupPolicy': {
        permissions: ['iam:putgrouppolicy'],
        optional: ['iam:listgrouppolicies'],
        riskLevel: 10,
        category: 'IAM Policy Manipulation',
        description: 'Can create inline admin policy on a group user belongs to'
    },
    'PutRolePolicy': {
        permissions: ['iam:putrolepolicy', 'sts:assumerole'],
        optional: ['iam:listrolepolicies'],
        riskLevel: 10,
        category: 'IAM Policy Manipulation',
        description: 'Can create inline admin policy on an assumable role'
    },
    
    // IAM Principal Manipulation
    'AddUserToGroup': {
        permissions: ['iam:addusertogroup'],
        optional: ['iam:listgroups'],
        riskLevel: 8,
        category: 'Principal Manipulation',
        description: 'Can add self to privileged group'
    },
    'CreateAccessKey': {
        permissions: ['iam:createaccesskey'],
        optional: ['iam:listusers'],
        riskLevel: 9,
        category: 'Principal Manipulation',
        description: 'Can create access keys for privileged users'
    },
    'CreateLoginProfile': {
        permissions: ['iam:createloginprofile'],
        optional: ['iam:listusers'],
        riskLevel: 8,
        category: 'Principal Manipulation',
        description: 'Can create console password for privileged users'
    },
    'UpdateLoginProfile': {
        permissions: ['iam:updateloginprofile'],
        optional: ['iam:listusers'],
        riskLevel: 8,
        category: 'Principal Manipulation',
        description: 'Can reset console password for privileged users'
    },
    'UpdateRolePolicyToAssumeIt': {
        permissions: ['iam:updateassumerolepolicy', 'sts:assumerole'],
        optional: ['iam:listroles'],
        riskLevel: 9,
        category: 'Principal Manipulation',
        description: 'Can modify role trust policy to assume privileged role'
    },
    
    // PassRole Escalation
    'PassRoleToEC2': {
        permissions: ['iam:passrole', 'ec2:runinstances'],
        optional: ['iam:listinstanceprofiles'],
        riskLevel: 9,
        category: 'PassRole Escalation',
        description: 'Can pass privileged role to EC2 and extract credentials'
    },
    'PassRoleToLambda': {
        permissions: ['iam:passrole', 'lambda:createfunction', 'lambda:invokefunction'],
        optional: ['iam:listroles'],
        riskLevel: 10,
        category: 'PassRole Escalation',
        description: 'Can create Lambda with privileged role and invoke it'
    },
    'PassRoleToLambdaDynamoDB': {
        permissions: ['iam:passrole', 'lambda:createfunction', 'lambda:createeventsourcemapping', 'dynamodb:putitem'],
        optional: ['dynamodb:createtable'],
        riskLevel: 9,
        category: 'PassRole Escalation',
        description: 'Can create Lambda with privileged role triggered by DynamoDB'
    },
    'UpdateLambdaFunction': {
        permissions: ['lambda:updatefunctioncode'],
        optional: ['lambda:listfunctions', 'lambda:invokefunction'],
        riskLevel: 9,
        category: 'PassRole Escalation',
        description: 'Can modify existing Lambda function with privileged role'
    },
    'PassRoleToGlue': {
        permissions: ['iam:passrole', 'glue:createdevendpoint'],
        optional: ['glue:getdevendpoint', 'iam:listroles'],
        riskLevel: 9,
        category: 'PassRole Escalation',
        description: 'Can create Glue Dev Endpoint with privileged role'
    },
    'UpdateGlueDevEndpoint': {
        permissions: ['glue:updatedevendpoint'],
        optional: ['glue:describedevendpoints'],
        riskLevel: 8,
        category: 'PassRole Escalation',
        description: 'Can add SSH key to existing Glue Dev Endpoint'
    },
    'PassRoleToCloudFormation': {
        permissions: ['iam:passrole', 'cloudformation:createstack'],
        optional: ['cloudformation:describestacks', 'iam:listroles'],
        riskLevel: 9,
        category: 'PassRole Escalation',
        description: 'Can create CloudFormation stack with privileged role'
    },
    'PassRoleToDataPipeline': {
        permissions: ['iam:passrole', 'datapipeline:createpipeline', 'datapipeline:putpipelinedefinition'],
        optional: ['iam:listroles'],
        riskLevel: 8,
        category: 'PassRole Escalation',
        description: 'Can create Data Pipeline with privileged role'
    },
    'PassRoleToCodeStar': {
        permissions: ['iam:passrole', 'codestar:createproject'],
        optional: [],
        riskLevel: 7,
        category: 'PassRole Escalation',
        description: 'Can create CodeStar project with privileged role'
    },
    
    // CodeStar Special
    'CodeStarCreateProjectFromTemplate': {
        permissions: ['codestar:createprojectfromtemplate'],
        optional: [],
        riskLevel: 7,
        category: 'Special Methods',
        description: 'Undocumented CodeStar API providing elevated permissions'
    },
    'CodeStarAssociateTeamMember': {
        permissions: ['codestar:createproject', 'codestar:associateteammember'],
        optional: [],
        riskLevel: 7,
        category: 'Special Methods',
        description: 'Can gain enumeration permissions through CodeStar Owner role'
    }
};

/**
 * Analyze policy document for shadow admin and privilege escalation issues
 */
export const analyzePolicyForShadowAdmin = (policyDocument) => {
    const issues = [];
    const detectedMethods = [];
    let maxRiskLevel = 0;
    
    if (!policyDocument || !policyDocument.Statement) {
        return { issues, riskLevel: 0, detectedMethods, summary: 'No policy statements found' };
    }
    
    const statements = Array.isArray(policyDocument.Statement) 
        ? policyDocument.Statement 
        : [policyDocument.Statement];
    
    // Collect all permissions
    const allowedPermissions = new Set();
    const deniedPermissions = new Set();
    let hasWildcardAction = false;
    let hasWildcardResource = false;
    
    statements.forEach((statement, idx) => {
        const effect = statement.Effect || 'Allow';
        const actions = statement.Action ? (Array.isArray(statement.Action) ? statement.Action : [statement.Action]) : [];
        const resources = statement.Resource ? (Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource]) : [];
        
        // Check for wildcards
        if (actions.includes('*')) {
            hasWildcardAction = true;
            if (resources.includes('*') && effect === 'Allow') {
                issues.push({
                    type: 'FULL_ADMIN',
                    severity: 'critical',
                    statementIndex: idx,
                    title: 'Full Administrator Access',
                    description: 'This statement grants Action: "*" on Resource: "*" - full admin permissions',
                    remediation: 'Restrict to specific actions and resources required for the task'
                });
                maxRiskLevel = 10;
            }
        }
        
        if (resources.includes('*')) {
            hasWildcardResource = true;
        }
        
        // Collect permissions
        actions.forEach(action => {
            const normalizedAction = action.toLowerCase().replace(/\s/g, '');
            if (effect === 'Allow') {
                allowedPermissions.add(normalizedAction);
                
                // Handle wildcards in actions
                if (action.includes('*')) {
                    // iam:* grants all IAM permissions
                    if (normalizedAction === 'iam:*') {
                        Object.keys(ESCALATION_METHODS).forEach(method => {
                            ESCALATION_METHODS[method].permissions.forEach(perm => {
                                if (perm.startsWith('iam:')) {
                                    allowedPermissions.add(perm);
                                }
                            });
                        });
                    }
                    // Handle service-level wildcards
                    const servicePart = normalizedAction.split(':')[0];
                    if (servicePart && normalizedAction.endsWith(':*')) {
                        Object.keys(ESCALATION_METHODS).forEach(method => {
                            ESCALATION_METHODS[method].permissions.forEach(perm => {
                                if (perm.startsWith(servicePart + ':')) {
                                    allowedPermissions.add(perm);
                                }
                            });
                        });
                    }
                }
            } else if (effect === 'Deny') {
                deniedPermissions.add(normalizedAction);
            }
        });
    });
    
    // Check for wildcard issues
    if (hasWildcardAction && !issues.some(i => i.type === 'FULL_ADMIN')) {
        issues.push({
            type: 'WILDCARD_ACTION',
            severity: 'high',
            statementIndex: -1,
            title: 'Wildcard Actions Detected',
            description: 'Policy contains wildcard (*) in Action field which may grant excessive permissions',
            remediation: 'Use specific action names instead of wildcards'
        });
        maxRiskLevel = Math.max(maxRiskLevel, 8);
    }
    
    if (hasWildcardResource && !issues.some(i => i.type === 'FULL_ADMIN')) {
        issues.push({
            type: 'WILDCARD_RESOURCE',
            severity: 'medium',
            statementIndex: -1,
            title: 'Wildcard Resources Detected',
            description: 'Policy contains wildcard (*) in Resource field which applies to all resources',
            remediation: 'Restrict to specific resource ARNs when possible'
        });
        maxRiskLevel = Math.max(maxRiskLevel, 6);
    }
    
    // Check for privilege escalation methods
    Object.entries(ESCALATION_METHODS).forEach(([methodName, methodInfo]) => {
        const requiredPerms = methodInfo.permissions.map(p => p.toLowerCase());
        const hasAllRequired = requiredPerms.every(perm => {
            // Check if permission is explicitly allowed
            if (allowedPermissions.has(perm)) return true;
            
            // Check if wildcard grants it
            if (allowedPermissions.has('*')) return true;
            
            // Check if service wildcard grants it
            const service = perm.split(':')[0];
            if (allowedPermissions.has(service + ':*')) return true;
            
            return false;
        });
        
        const hasAnyDenied = requiredPerms.some(perm => deniedPermissions.has(perm));
        
        if (hasAllRequired && !hasAnyDenied) {
            detectedMethods.push({
                method: methodName,
                ...methodInfo
            });
            
            issues.push({
                type: 'PRIVILEGE_ESCALATION',
                severity: methodInfo.riskLevel >= 9 ? 'critical' : 'high',
                statementIndex: -1,
                title: `Privilege Escalation: ${methodName}`,
                description: methodInfo.description,
                category: methodInfo.category,
                remediation: `Remove or restrict: ${requiredPerms.join(', ')}`
            });
            
            maxRiskLevel = Math.max(maxRiskLevel, methodInfo.riskLevel);
        }
    });
    
    // Generate summary
    let summary = '';
    if (maxRiskLevel === 10) {
        summary = 'CRITICAL: Full admin or direct privilege escalation possible';
    } else if (maxRiskLevel >= 8) {
        summary = `HIGH RISK: ${detectedMethods.length} privilege escalation method(s) detected`;
    } else if (maxRiskLevel >= 5) {
        summary = 'MEDIUM RISK: Some dangerous permissions present';
    } else if (issues.length > 0) {
        summary = 'LOW RISK: Minor security concerns detected';
    } else {
        summary = 'No significant security issues detected';
    }
    
    return {
        issues,
        riskLevel: maxRiskLevel,
        detectedMethods,
        summary,
        stats: {
            totalIssues: issues.length,
            criticalIssues: issues.filter(i => i.severity === 'critical').length,
            highIssues: issues.filter(i => i.severity === 'high').length,
            mediumIssues: issues.filter(i => i.severity === 'medium').length,
            escalationMethods: detectedMethods.length
        }
    };
};

