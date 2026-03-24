/**
 * AWS Handler Module
 * Manages AWS SDK interactions for IAM policy operations
 * 
 * Note: AWS SDK classes (IAMClient, STSClient, etc.) are loaded globally
 * from the importmap in index.html before this script runs.
 */

class AWSHandler {
    constructor() {
        this.iamClient = null;
        this.stsClient = null;
        this.credentials = null;
        this.currentIdentity = null;
        this.hasFullListPermissions = null; // null = unknown, true/false after check
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

        const clientConfig = {
            region: region || 'us-east-1',
            credentials: this.credentials
        };

        this.iamClient = new IAMClient(clientConfig);
        this.stsClient = new STSClient(clientConfig);
        this.hasFullListPermissions = null;

        return true;
    }

    /**
     * Test connection using STS GetCallerIdentity (almost always allowed)
     * Returns identity info which is useful for fallback operations
     */
    async testConnection() {
        try {
            const command = new GetCallerIdentityCommand({});
            const response = await this.stsClient.send(command);
            
            this.currentIdentity = {
                arn: response.Arn,
                accountId: response.Account,
                userId: response.UserId
            };

            // Extract username from ARN if it's an IAM user
            // ARN format: arn:aws:iam::123456789012:user/username
            const arnParts = response.Arn.split(':');
            if (arnParts.length >= 6 && arnParts[5].startsWith('user/')) {
                this.currentIdentity.userName = arnParts[5].substring(5);
                this.currentIdentity.isIamUser = true;
            } else if (arnParts[5].startsWith('assumed-role/')) {
                // For assumed roles: assumed-role/role-name/session-name
                const roleParts = arnParts[5].split('/');
                this.currentIdentity.roleName = roleParts[1];
                this.currentIdentity.sessionName = roleParts[2];
                this.currentIdentity.isAssumedRole = true;
            }

            return { 
                success: true,
                identity: this.currentIdentity
            };
        } catch (error) {
            return { 
                success: false, 
                error: error.message || 'Failed to connect to AWS'
            };
        }
    }

    /**
     * Get current identity info
     */
    getCurrentIdentity() {
        return this.currentIdentity;
    }

    /**
     * List all managed policies (AWS and Customer managed)
     * Handles pagination automatically
     * Falls back to user-attached policies if ListPolicies is not permitted
     */
    async listAllPolicies() {
        // First try the full list approach
        const fullListResult = await this.tryListAllPolicies();
        
        if (fullListResult.success) {
            this.hasFullListPermissions = true;
            return fullListResult;
        }

        // If ListPolicies failed due to permissions, try fallback
        if (fullListResult.error && fullListResult.error.includes('not authorized')) {
            console.log('ListPolicies not authorized, falling back to user-attached policies');
            this.hasFullListPermissions = false;
            return await this.listUserAttachedPolicies();
        }

        // Other error
        return fullListResult;
    }

    /**
     * Check if we have full list permissions
     */
    hasFullPermissions() {
        return this.hasFullListPermissions === true;
    }

    /**
     * Try to list all policies (requires iam:ListPolicies)
     */
    async tryListAllPolicies() {
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
                data: allPolicies,
                mode: 'full'
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
     * Fallback: Discover policies for the current user through multiple API paths.
     * Tries user-level, then group-level discovery. Each API call is independent
     * so partial failures don't block other discovery paths.
     *
     * Returns diagnostics about which APIs succeeded/failed so the UI can guide
     * the user toward the minimum permissions needed for self-scan.
     */
    async listUserAttachedPolicies() {
        if (!this.currentIdentity || !this.currentIdentity.userName) {
            return {
                success: false,
                error: 'Cannot list user policies: not logged in as an IAM user',
                diagnostics: [{
                    api: 'sts:GetCallerIdentity',
                    ok: true,
                    note: 'Identity resolved, but it is not an IAM user (may be a role or root). Self-scan requires an IAM user identity.'
                }]
            };
        }

        const userName = this.currentIdentity.userName;
        const result = {
            awsManaged: [],
            customerManaged: [],
            inlinePolicies: [],
            attachedPolicies: [],
            groupPolicies: []
        };
        const diagnostics = [];

        // ── 1. Attached managed policies on the user ────────────────────
        try {
            let marker = null;
            do {
                const command = new ListAttachedUserPoliciesCommand({
                    UserName: userName,
                    MaxItems: 100,
                    ...(marker && { Marker: marker })
                });
                
                const response = await this.iamClient.send(command);
                
                if (response.AttachedPolicies) {
                    for (const policy of response.AttachedPolicies) {
                        const detailResult = await this.getPolicyDetails(policy.PolicyArn);
                        if (detailResult.success) {
                            const fullPolicy = {
                                ...detailResult.data,
                                isAttachedToUser: true
                            };
                            if (policy.PolicyArn.includes(':aws:policy/')) {
                                result.awsManaged.push(fullPolicy);
                            } else {
                                result.customerManaged.push(fullPolicy);
                            }
                            result.attachedPolicies.push(fullPolicy);
                        } else {
                            const basicPolicy = {
                                PolicyName: policy.PolicyName,
                                Arn: policy.PolicyArn,
                                isAttachedToUser: true
                            };
                            if (policy.PolicyArn.includes(':aws:policy/')) {
                                result.awsManaged.push(basicPolicy);
                            } else {
                                result.customerManaged.push(basicPolicy);
                            }
                            result.attachedPolicies.push(basicPolicy);
                        }
                    }
                }
                
                marker = response.IsTruncated ? response.Marker : null;
            } while (marker);
            diagnostics.push({ api: 'iam:ListAttachedUserPolicies', ok: true, note: `${result.attachedPolicies.length} attached managed policy(ies)` });
        } catch (error) {
            console.warn('Could not list attached user policies:', error.message);
            diagnostics.push({ api: 'iam:ListAttachedUserPolicies', ok: false, error: error.message });
        }

        // ── 2. Inline policies on the user ──────────────────────────────
        try {
            const command = new ListUserPoliciesCommand({
                UserName: userName,
                MaxItems: 100
            });
            
            const response = await this.iamClient.send(command);
            
            if (response.PolicyNames) {
                for (const policyName of response.PolicyNames) {
                    try {
                        const getPolicyCmd = new GetUserPolicyCommand({
                            UserName: userName,
                            PolicyName: policyName
                        });
                        const policyResponse = await this.iamClient.send(getPolicyCmd);
                        
                        let policyDocument = policyResponse.PolicyDocument;
                        if (typeof policyDocument === 'string') {
                            policyDocument = JSON.parse(decodeURIComponent(policyDocument));
                        }
                        
                        result.inlinePolicies.push({
                            PolicyName: policyName,
                            PolicyDocument: policyDocument,
                            isInline: true,
                            userName: userName
                        });
                    } catch (err) {
                        result.inlinePolicies.push({
                            PolicyName: policyName,
                            isInline: true,
                            userName: userName
                        });
                    }
                }
            }
            const inlineCount = response.PolicyNames ? response.PolicyNames.length : 0;
            diagnostics.push({ api: 'iam:ListUserPolicies', ok: true, note: `${inlineCount} inline policy(ies)` });
        } catch (error) {
            console.warn('Could not list inline user policies:', error.message);
            diagnostics.push({ api: 'iam:ListUserPolicies', ok: false, error: error.message });
        }

        // ── 3. Group memberships → group-level policies ─────────────────
        let userGroups = [];
        try {
            let marker = null;
            do {
                const command = new ListGroupsForUserCommand({
                    UserName: userName,
                    MaxItems: 100,
                    ...(marker && { Marker: marker })
                });
                const response = await this.iamClient.send(command);
                if (response.Groups) {
                    userGroups = userGroups.concat(response.Groups);
                }
                marker = response.IsTruncated ? response.Marker : null;
            } while (marker);
            diagnostics.push({ api: 'iam:ListGroupsForUser', ok: true, note: `${userGroups.length} group(s)` });
        } catch (error) {
            console.warn('Could not list groups for user:', error.message);
            diagnostics.push({ api: 'iam:ListGroupsForUser', ok: false, error: error.message });
        }

        for (const group of userGroups) {
            // 3a. Attached managed policies on this group
            try {
                let marker = null;
                do {
                    const command = new ListAttachedGroupPoliciesCommand({
                        GroupName: group.GroupName,
                        MaxItems: 100,
                        ...(marker && { Marker: marker })
                    });
                    const response = await this.iamClient.send(command);
                    if (response.AttachedPolicies) {
                        for (const policy of response.AttachedPolicies) {
                            const detailResult = await this.getPolicyDetails(policy.PolicyArn);
                            const fullPolicy = detailResult.success
                                ? { ...detailResult.data, isGroupPolicy: true, groupName: group.GroupName }
                                : { PolicyName: policy.PolicyName, Arn: policy.PolicyArn, isGroupPolicy: true, groupName: group.GroupName };

                            if (policy.PolicyArn.includes(':aws:policy/')) {
                                result.awsManaged.push(fullPolicy);
                            } else {
                                result.customerManaged.push(fullPolicy);
                            }
                            result.groupPolicies.push(fullPolicy);
                        }
                    }
                    marker = response.IsTruncated ? response.Marker : null;
                } while (marker);
            } catch (error) {
                console.warn(`Could not list attached group policies for ${group.GroupName}:`, error.message);
            }

            // 3b. Inline policies on this group
            try {
                const listCmd = new ListGroupPoliciesCommand({
                    GroupName: group.GroupName,
                    MaxItems: 100
                });
                const listResponse = await this.iamClient.send(listCmd);
                if (listResponse.PolicyNames) {
                    for (const policyName of listResponse.PolicyNames) {
                        try {
                            const getCmd = new GetGroupPolicyCommand({
                                GroupName: group.GroupName,
                                PolicyName: policyName
                            });
                            const policyResponse = await this.iamClient.send(getCmd);
                            let policyDocument = policyResponse.PolicyDocument;
                            if (typeof policyDocument === 'string') {
                                policyDocument = JSON.parse(decodeURIComponent(policyDocument));
                            }
                            result.inlinePolicies.push({
                                PolicyName: policyName,
                                PolicyDocument: policyDocument,
                                isInline: true,
                                isGroupPolicy: true,
                                groupName: group.GroupName
                            });
                        } catch (err) {
                            result.inlinePolicies.push({
                                PolicyName: policyName,
                                isInline: true,
                                isGroupPolicy: true,
                                groupName: group.GroupName
                            });
                        }
                    }
                }
            } catch (error) {
                console.warn(`Could not list inline group policies for ${group.GroupName}:`, error.message);
            }
        }

        const totalPolicies = result.awsManaged.length + result.customerManaged.length + result.inlinePolicies.length;
        
        if (totalPolicies === 0) {
            return {
                success: false,
                error: 'Could not discover any policies. See details below for which API calls were attempted.',
                diagnostics,
                userName
            };
        }

        return {
            success: true,
            data: result,
            mode: 'limited',
            diagnostics,
            message: `Found ${totalPolicies} policies for user ${userName}`
        };
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
        this.stsClient = null;
        this.credentials = null;
        this.currentIdentity = null;
        this.hasFullListPermissions = null;
    }

    /**
     * Check if handler is initialized
     */
    isInitialized() {
        return this.iamClient !== null;
    }

    /**
     * Analyze an inline policy document (for user inline policies)
     */
    getInlinePolicyInfo(inlinePolicy) {
        return {
            success: true,
            data: {
                policy: {
                    PolicyName: inlinePolicy.PolicyName,
                    Arn: `inline:${inlinePolicy.userName}/${inlinePolicy.PolicyName}`,
                    isInline: true
                },
                currentVersion: {
                    Document: inlinePolicy.PolicyDocument,
                    VersionId: 'inline',
                    IsDefaultVersion: true
                },
                allVersions: [{
                    VersionId: 'inline',
                    IsDefaultVersion: true,
                    CreateDate: new Date().toISOString()
                }]
            }
        };
    }
}

// Global singleton instance
const awsHandler = new AWSHandler();

/**
 * Shadow Admin Detection - Privilege Escalation Methods
 * Based on pathfinding.cloud catalog (66 paths) and Rhino Security Labs Pacu research.
 *
 * Categories (from pathfinding.cloud schema):
 *   self-escalation   – principal modifies its own permissions
 *   principal-access  – gains access to another principal
 *   new-passrole      – creates a new resource with a privileged role
 *   existing-passrole – leverages an already-attached role on an existing resource
 *   credential-access – obtains credentials for another principal
 */

const ESCALATION_METHODS = {

    // ── IAM Self-Escalation ──────────────────────────────────────────────

    'iam-001: CreatePolicyVersion': {
        permissions: ['iam:createpolicyversion'],
        optional: ['iam:listattachedgrouppolicies', 'iam:listattachedrolepolicies', 'iam:listattacheduserpolicies'],
        riskLevel: 10,
        category: 'Self-Escalation',
        service: 'iam',
        description: 'Can create new policy version with admin permissions and set as default'
    },
    'iam-005: PutRolePolicy': {
        permissions: ['iam:putrolepolicy'],
        optional: ['iam:listrolepolicies'],
        riskLevel: 10,
        category: 'Self-Escalation',
        service: 'iam',
        description: 'Can attach inline admin policy to own role'
    },
    'iam-007: PutUserPolicy': {
        permissions: ['iam:putuserpolicy'],
        optional: ['iam:listuserpolicies'],
        riskLevel: 10,
        category: 'Self-Escalation',
        service: 'iam',
        description: 'Can create inline policy with admin permissions on own user'
    },
    'iam-008: AttachUserPolicy': {
        permissions: ['iam:attachuserpolicy'],
        optional: ['iam:listusers'],
        riskLevel: 10,
        category: 'Self-Escalation',
        service: 'iam',
        description: 'Can attach AdministratorAccess policy to own user'
    },
    'iam-009: AttachRolePolicy': {
        permissions: ['iam:attachrolepolicy'],
        optional: ['iam:listroles'],
        riskLevel: 10,
        category: 'Self-Escalation',
        service: 'iam',
        description: 'Can attach admin policy to own role'
    },
    'iam-010: AttachGroupPolicy': {
        permissions: ['iam:attachgrouppolicy'],
        optional: ['iam:listgroupsforuser'],
        riskLevel: 10,
        category: 'Self-Escalation',
        service: 'iam',
        description: 'Can attach admin policy to a group user belongs to'
    },
    'iam-011: PutGroupPolicy': {
        permissions: ['iam:putgrouppolicy'],
        optional: ['iam:listgrouppolicies'],
        riskLevel: 10,
        category: 'Self-Escalation',
        service: 'iam',
        description: 'Can create inline admin policy on a group user belongs to'
    },
    'iam-013: AddUserToGroup': {
        permissions: ['iam:addusertogroup'],
        optional: ['iam:listgroups'],
        riskLevel: 8,
        category: 'Self-Escalation',
        service: 'iam',
        description: 'Can add self to privileged group'
    },

    // ── IAM Principal Access ─────────────────────────────────────────────

    'iam-002: CreateAccessKey': {
        permissions: ['iam:createaccesskey'],
        optional: ['iam:listusers'],
        riskLevel: 9,
        category: 'Principal Access',
        service: 'iam',
        description: 'Can create access keys for privileged users'
    },
    'iam-003: CreateAccessKey + DeleteAccessKey': {
        permissions: ['iam:createaccesskey', 'iam:deleteaccesskey'],
        optional: ['iam:listusers', 'iam:listaccesskeys'],
        riskLevel: 9,
        category: 'Principal Access',
        service: 'iam',
        description: 'Can delete then create access keys even when user has 2 keys'
    },
    'iam-004: CreateLoginProfile': {
        permissions: ['iam:createloginprofile'],
        optional: ['iam:listusers'],
        riskLevel: 8,
        category: 'Principal Access',
        service: 'iam',
        description: 'Can create console password for privileged users'
    },
    'iam-006: UpdateLoginProfile': {
        permissions: ['iam:updateloginprofile'],
        optional: ['iam:listusers'],
        riskLevel: 8,
        category: 'Principal Access',
        service: 'iam',
        description: 'Can reset console password for privileged users'
    },
    'iam-012: UpdateAssumeRolePolicy': {
        permissions: ['iam:updateassumerolepolicy'],
        optional: ['iam:listroles'],
        riskLevel: 9,
        category: 'Principal Access',
        service: 'iam',
        description: 'Can modify role trust policy to assume privileged role'
    },
    'iam-014: AttachRolePolicy + AssumeRole': {
        permissions: ['iam:attachrolepolicy', 'sts:assumerole'],
        optional: ['iam:listroles', 'iam:getrole'],
        riskLevel: 10,
        category: 'Principal Access',
        service: 'iam',
        description: 'Can attach admin policy to another role then assume it'
    },
    'iam-015: AttachUserPolicy + CreateAccessKey': {
        permissions: ['iam:attachuserpolicy', 'iam:createaccesskey'],
        optional: ['iam:listusers', 'iam:listaccesskeys'],
        riskLevel: 10,
        category: 'Principal Access',
        service: 'iam',
        description: 'Can attach admin policy to another user then create access keys'
    },
    'iam-016: CreatePolicyVersion + AssumeRole': {
        permissions: ['iam:createpolicyversion', 'sts:assumerole'],
        optional: ['iam:getpolicy', 'iam:getpolicyversion'],
        riskLevel: 10,
        category: 'Principal Access',
        service: 'iam',
        description: 'Can modify a policy attached to another role then assume it'
    },
    'iam-017: PutRolePolicy + AssumeRole': {
        permissions: ['iam:putrolepolicy', 'sts:assumerole'],
        optional: ['iam:listroles', 'iam:listrolepolicies'],
        riskLevel: 10,
        category: 'Principal Access',
        service: 'iam',
        description: 'Can add inline admin policy to another role then assume it'
    },
    'iam-018: PutUserPolicy + CreateAccessKey': {
        permissions: ['iam:putuserpolicy', 'iam:createaccesskey'],
        optional: ['iam:listusers', 'iam:listaccesskeys'],
        riskLevel: 10,
        category: 'Principal Access',
        service: 'iam',
        description: 'Can add inline admin policy to another user then create access keys'
    },
    'iam-019: AttachRolePolicy + UpdateAssumeRolePolicy': {
        permissions: ['iam:attachrolepolicy', 'iam:updateassumerolepolicy'],
        optional: ['iam:listroles', 'iam:getrole'],
        riskLevel: 10,
        category: 'Principal Access',
        service: 'iam',
        description: 'Can attach admin policy to a role and modify its trust policy to assume it'
    },
    'iam-020: CreatePolicyVersion + UpdateAssumeRolePolicy': {
        permissions: ['iam:createpolicyversion', 'iam:updateassumerolepolicy'],
        optional: ['iam:getpolicy', 'iam:listroles'],
        riskLevel: 10,
        category: 'Principal Access',
        service: 'iam',
        description: 'Can modify policy on a role and update its trust policy to assume it'
    },
    'iam-021: PutRolePolicy + UpdateAssumeRolePolicy': {
        permissions: ['iam:putrolepolicy', 'iam:updateassumerolepolicy'],
        optional: ['iam:listroles', 'iam:listrolepolicies'],
        riskLevel: 10,
        category: 'Principal Access',
        service: 'iam',
        description: 'Can add inline policy to a role and modify its trust policy to assume it'
    },

    // ── STS ──────────────────────────────────────────────────────────────

    'sts-001: AssumeRole': {
        permissions: ['sts:assumerole'],
        optional: ['iam:listroles', 'iam:getrole'],
        riskLevel: 7,
        category: 'Principal Access',
        service: 'sts',
        description: 'Can assume an existing role with elevated permissions'
    },

    // ── SetDefaultPolicyVersion (Pacu legacy, not in pathfinding.cloud) ─

    'SetExistingDefaultPolicyVersion': {
        permissions: ['iam:setdefaultpolicyversion'],
        optional: ['iam:listpolicyversions', 'iam:listattacheduserpolicies'],
        riskLevel: 10,
        category: 'Self-Escalation',
        service: 'iam',
        description: 'Can revert to previous policy version with higher privileges'
    },

    // ── EC2 ──────────────────────────────────────────────────────────────

    'ec2-001: PassRole + RunInstances': {
        permissions: ['iam:passrole', 'ec2:runinstances'],
        optional: ['iam:listinstanceprofiles'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'ec2',
        description: 'Can pass privileged role to EC2 and extract credentials'
    },
    'ec2-002: ModifyInstanceAttribute + Stop/Start': {
        permissions: ['ec2:modifyinstanceattribute', 'ec2:stopinstances', 'ec2:startinstances'],
        optional: [],
        riskLevel: 8,
        category: 'Existing PassRole',
        service: 'ec2',
        description: 'Can modify user data of existing EC2 instance with privileged role'
    },
    'ec2-003: PassRole + RequestSpotInstances': {
        permissions: ['iam:passrole', 'ec2:requestspotinstances'],
        optional: ['iam:listroles', 'iam:listinstanceprofiles'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'ec2',
        description: 'Can launch spot instance with privileged role'
    },
    'ec2-004: CreateLaunchTemplateVersion + ModifyLaunchTemplate': {
        permissions: ['ec2:createlaunchtemplateversion', 'ec2:modifylaunchtemplate'],
        optional: ['ec2:describelaunchtemplates', 'ec2:describelaunchtemplateversions'],
        riskLevel: 8,
        category: 'Existing PassRole',
        service: 'ec2',
        description: 'Can modify launch template to inject user data for instances with privileged role'
    },

    // ── EC2 Instance Connect ─────────────────────────────────────────────

    'ec2ic-003: SendSSHPublicKey': {
        permissions: ['ec2-instance-connect:sendsshpublickey'],
        optional: ['ec2:describeinstances'],
        riskLevel: 8,
        category: 'Existing PassRole',
        service: 'ec2-instance-connect',
        description: 'Can push SSH key to EC2 instance and access its attached role'
    },

    // ── Lambda ───────────────────────────────────────────────────────────

    'lambda-001: PassRole + CreateFunction + InvokeFunction': {
        permissions: ['iam:passrole', 'lambda:createfunction', 'lambda:invokefunction'],
        optional: ['iam:listroles'],
        riskLevel: 10,
        category: 'New PassRole',
        service: 'lambda',
        description: 'Can create Lambda with privileged role and invoke it'
    },
    'lambda-002: PassRole + CreateFunction + CreateEventSourceMapping': {
        permissions: ['iam:passrole', 'lambda:createfunction', 'lambda:createeventsourcemapping'],
        optional: ['iam:listroles'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'lambda',
        description: 'Can create Lambda with privileged role triggered by event source'
    },
    'lambda-003: UpdateFunctionCode': {
        permissions: ['lambda:updatefunctioncode'],
        optional: ['lambda:listfunctions', 'lambda:getfunction'],
        riskLevel: 9,
        category: 'Existing PassRole',
        service: 'lambda',
        description: 'Can modify existing Lambda function with privileged role'
    },
    'lambda-004: UpdateFunctionCode + InvokeFunction': {
        permissions: ['lambda:updatefunctioncode', 'lambda:invokefunction'],
        optional: ['lambda:listfunctions', 'lambda:getfunction'],
        riskLevel: 9,
        category: 'Existing PassRole',
        service: 'lambda',
        description: 'Can modify and invoke existing Lambda with privileged role'
    },
    'lambda-005: UpdateFunctionCode + AddPermission': {
        permissions: ['lambda:updatefunctioncode', 'lambda:addpermission'],
        optional: ['lambda:listfunctions', 'lambda:getfunction'],
        riskLevel: 9,
        category: 'Existing PassRole',
        service: 'lambda',
        description: 'Can modify Lambda code and add invocation permission for external trigger'
    },
    'lambda-006: PassRole + CreateFunction + AddPermission': {
        permissions: ['iam:passrole', 'lambda:createfunction', 'lambda:addpermission'],
        optional: ['iam:listroles'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'lambda',
        description: 'Can create Lambda with privileged role and allow external invocation'
    },

    // ── CloudFormation ───────────────────────────────────────────────────

    'cfn-001: PassRole + CreateStack': {
        permissions: ['iam:passrole', 'cloudformation:createstack'],
        optional: ['cloudformation:describestacks', 'iam:listroles'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'cloudformation',
        description: 'Can create CloudFormation stack with privileged role'
    },
    'cfn-002: UpdateStack': {
        permissions: ['cloudformation:updatestack'],
        optional: ['cloudformation:describestacks', 'cloudformation:gettemplate'],
        riskLevel: 9,
        category: 'Existing PassRole',
        service: 'cloudformation',
        description: 'Can modify existing stack with privileged service role'
    },
    'cfn-003: PassRole + CreateStackSet + CreateStackInstances': {
        permissions: ['iam:passrole', 'cloudformation:createstackset', 'cloudformation:createstackinstances'],
        optional: ['cloudformation:describestackset'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'cloudformation',
        description: 'Can create StackSet with privileged role across accounts/regions'
    },
    'cfn-004: PassRole + UpdateStackSet': {
        permissions: ['iam:passrole', 'cloudformation:updatestackset'],
        optional: ['cloudformation:describestackset', 'cloudformation:gettemplate'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'cloudformation',
        description: 'Can update StackSet to deploy resources with privileged role'
    },
    'cfn-005: CreateChangeSet + ExecuteChangeSet': {
        permissions: ['cloudformation:createchangeset', 'cloudformation:executechangeset'],
        optional: ['cloudformation:describechangeset', 'cloudformation:describestacks'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'cloudformation',
        description: 'Can create and execute change set on a stack with privileged role'
    },

    // ── Glue ─────────────────────────────────────────────────────────────

    'glue-001: PassRole + CreateDevEndpoint': {
        permissions: ['iam:passrole', 'glue:createdevendpoint'],
        optional: ['glue:getdevendpoint', 'iam:listroles'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'glue',
        description: 'Can create Glue Dev Endpoint with privileged role'
    },
    'glue-002: UpdateDevEndpoint': {
        permissions: ['glue:updatedevendpoint'],
        optional: ['glue:getdevendpoints'],
        riskLevel: 8,
        category: 'Existing PassRole',
        service: 'glue',
        description: 'Can add SSH key to existing Glue Dev Endpoint'
    },
    'glue-003: PassRole + CreateJob + StartJobRun': {
        permissions: ['iam:passrole', 'glue:createjob', 'glue:startjobrun'],
        optional: ['iam:listroles'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'glue',
        description: 'Can create and run Glue job with privileged role'
    },
    'glue-004: PassRole + CreateJob + CreateTrigger': {
        permissions: ['iam:passrole', 'glue:createjob', 'glue:createtrigger'],
        optional: ['iam:listroles'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'glue',
        description: 'Can create Glue job and schedule trigger with privileged role'
    },
    'glue-005: PassRole + UpdateJob + StartJobRun': {
        permissions: ['iam:passrole', 'glue:updatejob', 'glue:startjobrun'],
        optional: ['glue:getjob'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'glue',
        description: 'Can update existing Glue job to use privileged role and run it'
    },
    'glue-006: PassRole + UpdateJob + CreateTrigger': {
        permissions: ['iam:passrole', 'glue:updatejob', 'glue:createtrigger'],
        optional: ['glue:getjob'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'glue',
        description: 'Can update existing Glue job to use privileged role with a trigger'
    },

    // ── DataPipeline ─────────────────────────────────────────────────────

    'datapipeline-001: PassRole + CreatePipeline + PutPipelineDefinition': {
        permissions: ['iam:passrole', 'datapipeline:createpipeline', 'datapipeline:putpipelinedefinition'],
        optional: ['iam:listroles'],
        riskLevel: 8,
        category: 'New PassRole',
        service: 'datapipeline',
        description: 'Can create Data Pipeline with privileged role'
    },

    // ── CodeBuild ────────────────────────────────────────────────────────

    'codebuild-001: PassRole + CreateProject + StartBuild': {
        permissions: ['iam:passrole', 'codebuild:createproject', 'codebuild:startbuild'],
        optional: ['iam:listroles', 'codebuild:batchgetbuilds'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'codebuild',
        description: 'Can create CodeBuild project with privileged role and start build'
    },
    'codebuild-002: StartBuild': {
        permissions: ['codebuild:startbuild'],
        optional: ['codebuild:listprojects', 'codebuild:batchgetprojects'],
        riskLevel: 8,
        category: 'Existing PassRole',
        service: 'codebuild',
        description: 'Can start build on existing project with privileged role'
    },
    'codebuild-003: StartBuildBatch': {
        permissions: ['codebuild:startbuildbatch'],
        optional: ['codebuild:listprojects', 'codebuild:batchgetprojects'],
        riskLevel: 8,
        category: 'Existing PassRole',
        service: 'codebuild',
        description: 'Can start batch build on existing project with privileged role'
    },
    'codebuild-004: PassRole + CreateProject + StartBuildBatch': {
        permissions: ['iam:passrole', 'codebuild:createproject', 'codebuild:startbuildbatch'],
        optional: ['iam:listroles', 'codebuild:batchgetbuildbatches'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'codebuild',
        description: 'Can create CodeBuild project with privileged role and batch build'
    },

    // ── ECS ──────────────────────────────────────────────────────────────

    'ecs-001: PassRole + CreateCluster + RegisterTaskDefinition + CreateService': {
        permissions: ['iam:passrole', 'ecs:createcluster', 'ecs:registertaskdefinition', 'ecs:createservice'],
        optional: ['ec2:describevpcs', 'ec2:describesubnets'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'ecs',
        description: 'Can create ECS cluster and service with privileged task role'
    },
    'ecs-002: PassRole + CreateCluster + RegisterTaskDefinition + RunTask': {
        permissions: ['iam:passrole', 'ecs:createcluster', 'ecs:registertaskdefinition', 'ecs:runtask'],
        optional: ['ec2:describevpcs', 'ec2:describesubnets'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'ecs',
        description: 'Can create ECS cluster and run task with privileged role'
    },
    'ecs-003: PassRole + RegisterTaskDefinition + CreateService': {
        permissions: ['iam:passrole', 'ecs:registertaskdefinition', 'ecs:createservice'],
        optional: ['ecs:listclusters', 'ec2:describevpcs'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'ecs',
        description: 'Can register task definition and create service with privileged role'
    },
    'ecs-004: PassRole + RegisterTaskDefinition + RunTask': {
        permissions: ['iam:passrole', 'ecs:registertaskdefinition', 'ecs:runtask'],
        optional: ['ecs:listclusters', 'ec2:describevpcs'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'ecs',
        description: 'Can register task definition and run task with privileged role'
    },
    'ecs-005: PassRole + RegisterTaskDefinition + StartTask': {
        permissions: ['iam:passrole', 'ecs:registertaskdefinition', 'ecs:starttask'],
        optional: ['ecs:listclusters', 'ecs:listcontainerinstances'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'ecs',
        description: 'Can register task definition and start task on container instance'
    },
    'ecs-006: ExecuteCommand + DescribeTasks': {
        permissions: ['ecs:executecommand', 'ecs:describetasks'],
        optional: ['ecs:listclusters', 'ecs:listtasks'],
        riskLevel: 8,
        category: 'Existing PassRole',
        service: 'ecs',
        description: 'Can exec into running ECS container with its attached role'
    },

    // ── AppRunner ────────────────────────────────────────────────────────

    'apprunner-001: PassRole + CreateService': {
        permissions: ['iam:passrole', 'apprunner:createservice'],
        optional: ['iam:listroles', 'iam:getrole'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'apprunner',
        description: 'Can create App Runner service with privileged role'
    },
    'apprunner-002: UpdateService': {
        permissions: ['apprunner:updateservice'],
        optional: ['apprunner:listservices', 'apprunner:describeservice'],
        riskLevel: 8,
        category: 'Existing PassRole',
        service: 'apprunner',
        description: 'Can modify existing App Runner service to leverage its attached role'
    },

    // ── SageMaker ────────────────────────────────────────────────────────

    'sagemaker-001: PassRole + CreateNotebookInstance': {
        permissions: ['iam:passrole', 'sagemaker:createnotebookinstance'],
        optional: ['iam:listroles', 'sagemaker:describenotebookinstance'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'sagemaker',
        description: 'Can create SageMaker notebook with privileged role'
    },
    'sagemaker-002: PassRole + CreateTrainingJob': {
        permissions: ['iam:passrole', 'sagemaker:createtrainingjob'],
        optional: ['iam:listroles'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'sagemaker',
        description: 'Can create SageMaker training job with privileged role'
    },
    'sagemaker-003: PassRole + CreateProcessingJob': {
        permissions: ['iam:passrole', 'sagemaker:createprocessingjob'],
        optional: ['iam:listroles'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'sagemaker',
        description: 'Can create SageMaker processing job with privileged role'
    },
    'sagemaker-004: CreatePresignedNotebookInstanceUrl': {
        permissions: ['sagemaker:createpresignednotebookinstanceurl'],
        optional: ['sagemaker:listnotebookinstances'],
        riskLevel: 8,
        category: 'Existing PassRole',
        service: 'sagemaker',
        description: 'Can get presigned URL to existing notebook with privileged role'
    },
    'sagemaker-005: LifecycleConfig + Stop/Update/StartNotebook': {
        permissions: ['sagemaker:createnotebookinstancelifecycleconfig', 'sagemaker:stopnotebookinstance', 'sagemaker:updatenotebookinstance', 'sagemaker:startnotebookinstance'],
        optional: ['sagemaker:listnotebookinstances', 'sagemaker:describenotebookinstance'],
        riskLevel: 8,
        category: 'Existing PassRole',
        service: 'sagemaker',
        description: 'Can inject lifecycle config into existing notebook to execute code as its role'
    },

    // ── SSM (Systems Manager) ────────────────────────────────────────────

    'ssm-001: StartSession': {
        permissions: ['ssm:startsession'],
        optional: ['ec2:describeinstances', 'ssm:describeinstanceinformation'],
        riskLevel: 8,
        category: 'Existing PassRole',
        service: 'ssm',
        description: 'Can start SSM session on EC2 instance with its attached role'
    },
    'ssm-002: SendCommand': {
        permissions: ['ssm:sendcommand'],
        optional: ['ec2:describeinstances', 'ssm:describeinstanceinformation'],
        riskLevel: 8,
        category: 'Existing PassRole',
        service: 'ssm',
        description: 'Can send commands to EC2 instances via SSM to access their roles'
    },

    // ── Bedrock ──────────────────────────────────────────────────────────

    'bedrock-001: PassRole + CreateCodeInterpreter + StartSession': {
        permissions: ['iam:passrole', 'bedrock-agentcore:createcodeinterpreter', 'bedrock-agentcore:startcodeinterpretersession'],
        optional: ['bedrock-agentcore:invokecodeinterpreter', 'iam:listroles'],
        riskLevel: 9,
        category: 'New PassRole',
        service: 'bedrock',
        description: 'Can create Bedrock code interpreter with privileged role'
    },
    'bedrock-002: StartCodeInterpreterSession + InvokeCodeInterpreter': {
        permissions: ['bedrock-agentcore:startcodeinterpretersession', 'bedrock-agentcore:invokecodeinterpreter'],
        optional: ['bedrock-agentcore:listcodeinterpreters'],
        riskLevel: 8,
        category: 'Existing PassRole',
        service: 'bedrock',
        description: 'Can invoke existing Bedrock code interpreter to access its role'
    },

    // ── CodeStar (Pacu legacy, not in pathfinding.cloud) ─────────────────

    'PassRoleToCodeStar': {
        permissions: ['iam:passrole', 'codestar:createproject'],
        optional: [],
        riskLevel: 7,
        category: 'New PassRole',
        service: 'codestar',
        description: 'Can create CodeStar project with privileged role'
    },
    'CodeStarCreateProjectFromTemplate': {
        permissions: ['codestar:createprojectfromtemplate'],
        optional: [],
        riskLevel: 7,
        category: 'Existing PassRole',
        service: 'codestar',
        description: 'Undocumented CodeStar API providing elevated permissions'
    },
    'CodeStarAssociateTeamMember': {
        permissions: ['codestar:createproject', 'codestar:associateteammember'],
        optional: [],
        riskLevel: 7,
        category: 'Existing PassRole',
        service: 'codestar',
        description: 'Can gain enumeration permissions through CodeStar Owner role'
    }
};

/**
 * Analyze policy document for shadow admin and privilege escalation issues
 */
/**
 * Check if an action pattern (which may contain wildcards) matches a specific permission.
 */
function actionPatternMatches(pattern, permission) {
    if (pattern === '*') return true;
    if (pattern === permission) return true;
    if (!pattern.includes('*')) return false;
    const regexStr = pattern.replace(/\*/g, '.*');
    const regex = new RegExp(`^${regexStr}$`, 'i');
    return regex.test(permission);
}

/**
 * Analyze policy document for shadow admin and privilege escalation issues.
 * Checks against all entries in ESCALATION_METHODS (pathfinding.cloud catalog).
 */
const analyzePolicyForShadowAdmin = (policyDocument) => {
    const totalKnownPaths = Object.keys(ESCALATION_METHODS).length;
    const issues = [];
    const detectedMethods = [];
    let maxRiskLevel = 0;
    
    if (!policyDocument || !policyDocument.Statement) {
        return { issues, riskLevel: 0, detectedMethods, summary: 'No policy statements found', totalKnownPaths };
    }
    
    const statements = Array.isArray(policyDocument.Statement) 
        ? policyDocument.Statement 
        : [policyDocument.Statement];
    
    const allowedPatterns = [];
    const deniedPatterns = [];
    let hasWildcardAction = false;
    let hasWildcardResource = false;
    
    statements.forEach((statement, idx) => {
        const effect = statement.Effect || 'Allow';
        const actions = statement.Action ? (Array.isArray(statement.Action) ? statement.Action : [statement.Action]) : [];
        const resources = statement.Resource ? (Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource]) : [];
        
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
        
        actions.forEach(action => {
            const normalized = action.toLowerCase().replace(/\s/g, '');
            if (effect === 'Allow') {
                allowedPatterns.push(normalized);
            } else if (effect === 'Deny') {
                deniedPatterns.push(normalized);
            }
        });
    });
    
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
    
    // Check each escalation method
    Object.entries(ESCALATION_METHODS).forEach(([methodName, methodInfo]) => {
        const requiredPerms = methodInfo.permissions.map(p => p.toLowerCase());

        const hasAllRequired = requiredPerms.every(perm =>
            allowedPatterns.some(pat => actionPatternMatches(pat, perm))
        );

        const hasAnyDenied = requiredPerms.some(perm =>
            deniedPatterns.some(pat => actionPatternMatches(pat, perm))
        );
        
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
                service: methodInfo.service,
                remediation: `Remove or restrict: ${requiredPerms.join(', ')}`
            });
            
            maxRiskLevel = Math.max(maxRiskLevel, methodInfo.riskLevel);
        }
    });
    
    let summary = '';
    if (maxRiskLevel === 10) {
        summary = 'CRITICAL: Full admin or direct privilege escalation possible';
    } else if (maxRiskLevel >= 8) {
        summary = `HIGH RISK: ${detectedMethods.length} privilege escalation path(s) detected`;
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
        totalKnownPaths,
        stats: {
            totalIssues: issues.length,
            criticalIssues: issues.filter(i => i.severity === 'critical').length,
            highIssues: issues.filter(i => i.severity === 'high').length,
            mediumIssues: issues.filter(i => i.severity === 'medium').length,
            escalationMethods: detectedMethods.length,
            totalKnownPaths
        }
    };
};

