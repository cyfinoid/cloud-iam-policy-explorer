/**
 * Policy Expansion Module
 * Analyzes IAM policy wildcards and shows their real impact using official AWS data
 */

// Create global app object for AWS policies script compatibility
window.app = window.app || {};

class PolicyExpansion {
    constructor() {
        this.awsData = null;
        this.allActions = [];
        this.isInitialized = false;
    }

    /**
     * Initialize by loading AWS IAM data
     */
    async initialize() {
        if (this.isInitialized) return;

        try {
            await this.loadAWSData();
            this.buildActionsIndex();
            this.isInitialized = true;
            console.log(`✅ Policy Expansion initialized: ${Object.keys(this.awsData.serviceMap).length} services, ${this.allActions.length} actions`);
        } catch (error) {
            console.error('❌ Failed to initialize Policy Expansion:', error);
            throw error;
        }
    }

    /**
     * Load AWS IAM policies data from official source
     */
    async loadAWSData() {
        return new Promise((resolve, reject) => {
            // Check if already loaded
            if (window.app && window.app.PolicyEditorConfig) {
                this.awsData = window.app.PolicyEditorConfig;
                resolve();
                return;
            }

            // Load the AWS policies script
            const script = document.createElement('script');
            script.src = 'https://awspolicygen.s3.amazonaws.com/js/policies.js';
            script.onload = () => {
                if (window.app && window.app.PolicyEditorConfig) {
                    this.awsData = window.app.PolicyEditorConfig;
                    resolve();
                } else {
                    reject(new Error('AWS policies script loaded but data not available'));
                }
            };
            script.onerror = () => {
                reject(new Error('Failed to load AWS policies script'));
            };

            document.head.appendChild(script);
        });
    }

    /**
     * Build index of all AWS actions for fast lookup
     */
    buildActionsIndex() {
        this.allActions = [];
        for (const [serviceName, serviceData] of Object.entries(this.awsData.serviceMap)) {
            const prefix = serviceData.StringPrefix;
            for (const action of serviceData.Actions) {
                this.allActions.push(`${prefix}:${action}`);
            }
        }
    }

    /**
     * Analyze policy for wildcard expansion impact
     */
    analyzePolicy(policyDocument) {
        if (!this.isInitialized) {
            throw new Error('PolicyExpansion not initialized. Call initialize() first.');
        }

        const result = {
            isValid: true,
            errors: [],
            summary: {
                totalStatements: 0,
                totalPatterns: 0,
                wildcardPatterns: 0,
                exactPatterns: 0,
                totalExpandedActions: 0,
                expansionRatio: 0,
                servicesAffected: new Set()
            },
            statements: []
        };

        if (!policyDocument || !policyDocument.Statement) {
            result.isValid = false;
            result.errors.push('Policy must contain a Statement field');
            return result;
        }

        const statements = Array.isArray(policyDocument.Statement)
            ? policyDocument.Statement
            : [policyDocument.Statement];

        result.summary.totalStatements = statements.length;

        statements.forEach((statement, index) => {
            const statementAnalysis = this.analyzeStatement(statement, index);
            result.statements.push(statementAnalysis);

            // Aggregate summary data
            result.summary.totalPatterns += statementAnalysis.patterns.length;
            result.summary.wildcardPatterns += statementAnalysis.wildcardPatterns;
            result.summary.exactPatterns += statementAnalysis.exactPatterns;
            result.summary.totalExpandedActions += statementAnalysis.totalExpandedActions;

            statementAnalysis.servicesAffected.forEach(service => {
                result.summary.servicesAffected.add(service);
            });
        });

        result.summary.servicesAffected = Array.from(result.summary.servicesAffected).sort();
        result.summary.expansionRatio = result.summary.totalPatterns > 0 ?
            result.summary.totalExpandedActions / result.summary.totalPatterns : 0;

        return result;
    }

    /**
     * Analyze a single policy statement
     */
    analyzeStatement(statement, index) {
        const analysis = {
            index: index + 1,
            effect: statement.Effect || 'Allow',
            patterns: [],
            wildcardPatterns: 0,
            exactPatterns: 0,
            totalExpandedActions: 0,
            servicesAffected: new Set(),
            expansions: []
        };

        // Analyze Actions
        if (statement.Action) {
            const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
            analysis.patterns.push(...actions);
        }

        // Analyze NotAction (inverted logic)
        if (statement.NotAction) {
            const notActions = Array.isArray(statement.NotAction) ? statement.NotAction : [statement.NotAction];
            analysis.patterns.push(...notActions.map(action => `NOT:${action}`));
        }

        // Expand each pattern
        analysis.patterns.forEach(pattern => {
            const expansion = this.expandPattern(pattern);
            analysis.expansions.push(expansion);

            if (expansion.hasWildcard) {
                analysis.wildcardPatterns++;
            } else {
                analysis.exactPatterns++;
            }

            analysis.totalExpandedActions += expansion.expandedCount;

            // Track services affected
            expansion.expandedActions.forEach(action => {
                const service = this.getServiceFromAction(action);
                analysis.servicesAffected.add(service);
            });
        });

        analysis.servicesAffected = Array.from(analysis.servicesAffected).sort();

        return analysis;
    }

    /**
     * Expand a single action pattern (Vue.js style logic)
     */
    expandPattern(actionPattern) {
        const expansion = {
            originalPattern: actionPattern,
            hasWildcard: actionPattern.includes('*'),
            expandedActions: [],
            expandedCount: 0,
            sampleActions: [],
            isNotAction: actionPattern.startsWith('NOT:')
        };

        // Handle NotAction by removing the NOT: prefix
        let cleanPattern = expansion.isNotAction ? actionPattern.substring(4) : actionPattern;

        if (expansion.hasWildcard) {
            // Convert wildcard to regex (same as Vue.js app)
            const pattern = cleanPattern.replace(/\*/g, '.*');
            const regex = new RegExp(`^${pattern}$`, 'i');

            // Find all matching actions
            const matchedActions = this.allActions.filter(action => regex.test(action));
            expansion.expandedActions = matchedActions;

            // If no matches found, keep original pattern
            if (matchedActions.length === 0) {
                expansion.expandedActions = [cleanPattern];
            }
        } else {
            // Exact match
            expansion.expandedActions = [cleanPattern];
        }

        expansion.expandedCount = expansion.expandedActions.length;
        expansion.sampleActions = expansion.expandedActions.slice(0, 5);

        return expansion;
    }

    /**
     * Get service name from action string
     */
    getServiceFromAction(action) {
        const [prefix] = action.split(':');
        for (const [serviceName, serviceData] of Object.entries(this.awsData.serviceMap)) {
            if (serviceData.StringPrefix === prefix) {
                return serviceName;
            }
        }
        return 'Unknown Service';
    }

    /**
     * Get impact severity level
     */
    getImpactLevel(expansionRatio) {
        if (expansionRatio >= 100) return 'critical';
        if (expansionRatio >= 50) return 'high';
        if (expansionRatio >= 10) return 'medium';
        return 'low';
    }

    /**
     * Get human-readable impact description
     */
    getImpactDescription(level) {
        switch (level) {
            case 'critical': return '🔴 Critical - Very broad permissions';
            case 'high': return '🟠 High - Broad permissions';
            case 'medium': return '🟡 Medium - Moderate permissions';
            case 'low': return '🟢 Low - Specific permissions';
            default: return '⚪ Unknown impact';
        }
    }
}
