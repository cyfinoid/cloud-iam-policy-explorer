/**
 * Policy Expansion Module
 * Analyzes IAM policy wildcards and shows their real impact using official AWS data.
 * Implements bigorange-style expansion: regex wildcard matching, proper NotAction
 * complement, per-resource grouping, and cross-statement Allow/Deny merging.
 */

window.app = window.app || {};

class PolicyExpansion {
    constructor() {
        this.awsData = null;
        this.allActions = [];
        this.isInitialized = false;
    }

    async initialize() {
        if (this.isInitialized) return;

        try {
            await this.loadAWSData();
            this.buildActionsIndex();
            this.isInitialized = true;
            console.log(`Policy Expansion initialized: ${Object.keys(this.awsData.serviceMap).length} services, ${this.allActions.length} actions`);
        } catch (error) {
            console.error('Failed to initialize Policy Expansion:', error);
            throw error;
        }
    }

    async loadAWSData() {
        return new Promise((resolve, reject) => {
            if (window.app && window.app.PolicyEditorConfig) {
                this.awsData = window.app.PolicyEditorConfig;
                resolve();
                return;
            }

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

    buildActionsIndex() {
        this.allActions = [];
        for (const [, serviceData] of Object.entries(this.awsData.serviceMap)) {
            const prefix = serviceData.StringPrefix;
            for (const action of serviceData.Actions) {
                this.allActions.push(`${prefix}:${action}`);
            }
        }
        this.allActions.sort();
    }

    /**
     * Expand a wildcard pattern against the full action catalog.
     * Returns matching action strings (sorted, unique).
     */
    expandWildcard(pattern) {
        if (!pattern.includes('*')) {
            return [pattern];
        }
        const regexStr = pattern.replace(/\*/g, '.*');
        const regex = new RegExp(`^${regexStr}$`, 'i');
        const matched = this.allActions.filter(a => regex.test(a));
        return matched.length > 0 ? matched : [pattern];
    }

    /**
     * Expand Action list: union of all matching actions for each pattern.
     */
    expandActions(patterns) {
        const result = new Set();
        for (const p of patterns) {
            for (const a of this.expandWildcard(p)) {
                result.add(a);
            }
        }
        return Array.from(result).sort();
    }

    /**
     * Expand NotAction list: complement — all known actions that do NOT match
     * any of the given patterns (correct IAM semantics).
     */
    expandNotActions(patterns) {
        const regexes = patterns.map(p => {
            const regexStr = p.replace(/\*/g, '.*');
            return new RegExp(`^${regexStr}$`, 'i');
        });
        const result = this.allActions.filter(action =>
            !regexes.some(rx => rx.test(action))
        );
        return result.length > 0 ? result : [];
    }

    /**
     * Normalize an array-or-string field to an array.
     */
    static toArray(val) {
        if (!val) return [];
        return Array.isArray(val) ? val : [val];
    }

    /**
     * Compute effective permissions per resource, merging Allow/Deny across statements.
     *
     * Per resource key:
     *   - Allow statements union their expanded actions into the set.
     *   - Deny statements subtract their expanded actions from the set.
     *
     * Returns { resources: { [resourceArn]: string[] }, statementsDetail: [...] }
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
                totalEffectiveActions: 0,
                expansionRatio: 0,
                servicesAffected: new Set()
            },
            statements: [],
            effectivePermissions: {}
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

        // Per-resource effective action sets: Map<string, Set<string>>
        const effective = {};

        statements.forEach((statement, index) => {
            const detail = this.analyzeStatement(statement, index);
            result.statements.push(detail);

            result.summary.totalPatterns += detail.patterns.length;
            result.summary.wildcardPatterns += detail.wildcardPatterns;
            result.summary.exactPatterns += detail.exactPatterns;
            result.summary.totalExpandedActions += detail.totalExpandedActions;

            detail.servicesAffected.forEach(s => result.summary.servicesAffected.add(s));

            // Merge into per-resource effective set
            const resources = PolicyExpansion.toArray(statement.Resource)
                .concat(PolicyExpansion.toArray(statement.NotResource).length > 0 && !statement.Resource ? ['*'] : []);
            if (resources.length === 0) resources.push('*');

            const effect = (statement.Effect || 'Allow').toLowerCase();

            for (const resource of resources) {
                if (!effective[resource]) {
                    effective[resource] = new Set();
                }

                if (effect === 'allow') {
                    for (const action of detail.expandedActions) {
                        effective[resource].add(action);
                    }
                } else if (effect === 'deny') {
                    for (const action of detail.expandedActions) {
                        effective[resource].delete(action);
                    }
                }
            }
        });

        // Convert effective sets to sorted arrays and compute services
        const allEffectiveServices = new Set();
        for (const [resource, actionSet] of Object.entries(effective)) {
            const sorted = Array.from(actionSet).sort();
            result.effectivePermissions[resource] = sorted;
            sorted.forEach(a => {
                const svc = a.split(':')[0];
                allEffectiveServices.add(svc);
            });
            result.summary.totalEffectiveActions += sorted.length;
        }

        result.summary.servicesAffected = Array.from(result.summary.servicesAffected).sort();
        result.summary.expansionRatio = result.summary.totalPatterns > 0 ?
            result.summary.totalExpandedActions / result.summary.totalPatterns : 0;

        return result;
    }

    /**
     * Analyze a single statement. Returns expanded actions for that statement.
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
            expandedActions: [],
            expansions: [],
            resources: PolicyExpansion.toArray(statement.Resource),
            isNotAction: false
        };

        let expanded;

        if (statement.Action) {
            const actions = PolicyExpansion.toArray(statement.Action);
            analysis.patterns = actions;
            expanded = this.expandActions(actions);
            analysis.isNotAction = false;
        } else if (statement.NotAction) {
            const notActions = PolicyExpansion.toArray(statement.NotAction);
            analysis.patterns = notActions.map(a => `NOT:${a}`);
            expanded = this.expandNotActions(notActions);
            analysis.isNotAction = true;
        } else {
            expanded = [];
        }

        analysis.expandedActions = expanded;
        analysis.totalExpandedActions = expanded.length;

        // Build per-pattern expansion detail for the UI
        if (statement.Action) {
            const actions = PolicyExpansion.toArray(statement.Action);
            for (const pattern of actions) {
                const exp = this.buildExpansionDetail(pattern, false);
                analysis.expansions.push(exp);
                if (exp.hasWildcard) analysis.wildcardPatterns++;
                else analysis.exactPatterns++;
            }
        } else if (statement.NotAction) {
            const notActions = PolicyExpansion.toArray(statement.NotAction);
            for (const pattern of notActions) {
                const exp = this.buildExpansionDetail(pattern, true);
                analysis.expansions.push(exp);
                if (exp.hasWildcard) analysis.wildcardPatterns++;
                else analysis.exactPatterns++;
            }
        }

        expanded.forEach(action => {
            const svc = action.split(':')[0];
            analysis.servicesAffected.add(svc);
        });
        analysis.servicesAffected = Array.from(analysis.servicesAffected).sort();

        return analysis;
    }

    buildExpansionDetail(pattern, isNotAction) {
        const expansion = {
            originalPattern: isNotAction ? `NOT:${pattern}` : pattern,
            hasWildcard: pattern.includes('*'),
            expandedActions: [],
            expandedCount: 0,
            sampleActions: [],
            isNotAction
        };

        if (isNotAction) {
            const complement = this.expandNotActions([pattern]);
            expansion.expandedActions = complement;
        } else {
            expansion.expandedActions = this.expandWildcard(pattern);
        }

        expansion.expandedCount = expansion.expandedActions.length;
        expansion.sampleActions = expansion.expandedActions.slice(0, 5);
        return expansion;
    }

    getServiceFromAction(action) {
        const [prefix] = action.split(':');
        if (!this.awsData) return 'Unknown Service';
        for (const [serviceName, serviceData] of Object.entries(this.awsData.serviceMap)) {
            if (serviceData.StringPrefix === prefix) {
                return serviceName;
            }
        }
        return prefix;
    }

    /**
     * Group actions by service prefix.
     * Returns sorted array of { service, prefix, count, actions }.
     */
    static groupByService(actions) {
        const groups = {};
        for (const action of actions) {
            const prefix = action.split(':')[0];
            if (!groups[prefix]) {
                groups[prefix] = [];
            }
            groups[prefix].push(action);
        }
        return Object.entries(groups)
            .map(([prefix, acts]) => ({ prefix, count: acts.length, actions: acts.sort() }))
            .sort((a, b) => b.count - a.count);
    }
}
