/**
 * Policy Visualizer Module
 * Handles rendering and visualization of IAM policies
 */

class PolicyVisualizer {
    /**
     * Render the list of policies
     */
    static renderPolicyList(policies, containerElement) {
        containerElement.innerHTML = '';

        if (!policies || policies.length === 0) {
            containerElement.innerHTML = '<p class="caption" style="text-align: center; padding: 2rem;">No policies found</p>';
            return;
        }

        policies.forEach(policy => {
            const policyItem = this.createPolicyListItem(policy);
            containerElement.appendChild(policyItem);
        });
    }

    /**
     * Create a single policy list item element
     */
    static createPolicyListItem(policy) {
        const item = document.createElement('div');
        item.className = 'policy-item';
        
        // Handle inline policies differently
        if (policy.isInline) {
            item.dataset.policyArn = `inline:${policy.userName}/${policy.PolicyName}`;
        } else {
            item.dataset.policyArn = policy.Arn;
        }

        let badgeClass, badgeText;
        if (policy.isInline) {
            badgeClass = 'badge-inline';
            badgeText = 'Inline Policy';
        } else if (policy.Arn && policy.Arn.includes(':aws:policy/')) {
            badgeClass = 'badge-aws';
            badgeText = 'AWS Managed';
        } else {
            badgeClass = 'badge-customer';
            badgeText = 'Customer Managed';
        }

        // Add attached badge if policy is attached to user
        const attachedBadge = policy.isAttachedToUser ? 
            '<div class="policy-badge badge-attached">Attached</div>' : '';

        const arnDisplay = policy.isInline ? 
            `Inline on user: ${policy.userName}` : 
            this.escapeHtml(policy.Arn || 'Unknown ARN');

        item.innerHTML = `
            <div class="policy-item-header">
                <div class="policy-name">${this.escapeHtml(policy.PolicyName)}</div>
                <div class="policy-badges">
                    <div class="policy-badge ${badgeClass}">${badgeText}</div>
                    ${attachedBadge}
                </div>
            </div>
            <div class="policy-arn">${arnDisplay}</div>
            ${policy.Description ? `<p class="caption mt-sm">${this.escapeHtml(policy.Description)}</p>` : ''}
        `;

        return item;
    }

    /**
     * Render policy details in visual format
     */
    static renderPolicyVisual(policyDocument, containerElement) {
        containerElement.innerHTML = '';

        if (!policyDocument || !policyDocument.Statement) {
            containerElement.innerHTML = '<p class="caption">No policy statements found</p>';
            return;
        }

        const statementList = document.createElement('div');
        statementList.className = 'statement-list';

        const statements = Array.isArray(policyDocument.Statement) 
            ? policyDocument.Statement 
            : [policyDocument.Statement];

        statements.forEach((statement, index) => {
            const statementCard = this.createStatementCard(statement, index);
            statementList.appendChild(statementCard);
        });

        containerElement.appendChild(statementList);
    }

    /**
     * Create a visual card for a policy statement
     */
    static createStatementCard(statement, index) {
        const card = document.createElement('div');
        const effect = statement.Effect || 'Allow';
        card.className = `statement-card ${effect.toLowerCase()}`;

        let html = `
            <div class="statement-header">
                <span class="section-header">Statement ${index + 1}</span>
                <span class="statement-effect effect-${effect.toLowerCase()}">${effect}</span>
            </div>
        `;

        // Sid (Statement ID)
        if (statement.Sid) {
            html += `
                <div class="statement-section">
                    <div class="statement-section-title">Statement ID:</div>
                    <div class="statement-section-content">${this.escapeHtml(statement.Sid)}</div>
                </div>
            `;
        }

        // Actions
        if (statement.Action) {
            const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
            html += `
                <div class="statement-section">
                    <div class="statement-section-title">Actions (${actions.length}):</div>
                    <div class="statement-section-content">
                        <ul>
                            ${actions.map(action => `<li>${this.escapeHtml(action)}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            `;
        }

        // NotAction
        if (statement.NotAction) {
            const notActions = Array.isArray(statement.NotAction) ? statement.NotAction : [statement.NotAction];
            html += `
                <div class="statement-section">
                    <div class="statement-section-title">Not Actions:</div>
                    <div class="statement-section-content">
                        <ul>
                            ${notActions.map(action => `<li>${this.escapeHtml(action)}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            `;
        }

        // Resources
        if (statement.Resource) {
            const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
            html += `
                <div class="statement-section">
                    <div class="statement-section-title">Resources (${resources.length}):</div>
                    <div class="statement-section-content">
                        <ul>
                            ${resources.map(resource => `<li>${this.escapeHtml(resource)}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            `;
        }

        // NotResource
        if (statement.NotResource) {
            const notResources = Array.isArray(statement.NotResource) ? statement.NotResource : [statement.NotResource];
            html += `
                <div class="statement-section">
                    <div class="statement-section-title">Not Resources:</div>
                    <div class="statement-section-content">
                        <ul>
                            ${notResources.map(resource => `<li>${this.escapeHtml(resource)}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            `;
        }

        // Conditions
        if (statement.Condition) {
            html += `
                <div class="statement-section">
                    <div class="statement-section-title">Conditions:</div>
                    <div class="statement-section-content">
                        ${this.renderConditions(statement.Condition)}
                    </div>
                </div>
            `;
        }

        // Principal (for resource-based policies, not common in IAM policies)
        if (statement.Principal) {
            html += `
                <div class="statement-section">
                    <div class="statement-section-title">Principal:</div>
                    <div class="statement-section-content">
                        <pre>${JSON.stringify(statement.Principal, null, 2)}</pre>
                    </div>
                </div>
            `;
        }

        card.innerHTML = html;
        return card;
    }

    /**
     * Render conditions in a readable format
     */
    static renderConditions(conditions) {
        let html = '<ul>';
        
        for (const [operator, values] of Object.entries(conditions)) {
            html += `<li><strong>${this.escapeHtml(operator)}:</strong><ul>`;
            
            for (const [key, value] of Object.entries(values)) {
                const valueStr = Array.isArray(value) ? value.join(', ') : value;
                html += `<li>${this.escapeHtml(key)}: ${this.escapeHtml(String(valueStr))}</li>`;
            }
            
            html += '</ul></li>';
        }
        
        html += '</ul>';
        return html;
    }

    /**
     * Render policy in JSON format
     */
    static renderPolicyJson(policyDocument, containerElement) {
        const pre = containerElement.querySelector('pre');
        const code = containerElement.querySelector('code');
        
        if (pre && code) {
            code.textContent = JSON.stringify(policyDocument, null, 2);
        }
    }

    /**
     * Render policy versions list
     */
    static renderVersionsList(versions, defaultVersionId, containerElement, onSetDefault) {
        containerElement.innerHTML = '';

        if (!versions || versions.length === 0) {
            containerElement.innerHTML = '<p class="caption">No versions found</p>';
            return;
        }

        versions.forEach(version => {
            const versionItem = this.createVersionItem(version, defaultVersionId, onSetDefault);
            containerElement.appendChild(versionItem);
        });
    }

    /**
     * Create a version list item
     */
    static createVersionItem(version, defaultVersionId, onSetDefault) {
        const item = document.createElement('div');
        const isDefault = version.VersionId === defaultVersionId;
        item.className = `version-item ${isDefault ? 'default' : ''}`;
        item.dataset.versionId = version.VersionId;

        const createDate = new Date(version.CreateDate).toLocaleString();

        item.innerHTML = `
            <input type="checkbox" class="version-checkbox" data-version-id="${version.VersionId}">
            <div class="version-info">
                <span class="version-id">${version.VersionId}</span>
                ${isDefault ? '<span class="version-default-badge">Default</span>' : ''}
                <span class="version-date">${createDate}</span>
            </div>
            <div class="version-actions">
                ${!isDefault ? `<button class="btn btn-warning set-default-btn" data-version-id="${version.VersionId}">Set as Default</button>` : ''}
            </div>
        `;

        // Add event listener for set default button
        if (!isDefault) {
            const setDefaultBtn = item.querySelector('.set-default-btn');
            if (setDefaultBtn) {
                setDefaultBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    if (onSetDefault) {
                        onSetDefault(version.VersionId);
                    }
                });
            }
        }

        return item;
    }

    /**
     * Update statistics display
     */
    static updateStats(stats) {
        const totalElement = document.getElementById('total-policies');
        const awsManagedElement = document.getElementById('aws-managed-count');
        const customerManagedElement = document.getElementById('customer-managed-count');

        if (totalElement) totalElement.textContent = stats.total || 0;
        if (awsManagedElement) awsManagedElement.textContent = stats.awsManaged || 0;
        if (customerManagedElement) customerManagedElement.textContent = stats.customerManaged || 0;
    }

    /**
     * Escape HTML to prevent XSS
     */
    static escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Format date for display
     */
    static formatDate(date) {
        if (!date) return 'N/A';
        return new Date(date).toLocaleString();
    }

    /**
     * Compare two policy versions and render differences
     */
    static renderVersionComparison(version1, version2, containerElement) {
        if (!containerElement || !version1 || !version2) return;

        const diff = this.calculatePolicyDiff(version1.Document, version2.Document);
        
        containerElement.innerHTML = '';

        // Determine which is older/newer
        const isVersion1Older = new Date(version1.CreateDate) < new Date(version2.CreateDate);
        const olderVersion = isVersion1Older ? version1 : version2;
        const newerVersion = isVersion1Older ? version2 : version1;

        // Add legend
        const legend = document.createElement('div');
        legend.className = 'diff-legend';
        legend.innerHTML = `
            <div class="legend-item">
                <div class="legend-color added"></div>
                <span>Added in ${newerVersion.VersionId} (newer)</span>
            </div>
            <div class="legend-item">
                <div class="legend-color removed"></div>
                <span>Removed from ${olderVersion.VersionId} (older)</span>
            </div>
            <div class="legend-item">
                <div class="legend-color modified"></div>
                <span>Modified</span>
            </div>
        `;
        containerElement.appendChild(legend);

        // Summary
        const summary = document.createElement('div');
        summary.className = 'diff-summary';
        summary.innerHTML = `
            <div class="diff-summary-item">
                <span class="diff-summary-value added">${diff.addedCount}</span>
                <span class="diff-summary-label">Items Added</span>
            </div>
            <div class="diff-summary-item">
                <span class="diff-summary-value removed">${diff.removedCount}</span>
                <span class="diff-summary-label">Items Removed</span>
            </div>
            <div class="diff-summary-item">
                <span class="diff-summary-value modified">${diff.modifiedCount}</span>
                <span class="diff-summary-label">Items Modified</span>
            </div>
        `;
        containerElement.appendChild(summary);

        // Side-by-side comparison
        const comparisonGrid = document.createElement('div');
        comparisonGrid.className = 'comparison-grid';

        // Column 1: Older version (left)
        const column1 = document.createElement('div');
        column1.className = 'comparison-column';
        column1.innerHTML = `
            <div class="comparison-header">
                <div class="version-id">${version1.VersionId} <span style="font-size: 12px; color: var(--text-secondary);">(older)</span></div>
                <div class="version-date">${this.formatDate(version1.CreateDate)}</div>
            </div>
        `;
        column1.appendChild(this.renderPolicyDiff(diff, 'old'));
        comparisonGrid.appendChild(column1);

        // Column 2: Newer version (right)
        const column2 = document.createElement('div');
        column2.className = 'comparison-column';
        column2.innerHTML = `
            <div class="comparison-header">
                <div class="version-id">${version2.VersionId} <span style="font-size: 12px; color: var(--text-secondary);">(newer)</span></div>
                <div class="version-date">${this.formatDate(version2.CreateDate)}</div>
            </div>
        `;
        column2.appendChild(this.renderPolicyDiff(diff, 'new'));
        comparisonGrid.appendChild(column2);

        containerElement.appendChild(comparisonGrid);
    }

    /**
     * Calculate differences between two policy documents
     */
    static calculatePolicyDiff(doc1, doc2) {
        const diff = {
            actions: { added: [], removed: [], unchanged: [], modified: [] },
            resources: { added: [], removed: [], unchanged: [], modified: [] },
            statements: { added: [], removed: [], modified: [] },
            addedCount: 0,
            removedCount: 0,
            modifiedCount: 0
        };

        if (!doc1 || !doc2) return diff;

        const statements1 = Array.isArray(doc1.Statement) ? doc1.Statement : [doc1.Statement];
        const statements2 = Array.isArray(doc2.Statement) ? doc2.Statement : [doc2.Statement];

        // Collect all actions and resources
        const actions1 = new Set();
        const actions2 = new Set();
        const resources1 = new Set();
        const resources2 = new Set();

        statements1.forEach(stmt => {
            if (stmt.Action) {
                const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
                actions.forEach(a => actions1.add(a));
            }
            if (stmt.Resource) {
                const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
                resources.forEach(r => resources1.add(r));
            }
        });

        statements2.forEach(stmt => {
            if (stmt.Action) {
                const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
                actions.forEach(a => actions2.add(a));
            }
            if (stmt.Resource) {
                const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
                resources.forEach(r => resources2.add(r));
            }
        });

        // Calculate action differences
        actions1.forEach(action => {
            if (!actions2.has(action)) {
                diff.actions.removed.push(action);
                diff.removedCount++;
            } else {
                diff.actions.unchanged.push(action);
            }
        });

        actions2.forEach(action => {
            if (!actions1.has(action)) {
                diff.actions.added.push(action);
                diff.addedCount++;
            }
        });

        // Calculate resource differences
        resources1.forEach(resource => {
            if (!resources2.has(resource)) {
                diff.resources.removed.push(resource);
                diff.removedCount++;
            } else {
                diff.resources.unchanged.push(resource);
            }
        });

        resources2.forEach(resource => {
            if (!resources1.has(resource)) {
                diff.resources.added.push(resource);
                diff.addedCount++;
            }
        });

        return diff;
    }

    /**
     * Render policy diff for a specific side (old or new)
     */
    static renderPolicyDiff(diff, side) {
        const container = document.createElement('div');

        // Actions section
        if (diff.actions.added.length > 0 || diff.actions.removed.length > 0 || diff.actions.unchanged.length > 0) {
            const actionsSection = document.createElement('div');
            actionsSection.className = 'diff-section';
            actionsSection.innerHTML = '<div class="diff-section-title">Actions</div>';

            if (side === 'old') {
                // Show removed and unchanged for old version
                [...diff.actions.removed, ...diff.actions.unchanged].forEach(action => {
                    const item = document.createElement('div');
                    item.className = `diff-item ${diff.actions.removed.includes(action) ? 'diff-removed' : 'diff-unchanged'}`;
                    item.textContent = action;
                    actionsSection.appendChild(item);
                });
            } else {
                // Show added and unchanged for new version
                [...diff.actions.added, ...diff.actions.unchanged].forEach(action => {
                    const item = document.createElement('div');
                    item.className = `diff-item ${diff.actions.added.includes(action) ? 'diff-added' : 'diff-unchanged'}`;
                    item.textContent = action;
                    actionsSection.appendChild(item);
                });
            }

            container.appendChild(actionsSection);
        }

        // Resources section
        if (diff.resources.added.length > 0 || diff.resources.removed.length > 0 || diff.resources.unchanged.length > 0) {
            const resourcesSection = document.createElement('div');
            resourcesSection.className = 'diff-section';
            resourcesSection.innerHTML = '<div class="diff-section-title">Resources</div>';

            if (side === 'old') {
                // Show removed and unchanged for old version
                [...diff.resources.removed, ...diff.resources.unchanged].forEach(resource => {
                    const item = document.createElement('div');
                    item.className = `diff-item ${diff.resources.removed.includes(resource) ? 'diff-removed' : 'diff-unchanged'}`;
                    item.textContent = resource;
                    resourcesSection.appendChild(item);
                });
            } else {
                // Show added and unchanged for new version
                [...diff.resources.added, ...diff.resources.unchanged].forEach(resource => {
                    const item = document.createElement('div');
                    item.className = `diff-item ${diff.resources.added.includes(resource) ? 'diff-added' : 'diff-unchanged'}`;
                    item.textContent = resource;
                    resourcesSection.appendChild(item);
                });
            }

            container.appendChild(resourcesSection);
        }

        return container;
    }
}

/**
 * Security Visualizer - Display shadow admin detection results
 */
class SecurityVisualizer {
    /**
     * Render security analysis results
     */
    static renderSecurityAnalysis(analysis, containerElement) {
        if (!containerElement) return;

        containerElement.innerHTML = '';

        // Risk level banner
        const riskBanner = this.createRiskBanner(analysis);
        containerElement.appendChild(riskBanner);

        // Statistics cards
        if (analysis.stats && analysis.stats.totalIssues > 0) {
            const statsSection = this.createStatsSection(analysis.stats);
            containerElement.appendChild(statsSection);
        }

        // Detected escalation methods
        if (analysis.detectedMethods && analysis.detectedMethods.length > 0) {
            const methodsSection = this.createEscalationMethodsSection(analysis.detectedMethods);
            containerElement.appendChild(methodsSection);
        }

        // Issues list
        if (analysis.issues && analysis.issues.length > 0) {
            const issuesSection = this.createIssuesSection(analysis.issues);
            containerElement.appendChild(issuesSection);
        }

        // No issues message
        if (!analysis.issues || analysis.issues.length === 0) {
            containerElement.innerHTML += '<p class="security-safe-message">✓ No security issues detected in this policy</p>';
        }
    }

    /**
     * Create risk level banner
     */
    static createRiskBanner(analysis) {
        const banner = document.createElement('div');
        const riskLevel = analysis.riskLevel || 0;
        
        let riskClass = 'risk-low';
        let riskLabel = 'Low Risk';
        let riskIcon = '●';
        
        if (riskLevel >= 9) {
            riskClass = 'risk-critical';
            riskLabel = 'Critical Risk';
            riskIcon = '⚠';
        } else if (riskLevel >= 7) {
            riskClass = 'risk-high';
            riskLabel = 'High Risk';
            riskIcon = '⚠';
        } else if (riskLevel >= 5) {
            riskClass = 'risk-medium';
            riskLabel = 'Medium Risk';
            riskIcon = '◆';
        } else if (riskLevel > 0) {
            riskClass = 'risk-low';
            riskLabel = 'Low Risk';
            riskIcon = '○';
        } else {
            riskClass = 'risk-safe';
            riskLabel = 'Safe';
            riskIcon = '✓';
        }

        banner.className = `security-banner ${riskClass}`;
        banner.innerHTML = `
            <div class="security-banner-content">
                <span class="risk-icon">${riskIcon}</span>
                <div class="risk-info">
                    <div class="risk-label">${riskLabel}</div>
                    <div class="risk-summary">${this.escapeHtml(analysis.summary || 'Analysis complete')}</div>
                </div>
                <div class="risk-score">${riskLevel}/10</div>
            </div>
        `;

        return banner;
    }

    /**
     * Create statistics section
     */
    static createStatsSection(stats) {
        const section = document.createElement('div');
        section.className = 'security-stats';

        section.innerHTML = `
            <div class="security-stat-card">
                <div class="stat-number">${stats.totalIssues || 0}</div>
                <div class="stat-label">Total Issues</div>
            </div>
            <div class="security-stat-card critical">
                <div class="stat-number">${stats.criticalIssues || 0}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="security-stat-card high">
                <div class="stat-number">${stats.highIssues || 0}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="security-stat-card medium">
                <div class="stat-number">${stats.mediumIssues || 0}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="security-stat-card escalation">
                <div class="stat-number">${stats.escalationMethods || 0}</div>
                <div class="stat-label">Escalation Paths</div>
            </div>
        `;

        return section;
    }

    /**
     * Create escalation methods section
     */
    static createEscalationMethodsSection(methods) {
        const section = document.createElement('div');
        section.className = 'escalation-methods-section';

        const header = document.createElement('h4');
        header.className = 'section-header';
        header.textContent = 'Detected Privilege Escalation Methods';
        section.appendChild(header);

        const methodsList = document.createElement('div');
        methodsList.className = 'escalation-methods-list';

        methods.forEach(method => {
            const methodCard = document.createElement('div');
            methodCard.className = 'escalation-method-card';
            
            const severityClass = method.riskLevel >= 9 ? 'severity-critical' : 
                                 method.riskLevel >= 7 ? 'severity-high' : 'severity-medium';

            methodCard.innerHTML = `
                <div class="method-header">
                    <span class="method-name">${this.escapeHtml(method.method)}</span>
                    <span class="method-severity ${severityClass}">${method.riskLevel}/10</span>
                </div>
                <div class="method-category">${this.escapeHtml(method.category)}</div>
                <div class="method-description">${this.escapeHtml(method.description)}</div>
                <div class="method-permissions">
                    <strong>Required:</strong> ${method.permissions.map(p => `<code>${this.escapeHtml(p)}</code>`).join(', ')}
                </div>
            `;

            methodsList.appendChild(methodCard);
        });

        section.appendChild(methodsList);
        return section;
    }

    /**
     * Create issues section
     */
    static createIssuesSection(issues) {
        const section = document.createElement('div');
        section.className = 'security-issues-section';

        const header = document.createElement('h4');
        header.className = 'section-header';
        header.textContent = 'Security Issues & Recommendations';
        section.appendChild(header);

        const issuesList = document.createElement('div');
        issuesList.className = 'security-issues-list';

        // Group issues by severity
        const criticalIssues = issues.filter(i => i.severity === 'critical');
        const highIssues = issues.filter(i => i.severity === 'high');
        const mediumIssues = issues.filter(i => i.severity === 'medium');
        const lowIssues = issues.filter(i => i.severity === 'low');

        const grouped = [
            { label: 'Critical Issues', issues: criticalIssues, class: 'critical' },
            { label: 'High Risk Issues', issues: highIssues, class: 'high' },
            { label: 'Medium Risk Issues', issues: mediumIssues, class: 'medium' },
            { label: 'Low Risk Issues', issues: lowIssues, class: 'low' }
        ];

        grouped.forEach(group => {
            if (group.issues.length > 0) {
                const groupHeader = document.createElement('h5');
                groupHeader.className = `issue-group-header ${group.class}`;
                groupHeader.textContent = `${group.label} (${group.issues.length})`;
                issuesList.appendChild(groupHeader);

                group.issues.forEach(issue => {
                    const issueCard = this.createIssueCard(issue);
                    issuesList.appendChild(issueCard);
                });
            }
        });

        section.appendChild(issuesList);
        return section;
    }

    /**
     * Create individual issue card
     */
    static createIssueCard(issue) {
        const card = document.createElement('div');
        card.className = `security-issue-card severity-${issue.severity}`;

        card.innerHTML = `
            <div class="issue-title">
                <span class="issue-type-badge">${this.escapeHtml(issue.type)}</span>
                ${this.escapeHtml(issue.title)}
            </div>
            <div class="issue-description">${this.escapeHtml(issue.description)}</div>
            ${issue.category ? `<div class="issue-category"><strong>Category:</strong> ${this.escapeHtml(issue.category)}</div>` : ''}
            <div class="issue-remediation">
                <strong>Remediation:</strong> ${this.escapeHtml(issue.remediation)}
            </div>
        `;

        return card;
    }

    /**
     * Get risk badge HTML for policy list items
     */
    static getRiskBadgeHtml(riskLevel) {
        if (riskLevel >= 9) {
            return '<span class="risk-badge risk-critical">CRITICAL</span>';
        } else if (riskLevel >= 7) {
            return '<span class="risk-badge risk-high">HIGH RISK</span>';
        } else if (riskLevel >= 5) {
            return '<span class="risk-badge risk-medium">MEDIUM</span>';
        } else if (riskLevel > 0) {
            return '<span class="risk-badge risk-low">LOW</span>';
        }
        return '<span class="risk-badge risk-safe">SAFE</span>';
    }

    /**
     * Render policy expansion analysis
     */
    static renderPolicyExpansion(analysisResult, containerElement) {
        containerElement.innerHTML = '';

        if (!analysisResult || !analysisResult.isValid) {
            containerElement.innerHTML = '<p class="caption">Unable to analyze policy expansion</p>';
            return;
        }

        const expansionContainer = document.createElement('div');
        expansionContainer.className = 'expansion-analysis';

        // Overall impact summary
        const summaryCard = this.createExpansionSummary(analysisResult);
        expansionContainer.appendChild(summaryCard);

        // Statement-by-statement breakdown
        if (analysisResult.statements && analysisResult.statements.length > 0) {
            const statementsSection = this.createExpansionStatements(analysisResult.statements);
            expansionContainer.appendChild(statementsSection);
        }

        containerElement.appendChild(expansionContainer);
    }

    /**
     * Create expansion impact summary card
     */
    static createExpansionSummary(analysisResult) {
        const summary = analysisResult.summary;
        const impactLevel = this.getExpansionImpactLevel(summary.expansionRatio);

        const card = document.createElement('div');
        card.className = `expansion-summary impact-${impactLevel}`;

        card.innerHTML = `
            <div class="expansion-summary-header">
                <h3 class="section-header">🔍 Permission Expansion Analysis</h3>
                <div class="impact-badge">${this.getExpansionImpactDescription(impactLevel)}</div>
            </div>

            <div class="expansion-stats">
                <div class="stat-item">
                    <div class="stat-value">${summary.totalPatterns}</div>
                    <div class="stat-label">Total Patterns</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${summary.totalExpandedActions}</div>
                    <div class="stat-label">Expanded Actions</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${summary.expansionRatio.toFixed(1)}x</div>
                    <div class="stat-label">Expansion Ratio</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${summary.servicesAffected.length}</div>
                    <div class="stat-label">Services Affected</div>
                </div>
            </div>

            <div class="expansion-details">
                <div class="detail-row">
                    <span class="detail-label">Wildcard patterns:</span>
                    <span class="detail-value">${summary.wildcardPatterns}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Exact patterns:</span>
                    <span class="detail-value">${summary.exactPatterns}</span>
                </div>
            </div>
        `;

        return card;
    }

    /**
     * Create statement-by-statement expansion breakdown
     */
    static createExpansionStatements(statements) {
        const section = document.createElement('div');
        section.className = 'expansion-statements';

        const header = document.createElement('h4');
        header.className = 'section-header';
        header.textContent = 'Statement Analysis';
        section.appendChild(header);

        statements.forEach(statement => {
            const statementCard = this.createExpansionStatementCard(statement);
            section.appendChild(statementCard);
        });

        return section;
    }

    /**
     * Create expansion card for a single statement
     */
    static createExpansionStatementCard(statement) {
        const card = document.createElement('div');
        card.className = `expansion-statement effect-${statement.effect.toLowerCase()}`;

        let html = `
            <div class="statement-header">
                <span class="statement-title">Statement ${statement.index}</span>
                <span class="statement-effect effect-${statement.effect.toLowerCase()}">${statement.effect}</span>
            </div>
            <div class="statement-stats">
                <span class="stat">${statement.patterns.length} patterns</span>
                <span class="stat">${statement.totalExpandedActions} actions</span>
                <span class="stat">${statement.servicesAffected.length} services</span>
            </div>
        `;

        if (statement.expansions && statement.expansions.length > 0) {
            html += '<div class="pattern-expansions">';

            statement.expansions.forEach(expansion => {
                const patternClass = expansion.hasWildcard ? 'pattern-wildcard' : 'pattern-exact';
                const typeIcon = expansion.hasWildcard ? '🔸' : '🔹';
                const sampleText = expansion.sampleActions.slice(0, 3).join(', ') +
                    (expansion.expandedCount > 3 ? ` ... +${expansion.expandedCount - 3} more` : '');

                html += `
                    <div class="pattern-expansion ${patternClass}">
                        <div class="pattern-header">
                            <span class="pattern-type">${typeIcon}</span>
                            <code class="pattern-text">${this.escapeHtml(expansion.originalPattern)}</code>
                            <span class="pattern-count">${expansion.expandedCount} actions</span>
                        </div>
                        ${expansion.expandedCount > 0 ? `<div class="pattern-sample">${this.escapeHtml(sampleText)}</div>` : ''}
                    </div>
                `;
            });

            html += '</div>';
        }

        card.innerHTML = html;
        return card;
    }

    /**
     * Get expansion impact level based on ratio
     */
    static getExpansionImpactLevel(ratio) {
        if (ratio >= 100) return 'critical';
        if (ratio >= 50) return 'high';
        if (ratio >= 10) return 'medium';
        return 'low';
    }

    /**
     * Get human-readable impact description
     */
    static getExpansionImpactDescription(level) {
        switch (level) {
            case 'critical': return '🔴 CRITICAL - Very Broad Permissions';
            case 'high': return '🟠 HIGH - Broad Permissions';
            case 'medium': return '🟡 MEDIUM - Moderate Permissions';
            case 'low': return '🟢 LOW - Specific Permissions';
            default: return '⚪ UNKNOWN';
        }
    }

    /**
     * Escape HTML to prevent XSS
     */
    static escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

