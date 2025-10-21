/**
 * Policy Visualizer Module
 * Handles rendering and visualization of IAM policies
 */

export class PolicyVisualizer {
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
        item.dataset.policyArn = policy.Arn;

        const isAwsManaged = policy.Arn.includes(':aws:policy/');
        const badgeClass = isAwsManaged ? 'badge-aws' : 'badge-customer';
        const badgeText = isAwsManaged ? 'AWS Managed' : 'Customer Managed';

        item.innerHTML = `
            <div class="policy-item-header">
                <div class="policy-name">${this.escapeHtml(policy.PolicyName)}</div>
                <div class="policy-badge ${badgeClass}">${badgeText}</div>
            </div>
            <div class="policy-arn">${this.escapeHtml(policy.Arn)}</div>
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

        const createDate = new Date(version.CreateDate).toLocaleString();

        item.innerHTML = `
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
}

/**
 * Security Visualizer - Display shadow admin detection results
 */
export class SecurityVisualizer {
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
     * Escape HTML to prevent XSS
     */
    static escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

