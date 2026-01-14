/**
 * Main Application Module
 * Coordinates UI interactions and AWS operations
 * 
 * Note: All dependencies (awsHandler, PolicyVisualizer, SecurityVisualizer, 
 * PolicyExpansion, analyzePolicyForShadowAdmin) are loaded as globals
 * from previous script tags.
 */

class App {
    constructor() {
        this.allPolicies = [];
        this.filteredPolicies = [];
        this.currentPolicy = null;
        this.currentPolicyArn = null;
        this.currentSecurityAnalysis = null;
        this.policyExpansion = new PolicyExpansion();
        this.isLimitedMode = false;
        this.inlinePolicies = [];

        this.init();
    }

    /**
     * Initialize the application
     */
    async init() {
        try {
            // Initialize policy expansion analyzer
            await this.policyExpansion.initialize();

            this.setupEventListeners();
            console.log('AWS Policy Explorer initialized');
        } catch (error) {
            console.error('Failed to initialize Policy Expansion:', error);
            // Continue without expansion features
            this.setupEventListeners();
            console.log('AWS Policy Explorer initialized (without expansion analysis)');
        }
    }

    /**
     * Setup all event listeners
     */
    setupEventListeners() {
        // Credential form submission
        const credentialForm = document.getElementById('credential-form');
        if (credentialForm) {
            credentialForm.addEventListener('submit', (e) => this.handleConnect(e));
        }

        // Disconnect button
        const disconnectBtn = document.getElementById('disconnect-btn');
        if (disconnectBtn) {
            disconnectBtn.addEventListener('click', () => this.handleDisconnect());
        }

        // Search input
        const searchInput = document.getElementById('policy-search');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => this.handleSearch(e.target.value));
        }

        // Filter dropdown
        const filterSelect = document.getElementById('policy-filter');
        if (filterSelect) {
            filterSelect.addEventListener('change', (e) => this.handleFilter(e.target.value));
        }

        // Back to list button
        const backBtn = document.getElementById('back-to-list');
        if (backBtn) {
            backBtn.addEventListener('click', () => this.showPolicyList());
        }

        // View toggle buttons
        const toggleBtns = document.querySelectorAll('.toggle-btn');
        toggleBtns.forEach(btn => {
            btn.addEventListener('click', (e) => this.handleViewToggle(e.target.dataset.view));
        });

        // Version comparison buttons
        const compareBtn = document.getElementById('compare-versions-btn');
        if (compareBtn) {
            compareBtn.addEventListener('click', () => this.handleCompareVersions());
        }

        const closeComparisonBtn = document.getElementById('close-comparison-btn');
        if (closeComparisonBtn) {
            closeComparisonBtn.addEventListener('click', () => this.closeVersionComparison());
        }

        // Manual ARN entry
        const toggleManualArnBtn = document.getElementById('toggle-manual-arn');
        if (toggleManualArnBtn) {
            toggleManualArnBtn.addEventListener('click', () => this.toggleManualArnForm());
        }

        const analyzeArnBtn = document.getElementById('analyze-arn-btn');
        if (analyzeArnBtn) {
            analyzeArnBtn.addEventListener('click', () => this.handleManualArnAnalyze());
        }

        const manualArnInput = document.getElementById('manual-policy-arn');
        if (manualArnInput) {
            manualArnInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.handleManualArnAnalyze();
                }
            });
        }
    }

    /**
     * Toggle manual ARN form visibility
     */
    toggleManualArnForm() {
        const form = document.getElementById('manual-arn-form');
        const toggleBtn = document.getElementById('toggle-manual-arn');
        
        if (form.style.display === 'none') {
            form.style.display = 'flex';
            toggleBtn.textContent = 'Hide';
        } else {
            form.style.display = 'none';
            toggleBtn.textContent = 'Show';
        }
    }

    /**
     * Handle manual ARN analysis
     */
    async handleManualArnAnalyze() {
        const arnInput = document.getElementById('manual-policy-arn');
        const arn = arnInput.value.trim();

        if (!arn) {
            this.showError('Please enter a policy ARN');
            return;
        }

        // Basic ARN validation
        if (!arn.startsWith('arn:aws:iam::')) {
            this.showError('Invalid ARN format. Expected: arn:aws:iam::ACCOUNT:policy/NAME or arn:aws:iam::aws:policy/NAME');
            return;
        }

        await this.showPolicyDetail(arn);
    }

    /**
     * Handle AWS connection
     */
    async handleConnect(event) {
        event.preventDefault();

        const accessKeyId = document.getElementById('accessKeyId').value.trim();
        const secretAccessKey = document.getElementById('secretAccessKey').value.trim();
        const sessionToken = document.getElementById('sessionToken').value.trim();
        const region = document.getElementById('region').value;

        if (!accessKeyId || !secretAccessKey) {
            this.showError('Please provide AWS Access Key ID and Secret Access Key');
            return;
        }

        const connectBtn = document.getElementById('connect-btn');
        connectBtn.disabled = true;
        connectBtn.textContent = 'Connecting...';

        try {
            // Initialize AWS handler
            awsHandler.initialize(accessKeyId, secretAccessKey, sessionToken, region);

            // Test connection using STS GetCallerIdentity
            const testResult = await awsHandler.testConnection();
            
            if (!testResult.success) {
                this.showError(`Connection failed: ${testResult.error}`);
                connectBtn.disabled = false;
                connectBtn.textContent = 'Connect';
                return;
            }

            // Connection successful - show identity info
            this.showSuccess('Connected successfully! Loading policies...');
            
            // Display identity information
            this.displayIdentityInfo(testResult.identity);
            
            // Hide credential form, show explorer
            document.getElementById('credential-section').style.display = 'none';
            document.getElementById('explorer-section').style.display = 'block';
            
            // Load policies
            await this.loadPolicies();

        } catch (error) {
            this.showError(`Error: ${error.message}`);
            connectBtn.disabled = false;
            connectBtn.textContent = 'Connect';
        }
    }

    /**
     * Display the current AWS identity info
     */
    displayIdentityInfo(identity) {
        const identityInfo = document.getElementById('identity-info');
        const identityArn = document.getElementById('identity-arn');
        
        if (identityInfo && identityArn && identity) {
            identityArn.textContent = identity.arn;
            identityInfo.style.display = 'flex';
        }
    }

    /**
     * Handle disconnect
     */
    handleDisconnect() {
        if (confirm('Are you sure you want to disconnect? Your credentials will be cleared from memory.')) {
            awsHandler.disconnect();
            
            // Clear form
            document.getElementById('credential-form').reset();
            
            // Reset UI
            document.getElementById('credential-section').style.display = 'block';
            document.getElementById('explorer-section').style.display = 'none';
            document.getElementById('policy-list').innerHTML = '';
            document.getElementById('policy-detail').style.display = 'none';
            
            // Hide identity info and limited mode notice
            const identityInfo = document.getElementById('identity-info');
            if (identityInfo) identityInfo.style.display = 'none';
            
            const limitedNotice = document.getElementById('limited-permissions-notice');
            if (limitedNotice) limitedNotice.style.display = 'none';
            
            // Reset manual ARN form
            const manualArnForm = document.getElementById('manual-arn-form');
            if (manualArnForm) manualArnForm.style.display = 'none';
            const toggleBtn = document.getElementById('toggle-manual-arn');
            if (toggleBtn) toggleBtn.textContent = 'Show';
            const manualArnInput = document.getElementById('manual-policy-arn');
            if (manualArnInput) manualArnInput.value = '';
            
            // Reset state
            this.allPolicies = [];
            this.filteredPolicies = [];
            this.currentPolicy = null;
            this.isLimitedMode = false;
            this.inlinePolicies = [];
            
            const connectBtn = document.getElementById('connect-btn');
            connectBtn.disabled = false;
            connectBtn.textContent = 'Connect';
            
            this.clearMessages();
        }
    }

    /**
     * Load all policies from AWS
     */
    async loadPolicies() {
        const loadingIndicator = document.getElementById('loading-indicator');
        const policyList = document.getElementById('policy-list');
        const statsSection = document.getElementById('policy-stats');
        const searchSection = document.getElementById('search-section');
        const limitedNotice = document.getElementById('limited-permissions-notice');
        const manualArnSection = document.getElementById('manual-arn-section');

        loadingIndicator.style.display = 'block';
        policyList.style.display = 'none';
        statsSection.style.display = 'none';
        searchSection.style.display = 'none';
        if (limitedNotice) limitedNotice.style.display = 'none';

        try {
            const result = await awsHandler.listAllPolicies();

            if (!result.success) {
                this.showError(`Failed to load policies: ${result.error}`);
                loadingIndicator.style.display = 'none';
                
                // Even if we can't list policies, show the manual ARN section
                if (manualArnSection) {
                    manualArnSection.style.display = 'block';
                    // Auto-expand the manual ARN form
                    const form = document.getElementById('manual-arn-form');
                    const toggleBtn = document.getElementById('toggle-manual-arn');
                    if (form) form.style.display = 'flex';
                    if (toggleBtn) toggleBtn.textContent = 'Hide';
                }
                return;
            }

            // Check if we're in limited mode
            this.isLimitedMode = result.mode === 'limited';
            
            // Store inline policies separately
            this.inlinePolicies = result.data.inlinePolicies || [];

            // Combine all policies
            this.allPolicies = [
                ...result.data.awsManaged.map(p => ({ ...p, type: 'aws-managed' })),
                ...result.data.customerManaged.map(p => ({ ...p, type: 'customer-managed' })),
                ...this.inlinePolicies.map(p => ({ ...p, type: 'inline' }))
            ];

            this.filteredPolicies = [...this.allPolicies];

            // Update statistics
            PolicyVisualizer.updateStats({
                total: this.allPolicies.length,
                awsManaged: result.data.awsManaged.length,
                customerManaged: result.data.customerManaged.length
            });

            // Show limited permissions notice if applicable
            if (this.isLimitedMode && limitedNotice) {
                limitedNotice.style.display = 'flex';
            }

            // Render policy list
            this.renderPolicies();

            // Show UI elements
            loadingIndicator.style.display = 'none';
            policyList.style.display = 'block';
            statsSection.style.display = 'grid';
            searchSection.style.display = 'grid';
            
            // Show success message in limited mode
            if (this.isLimitedMode && result.message) {
                this.showSuccess(result.message);
            }

        } catch (error) {
            this.showError(`Error loading policies: ${error.message}`);
            loadingIndicator.style.display = 'none';
        }
    }

    /**
     * Render the policy list
     */
    renderPolicies() {
        const policyListElement = document.getElementById('policy-list');
        PolicyVisualizer.renderPolicyList(this.filteredPolicies, policyListElement);

        // Add click listeners to policy items
        const policyItems = policyListElement.querySelectorAll('.policy-item');
        policyItems.forEach(item => {
            item.addEventListener('click', () => {
                const policyArn = item.dataset.policyArn;
                this.showPolicyDetail(policyArn);
            });
        });
    }

    /**
     * Handle search input
     */
    handleSearch(searchTerm) {
        const term = searchTerm.toLowerCase();
        const filterValue = document.getElementById('policy-filter').value;

        this.filteredPolicies = this.allPolicies.filter(policy => {
            const matchesSearch = policy.PolicyName.toLowerCase().includes(term) ||
                                policy.Arn.toLowerCase().includes(term) ||
                                (policy.Description && policy.Description.toLowerCase().includes(term));
            
            const matchesFilter = filterValue === 'all' || policy.type === filterValue;

            return matchesSearch && matchesFilter;
        });

        this.renderPolicies();
    }

    /**
     * Handle filter dropdown
     */
    handleFilter(filterValue) {
        const searchTerm = document.getElementById('policy-search').value.toLowerCase();

        this.filteredPolicies = this.allPolicies.filter(policy => {
            const matchesSearch = !searchTerm || 
                                policy.PolicyName.toLowerCase().includes(searchTerm) ||
                                (policy.Arn && policy.Arn.toLowerCase().includes(searchTerm)) ||
                                (policy.Description && policy.Description.toLowerCase().includes(searchTerm));
            
            let matchesFilter;
            if (filterValue === 'all') {
                matchesFilter = true;
            } else if (filterValue === 'attached') {
                matchesFilter = policy.isAttachedToUser || policy.isInline;
            } else {
                matchesFilter = policy.type === filterValue;
            }

            return matchesSearch && matchesFilter;
        });

        this.renderPolicies();
    }

    /**
     * Show policy detail view
     */
    async showPolicyDetail(policyArn) {
        const policyList = document.getElementById('policy-list');
        const policyDetail = document.getElementById('policy-detail');
        const searchSection = document.getElementById('search-section');
        const statsSection = document.getElementById('policy-stats');
        const loadingIndicator = document.getElementById('loading-indicator');

        // Hide list, show loading
        policyList.style.display = 'none';
        searchSection.style.display = 'none';
        statsSection.style.display = 'none';
        loadingIndicator.style.display = 'block';

        try {
            let result;
            
            // Check if this is an inline policy (identified by inline: prefix)
            if (policyArn.startsWith('inline:')) {
                // Find the inline policy in our stored list
                const inlineId = policyArn.substring(7); // Remove 'inline:' prefix
                const [userName, policyName] = inlineId.split('/');
                const inlinePolicy = this.inlinePolicies.find(p => 
                    p.PolicyName === policyName && p.userName === userName
                );
                
                if (inlinePolicy) {
                    result = awsHandler.getInlinePolicyInfo(inlinePolicy);
                } else {
                    this.showError('Inline policy not found');
                    this.showPolicyList();
                    return;
                }
            } else {
                result = await awsHandler.getCompletePolicyInfo(policyArn);
            }

            if (!result.success) {
                this.showError(`Failed to load policy details: ${result.error}`);
                loadingIndicator.style.display = 'none';
                this.showPolicyList();
                return;
            }

            this.currentPolicy = result.data;
            this.currentPolicyArn = policyArn;

            // Determine policy type
            let policyType = 'Customer Managed';
            if (result.data.policy.isInline) {
                policyType = 'Inline Policy';
            } else if (result.data.policy.Arn && result.data.policy.Arn.includes(':aws:policy/')) {
                policyType = 'AWS Managed';
            }

            // Update detail view
            document.getElementById('detail-policy-name').textContent = result.data.policy.PolicyName;
            document.getElementById('detail-policy-arn').textContent = result.data.policy.Arn || 'N/A (Inline Policy)';
            document.getElementById('detail-policy-type').textContent = policyType;
            document.getElementById('detail-policy-created').textContent = 
                PolicyVisualizer.formatDate(result.data.policy.CreateDate);
            document.getElementById('detail-policy-updated').textContent = 
                PolicyVisualizer.formatDate(result.data.policy.UpdateDate);

            // Render versions list (inline policies don't have versions)
            const versionsList = document.getElementById('version-list');
            if (result.data.policy.isInline) {
                versionsList.innerHTML = '<p class="caption">Inline policies do not have versions</p>';
            } else {
                PolicyVisualizer.renderVersionsList(
                    result.data.allVersions,
                    result.data.policy.DefaultVersionId,
                    versionsList,
                    (versionId) => this.handleSetDefaultVersion(policyArn, versionId)
                );

                // Setup version checkbox listeners
                this.setupVersionCheckboxListeners();
            }

            // Run security analysis
            this.currentSecurityAnalysis = analyzePolicyForShadowAdmin(result.data.currentVersion.Document);

            // Render policy content
            const visualContent = document.getElementById('policy-content-visual');
            PolicyVisualizer.renderPolicyVisual(result.data.currentVersion.Document, visualContent);

            const jsonContent = document.getElementById('policy-content-json');
            PolicyVisualizer.renderPolicyJson(result.data.currentVersion.Document, jsonContent);

            // Render security analysis
            const securityContent = document.getElementById('policy-content-security');
            SecurityVisualizer.renderSecurityAnalysis(this.currentSecurityAnalysis, securityContent);

            // Show detail view (default to security tab)
            loadingIndicator.style.display = 'none';
            policyDetail.style.display = 'block';

        } catch (error) {
            this.showError(`Error loading policy details: ${error.message}`);
            loadingIndicator.style.display = 'none';
            this.showPolicyList();
        }
    }

    /**
     * Show policy list view
     */
    showPolicyList() {
        const policyList = document.getElementById('policy-list');
        const policyDetail = document.getElementById('policy-detail');
        const searchSection = document.getElementById('search-section');
        const statsSection = document.getElementById('policy-stats');

        policyDetail.style.display = 'none';
        policyList.style.display = 'block';
        searchSection.style.display = 'grid';
        statsSection.style.display = 'grid';

        this.currentPolicy = null;
        this.currentPolicyArn = null;
    }

    /**
     * Handle view toggle between security, visual, and JSON
     */
    handleViewToggle(view) {
        const securityContent = document.getElementById('policy-content-security');
        const visualContent = document.getElementById('policy-content-visual');
        const expansionContent = document.getElementById('policy-content-expansion');
        const jsonContent = document.getElementById('policy-content-json');
        const toggleBtns = document.querySelectorAll('.toggle-btn');

        // Update button states
        toggleBtns.forEach(btn => {
            if (btn.dataset.view === view) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });

        // Toggle content
        if (view === 'security') {
            securityContent.style.display = 'block';
            visualContent.style.display = 'none';
            expansionContent.style.display = 'none';
            jsonContent.style.display = 'none';
        } else if (view === 'visual') {
            securityContent.style.display = 'none';
            visualContent.style.display = 'block';
            expansionContent.style.display = 'none';
            jsonContent.style.display = 'none';
        } else if (view === 'expansion') {
            securityContent.style.display = 'none';
            visualContent.style.display = 'none';
            expansionContent.style.display = 'block';
            jsonContent.style.display = 'none';

            // Render expansion analysis
            this.renderExpansionAnalysis();
        } else {
            securityContent.style.display = 'none';
            visualContent.style.display = 'none';
            expansionContent.style.display = 'none';
            jsonContent.style.display = 'block';
        }
    }

    /**
     * Render policy expansion analysis
     */
    renderExpansionAnalysis() {
        const expansionContent = document.getElementById('policy-content-expansion');

        if (!this.currentPolicy || !this.policyExpansion) {
            expansionContent.innerHTML = '<p class="caption">No policy loaded for expansion analysis</p>';
            return;
        }

        try {
            // Get the policy document
            const policyDocument = this.currentPolicy.Document;

            // Analyze expansion
            const analysisResult = this.policyExpansion.analyzePolicy(policyDocument);

            // Render the analysis
            PolicyVisualizer.renderPolicyExpansion(analysisResult, expansionContent);

        } catch (error) {
            console.error('Error analyzing policy expansion:', error);
            expansionContent.innerHTML = `<p class="caption error">Error analyzing policy: ${error.message}</p>`;
        }
    }

    /**
     * Handle setting a policy version as default
     */
    async handleSetDefaultVersion(policyArn, versionId) {
        if (!confirm(`Are you sure you want to set ${versionId} as the default version?`)) {
            return;
        }

        const loadingIndicator = document.getElementById('loading-indicator');
        loadingIndicator.style.display = 'block';

        try {
            const result = await awsHandler.setDefaultPolicyVersion(policyArn, versionId);

            if (!result.success) {
                this.showError(`Failed to set default version: ${result.error}`);
                loadingIndicator.style.display = 'none';
                return;
            }

            this.showSuccess(result.message);
            
            // Reload policy details
            await this.showPolicyDetail(policyArn);

        } catch (error) {
            this.showError(`Error setting default version: ${error.message}`);
            loadingIndicator.style.display = 'none';
        }
    }

    /**
     * Show error message
     */
    showError(message) {
        const errorElement = document.getElementById('error-message');
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.style.display = 'block';
            
            // Hide success message
            const successElement = document.getElementById('success-message');
            if (successElement) {
                successElement.style.display = 'none';
            }

            // Auto-hide after 10 seconds
            setTimeout(() => {
                errorElement.style.display = 'none';
            }, 10000);
        }
    }

    /**
     * Show success message
     */
    showSuccess(message) {
        const successElement = document.getElementById('success-message');
        if (successElement) {
            successElement.textContent = message;
            successElement.style.display = 'block';
            
            // Hide error message
            const errorElement = document.getElementById('error-message');
            if (errorElement) {
                errorElement.style.display = 'none';
            }

            // Auto-hide after 5 seconds
            setTimeout(() => {
                successElement.style.display = 'none';
            }, 5000);
        }
    }

    /**
     * Clear all messages
     */
    clearMessages() {
        const errorElement = document.getElementById('error-message');
        const successElement = document.getElementById('success-message');
        
        if (errorElement) errorElement.style.display = 'none';
        if (successElement) successElement.style.display = 'none';
    }

    /**
     * Setup event listeners for version checkboxes
     */
    setupVersionCheckboxListeners() {
        const checkboxes = document.querySelectorAll('.version-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.addEventListener('change', () => this.updateCompareButton());
        });
    }

    /**
     * Update compare button visibility based on selected versions
     */
    updateCompareButton() {
        const compareBtn = document.getElementById('compare-versions-btn');
        const checkboxes = document.querySelectorAll('.version-checkbox:checked');
        
        if (checkboxes.length === 2) {
            compareBtn.style.display = 'inline-block';
        } else {
            compareBtn.style.display = 'none';
        }
    }

    /**
     * Handle compare versions button click
     */
    async handleCompareVersions() {
        const checkboxes = document.querySelectorAll('.version-checkbox:checked');
        
        if (checkboxes.length !== 2) {
            this.showError('Please select exactly 2 versions to compare');
            return;
        }

        const versionIds = Array.from(checkboxes).map(cb => cb.dataset.versionId);
        
        // Fetch both versions
        const loadingIndicator = document.getElementById('loading-indicator');
        loadingIndicator.style.display = 'block';

        try {
            const version1Result = await awsHandler.getPolicyVersion(this.currentPolicyArn, versionIds[0]);
            const version2Result = await awsHandler.getPolicyVersion(this.currentPolicyArn, versionIds[1]);

            if (!version1Result.success || !version2Result.success) {
                this.showError('Failed to load policy versions for comparison');
                loadingIndicator.style.display = 'none';
                return;
            }

            // Sort versions by date (older first, newer second)
            const versions = [version1Result.data, version2Result.data];
            versions.sort((a, b) => new Date(a.CreateDate) - new Date(b.CreateDate));

            // Show comparison (older on left, newer on right)
            const comparisonSection = document.getElementById('version-comparison-section');
            const comparisonContent = document.getElementById('version-comparison-content');
            
            PolicyVisualizer.renderVersionComparison(
                versions[0], // Older version (left)
                versions[1], // Newer version (right)
                comparisonContent
            );

            comparisonSection.style.display = 'block';
            
            // Scroll to comparison
            comparisonSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

            loadingIndicator.style.display = 'none';

        } catch (error) {
            this.showError(`Error comparing versions: ${error.message}`);
            loadingIndicator.style.display = 'none';
        }
    }

    /**
     * Close version comparison view
     */
    closeVersionComparison() {
        const comparisonSection = document.getElementById('version-comparison-section');
        comparisonSection.style.display = 'none';

        // Uncheck all version checkboxes
        const checkboxes = document.querySelectorAll('.version-checkbox');
        checkboxes.forEach(cb => cb.checked = false);

        // Hide compare button
        this.updateCompareButton();
    }
}

// Initialize the application when DOM is ready AND AWS SDK is loaded
function initApp() {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => initApp());
        return;
    }
    
    if (!window.awsSdkLoaded) {
        window.addEventListener('aws-sdk-loaded', () => initApp());
        return;
    }
    
    new App();
}

initApp();

