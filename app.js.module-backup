/**
 * Main Application Module
 * Coordinates UI interactions and AWS operations
 */

import { awsHandler, analyzePolicyForShadowAdmin } from './aws-handler.js';
import { PolicyVisualizer, SecurityVisualizer } from './policy-visualizer.js';

class App {
    constructor() {
        this.allPolicies = [];
        this.filteredPolicies = [];
        this.currentPolicy = null;
        this.currentPolicyArn = null;
        this.currentSecurityAnalysis = null;
        
        this.init();
    }

    /**
     * Initialize the application
     */
    init() {
        this.setupEventListeners();
        console.log('AWS Policy Explorer initialized');
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

            // Test connection
            const testResult = await awsHandler.testConnection();
            
            if (!testResult.success) {
                this.showError(`Connection failed: ${testResult.error}`);
                connectBtn.disabled = false;
                connectBtn.textContent = 'Connect';
                return;
            }

            // Connection successful
            this.showSuccess('Connected successfully! Loading policies...');
            
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
            
            // Reset state
            this.allPolicies = [];
            this.filteredPolicies = [];
            this.currentPolicy = null;
            
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

        loadingIndicator.style.display = 'block';
        policyList.style.display = 'none';
        statsSection.style.display = 'none';
        searchSection.style.display = 'none';

        try {
            const result = await awsHandler.listAllPolicies();

            if (!result.success) {
                this.showError(`Failed to load policies: ${result.error}`);
                loadingIndicator.style.display = 'none';
                return;
            }

            // Combine all policies
            this.allPolicies = [
                ...result.data.awsManaged.map(p => ({ ...p, type: 'aws-managed' })),
                ...result.data.customerManaged.map(p => ({ ...p, type: 'customer-managed' }))
            ];

            this.filteredPolicies = [...this.allPolicies];

            // Update statistics
            PolicyVisualizer.updateStats({
                total: this.allPolicies.length,
                awsManaged: result.data.awsManaged.length,
                customerManaged: result.data.customerManaged.length
            });

            // Render policy list
            this.renderPolicies();

            // Show UI elements
            loadingIndicator.style.display = 'none';
            policyList.style.display = 'block';
            statsSection.style.display = 'grid';
            searchSection.style.display = 'grid';

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
                                policy.Arn.toLowerCase().includes(searchTerm) ||
                                (policy.Description && policy.Description.toLowerCase().includes(searchTerm));
            
            const matchesFilter = filterValue === 'all' || policy.type === filterValue;

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
            const result = await awsHandler.getCompletePolicyInfo(policyArn);

            if (!result.success) {
                this.showError(`Failed to load policy details: ${result.error}`);
                this.showPolicyList();
                return;
            }

            this.currentPolicy = result.data;
            this.currentPolicyArn = policyArn;

            // Update detail view
            document.getElementById('detail-policy-name').textContent = result.data.policy.PolicyName;
            document.getElementById('detail-policy-arn').textContent = result.data.policy.Arn;
            document.getElementById('detail-policy-type').textContent = 
                result.data.policy.Arn.includes(':aws:policy/') ? 'AWS Managed' : 'Customer Managed';
            document.getElementById('detail-policy-created').textContent = 
                PolicyVisualizer.formatDate(result.data.policy.CreateDate);
            document.getElementById('detail-policy-updated').textContent = 
                PolicyVisualizer.formatDate(result.data.policy.UpdateDate);

            // Render versions list
            const versionsList = document.getElementById('version-list');
            PolicyVisualizer.renderVersionsList(
                result.data.allVersions,
                result.data.policy.DefaultVersionId,
                versionsList,
                (versionId) => this.handleSetDefaultVersion(policyArn, versionId)
            );

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
            jsonContent.style.display = 'none';
        } else if (view === 'visual') {
            securityContent.style.display = 'none';
            visualContent.style.display = 'block';
            jsonContent.style.display = 'none';
        } else {
            securityContent.style.display = 'none';
            visualContent.style.display = 'none';
            jsonContent.style.display = 'block';
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
}

// Initialize the application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new App();
});

