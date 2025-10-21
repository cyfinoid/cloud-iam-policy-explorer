# AWS Policy Explorer

A client-side web application for exploring and managing AWS IAM policies. Built with vanilla HTML/CSS/JavaScript and styled according to Cyfinoid branding guidelines.

## Features

- **Secure Credential Handling**: Enter AWS credentials directly in the browser - never stored or transmitted to any server
- **Policy Discovery**: Automatically fetch and list all IAM policies (AWS Managed and Customer Managed)
- **Shadow Admin Detection**: Automated security analysis identifying 23+ privilege escalation paths and shadow admin scenarios
- **Visual & JSON Views**: View policies in both human-readable visual format and raw JSON
- **Policy Search & Filter**: Search policies by name, ARN, or description; filter by type
- **Version Management**: View all policy versions and set a specific version as default
- **Risk Scoring**: Automatic risk assessment with color-coded severity levels (0-10 scale)
- **Security Recommendations**: Actionable remediation advice for each detected issue
- **Modern UI**: Clean, responsive design following Cyfinoid branding guidelines

## Getting Started

### Prerequisites

- AWS account with IAM access
- AWS credentials (Access Key ID and Secret Access Key)
- Modern web browser with ES6 module support
- Web server (to serve files with proper MIME types)

### AWS Configuration

The test scripts support multiple configuration methods to keep your base Python installation clean:

#### Option 1: Quick Configuration Wizard (Recommended)
```bash
./configure.sh
```

This interactive wizard will:
- Install AWS CLI with `uv` (isolated from system Python)
- Set up AWS profiles or direct credentials
- Create a `.env` file with your configuration
- Verify AWS access

#### Option 2: Using AWS Profiles
```bash
# Use a specific AWS profile
export AWS_PROFILE=your-test-profile
./setup-test-accounts.sh

# Or pass it directly
./setup-test-accounts.sh --profile your-test-profile
```

#### Option 3: Using .env File
```bash
# Copy the example
cp .env.example .env

# Edit with your configuration
nano .env

# Scripts will automatically load it
./setup-test-accounts.sh
```

#### Option 4: Install AWS CLI with uv
```bash
# Install AWS CLI in project-local virtual environment
./setup-aws-cli.sh

# This creates .venv/ with AWS CLI - no base Python pollution!
```

See [AWS-CONFIG-GUIDE.md](AWS-CONFIG-GUIDE.md) for detailed configuration options.

### Testing with Pre-configured Scenarios

For comprehensive testing, use the provided test account setup scripts:

```bash
# Create test accounts with various privilege escalation scenarios
./setup-test-accounts.sh

# After testing, clean up all test resources
./cleanup-test-accounts.sh
```

See [TESTING-GUIDE.md](TESTING-GUIDE.md) for detailed testing instructions and scenarios.

**⚠️ Only run test scripts in sandbox/test AWS accounts, never in production!**

### Installation

**Important:** This application uses ES6 modules and must be served over HTTP/HTTPS (not file://). You need to run a local web server.

#### Quick Start - Use the Provided Script

```bash
./start-server.sh
```

Then open your browser to: **http://localhost:8000**

#### Alternative Server Options

**Python 3:**
```bash
python3 -m http.server 8000
```

**Python 2:**
```bash
python -m SimpleHTTPServer 8000
```

**PHP:**
```bash
php -S localhost:8000
```

**Node.js:**
```bash
npx http-server -p 8000
```

**Demo Script (Interactive):**
```bash
./demo.sh
```

Then open your browser to: **http://localhost:8000**

> ⚠️ **Why a server?** This app uses modern ES6 modules which browsers block on `file://` protocol for security. See [docs/CORS-ISSUE-EXPLAINED.md](docs/CORS-ISSUE-EXPLAINED.md) for details.

### Usage

1. **Connect to AWS**
   - Enter your AWS Access Key ID
   - Enter your AWS Secret Access Key
   - (Optional) Enter Session Token for temporary credentials
   - Select your AWS region
   - Click "Connect"

2. **Browse Policies**
   - View statistics on total policies
   - Use the search bar to find specific policies
   - Filter by AWS Managed or Customer Managed policies
   - Click on any policy to view details

3. **View Policy Details**
   - **Security Analysis Tab**: Automated privilege escalation and shadow admin detection
     - Risk level assessment (Critical/High/Medium/Low/Safe)
     - Detected escalation methods with descriptions
     - Security issues grouped by severity
     - Remediation recommendations
   - **Visual Tab**: Human-readable policy display
   - **JSON Tab**: Raw policy document
   - Explore all policy versions
   - Set a different version as default (if you have permissions)

4. **Disconnect**
   - Click "Disconnect" to clear credentials from memory
   - Your credentials are never saved to disk or cookies

## Required AWS Permissions

To use all features of this application, your AWS credentials should have the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListPolicyVersions",
        "iam:SetDefaultPolicyVersion"
      ],
      "Resource": "*"
    }
  ]
}
```

**Note**: `iam:SetDefaultPolicyVersion` is only required if you want to change default policy versions.

## Security Considerations

- **Client-Side Only**: All operations run in your browser. No server-side components.
- **Credentials**: Stored in memory only, cleared on disconnect or page refresh.
- **HTTPS Recommended**: Use HTTPS in production to encrypt credential transmission.
- **Permissions**: Grant minimum required IAM permissions to credentials.
- **Browser Security**: Ensure your browser is up to date for best security practices.

## File Structure

```
/
├── index.html           # Main HTML structure
├── styles.css           # Cyfinoid-branded styles
├── app.js              # Core application logic
├── aws-handler.js      # AWS SDK integration
├── policy-visualizer.js # Policy rendering & visualization
├── brandguideline.md   # Cyfinoid branding specifications
└── README.md           # This file
```

## Technology Stack

- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **AWS SDK**: AWS SDK for JavaScript v3 (loaded from CDN)
- **Font**: Sen (Google Fonts)
- **Architecture**: Single Page Application (SPA)

## Branding

This application follows the Cyfinoid branding guidelines:

### Colors
- Primary Background: `#121212`
- Primary Text: `#50c878` (Emerald Green)
- Secondary Text: `#8a8f98`
- Accent Colors: Yellow `#fdcb52`, Red `#d63c53`, Blue `#466fe0`

### Typography
- Font Family: Sen
- Title: 42px
- Heading: 32px
- Body: 16px

## Shadow Admin Detection (Implemented)

The application now includes comprehensive security analysis to identify privilege escalation paths and shadow admin scenarios:

### Detection Categories

1. **IAM Policy Manipulation** (8 methods)
   - CreateNewPolicyVersion, SetExistingDefaultPolicyVersion
   - AttachUserPolicy, AttachGroupPolicy, AttachRolePolicy
   - PutUserPolicy, PutGroupPolicy, PutRolePolicy

2. **IAM Principal Manipulation** (5 methods)
   - AddUserToGroup, CreateAccessKey, CreateLoginProfile
   - UpdateLoginProfile, UpdateRolePolicyToAssumeIt

3. **PassRole Privilege Escalation** (11 methods)
   - EC2, Lambda, DynamoDB, Glue, CloudFormation
   - DataPipeline, CodeStar integrations

4. **CodeStar Special Methods** (2 methods)
   - Undocumented API exploits

5. **Dangerous Permission Patterns**
   - Wildcard actions (`Action: "*"`)
   - Wildcard resources (`Resource: "*"`)
   - Full admin detection (`Action: "*"` on `Resource: "*"`)

### Risk Scoring

- **Critical (10/10)**: Full admin or direct privilege escalation
- **High (7-9/10)**: PassRole with compute services, credential manipulation
- **Medium (4-6/10)**: Limited escalation capabilities
- **Low (1-3/10)**: Minor security concerns

### Security Analysis Features

- Real-time policy analysis on policy load
- Color-coded risk indicators
- Detailed escalation method descriptions
- Required permissions for each method
- Actionable remediation recommendations
- Statistics dashboard (total issues, critical/high/medium counts)

For implementation details, see `shadow-admin-logic.md`.

## Browser Compatibility

- Chrome 90+
- Firefox 88+
- Safari 15+
- Edge 90+

ES6 modules and AWS SDK v3 require modern browser support.

## Troubleshooting

### "Failed to connect to AWS"
- Verify your credentials are correct
- Check that your IAM user/role has required permissions
- Ensure the selected region is correct
- Check browser console for detailed error messages

### "CORS Error"
- Make sure you're serving files through a web server (not `file://`)
- AWS SDK CDN should be accessible from your network

### Policies Not Loading
- Verify IAM permissions include `iam:ListPolicies`
- Check AWS service availability in your region
- Review browser console for API errors

### Cannot Set Default Version
- Ensure credentials have `iam:SetDefaultPolicyVersion` permission
- Only customer-managed policies can have their default version changed
- AWS managed policies are read-only

## Credits & Acknowledgments

### Shadow Admin Detection Logic

The privilege escalation detection methods implemented in this tool are based on research from the [**Pacu**](https://github.com/RhinoSecurityLabs/pacu) framework by Rhino Security Labs. Pacu is an open-source AWS exploitation framework designed for offensive security testing.

Specifically, the shadow admin detection logic was derived from Pacu's `iam__privesc_scan` module, which identifies 23+ distinct privilege escalation paths in AWS IAM policies. We are grateful to the Rhino Security Labs team and the Pacu contributors for their excellent research and tooling.

**Pacu Repository:** https://github.com/RhinoSecurityLabs/pacu

### Development

This tool was developed with the assistance of AI (Claude by Anthropic) to accelerate development, ensure code quality, and implement comprehensive security analysis features. The AI assistance included:
- Code architecture and implementation
- Security analysis logic translation from Pacu
- Documentation and testing framework
- Configuration system design

While AI-assisted, all code has been reviewed, tested, and validated for production use.

## License

This project is provided as-is for educational and internal use.

The shadow admin detection logic is based on the [Pacu framework](https://github.com/RhinoSecurityLabs/pacu), which is licensed under the BSD-3-Clause License.

## Contributing

This is an internal Cyfinoid tool. For questions or improvements, please contact the security team.

---

**Cyfinoid** - AWS Policy Explorer v1.0


