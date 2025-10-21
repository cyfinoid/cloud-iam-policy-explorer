# GitHub Pages Deployment Guide

## Overview

This repository is configured to automatically deploy to GitHub Pages when a release is created. The deployment includes only the necessary files for the web application to run.

---

## Automatic Deployment

### Trigger: Release Creation

The deployment is triggered when you create a release on GitHub.

**Steps to Deploy:**

1. **Create a Git Tag**
   ```bash
   git tag -a v1.1.1 -m "Version 1.1.1 - Improved diff styling"
   git push origin v1.1.1
   ```

2. **Create Release on GitHub**
   - Go to your repository on GitHub
   - Click "Releases" → "Draft a new release"
   - Choose the tag you just created (v1.1.1)
   - Fill in release notes
   - Click "Publish release"

3. **Automatic Deployment**
   - GitHub Actions automatically starts
   - Builds and deploys to GitHub Pages
   - Usually takes 1-2 minutes

4. **Access Your Site**
   - URL: `https://YOUR_USERNAME.github.io/REPO_NAME/`
   - Or check the Actions tab for the deployment URL

---

## Files Deployed

### ✅ Included in Deployment

**Application Files:**
- `index.html` - Main application page
- `styles.css` - All styles with Cyfinoid branding
- `aws-handler.js` - AWS SDK interactions
- `policy-visualizer.js` - Policy rendering logic
- `app.js` - Main application logic

**Documentation:**
- `README.md` - Main documentation
- `docs/` - Additional documentation files

**Configuration:**
- `.nojekyll` - Prevents Jekyll processing

### ❌ Excluded from Deployment

**Test Scripts:**
- `*.sh` files (setup, cleanup, demo scripts)
- Test account configurations

**Development Files:**
- `.gitignore`
- `version.txt`
- `.github/` directory
- Build and configuration files

---

## Manual Deployment

You can also trigger deployment manually:

1. Go to "Actions" tab on GitHub
2. Select "Deploy to GitHub Pages" workflow
3. Click "Run workflow"
4. Choose branch
5. Click "Run workflow"

---

## GitHub Pages Setup

### First-Time Setup

1. **Enable GitHub Pages:**
   - Go to repository Settings
   - Navigate to "Pages" section
   - Under "Source", select "GitHub Actions"
   - Save

2. **Verify Permissions:**
   The workflow needs these permissions (already configured):
   - `contents: read` - Read repository files
   - `pages: write` - Deploy to Pages
   - `id-token: write` - OIDC token for deployment

3. **Access URL:**
   Your site will be available at:
   ```
   https://YOUR_USERNAME.github.io/REPO_NAME/
   ```

---

## Workflows

### 1. Deploy to GitHub Pages (`deploy-pages.yml`)

**Triggers:**
- Release created or published
- Manual trigger via workflow_dispatch

**What it does:**
1. Checks out the repository
2. Copies only necessary files to `deploy/` directory
3. Creates `.nojekyll` file
4. Uploads artifact
5. Deploys to GitHub Pages
6. Shows deployment URL

**View logs:**
- Go to Actions tab
- Click on the workflow run
- View detailed logs

### 2. Verify Build (`verify-build.yml`)

**Triggers:**
- Push to main/master branch
- Pull requests

**What it does:**
1. Checks all required files exist
2. Validates HTML syntax
3. Verifies ES6 module usage
4. Checks cache-busting parameters
5. Provides summary

---

## Version Management

### Before Creating a Release

1. **Update version number:**
   ```bash
   # In version.txt
   echo "1.1.2" > version.txt
   
   # In index.html (update ?v= parameters)
   # styles.css?v=1.1.2
   # aws-handler.js?v=1.1.2
   # policy-visualizer.js?v=1.1.2
   # app.js?v=1.1.2
   ```

2. **Commit changes:**
   ```bash
   git add .
   git commit -m "Bump version to 1.1.2"
   git push
   ```

3. **Create tag and release** (see above)

---

## Troubleshooting

### Deployment Failed

**Check Actions Tab:**
1. Go to repository → Actions
2. Find the failed workflow
3. Click to view logs
4. Look for error messages

**Common Issues:**

1. **Missing files:**
   - Ensure all files are committed
   - Check file names match exactly

2. **Permissions error:**
   - Go to Settings → Actions → General
   - Under "Workflow permissions"
   - Select "Read and write permissions"
   - Save

3. **Pages not enabled:**
   - Go to Settings → Pages
   - Source should be "GitHub Actions"

### Site Not Loading

1. **Check deployment status:**
   - Actions tab → Latest deployment
   - Should show green checkmark

2. **Check Pages settings:**
   - Settings → Pages
   - "Your site is live at..." should be visible

3. **Cache issues:**
   - Hard refresh: Ctrl+Shift+R (Windows/Linux) or Cmd+Shift+R (Mac)
   - Cache-busting versions prevent most issues

4. **Console errors:**
   - Open browser DevTools (F12)
   - Check Console tab for errors
   - Usually CORS or module loading issues

### CORS Errors

GitHub Pages serves over HTTPS, which works with ES6 modules.

If you see CORS errors:
1. Ensure files are in the root of the deployed directory
2. Check `.nojekyll` file exists
3. Verify import paths in JS files are correct

---

## Testing Before Release

### Local Testing

Always test locally before creating a release:

```bash
# Start local server
./start-server.sh

# Or
python3 -m http.server 8000

# Open: http://localhost:8000
# Test all functionality
```

### Verify Build Action

The verify-build action runs on every push to main, catching issues early.

---

## Deployment Checklist

Before creating a release:

- [ ] All features tested locally
- [ ] Version number updated in version.txt
- [ ] Cache-busting versions updated in index.html
- [ ] README.md updated with changes
- [ ] Commit and push all changes
- [ ] Create git tag
- [ ] Create GitHub release
- [ ] Monitor deployment in Actions tab
- [ ] Verify site works at GitHub Pages URL
- [ ] Test with different browsers

---

## Example Release Notes

```markdown
## Version 1.1.1 - Improved Diff Styling

### Features
- Improved version comparison diff styling
- Removed strikethrough for better readability
- Added git-style +/− indicators
- Enhanced visual clarity

### Bug Fixes
- Fixed emoji auto-conversion in policy text
- Resolved checkbox overlap with buttons

### Technical
- Global emoji prevention in CSS
- Cache-busting version parameters
```

---

## URLs and Access

### Production URL
```
https://YOUR_USERNAME.github.io/aws-policy-explorer/
```

### Custom Domain (Optional)

To use a custom domain:

1. Go to Settings → Pages
2. Under "Custom domain", enter your domain
3. Add CNAME record in your DNS:
   ```
   CNAME YOUR_USERNAME.github.io
   ```
4. Enable "Enforce HTTPS"

---

## Monitoring

### Check Deployment Status

**Via GitHub Interface:**
- Repository → Actions → Latest workflow run

**Via API:**
```bash
curl -H "Authorization: token YOUR_TOKEN" \
  https://api.github.com/repos/YOUR_USERNAME/REPO_NAME/deployments
```

### View Logs

1. Actions tab
2. Click workflow run
3. Expand "build" and "deploy" jobs
4. View detailed logs

---

## Rollback

To rollback to a previous version:

1. **Find previous release:**
   - Go to Releases
   - Find the version you want to rollback to

2. **Delete current release:**
   - Click "Delete" on the current release
   - This won't re-deploy old version automatically

3. **Redeploy old version:**
   - Go to Actions
   - Find successful deployment from old release
   - Click "Re-run jobs"

Or manually:
```bash
git checkout v1.1.0  # Tag of old version
# Create new release from this tag
```

---

## Security Notes

### Credentials in Browser

- This application runs 100% client-side
- AWS credentials entered by users stay in browser memory
- Never stored on GitHub Pages
- Never transmitted to any server except AWS APIs

### HTTPS

- GitHub Pages automatically uses HTTPS
- Secure for credential input
- Prevents man-in-the-middle attacks

---

## Support

For issues with:
- **Deployment:** Check Actions logs
- **Application bugs:** Open an issue
- **GitHub Pages:** See [GitHub Pages docs](https://docs.github.com/en/pages)

---

**Last Updated:** Version 1.1.1
**Maintained by:** Cyfinoid Team

