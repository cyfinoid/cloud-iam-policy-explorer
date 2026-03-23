# Agent and contributor guide

This document orients anyone (including coding agents) working on **AWS Policy Explorer** (Cyfinoid): a static, client-side web app for exploring IAM policies, comparing versions, and running security analysis including shadow-admin style checks. All AWS calls run in the user’s browser; credentials are not sent to this repository or any Cyfinoid server.

## Tech stack

- **No bundler or Node build step.** The shipped app is plain HTML, CSS, and browser JavaScript.
- **AWS SDK v3** is loaded from a CDN via an **import map** in `index.html`, then re-exposed on `window` (`IAMClient`, `STSClient`, commands, `awsSdkLoaded`, and an `aws-sdk-loaded` event).
- **Application code** is loaded as classic `<script src="…">` files (not ES modules). They rely on globals from earlier tags and from the SDK bootstrap block.

## Repository layout

| Path | Role |
|------|------|
| `index.html` | Shell UI, import map, SDK bootstrap module, script tags and cache-busting query params |
| `styles.css` | Global styling |
| `app.js` | `App` class: wiring, navigation, orchestration |
| `aws-handler.js` | `AWSHandler`, IAM/STS usage, `analyzePolicyForShadowAdmin` |
| `policy-visualizer.js` | `PolicyVisualizer`, `SecurityVisualizer`, list/detail/version UI and diff-style views |
| `policy-expansion.js` | `PolicyExpansion` (expanded/effective permission style analysis) |
| `version.txt` | Human-readable version notes; **instructions for bumping cache-busting** |
| `start-server.sh` | Serves the repo root over HTTP (needed for import maps / modules) |
| `.github/workflows/verify-build.yml` | CI: required files, basic HTML/JS checks |
| `.github/workflows/deploy-pages.yml` | Publishes a fixed set of root files to GitHub Pages (on release or manual run) |
| `test-scripts/` | AWS CLI helpers for setting up/cleaning up demo IAM accounts; use `.env` from `.env.example` |

The `projects/` tree and other captured third-party assets under git status are not part of the core app; do not treat them as the source of truth for this tool unless a task explicitly says otherwise.

## Local development

1. From the repository root, run `./start-server.sh` (or any static server on the project root). Opening `index.html` as a `file://` URL is unreliable because of ES modules and the import map.
2. Use real or test credentials only in the browser form or in a local `.env` for shell scripts—never commit them.

## Architecture notes

- **Load order** (see `index.html`): inline module (SDK → globals) → `policy-visualizer.js` → `policy-expansion.js` → `aws-handler.js` → `app.js`.
- **Shadow-admin-style logic** lives in `aws-handler.js` (`analyzePolicyForShadowAdmin`); **presentation** of that analysis is in `policy-visualizer.js` (`SecurityVisualizer`). Conceptually this traces to Pacu’s `iam__privesc_scan` research (see `README.md`).
- **`PolicyExpansion`** may fail initialization gracefully; `app.js` continues with reduced functionality if expansion data does not load.

## Changing the app

- Prefer **small, focused edits** that match existing patterns (plain classes, `static` helpers, DOM APIs, minimal new abstractions).
- When you change behavior users would notice, update `README.md` only if the user-facing story actually changed.
- **Cache busting:** After meaningful changes to `styles.css` or any root `.js` asset, bump the `?v=` query string on those URLs in `index.html` and align with the process described in `version.txt` (keep `version.txt` and `index.html` consistent to avoid confusion).

## Verification and CI

There is no unit test runner in-repo. **CI** (`.github/workflows/verify-build.yml`) checks:

- Presence of: `index.html`, `styles.css`, `aws-handler.js`, `policy-visualizer.js`, `policy-expansion.js`, `app.js`, `README.md`
- Basic `index.html` structure (`<!DOCTYPE html>`, closing `</html>`)
- Expected class names in the JS files and hints about import map / SDK globals / `?v=` on assets

Before pushing, sanity-check the app in a browser against a safe AWS account or mock usage.

## Deployment

**GitHub Pages** deployment (`.github/workflows/deploy-pages.yml`) copies a specific list of files into `deploy/` and uploads that artifact. **`AGENTS.md` is intentionally not deployed** (repository guidance only). If you add a new root asset required at runtime, add it to that copy step **and** to `verify-build.yml`’s required-file list if it should block broken releases.

## Security and compliance

- **Do not** commit credentials, `.env`, keys, or customer data. `.gitignore` already excludes common cases; extend it if you introduce new secret paths.
- The app is **GPLv3** (`LICENSE`). New dependencies or copied code must remain compatible with that license.
- Treat this as a security-auditing tool: document behavior honestly; avoid weakening checks for convenience without explicit product intent.

## What agents should avoid

- Introducing a build pipeline, framework rewrite, or large refactors unless the maintainer explicitly requests it.
- Committing contents of `junk/`, local `docs/` trees, or one-off scraped sites unless the task is to vendor them deliberately.
- Storing or exfiltrating AWS credentials from user input.

When in doubt, mirror the style of the file you are editing and keep the static, no-build deployment model intact.
