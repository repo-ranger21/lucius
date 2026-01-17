# Lucius Git Branching Strategy

## 📊 Branch Structure

### **Core Branches** (Long-lived)

#### `main`
- **Purpose**: Production-ready code
- **Protection**: Protected branch, requires PR + reviews
- **Deployment**: Auto-deploys to production
- **Merge From**: `release/*` and `hotfix/*` only
- **Never**: Direct commits

#### `develop`
- **Purpose**: Integration branch for active development
- **Protection**: Protected, requires PR
- **Deployment**: Auto-deploys to development environment
- **Merge From**: `feature/*`, `bugfix/*`, `release/*`, `hotfix/*`
- **Default Branch**: For new feature development

#### `staging`
- **Purpose**: Pre-production testing and QA validation
- **Protection**: Protected, requires PR
- **Deployment**: Auto-deploys to staging environment
- **Merge From**: `develop` (via release branches)
- **Testing**: Full integration, security, and performance testing

---

## 🌿 Supporting Branches (Short-lived)

### `feature/*`
- **Purpose**: New features and enhancements
- **Created From**: `develop`
- **Merged Into**: `develop`
- **Naming**: `feature/scanner-type`, `feature/api-enhancement`
- **Lifetime**: Deleted after merge

**Example:**
```bash
git checkout develop
git checkout -b feature/dast-scanner
# ... work on feature ...
git push -u origin feature/dast-scanner
# Create PR to develop
```

### `bugfix/*`
- **Purpose**: Bug fixes for develop branch
- **Created From**: `develop`
- **Merged Into**: `develop`
- **Naming**: `bugfix/fix-description`
- **Lifetime**: Deleted after merge

### `hotfix/*`
- **Purpose**: Urgent production fixes
- **Created From**: `main`
- **Merged Into**: `main` AND `develop`
- **Naming**: `hotfix/critical-cve-fix`
- **Lifetime**: Deleted after merge

**Example:**
```bash
git checkout main
git checkout -b hotfix/cve-2024-xxxx
# ... fix critical issue ...
git checkout main
git merge hotfix/cve-2024-xxxx
git checkout develop
git merge hotfix/cve-2024-xxxx
git branch -d hotfix/cve-2024-xxxx
```

### `release/*`
- **Purpose**: Release preparation and final testing
- **Created From**: `develop`
- **Merged Into**: `main` AND `develop`
- **Naming**: `release/v1.2.0`
- **Lifetime**: Deleted after merge

**Example:**
```bash
git checkout develop
git checkout -b release/v1.2.0
# ... bump version, update changelog, final testing ...
git checkout main
git merge release/v1.2.0
git tag -a v1.2.0 -m "Release v1.2.0"
git checkout develop
git merge release/v1.2.0
git branch -d release/v1.2.0
```

---

## 🚀 Workflow Examples

### **Feature Development** (Standard)

```bash
# 1. Start from latest develop
git checkout develop
git pull origin develop

# 2. Create feature branch
git checkout -b feature/ml-threat-analysis

# 3. Develop feature
# ... code, test, commit ...

# 4. Push and create PR
git push -u origin feature/ml-threat-analysis

# 5. Create PR on GitHub: feature/ml-threat-analysis → develop
# 6. After review and merge, delete branch
git branch -d feature/ml-threat-analysis
git push origin --delete feature/ml-threat-analysis
```

### **Release Process**

```bash
# 1. Create release branch from develop
git checkout develop
git pull origin develop
git checkout -b release/v1.3.0

# 2. Prepare release
# - Update version in pyproject.toml, __init__.py
# - Update CHANGELOG.md
# - Run final tests
# - Fix any release-blocking issues

# 3. Merge to staging for QA
git checkout staging
git merge release/v1.3.0
git push origin staging

# 4. After QA approval, merge to main
git checkout main
git pull origin main
git merge --no-ff release/v1.3.0

# 5. Tag the release
git tag -a v1.3.0 -m "Release v1.3.0: Advanced Scanning Features"
git push origin main --tags

# 6. Merge back to develop
git checkout develop
git merge --no-ff release/v1.3.0
git push origin develop

# 7. Delete release branch
git branch -d release/v1.3.0
git push origin --delete release/v1.3.0
```

### **Hotfix Process** (Emergency)

```bash
# 1. Create hotfix from main
git checkout main
git pull origin main
git checkout -b hotfix/critical-sql-injection

# 2. Fix the issue
# ... make fix, test thoroughly ...

# 3. Merge to main
git checkout main
git merge --no-ff hotfix/critical-sql-injection
git tag -a v1.2.1 -m "Hotfix v1.2.1: SQL injection fix"
git push origin main --tags

# 4. Merge to develop
git checkout develop
git merge --no-ff hotfix/critical-sql-injection
git push origin develop

# 5. Merge to staging (if active)
git checkout staging
git merge --no-ff hotfix/critical-sql-injection
git push origin staging

# 6. Delete hotfix branch
git branch -d hotfix/critical-sql-injection
git push origin --delete hotfix/critical-sql-injection
```

---

## 🔒 Branch Protection Rules (GitHub Settings)

### **`main` Branch**
```yaml
Protection Settings:
  ✓ Require pull request before merging
    ✓ Require approvals: 2
    ✓ Dismiss stale reviews
    ✓ Require review from Code Owners
  ✓ Require status checks to pass
    - CI tests
    - Security scan (Bandit, Semgrep)
    - License compliance
    - Code coverage > 80%
  ✓ Require conversation resolution
  ✓ Require signed commits
  ✓ Include administrators
  ✓ Restrict who can push
  ✓ Allow force pushes: OFF
  ✓ Allow deletions: OFF
```

### **`develop` Branch**
```yaml
Protection Settings:
  ✓ Require pull request before merging
    ✓ Require approvals: 1
  ✓ Require status checks to pass
    - CI tests
    - Security scan
    - Linting (ruff, mypy)
  ✓ Require conversation resolution
  ✓ Allow force pushes: OFF
  ✓ Allow deletions: OFF
```

### **`staging` Branch**
```yaml
Protection Settings:
  ✓ Require pull request before merging
    ✓ Require approvals: 1
  ✓ Require status checks to pass
    - CI tests
    - Integration tests
  ✓ Allow force pushes: OFF
```

---

## 📝 Commit Message Convention

Follow **Conventional Commits** specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### **Types**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Build process, dependencies, etc.
- `security`: Security fixes
- `ci`: CI/CD changes

### **Examples**

```bash
feat(scanner): add DAST dynamic analysis scanner

Implements dynamic application security testing with:
- Active vulnerability probing
- Authentication handling
- Session management
- Request/response analysis

Closes #123

---

fix(remediation): handle version comparison edge cases

Fixes version parsing for pre-release versions and build metadata.

Fixes #456

---

security(secrets): add detection for Azure credentials

Adds patterns for Azure Storage Account keys and SAS tokens.

CVE: N/A
CVSS: N/A
```

---

## 🎯 Quick Reference

### **Daily Development**
```bash
# Start work
git checkout develop
git pull origin develop
git checkout -b feature/my-feature

# Commit often
git add .
git commit -m "feat(scope): description"

# Push and PR
git push -u origin feature/my-feature
# Create PR on GitHub
```

### **Sync with develop**
```bash
git checkout develop
git pull origin develop
git checkout feature/my-feature
git merge develop
# Resolve conflicts if any
git push origin feature/my-feature
```

### **Check branch status**
```bash
git branch -a                    # List all branches
git log --oneline --graph --all  # Visual branch history
git status                       # Current branch status
```

---

## 🔄 CI/CD Integration

### **Automated Deployments**

| Branch | Environment | Trigger | Tests |
|--------|-------------|---------|-------|
| `main` | Production | Merge to main | Full suite + security |
| `staging` | Staging | Merge to staging | Integration + E2E |
| `develop` | Development | Merge to develop | Unit + Integration |
| `feature/*` | Preview | Push | Unit tests |

### **Required Checks**

All PRs must pass:
1. ✅ All tests (pytest)
2. ✅ Code coverage > 80%
3. ✅ Linting (ruff, black)
4. ✅ Type checking (mypy)
5. ✅ Security scan (bandit, semgrep)
6. ✅ License compliance
7. ✅ Dependency audit (pip-audit)

---

## 🛠️ Setup Instructions

### **Initial Repository Setup**

```bash
# Clone repository
git clone https://github.com/Lucius-SecOps/lucius.git
cd lucius

# Fetch all branches
git fetch origin

# Set up local branches
git checkout -b develop origin/develop
git checkout -b staging origin/staging
git checkout main

# Configure Git
git config pull.rebase false
git config core.autocrlf input
git config commit.gpgsign true  # If using signed commits
```

### **Push Core Branches to Remote**

```bash
# From main branch
git checkout main

# Create and push develop
git checkout -b develop
git push -u origin develop

# Create and push staging
git checkout -b staging
git push -u origin staging

# Return to main
git checkout main
```

### **Configure GitHub Settings**

1. **Settings** → **Branches** → **Add rule**
2. Apply protection rules (see above)
3. **Settings** → **General** → **Default branch** → Set to `develop`
4. **Settings** → **Actions** → Enable workflow permissions

---

## 📚 Best Practices

### **DO:**
- ✅ Always create feature branches from `develop`
- ✅ Keep commits atomic and focused
- ✅ Write descriptive commit messages
- ✅ Rebase feature branches on develop regularly
- ✅ Delete branches after merge
- ✅ Tag releases on main
- ✅ Run tests before pushing

### **DON'T:**
- ❌ Commit directly to main, develop, or staging
- ❌ Force push to protected branches
- ❌ Merge without PR review
- ❌ Commit secrets or credentials
- ❌ Commit large binary files
- ❌ Leave stale branches

---

## 🆘 Troubleshooting

### **"My branch is behind develop"**
```bash
git checkout develop
git pull origin develop
git checkout your-branch
git rebase develop
git push --force-with-lease origin your-branch
```

### **"I committed to the wrong branch"**
```bash
# If not pushed yet
git reset --soft HEAD~1  # Undo commit, keep changes
git stash                 # Save changes
git checkout correct-branch
git stash pop            # Apply changes
git add .
git commit -m "..."
```

### **"I need to undo a commit"**
```bash
# If not pushed
git reset --soft HEAD~1  # Undo commit, keep changes
git reset --hard HEAD~1  # Undo commit, discard changes

# If pushed (creates revert commit)
git revert HEAD
git push origin your-branch
```

### **"Merge conflict!"**
```bash
# 1. Identify conflicting files
git status

# 2. Open files and resolve conflicts
# Look for <<<<<<< HEAD markers

# 3. Mark as resolved
git add resolved-file.py

# 4. Complete merge
git commit -m "fix: resolve merge conflicts"
```

---

## 📊 Branch Lifecycle

```
┌─────────────────────────────────────────────────────────┐
│                         main                            │
│              (Production - Protected)                    │
└──────▲──────────────────────────▲──────────────────────┘
       │                           │
       │ release/v1.x.0            │ hotfix/critical-fix
       │                           │
┌──────┴──────────────────────────┴──────────────────────┐
│                       develop                            │
│              (Integration - Protected)                   │
└──▲────▲────▲────────────────────────────────────────────┘
   │    │    │
   │    │    └── feature/new-scanner
   │    └──────── bugfix/fix-typo
   └───────────── feature/api-v2
```

---

**Created by**: Lucius Security Team
**Last Updated**: 2026-01-17
**Version**: 1.0
