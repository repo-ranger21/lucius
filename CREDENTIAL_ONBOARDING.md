# Team Credential Management Onboarding Guide

Welcome to the Lucius platform! This guide helps you set up secure credential management as a team member.

## 5-Minute Quick Start

### 1. Get Your API Keys
Ask your team lead for:
- NVD API key
- GitHub token
- Any other required keys for your role

### 2. Create `.env` File
```bash
cd /Users/chris-peterson/Documents/GitHub/lucius/lucius-workspace
cp .env.example .env
nano .env  # Edit with your credentials
```

### 3. Test It Works
```bash
python -c "from shared import CredentialManager; print('✓ Working!' if CredentialManager().get_secret('NVD_API_KEY') else '✗ Missing NVD_API_KEY')"
```

### 4. You're Done! ✅
Start developing with secure credentials.

## Role-Based Setup

### Backend Developer

**Required Credentials**:
- NVD_API_KEY - for vulnerability scanning
- GITHUB_TOKEN - for source code access
- TALON_API_KEY - for internal testing

**Setup Steps**:
```bash
# 1. Create .env file
cp .env.example .env

# 2. Ask team lead for credentials
# 3. Add to .env file

# 4. Verify all working
pytest tests/  # All tests should pass
```

**Using in Code**:
```python
from shared import CredentialManager

creds = CredentialManager()
nvd_key = creds.get_secret("NVD_API_KEY", required=True)
```

### DevOps / Infrastructure

**Required Credentials**:
- All of the above
- DATABASE_PASSWORD - for database access
- REDIS_URL - for cache configuration

**Production Setup**:
- Store credentials in AWS Secrets Manager or Azure Key Vault
- Never use `.env` files in production
- Enable audit logging

**Verification Steps**:
```bash
# Test production configuration
python -c "from shared import CredentialManager; cm = CredentialManager(); print(cm.validate_required())"
```

### QA / Testing

**Required Credentials**:
- Test credentials (provided in tests)
- Optional: Production-like credentials for staging

**Testing with Credentials**:
```python
import tempfile
from pathlib import Path
from shared import CredentialManager

def test_with_credentials():
    with tempfile.TemporaryDirectory() as tmpdir:
        env_file = Path(tmpdir) / ".env"
        env_file.write_text("NVD_API_KEY=test_key")
        creds = CredentialManager(env_file=env_file)
        # Your test here
```

## Common Tasks

### Task: Run Tests

```bash
# All tests
pytest tests/

# Credential tests only
pytest tests/shared/test_credentials.py -v

# With coverage
pytest tests/ --cov=shared
```

### Task: Update a Credential

```bash
# 1. Edit .env file
nano .env

# 2. Change the value
OLD_VALUE=value
NEW_VALUE=value  # Change this

# 3. No need to restart - loads on next import
```

### Task: Check Which Credentials Are Loaded

```python
from shared import CredentialManager
import json

creds = CredentialManager()
audit = creds.audit_log()

print("Loaded credentials:")
for name in audit.keys():
    print(f"  ✓ {name}")

print("\nMissing required:")
for missing in creds.validate_required():
    print(f"  ✗ {missing}")
```

### Task: Debug Credential Issues

```bash
# Check .env file exists
ls -la .env

# Check environment variables
echo $NVD_API_KEY

# Check permissions
ls -la .env  # Should show -rw------- (600)

# Run diagnostic
python -c "
from shared import CredentialManager
creds = CredentialManager()
print('Loaded:', len(creds.credentials))
print('Missing:', creds.validate_required())
"
```

### Task: Add a New Credential

1. **Ask your team lead** for the new credential
2. **Add to .env.example** (without value):
   ```dotenv
   # NEW_SERVICE_API_KEY=
   ```
3. **Add to .env**:
   ```dotenv
   NEW_SERVICE_API_KEY=your_value_here
   ```
4. **Use in code**:
   ```python
   from shared import CredentialManager
   creds = CredentialManager()
   key = creds.get_secret("NEW_SERVICE_API_KEY")
   ```

## Security Reminders

### DO ✅
- Store .env in your user home directory
- Use strong, unique API keys
- Keep credentials secure
- Report compromised credentials immediately
- Update credentials when asked
- Rotate credentials when they expire
- Use password managers for local credentials
- Ask for help if unsure

### DON'T ❌
- Commit .env to version control
- Share credentials via email
- Paste credentials in chat or logs
- Hardcode secrets in code
- Use the same key for different services
- Leave credentials on shared computers
- Share your .env file
- Print credentials for debugging

## Troubleshooting

### "CredentialError: Missing required credential 'NVD_API_KEY'"

**Check**:
```bash
# 1. File exists?
ls -la .env

# 2. Has the key?
grep NVD_API_KEY .env

# 3. Has a value?
grep "NVD_API_KEY=" .env

# 4. Environment?
echo $NVD_API_KEY
```

**Fix**:
```bash
# Add to .env
echo "NVD_API_KEY=your_key_here" >> .env

# Or edit manually
nano .env
```

### ".env not found"

**Fix**:
```bash
# Create from template
cp .env.example .env

# Add your credentials
nano .env
```

### "Permission denied" reading .env

**Fix**:
```bash
# Fix permissions
chmod 600 .env

# Verify
ls -la .env
# Should show: -rw------- (600)
```

### "Credential loading slowly"

**Normal behavior** - First load takes ~1ms, subsequent loads are instant (credentials cached).

If tests hang:
- Check .env file is valid
- Check permissions: `chmod 600 .env`
- Restart Python interpreter

### "Can't import CredentialManager"

**Check**:
```python
# Should work
from shared import CredentialManager

# Or
from shared.credentials import CredentialManager
```

**If not**:
```bash
# Verify module exists
ls shared/credentials.py

# Check __init__.py exports
grep CredentialManager shared/__init__.py
```

## Getting Help

### Resources
1. **Setup Guide**: [CREDENTIAL_SETUP.md](./CREDENTIAL_SETUP.md)
2. **Full Reference**: [CREDENTIAL_MANAGEMENT.md](./CREDENTIAL_MANAGEMENT.md)
3. **Code Examples**: [tests/shared/test_credentials.py](./tests/shared/test_credentials.py)
4. **Team Contacts**: Ask in #lucius-dev Slack channel

### Common Questions

**Q: Should I commit my .env file?**
A: No! It's in `.gitignore`. Never commit secrets.

**Q: Can I use different credentials for testing?**
A: Yes! Tests automatically use isolated temporary credentials.

**Q: What if my key expires?**
A: Ask your team lead for a new one. Update .env and restart your application.

**Q: Can multiple people share .env credentials?**
A: No! Each developer gets their own credentials for tracking/auditing.

**Q: What if I see a credential in git history?**
A: Report immediately to your team lead. We'll rotate the credential.

**Q: How do I know which credentials I need?**
A: Check the required list:
   ```python
   from shared.credentials import CredentialManager
   print(CredentialManager.REQUIRED_CREDENTIALS)
   ```

## First Day Checklist

- [ ] Cloned Lucius repository
- [ ] Created .env file from .env.example
- [ ] Received API keys from team lead
- [ ] Added credentials to .env
- [ ] Ran `pytest tests/` - all pass ✓
- [ ] Can import CredentialManager without errors
- [ ] Understand "never commit .env" rule
- [ ] Know who to ask for help (#lucius-dev)
- [ ] Know how to rotate credentials
- [ ] Know security best practices

## Team Lead: Credential Onboarding

When adding a new team member:

1. **Provide credentials** for their role:
   ```
   - NVD API key
   - GitHub token
   - Any role-specific keys
   ```

2. **Point to setup guide**:
   ```
   Read CREDENTIAL_SETUP.md
   Follow the steps
   Ask if stuck
   ```

3. **Verify setup**:
   ```bash
   # Ask them to run
   pytest tests/ --tb=short
   # All tests should pass
   ```

4. **Add to audit**:
   ```
   - Document key distribution
   - Record access dates
   - Set rotation reminders
   ```

5. **Onboarding complete** when:
   - [ ] Developer has .env file created
   - [ ] All credentials added
   - [ ] Tests passing
   - [ ] Understands security practices
   - [ ] Knows how to report issues

## Production Deployment

**For DevOps/Deployment Engineers**:

```bash
# Development
.env file loaded automatically

# Staging
Set environment variables
Verify with: python -c "from shared import CredentialManager; CredentialManager().validate_required()"

# Production
Use secret manager (AWS, Azure, etc.)
Set environment variables from secret manager
Enable audit logging
Test credential loading before serving requests
```

See [CREDENTIAL_MANAGEMENT.md](./CREDENTIAL_MANAGEMENT.md) for production setup details.

## Security Review Checklist

**Monthly reviews**:
- [ ] All team members have personal credentials
- [ ] No shared .env files
- [ ] Audit log shows expected access
- [ ] No suspicious activity detected
- [ ] Expired credentials rotated
- [ ] Unused credentials revoked

**Quarterly**:
- [ ] All credentials rotated
- [ ] Access logs reviewed
- [ ] Compliance verified
- [ ] Team trained on updates

## Next Steps

1. **Complete setup**: Follow first day checklist above
2. **Read documentation**: Review CREDENTIAL_SETUP.md (10 minutes)
3. **Review examples**: Look at tests/shared/test_credentials.py
4. **Start developing**: Use CredentialManager in your code
5. **Ask questions**: Reach out in #lucius-dev if stuck

---

**Welcome to the team!** 🎉 

If you have any questions about credentials or security, ask your team lead or reach out in #lucius-dev.

*Last Updated: 2024*
*Questions? See CREDENTIAL_MANAGEMENT.md or ask your team lead.*
