# Secure Credential Management - Quick Reference Card

## 🚀 Quick Start (5 minutes)

```bash
# 1. Create .env file
cp .env.example .env

# 2. Add your credentials to .env
nano .env

# 3. Test it works
python -c "from shared import CredentialManager; print('✓ Ready!' if CredentialManager().get_secret('NVD_API_KEY') else '✗ Missing NVD_API_KEY')"
```

## 📚 Documentation Map

| Need | Read | Time |
|------|------|------|
| Get started | [CREDENTIAL_SETUP.md](./CREDENTIAL_SETUP.md) | 20 min |
| New to team | [CREDENTIAL_ONBOARDING.md](./CREDENTIAL_ONBOARDING.md) | 10 min |
| Use in code | [CREDENTIAL_MANAGEMENT.md](./CREDENTIAL_MANAGEMENT.md) | 30 min |
| Security check | [CREDENTIAL_SECURITY_CHECKLIST.md](./CREDENTIAL_SECURITY_CHECKLIST.md) | 15 min |
| Deploy to prod | [CREDENTIAL_MANAGEMENT.md - Production](./CREDENTIAL_MANAGEMENT.md#production-deployment) | 30 min |
| All docs | [CREDENTIAL_DOCUMENTATION_INDEX.md](./CREDENTIAL_DOCUMENTATION_INDEX.md) | 5 min |

## 💻 Code Examples

### Get a Credential
```python
from shared import CredentialManager

creds = CredentialManager()
key = creds.get_secret("NVD_API_KEY", required=True)
```

### Validate Required
```python
missing = creds.validate_required()
if missing:
    print(f"Missing: {missing}")
    exit(1)
```

### Get All for Component
```python
nvd_creds = creds.get_secrets("nvd")
talon_creds = creds.get_secrets("talon")
```

### Audit Log
```python
import json
audit = creds.audit_log()
print(json.dumps(audit, indent=2))
```

## 🔐 Security Rules

✅ DO
- Store .env in home directory
- Use strong API keys
- Keep credentials secure
- Report compromises immediately
- Ask for help if unsure

❌ DON'T
- Commit .env to git
- Share credentials via email
- Hardcode secrets in code
- Paste credentials in chat
- Use same key for everything

## 📋 Common Tasks

### Add a New Credential
```bash
# 1. Get from team lead
# 2. Add to .env: NEWKEY=value
# 3. Use in code: creds.get_secret("NEWKEY")
```

### Fix "Missing Credential" Error
```bash
# Check 1: File exists?
ls -la .env

# Check 2: Has the key?
grep KEYNAME .env

# Check 3: Fix it
echo "KEYNAME=value" >> .env
```

### Test Your Setup
```bash
pytest tests/shared/test_credentials.py -v
```

## 🌐 Supported Services

| Service | Key | Required |
|---------|-----|----------|
| NVD | NVD_API_KEY | ✅ |
| GitHub | GITHUB_TOKEN | ✅ |
| HackerOne | HACKERONE_API_KEY | ⚠️ |
| Talon | TALON_API_KEY | ✅ |
| Database | DATABASE_URL | ⚠️ |
| Redis | REDIS_URL | ⚠️ |
| Twilio | TWILIO_* | ⚠️ |
| Slack | SLACK_WEBHOOK_URL | ⚠️ |

Legend: ✅ Required | ⚠️ Optional

## 🐛 Troubleshooting

### Problem: "Missing required credential"
```bash
# Solution:
echo "CREDENTIAL_NAME=your_value" >> .env
```

### Problem: ".env not found"
```bash
# Solution:
cp .env.example .env
```

### Problem: "Permission denied"
```bash
# Solution:
chmod 600 .env
```

### Problem: "Can't import CredentialManager"
```bash
# Solution:
python -c "from shared import CredentialManager"
# If that fails, check: ls shared/credentials.py
```

## 📊 File Structure

```
shared/
├── credentials.py        ← Core module
└── __init__.py          ← Exports

tests/shared/
└── test_credentials.py  ← Tests (19 tests)

.env.example             ← Template
.env                     ← Your credentials (ignored by git)

Documentation:
├── CREDENTIAL_SETUP.md
├── CREDENTIAL_MANAGEMENT.md
├── CREDENTIAL_ONBOARDING.md
├── CREDENTIAL_SECURITY_CHECKLIST.md
├── CREDENTIAL_IMPLEMENTATION_SUMMARY.md
├── CREDENTIAL_DOCUMENTATION_INDEX.md
└── CREDENTIAL_COMPLETION_REPORT.md
```

## ✅ Status Check

```bash
# All working?
python -c "
from shared import CredentialManager
creds = CredentialManager()
print(f'✓ Loaded {len(creds.credentials)} credentials')
missing = creds.validate_required()
print(f'✓ All required present' if not missing else f'✗ Missing: {missing}')
"
```

## 🎯 Production Checklist

- [ ] All required credentials obtained
- [ ] .env file created and filled
- [ ] Credentials load without errors
- [ ] Tests pass: `pytest tests/`
- [ ] .gitignore includes .env
- [ ] No credentials in code
- [ ] Ready to deploy

## 📞 Getting Help

1. **Quick issue**: See "Troubleshooting" above
2. **Need details**: Read [CREDENTIAL_SETUP.md](./CREDENTIAL_SETUP.md)
3. **Using in code**: Read [CREDENTIAL_MANAGEMENT.md](./CREDENTIAL_MANAGEMENT.md)
4. **Security check**: Use [CREDENTIAL_SECURITY_CHECKLIST.md](./CREDENTIAL_SECURITY_CHECKLIST.md)
5. **Team help**: Ask in #lucius-dev Slack

## 🔗 Quick Links

| Link | Purpose |
|------|---------|
| [Setup](./CREDENTIAL_SETUP.md) | Get started |
| [API Ref](./CREDENTIAL_MANAGEMENT.md) | Use in code |
| [Security](./CREDENTIAL_SECURITY_CHECKLIST.md) | Verify safety |
| [Tests](./tests/shared/test_credentials.py) | Code examples |
| [Config](./CREDENTIAL_DOCUMENTATION_INDEX.md) | All resources |

## 💡 Pro Tips

1. **Development**: Use .env file
2. **Production**: Use environment variables
3. **Testing**: Use temporary .env files
4. **Security**: Enable audit logging
5. **Monitoring**: Check audit logs regularly

## 📈 Test Results

```
Total: 235 tests
Passed: 235 ✅
Failed: 0
Status: READY FOR PRODUCTION
```

## 🎓 Learning Path

1. **5 min**: Read this quick reference
2. **10 min**: Read [CREDENTIAL_ONBOARDING.md](./CREDENTIAL_ONBOARDING.md)
3. **20 min**: Follow [CREDENTIAL_SETUP.md](./CREDENTIAL_SETUP.md)
4. **30 min**: Read [CREDENTIAL_MANAGEMENT.md](./CREDENTIAL_MANAGEMENT.md)
5. **Start coding**: Use examples from [tests](./tests/shared/test_credentials.py)

---

**Need More Help?** See [CREDENTIAL_DOCUMENTATION_INDEX.md](./CREDENTIAL_DOCUMENTATION_INDEX.md)

**Report Issues?** Check [CREDENTIAL_SECURITY_CHECKLIST.md](./CREDENTIAL_SECURITY_CHECKLIST.md)

**Got Questions?** Email your team lead or ask in #lucius-dev

---

*Secure Credential Management System - Ready to Use*
