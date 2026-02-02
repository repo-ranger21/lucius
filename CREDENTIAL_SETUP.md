# Secure Credential Setup Guide

This quick-start guide walks you through setting up secure credentials for the Lucius platform.

## Prerequisites

- Python 3.8+
- Access to the required third-party APIs
- A terminal/command line interface

## Step 1: Obtain Required API Keys

### 1.1 NVD API Key (Required)

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Click "Request API Key"
3. Fill in your information
4. Check your email for the API key
5. Save the key securely

### 1.2 GitHub Token (Recommended)

1. Visit: https://github.com/settings/tokens
2. Click "Generate new token"
3. Select scopes: `read:packages`, `repo` (for private repos)
4. Copy the token
5. Save securely (GitHub won't show it again)

### 1.3 HackerOne API Key (Optional)

1. Visit: https://hackerone.com/settings/api
2. Create a new API token
3. Save securely

### 1.4 Other Services (Optional)

- **Twilio**: https://console.twilio.com/
- **SendGrid**: https://sendgrid.com/marketing/sendgrid-free-marketing-email/
- **Slack**: Create a webhook at https://api.slack.com/apps

## Step 2: Create Local `.env` File

```bash
# Navigate to project root
cd /Users/chris-peterson/Documents/GitHub/lucius/lucius-workspace

# Copy the example file
cp .env.example .env

# Edit with your credentials
nano .env  # or use your preferred editor
```

## Step 3: Fill In Required Credentials

Edit `.env` and add your credentials:

```dotenv
# Database (keep defaults for local development)
POSTGRES_USER=lucius
POSTGRES_PASSWORD=lucius_secret
POSTGRES_DB=lucius_db
DATABASE_URL=postgresql://lucius:lucius_secret@localhost:5432/lucius_db

# Redis (keep defaults for local development)
REDIS_URL=redis://localhost:6379/0

# NVD API (REQUIRED - from step 1.1)
NVD_API_KEY=your_nvd_api_key_here

# GitHub (RECOMMENDED - from step 1.2)
GITHUB_TOKEN=your_github_token_here

# Talon (internal - keep as-is for local development)
TALON_API_URL=http://localhost:5000
TALON_API_KEY=local-development-key

# Optional: HackerOne
HACKERONE_API_KEY=your_h1_api_key_here

# Other optional services...
```

## Step 4: Verify Credentials Load

Run a quick test:

```python
# test_creds.py
from shared.credentials import CredentialManager

creds = CredentialManager()

# List all loaded credentials
audit = creds.audit_log()
print(f"✓ Loaded {len(audit)} credentials:")
for name in audit.keys():
    print(f"  - {name}")

# Validate required credentials
missing = creds.validate_required()
if missing:
    print(f"\n⚠ Missing credentials: {missing}")
    exit(1)
else:
    print("\n✓ All required credentials present")
```

Run it:

```bash
python test_creds.py
```

Expected output:

```
✓ Loaded 15 credentials:
  - POSTGRES_USER
  - POSTGRES_PASSWORD
  - DATABASE_URL
  - NVD_API_KEY
  - TALON_API_KEY
  - ... (etc)

✓ All required credentials present
```

## Step 5: Protect Your Credentials

Ensure `.gitignore` includes:

```bash
# ~/.gitignore or .gitignore in project
.env
.env.local
.env.*.local
*.key
*.pem
secrets/
```

Verify it's working:

```bash
git status | grep .env
# Should show nothing (file is ignored)
```

## Step 6: Use Credentials in Code

### In Services

```python
from shared.credentials import CredentialManager

class NVDService:
    def __init__(self):
        self.creds = CredentialManager()
        self.api_key = self.creds.get_secret("NVD_API_KEY", required=True)
    
    def fetch_data(self):
        # Use self.api_key
        pass
```

### In Configuration

```python
from shared.credentials import CredentialManager

creds = CredentialManager()

# Validate on startup
missing = creds.validate_required()
if missing:
    raise RuntimeError(f"Missing: {missing}")

# Use in config
DATABASE_URL = creds.get_secret("DATABASE_URL")
NVD_API_KEY = creds.get_secret("NVD_API_KEY", required=True)
```

### In Tests

```python
import tempfile
from pathlib import Path
from shared.credentials import CredentialManager

def test_with_credentials():
    with tempfile.TemporaryDirectory() as tmpdir:
        env_file = Path(tmpdir) / ".env"
        env_file.write_text("""
NVD_API_KEY=test_key
TALON_API_KEY=test_talon_key
DATABASE_URL=sqlite:///:memory:
""")
        
        creds = CredentialManager(env_file=env_file)
        
        # Run your test with test credentials
        result = my_function(creds.get_secret("NVD_API_KEY"))
        assert result is not None
```

## Step 7: Production Deployment

For production environments, **NEVER use `.env` files**. Instead:

### Option A: Use System Environment Variables

```bash
# Set via environment
export NVD_API_KEY="production_key"
export TALON_API_KEY="production_talon_key"

# Start application
python app.py
```

### Option B: Use Docker Secrets (Swarm)

```yaml
# docker-compose.yml
services:
  lucius:
    image: lucius:latest
    secrets:
      - nvd_api_key
      - talon_api_key
    environment:
      NVD_API_KEY: /run/secrets/nvd_api_key
      TALON_API_KEY: /run/secrets/talon_api_key

secrets:
  nvd_api_key:
    external: true
  talon_api_key:
    external: true
```

### Option C: Use Kubernetes Secrets

```yaml
# k8s-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: lucius-credentials
type: Opaque
stringData:
  NVD_API_KEY: "production_key"
  TALON_API_KEY: "production_talon_key"
---
# deployment.yaml
spec:
  containers:
  - name: lucius
    env:
    - name: NVD_API_KEY
      valueFrom:
        secretKeyRef:
          name: lucius-credentials
          key: NVD_API_KEY
```

### Option D: Use AWS Secrets Manager

```python
import boto3
import json

def get_secret():
    client = boto3.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId='lucius/credentials')
        secret = json.loads(response['SecretString'])
        return secret
    except Exception as e:
        raise Exception(f"Error retrieving secret: {e}")
```

## Step 8: Verification Checklist

- [ ] `.env` file created from `.env.example`
- [ ] All required API keys obtained
- [ ] Credentials added to `.env`
- [ ] `test_creds.py` runs without missing credentials
- [ ] `.env` is in `.gitignore`
- [ ] Can import `CredentialManager` in code
- [ ] Services using credentials initialize correctly
- [ ] Tests pass with controlled credentials
- [ ] Production deployment plan created
- [ ] Audit logging enabled (`AUDIT_CREDENTIALS=true` in `.env`)

## Troubleshooting

### Issue: "CredentialError: Missing required credential 'NVD_API_KEY'"

**Solution:**
1. Verify `.env` file exists: `ls -la .env`
2. Verify NVD_API_KEY is set: `grep NVD_API_KEY .env`
3. Check for typos (case-sensitive)
4. Verify no quotes around value: `NVD_API_KEY=value` (not `NVD_API_KEY="value"`)

### Issue: Credentials not loading from environment variable

**Solution:**
1. Verify environment variable is set:
   ```bash
   echo $NVD_API_KEY
   ```
2. If not set, export it:
   ```bash
   export NVD_API_KEY="your_key_here"
   ```
3. Restart application or Python interpreter

### Issue: "Permission denied" when reading `.env`

**Solution:**
```bash
# Fix permissions
chmod 600 .env

# Verify
ls -la .env  # Should show -rw------- (only owner can read)
```

### Issue: API keys not working in production

**Solution:**
1. Verify correct key is deployed (not development key)
2. Check key hasn't expired or been revoked
3. Verify key has correct permissions/scopes
4. Check rate limits aren't exceeded
5. Enable debug logging:
   ```python
   import logging
   logging.getLogger("shared.credentials").setLevel(logging.DEBUG)
   ```

## Security Best Practices

1. **Never commit secrets**: Verify `.env` in `.gitignore`
2. **Rotate keys regularly**: Update keys in secret manager
3. **Use strong keys**: Ensure API keys are sufficiently random
4. **Limit scope**: Give tokens only necessary permissions
5. **Audit access**: Check `creds.audit_log()` regularly
6. **Monitor usage**: Set up alerts for unexpected API usage

## Next Steps

1. Review [CREDENTIAL_MANAGEMENT.md](./CREDENTIAL_MANAGEMENT.md) for detailed API reference
2. Check service integrations using credentials
3. Run full test suite: `pytest tests/`
4. Review audit logs: `python -c "from shared.credentials import CredentialManager; import json; print(json.dumps(CredentialManager().audit_log(), indent=2))"`

## Support

For issues:
1. Check troubleshooting section above
2. Review logs with debug level: `LOG_LEVEL=DEBUG`
3. Check credential validation: `python test_creds.py`
4. Review test examples: `grep -r "CredentialManager" tests/`
