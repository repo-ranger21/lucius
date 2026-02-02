# Secure Credential Management Guide

This guide explains how to properly manage credentials and secrets in the Lucius platform using the secure credential management system.

## Overview

The credential management system provides:

- **Secure loading** from environment variables, `.env` files, and vault backends
- **Masking** of sensitive values in logs and representations
- **Audit logging** with SHA256 hashing for compliance
- **Validation** of required credentials
- **Component-based organization** (NVD, Talon, HackerOne, GitHub)

## Quick Start

### 1. Load Credentials in Your Application

```python
from shared.credentials import CredentialManager

# Initialize credential manager (loads from env and .env file)
creds = CredentialManager()

# Get a required credential (raises error if missing)
api_key = creds.get_secret("NVD_API_KEY")

# Get an optional credential with fallback
github_token = creds.get_secret("GITHUB_TOKEN", required=False)

# Get a credential with default value
database_url = creds.get_secret("DATABASE_URL", default="postgresql://localhost/db")
```

### 2. Set Up Environment

Create a `.env` file in the project root (never commit this):

```bash
# NVD Configuration
NVD_API_KEY=your_nvd_api_key_here

# Talon Configuration
TALON_API_URL=http://talon-service:5000
TALON_API_KEY=your_talon_api_key

# HackerOne Configuration
HACKERONE_API_KEY=your_h1_api_key

# GitHub Configuration
GITHUB_TOKEN=your_github_token

# Optional: Database Configuration
DATABASE_URL=postgresql://user:password@localhost/lucius_db

# Optional: Redis Configuration
REDIS_URL=redis://localhost:6379/0
```

### 3. Production Deployment

For production, never use `.env` files. Instead:

1. **Use Secret Management Services:**
   - AWS Secrets Manager
   - Azure Key Vault
   - HashiCorp Vault
   - Kubernetes Secrets

2. **Set Environment Variables:**
   ```bash
   export NVD_API_KEY="production_api_key"
   export TALON_API_KEY="production_talon_key"
   # ... etc
   ```

3. **Use Docker Secrets (Swarm):**
   ```yaml
   services:
     lucius:
       secrets:
         - nvd_api_key
         - talon_api_key
   
   secrets:
     nvd_api_key:
       external: true
     talon_api_key:
       external: true
   ```

## API Reference

### CredentialManager

#### `__init__(env_file: Optional[Path] = None)`

Initialize the credential manager.

**Parameters:**
- `env_file`: Path to `.env` file (defaults to `./.env`)

**Example:**
```python
from pathlib import Path
from shared.credentials import CredentialManager

# Use default .env location
creds = CredentialManager()

# Use custom location
creds = CredentialManager(env_file=Path("/etc/lucius/.env"))
```

#### `get_secret(name: str, required: bool = False, default: Optional[str] = None) -> str`

Retrieve a credential by name.

**Parameters:**
- `name`: Name of the credential to retrieve
- `required`: If True, raises CredentialError if not found
- `default`: Default value if credential not found (and not required)

**Returns:** The credential value or default/None

**Raises:** `CredentialError` if required and not found

**Example:**
```python
# Required credential
api_key = creds.get_secret("NVD_API_KEY", required=True)

# Optional with fallback
port = creds.get_secret("PORT", default="5000")
```

#### `get_secrets(component: str) -> dict[str, str]`

Get all credentials for a specific component.

**Parameters:**
- `component`: Component name (e.g., "nvd", "talon", "github")

**Returns:** Dictionary of component credentials

**Example:**
```python
nvd_creds = creds.get_secrets("nvd")
# Returns: {"NVD_API_KEY": "..."}

talon_creds = creds.get_secrets("talon")
# Returns: {"TALON_API_URL": "...", "TALON_API_KEY": "..."}
```

#### `validate_required() -> list[str]`

Validate that all required credentials are present.

**Returns:** List of missing required credentials

**Example:**
```python
missing = creds.validate_required()
if missing:
    print(f"Missing credentials: {', '.join(missing)}")
    sys.exit(1)
```

#### `audit_log() -> dict`

Generate an audit log with masked credentials and hashes.

**Returns:** Dictionary with credential metadata (no plain values)

**Example:**
```python
audit = creds.audit_log()
print(json.dumps(audit, indent=2))
# Output:
# {
#   "NVD_API_KEY": {
#     "masked": "nVd...EY=",
#     "source": "env",
#     "hash": "5f7c4ab08da0d518149a4f2b1fd10f10"
#   }
# }
```

### Credential

Data class representing a single credential.

**Attributes:**
- `name`: Credential name
- `value`: Credential value (sensitive)
- `source`: Source ("env", "file", "vault")
- `masked_value`: Masked representation for logging
- `last_accessed`: Timestamp of last access

**Example:**
```python
from shared.credentials import Credential

cred = Credential(
    name="API_KEY",
    value="secret_value_here",
    source="env"
)

# Safe to log
print(f"Using credential: {cred.masked_value}")  # Shows: "sec...ere"
```

## Security Best Practices

### 1. Never Commit Secrets

```bash
# .gitignore
.env
.env.local
.env.*.local
*.key
*.pem
secrets/
```

### 2. Use Environment Variables in Production

```python
# Good: Loaded from environment (via secret manager)
api_key = creds.get_secret("NVD_API_KEY", required=True)

# Bad: Hardcoded secrets
api_key = "nvd_api_key_here"  # DON'T DO THIS!
```

### 3. Validate on Startup

```python
def main():
    creds = CredentialManager()
    
    # Validate all required credentials are present
    missing = creds.validate_required()
    if missing:
        logger.error(f"Missing required credentials: {missing}")
        sys.exit(1)
    
    # Log audit trail (no secrets exposed)
    logger.info(f"Credentials loaded: {creds.audit_log()}")
    
    # Start application
    run_application(creds)
```

### 4. Mask Secrets in Logs

```python
# Bad: Exposes secrets
logger.debug(f"Using API key: {api_key}")

# Good: Logs masked value
logger.debug(f"Using API key: {creds.credentials['NVD_API_KEY'].masked_value}")
```

### 5. Rotate Credentials Regularly

- Update API keys in secret management system
- Environment variables are immediately updated
- No application restart needed for environment-based secrets

### 6. Audit Access

```python
# Generate audit trail for compliance
audit = creds.audit_log()
with open("credential_audit.json", "w") as f:
    json.dump(audit, f, indent=2)
```

## Integration Examples

### Django Integration

```python
# settings.py
from shared.credentials import CredentialManager

creds = CredentialManager()

# Validate on startup
missing = creds.validate_required()
if missing:
    raise ImproperlyConfigured(f"Missing credentials: {missing}")

# Configure settings
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'lucius_db',
        'HOST': 'localhost',
        'PORT': '5432',
        'USER': 'lucius',
        'PASSWORD': creds.get_secret("DATABASE_PASSWORD"),
    }
}

NVD_API_KEY = creds.get_secret("NVD_API_KEY", required=True)
```

### Flask Integration

```python
# app.py
from flask import Flask
from shared.credentials import CredentialManager

def create_app():
    app = Flask(__name__)
    
    # Load credentials
    creds = CredentialManager()
    
    # Validate on startup
    missing = creds.validate_required()
    if missing:
        raise RuntimeError(f"Missing credentials: {missing}")
    
    # Store in app config
    app.config['NVD_API_KEY'] = creds.get_secret("NVD_API_KEY")
    app.config['DATABASE_URL'] = creds.get_secret("DATABASE_URL", default="sqlite:///db.sqlite")
    
    # Make available to routes
    app.creds = creds
    
    return app
```

### Service Integration

```python
# services/nvd_service.py
from shared.credentials import CredentialManager

class NVDService:
    def __init__(self):
        self.creds = CredentialManager()
        self.api_key = self.creds.get_secret("NVD_API_KEY", required=True)
        self.api_url = self.creds.get_secret("NVD_API_URL", default="https://services.nvd.nist.gov")
    
    def fetch_vulnerabilities(self, cpe):
        """Fetch vulnerabilities from NVD using API key."""
        headers = {
            "X-API-Key": self.api_key,
            "Accept": "application/json"
        }
        # Make API request...
```

## Troubleshooting

### Issue: "Missing required credentials"

**Solution:**
1. Check `.env` file exists and is readable
2. Verify environment variables are set: `echo $NVD_API_KEY`
3. Check file permissions: `ls -la .env`

```bash
# Verify credentials are set
echo "NVD_API_KEY: $NVD_API_KEY"
echo "TALON_API_KEY: $TALON_API_KEY"

# Create .env from template
cp .env.example .env
# Edit with your credentials
```

### Issue: Credentials not loading from `.env`

**Solution:**
1. Ensure `.env` file is in the correct location
2. Check file format - one credential per line
3. Remove quotes around values (manager handles this)

```bash
# Bad format
NVD_API_KEY="key"  # Keep quotes - manager strips them

# Good format
NVD_API_KEY=key
```

### Issue: Secrets appear in logs

**Solution:**
1. Use masked values: `credential.masked_value`
2. Use audit_log() instead of printing raw credentials
3. Check log configuration doesn't include sensitive data

## Migration Guide

### From Hardcoded Secrets

Before:
```python
# Bad: Hardcoded secrets
NVD_API_KEY = "hardcoded_key_12345"
TALON_API_KEY = "hardcoded_talon_key"
```

After:
```python
# Good: Load from credentials manager
from shared.credentials import CredentialManager

creds = CredentialManager()
NVD_API_KEY = creds.get_secret("NVD_API_KEY", required=True)
TALON_API_KEY = creds.get_secret("TALON_API_KEY", required=True)
```

### From Direct Environment Access

Before:
```python
# Okay but unvalidated
import os
NVD_API_KEY = os.getenv("NVD_API_KEY")
```

After:
```python
# Better: Validated and audited
from shared.credentials import CredentialManager

creds = CredentialManager()
NVD_API_KEY = creds.get_secret("NVD_API_KEY", required=True)
```

## Testing with Credentials

```python
import tempfile
from pathlib import Path
from shared.credentials import CredentialManager

def test_service_with_credentials():
    """Test service with mocked credentials."""
    with tempfile.TemporaryDirectory() as tmpdir:
        env_file = Path(tmpdir) / ".env"
        env_file.write_text("""
NVD_API_KEY=test_key
TALON_API_KEY=test_talon_key
""")
        
        creds = CredentialManager(env_file=env_file)
        service = MyService(creds)
        
        # Test with controlled credentials
        assert service.api_key == "test_key"
```

## Compliance and Audit

The credential manager supports compliance requirements:

- **HIPAA**: Audit logging with credential hashing
- **PCI-DSS**: Never logs plain credential values
- **SOC 2**: Tracks credential access and sources
- **GDPR**: Supports encrypted credential storage

Generate compliance reports:

```python
from shared.credentials import CredentialManager
import json

creds = CredentialManager()
audit = creds.audit_log()

# Export for compliance
with open("credentials_audit.json", "w") as f:
    json.dump(audit, f, indent=2, default=str)

print(f"Loaded {len(audit)} credentials")
for name, info in audit.items():
    print(f"  {name}: {info['source']} (hash: {info['hash'][:8]}...)")
```

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review tests in `tests/shared/test_credentials.py`
3. Check logs with `creds.audit_log()`
4. Enable debug logging: `logging.getLogger("shared.credentials").setLevel(logging.DEBUG)`
