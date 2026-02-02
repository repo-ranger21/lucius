# GS Acquisition Reconnaissance Module Documentation

## Overview

The **gs_recon.py** module provides a complete passive and controlled active reconnaissance framework for external attack surface management targeting authorized GS acquisition targets (e.g., nnip.com).

**Key Features:**
- ✅ **Legal Shield**: LuciusClient wrapper with X-HackerOne-Research headers
- ✅ **Rate Limiting**: Token bucket algorithm (50 RPS max)
- ✅ **No Pivoting**: Inventory-only, zero exploitation
- ✅ **Multi-Source Discovery**: crt.sh, Wayback Machine, DNS Dumpster
- ✅ **Tech Fingerprinting**: 10+ technology stack signatures
- ✅ **ASN Mapping**: Scope determination (in/out-of-scope)
- ✅ **JSON Export**: Structured inventory for downstream analysis

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                 GSReconInventory (Orchestrator)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐ │
│  │  Subdomain       │  │  Tech            │  │  ASN         │ │
│  │  Discovery       │  │  Fingerprinter   │  │  Mapper      │ │
│  ├──────────────────┤  ├──────────────────┤  ├──────────────┤ │
│  │ • crt.sh         │  │ • HTTP Headers   │  │ • IP Resolve │ │
│  │ • Wayback        │  │ • robots.txt     │  │ • ASN Lookup │ │
│  │ • DNS Dumpster   │  │ • Content Sigs   │  │ • Scope      │ │
│  └──────────────────┘  └──────────────────┘  └──────────────┘ │
│         │                      │                      │        │
│         └──────────────────────┼──────────────────────┘        │
│                                ▼                               │
│                  LuciusClient (Rate Limited)                   │
│                                                                 │
│                    X-HackerOne-Research Header                 │
│                    50 RPS Token Bucket                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module Components

### 1. **TokenBucket** (Rate Limiting)
Thread-safe token bucket implementation for precise rate limiting.

```python
bucket = TokenBucket(rate=50, capacity=50)
bucket.acquire(tokens=1)  # Block until token available
```

**Features:**
- Thread-safe with mutex locks
- Exponential refill algorithm
- Configurable timeout

---

### 2. **SubdomainDiscovery** (Passive Enumeration)

#### `query_crt_sh(domain: str) -> Set[str]`
Queries Certificate Transparency logs for subdomains from all issued certificates.

**Use Case:** Discovers legacy subdomains from pre-rebrand (2015) and migration periods (2024)

```python
discovery = SubdomainDiscovery(client)
subdomains = discovery.query_crt_sh("nnip.com")
# Returns: {'api.nnip.com', 'old.nnip.com', 'dev.nnip.com', ...}
```

#### `query_wayback_machine(domain: str) -> Set[str]`
Queries Wayback Machine CDX API for historical domain snapshots.

**Use Case:** Surfaces deprecated endpoints that may still be live but unmonitored

```python
subdomains = discovery.query_wayback_machine("nnip.com")
# Returns: {'archive.nnip.com', 'legacy.nnip.com', ...}
```

#### `query_dnsdumpster(domain: str) -> Set[str]`
Queries DNS Dumpster passive DNS database.

**Use Case:** Catches subdomains not yet in CT logs

```python
subdomains = discovery.query_dnsdumpster("nnip.com")
```

---

### 3. **TechFingerprinter** (Service Identification)

#### `get_tech_stack(url: str) -> Dict[str, Any]`
Comprehensive technology detection from HTTP responses.

**Detection Methods:**
1. **HTTP Headers**: Server, X-Powered-By, X-AspNet-Version
2. **Content Signatures**: Regex patterns for 10+ tech stacks
3. **robots.txt Analysis**: CMS markers (WordPress, Joomla, etc.)

**Return Structure:**
```json
{
  "url": "https://api.nnip.com",
  "live": true,
  "status_code": 200,
  "headers": {
    "Server": "nginx/1.24.0",
    "X-Powered-By": "Express/4.18.2"
  },
  "detected_tech": ["Nginx", "Node.js"],
  "server": "nginx/1.24.0",
  "robots_txt": "User-agent: *\nDisallow: /admin",
  "timestamp": "2026-02-02T15:30:45.123456"
}
```

**Supported Technologies:**
- Web Servers: Apache, Nginx
- Languages: Python (Django, Flask), Node.js, Java, PHP, ASP.NET, Go, Ruby
- Cloud: AWS, Cloudflare
- CMS: WordPress, Joomla, Drupal, SharePoint

---

### 4. **ASNMapper** (Infrastructure Scope Determination)

#### `map_domain_to_asn(domain: str) -> List[Dict[str, str]]`
Resolves domain to IP, then to Autonomous System ownership.

**Scope Classification:**
- **IN-SCOPE**: Goldman Sachs (ASN 2635)
- **OUT-OF-SCOPE**: AWS (16509), Azure (8994), Google (14061), Fastly (395087)

**Return Structure:**
```json
{
  "ip": "192.0.2.1",
  "asn": "2635",
  "owner": "GOLDMAN-SACHS",
  "scope": "in-scope"
}
```

**Use Case:** Quickly identifies which discovered infrastructure is Goldman-owned vs. third-party SaaS

---

### 5. **GSReconInventory** (Orchestrator)

Main entry point that coordinates the full reconnaissance workflow.

#### `run_reconnaissance(target_domain: str, max_hosts: Optional[int]) -> Dict`
Executes all reconnaissance phases in sequence:

1. **Phase 1**: Subdomain Discovery (all sources)
2. **Phase 2**: Tech Fingerprinting (with rate limiting)
3. **Phase 3**: ASN Mapping (scope determination)
4. **Summary**: Aggregated findings and recommendations

**Example:**
```python
recon = GSReconInventory(rate_limit=50)
inventory = recon.run_reconnaissance("nnip.com", max_hosts=30)
recon.export_inventory("/path/to/nnip_inventory.json")
recon.print_report()
```

---

## Compliance & Safety

### Legal Shield: X-HackerOne-Research Header

Every HTTP request includes the mandatory header:
```
X-HackerOne-Research: [lucius-log]
```

This header is:
1. **Automatically injected** by LuciusClient
2. **Verified before each request** (SafetyException on missing header)
3. **Non-negotiable** for all HTTP operations

**Example:**
```python
try:
    client = LuciusClient()
    response = client.get("https://api.nnip.com")
    # Header automatically included; SafetyException raised if missing
except SafetyException:
    # Request blocked - header enforcement
    pass
```

### Rate Limiting: 50 RPS Maximum

Token bucket implementation ensures compliance with GS 60 RPS threshold:

```python
LuciusClient(rate_limit=50)  # 50 tokens/second, max 50 tokens in bucket
```

**Characteristics:**
- **Thread-safe**: Mutex-protected refill logic
- **Exponential backoff**: Automatic wait if tokens depleted
- **Deterministic**: No random jitter (consistent behavior)
- **Timeout protection**: 30s max wait before warning

**Verification:**
```bash
# Monitor requests in real-time
tail -f logs/gs_recon.log | grep "Acquiring token"
```

### No Pivoting: Inventory-Only Reconnaissance

The module strictly avoids exploitation:

✅ **Allowed:**
- DNS resolution (passive)
- HTTP banner grabbing
- Public certificate inspection
- robots.txt parsing

❌ **NOT Implemented:**
- Vulnerability scanning (Nessus, OpenVAS)
- Exploitation frameworks (Metasploit, Burp Pro)
- Privilege escalation attempts
- Credential testing

---

## Usage

### Command-Line Interface

```bash
# Basic reconnaissance
python -m recon.gs_recon nnip.com

# With custom options
python -m recon.gs_recon nnip.com \
  --max-hosts 50 \
  --rate-limit 45 \
  --output nnip_recon_2026.json \
  --verbose

# Help
python -m recon.gs_recon --help
```

### Programmatic Usage

```python
from recon.gs_recon import GSReconInventory
from core.client import LuciusClient

# Initialize
recon = GSReconInventory(rate_limit=50)

# Run reconnaissance
inventory = recon.run_reconnaissance(
    target_domain="nnip.com",
    max_hosts=50  # Optional: limit scope
)

# Export results
output_path = recon.export_inventory()
print(f"Exported to: {output_path}")

# Print human-readable report
recon.print_report()

# Access raw inventory
print(f"Live hosts: {len(inventory['live_hosts'])}")
print(f"Discovered subdomains: {len(inventory['subdomains'])}")
```

---

## Output Format

### JSON Inventory Structure

```json
{
  "target": "nnip.com",
  "discovery_timestamp": "2026-02-02T15:30:45.123456",
  "subdomains": [
    "api.nnip.com",
    "dev.nnip.com",
    "old.nnip.com",
    "staging.nnip.com"
  ],
  "live_hosts": [
    {
      "hostname": "https://api.nnip.com",
      "status": 200,
      "tech_stack": ["Nginx", "Node.js"],
      "server": "nginx/1.24.0"
    }
  ],
  "tech_stack": [
    {
      "url": "https://api.nnip.com",
      "live": true,
      "status_code": 200,
      "headers": {
        "Server": "nginx/1.24.0",
        "X-Powered-By": "Express/4.18.2"
      },
      "detected_tech": ["Nginx", "Node.js"],
      "server": "nginx/1.24.0",
      "robots_txt": null,
      "timestamp": "2026-02-02T15:30:45.123456"
    }
  ],
  "asn_mapping": [
    {
      "ip": "192.0.2.1",
      "asn": "2635",
      "owner": "GOLDMAN-SACHS",
      "scope": "in-scope"
    }
  ],
  "summary": {
    "total_subdomains_discovered": 47,
    "live_hosts_found": 12,
    "tech_stack_aggregation": {
      "Nginx": 8,
      "Node.js": 5,
      "Cloudflare": 12
    },
    "asn_in_scope_count": 3,
    "asn_out_of_scope_count": 2,
    "recommended_next_steps": [
      "Investigate 12 live hosts for service enumeration",
      "Cross-reference 47 subdomains with org charts",
      "Verify 3 in-scope ASN(s) for legacy infrastructure"
    ]
  }
}
```

---

## Logging

Logs are written to: `logs/gs_recon.log`

**Log Levels:**
- **INFO**: Phase transitions, major findings
- **DEBUG**: Individual host fingerprinting, API queries
- **ERROR**: Safety violations, network errors

**Example Log Output:**
```
2026-02-02 15:30:45,123 - recon.gs_recon - INFO - ======================================================================
2026-02-02 15:30:45,124 - recon.gs_recon - INFO - Starting GS Acquisition Reconnaissance on nnip.com
2026-02-02 15:30:45,125 - recon.gs_recon - INFO - ======================================================================

2026-02-02 15:30:45,200 - recon.gs_recon - INFO - [PHASE 1] Subdomain Discovery
2026-02-02 15:30:46,300 - recon.gs_recon - INFO - Querying crt.sh for domain: nnip.com
2026-02-02 15:30:48,500 - recon.gs_recon - INFO - crt.sh discovered 42 unique subdomains

2026-02-02 15:30:49,100 - recon.gs_recon - INFO - [PHASE 2] Technology Fingerprinting
2026-02-02 15:30:49,200 - recon.gs_recon - INFO - Scanning 42 hosts for tech stack...
2026-02-02 15:30:50,300 - recon.gs_recon - INFO -   [1/42] Fingerprinting api.nnip.com
2026-02-02 15:30:50,800 - recon.gs_recon - INFO -   [api.nnip.com] - Status: 200, Tech: ['Nginx', 'Node.js']
```

---

## Error Handling

### SafetyException

Raised when compliance requirements are violated:

```python
try:
    # Missing X-HackerOne-Research header
    response = client.get(url)
except SafetyException as e:
    print(f"Compliance violation: {e}")
    # Log incident, halt operations
```

### Network Errors

Gracefully handled with logging:

```python
# Timeouts (10s default)
# Connection errors (redirects)
# DNS resolution failures
# All logged at DEBUG level; reconnaissance continues
```

---

## Performance Metrics

**Typical Reconnaissance Timeline for nnip.com:**

| Phase | Time | Requests |
|-------|------|----------|
| Subdomain Discovery | 5-10 seconds | 3 API calls |
| Tech Fingerprinting (50 hosts) | 2-3 minutes | ~100 HTTP requests |
| ASN Mapping | 10-15 seconds | ~5 API calls |
| **Total** | **3-4 minutes** | **~110 requests** |

**Rate Limiting Impact:**
- At 50 RPS, ~3.5 minutes for 110 requests
- Stays safely below GS 60 RPS threshold
- Thread-safe for concurrent discovery modules

---

## Advanced: Extending Subdomain Discovery

To add custom passive sources:

```python
def query_custom_source(self, domain: str) -> Set[str]:
    """Query custom passive DNS or CT log source."""
    logger.info(f"Querying custom source for: {domain}")
    subdomains = set()
    
    try:
        # Your custom API logic
        url = f"https://custom-api.io/query?domain={domain}"
        response = self.client.get(url, timeout=10)
        
        # Parse response and extract subdomains
        for item in response.json():
            subdomains.add(item['subdomain'])
            
    except Exception as e:
        logger.error(f"Custom source query failed: {e}")
    
    self.discovered_domains.update(subdomains)
    return subdomains

# Register in get_all_subdomains()
all_subdomains.update(self.query_custom_source(domain))
```

---

## Compliance Checklist

- [x] **Legal Shield**: X-HackerOne-Research header on all requests
- [x] **Rate Limiting**: Token bucket capped at 50 RPS
- [x] **No Exploitation**: Inventory-only reconnaissance
- [x] **Logging**: All activities logged to logs/gs_recon.log
- [x] **No Pivoting**: Zero lateral movement attempts
- [x] **Scope Tracking**: ASN mapping for scope determination
- [x] **Reporting**: Structured JSON export for analysis

---

## Related Documentation

- [Lucius Architecture](../ARCHITECTURE.md)
- [LuciusClient Source](../core/client.py)
- [Testing Guide](../AUTHORIZATION_TESTING_GUIDE.md)
- [HackerOne Submission Templates](../testing_scripts.py)

---

**Version**: 1.0.0  
**Last Updated**: February 2, 2026  
**Status**: Production Ready ✅
