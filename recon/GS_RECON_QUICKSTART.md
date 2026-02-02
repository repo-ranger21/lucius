# GS Reconnaissance Module - Quick Start Guide

## Installation

### Prerequisites
```bash
# Ensure you're in the workspace directory
cd /Users/chris-peterson/Documents/GitHub/lucius/lucius-workspace

# Activate virtual environment
source .venv/bin/activate

# Verify dependencies are installed
pip install requests
```

### Verify Installation
```bash
# Check gs_recon.py exists
ls -la recon/gs_recon.py

# Check test suite exists
ls -la tests/test_gs_recon.py

# Run basic syntax check
python -m py_compile recon/gs_recon.py
```

---

## Quick Start: Reconnaissance on nnip.com

### Basic Usage (Command Line)

```bash
# Simple reconnaissance
python -m recon.gs_recon nnip.com

# With verbose logging
python -m recon.gs_recon nnip.com --verbose

# Limit scope (50 hosts max)
python -m recon.gs_recon nnip.com --max-hosts 50

# Custom output file
python -m recon.gs_recon nnip.com --output nnip_results.json

# All options
python -m recon.gs_recon nnip.com \
  --max-hosts 100 \
  --rate-limit 45 \
  --output nnip_recon_final.json \
  --verbose
```

### Expected Output

```
======================================================================
Starting GS Acquisition Reconnaissance on nnip.com
======================================================================

[PHASE 1] Subdomain Discovery
----------------------------------------------------------------------
Querying crt.sh for domain: nnip.com
crt.sh discovered 42 unique subdomains
Querying Wayback Machine for domain: nnip.com
Wayback Machine discovered 18 unique subdomains

[PHASE 2] Technology Fingerprinting
----------------------------------------------------------------------
Scanning 42 hosts for tech stack...
  [1/42] Fingerprinting api.nnip.com
  [api.nnip.com] - Status: 200, Tech: ['Nginx', 'Node.js']
  [2/42] Fingerprinting dev.nnip.com
  [dev.nnip.com] - Status: 503, (not in range)
...

[PHASE 3] ASN Mapping
----------------------------------------------------------------------
Mapping domain nnip.com to ASN(s)
  Resolved nnip.com to IPs: ['192.0.2.1']
  IP 192.0.2.1 -> ASN 2635 (Goldman Sachs)

======================================================================
Reconnaissance Complete
======================================================================

✓ Reconnaissance completed successfully!
✓ Full inventory: logs/nnip_inventory_20260202_153045.json
```

### Report Output

```
======================================================================
GS ACQUISITION RECONNAISSANCE REPORT
======================================================================

Target: nnip.com
Discovery Time: 2026-02-02T15:30:45.123456

[SUMMARY]
  Total Subdomains Discovered: 47
  Live Hosts Found: 12
  In-Scope ASNs: 3
  Out-of-Scope ASNs: 2

[LIVE HOSTS]
  • https://api.nnip.com (200)
    Tech: Nginx, Node.js
    Server: nginx/1.24.0
  • https://dev.nnip.com (403)
    Tech: Apache
    Server: Apache/2.4.41

[ASN MAPPING]
  • 192.0.2.1 -> ASN2635 (GOLDMAN-SACHS) [✓ IN-SCOPE]
  • 192.0.3.1 -> ASN16509 (AMAZON-02) [✗ OUT]
  • 192.0.4.1 -> ASN14061 (GOOGLE) [✗ OUT]

[RECOMMENDED NEXT STEPS]
  → Investigate 12 live hosts for service enumeration
  → Cross-reference 47 subdomains with org charts
  → Verify 3 in-scope ASN(s) for legacy infrastructure

======================================================================
```

---

## Programmatic Usage

### Example 1: Basic Reconnaissance

```python
#!/usr/bin/env python3
"""Reconnaissance script for nnip.com."""

from recon.gs_recon import GSReconInventory

# Initialize orchestrator (50 RPS rate limit)
recon = GSReconInventory(rate_limit=50)

# Run reconnaissance
inventory = recon.run_reconnaissance(
    target_domain="nnip.com",
    max_hosts=50  # Optional: limit fingerprinting scope
)

# Print human-readable report
recon.print_report()

# Export inventory to JSON
output_file = recon.export_inventory()
print(f"\n✓ Full inventory saved: {output_file}")
```

### Example 2: Custom Analysis

```python
#!/usr/bin/env python3
"""Advanced reconnaissance with custom analysis."""

import json
from recon.gs_recon import GSReconInventory

# Run reconnaissance
recon = GSReconInventory(rate_limit=50)
inventory = recon.run_reconnaissance("nnip.com")

# Extract custom metrics
live_hosts = inventory['live_hosts']
tech_stack = inventory['tech_stack']
asn_mapping = inventory['asn_mapping']

# Find all Nginx instances
nginx_hosts = [
    h for h in live_hosts 
    if "Nginx" in h.get('tech_stack', [])
]
print(f"Nginx Instances: {len(nginx_hosts)}")
for host in nginx_hosts:
    print(f"  - {host['hostname']}")

# Find in-scope infrastructure
in_scope = [
    asn for asn in asn_mapping 
    if asn['scope'] == 'in-scope'
]
print(f"\nIn-Scope IPs (Goldman Sachs): {len(in_scope)}")
for asn in in_scope:
    print(f"  - {asn['ip']} (ASN{asn['asn']})")

# Export filtered results
filtered_inventory = {
    "target": inventory['target'],
    "timestamp": inventory['discovery_timestamp'],
    "nginx_hosts": nginx_hosts,
    "in_scope_infrastructure": in_scope,
    "summary": inventory['summary']
}

with open("filtered_results.json", "w") as f:
    json.dump(filtered_inventory, f, indent=2)
```

### Example 3: Integration with Downstream Tools

```python
#!/usr/bin/env python3
"""Integration with other Lucius modules."""

from recon.gs_recon import GSReconInventory
from sentinel.cli import SentinelScanner
from talon.api import ThreatScorer

# Step 1: Discover assets
recon = GSReconInventory()
inventory = recon.run_reconnaissance("nnip.com", max_hosts=50)

# Step 2: Scan discovered hosts
scanner = SentinelScanner()
for host in inventory['live_hosts']:
    hostname = host['hostname'].replace('https://', '').replace('http://', '')
    print(f"Scanning {hostname}...")
    scan_results = scanner.scan_web_app(hostname)
    
    # Step 3: Score findings
    scorer = ThreatScorer()
    threat_level = scorer.calculate_cvss(scan_results)
    print(f"  Threat Level: {threat_level}")

print("\n✓ Full pipeline complete")
```

---

## Testing

### Run Unit Tests

```bash
# Run all gs_recon tests
python -m pytest tests/test_gs_recon.py -v

# Run specific test class
python -m pytest tests/test_gs_recon.py::TestTokenBucket -v

# Run with coverage
python -m pytest tests/test_gs_recon.py --cov=recon.gs_recon --cov-report=html
```

### Test Results Expected

```
test_gs_recon.py::TestTokenBucket::test_token_bucket_initialization PASSED
test_gs_recon.py::TestTokenBucket::test_token_acquisition_success PASSED
test_gs_recon.py::TestSubdomainDiscovery::test_crt_sh_query_parsing PASSED
test_gs_recon.py::TestSubdomainDiscovery::test_wayback_machine_query_parsing PASSED
test_gs_recon.py::TestTechFingerprinter::test_http_headers_analysis_nginx PASSED
test_gs_recon.py::TestTechFingerprinter::test_http_headers_analysis_aspnet PASSED
test_gs_recon.py::TestASNMapper::test_ip_resolution PASSED
test_gs_recon.py::TestASNMapper::test_asn_lookup_in_scope PASSED
test_gs_recon.py::TestComplianceRequirements::test_lucius_client_header_enforcement PASSED
test_gs_recon.py::TestComplianceRequirements::test_rate_limit_enforcement_50_rps_max PASSED

======================== 16 passed in 2.34s ========================
```

---

## Configuration

### Rate Limiting

The module respects a strict 50 RPS rate limit (GS threshold is 60 RPS):

```python
# This caps at 50 RPS automatically
recon = GSReconInventory(rate_limit=50)

# Token bucket ensures no bursts exceed limit
# Tokens refill at: 50 tokens/second
# Max capacity: 50 tokens
# If exhausted, requests block until tokens available
```

### Timeouts

Default timeouts for network operations:

```python
# HTTP requests: 10 seconds
# robots.txt fetch: 5 seconds
# ASN API: 5 seconds
# Certificate API: 10 seconds
# Wayback Machine: 15 seconds
```

### Logging

Logs are written to: `logs/gs_recon.log`

Control verbosity:

```python
import logging

# Increase logging detail
logging.getLogger("recon.gs_recon").setLevel(logging.DEBUG)

# Or use CLI flag
# python -m recon.gs_recon nnip.com --verbose
```

---

## Compliance Verification

### Verify X-HackerOne-Research Header

```bash
# Check that all requests include required header
grep -c "X-HackerOne-Research" logs/gs_recon.log

# Should show multiple matches (one per request)
```

### Verify Rate Limiting

```bash
# Monitor requests per second
tail -f logs/gs_recon.log | \
  awk '{print $1,$2}' | \
  sort | uniq -c | tail -10

# Should never exceed 50 requests in a 1-second window
```

### Verify No Exploitation

```bash
# Search for exploitation attempts
grep -E "(exploit|rce|sqli|xss|privesc)" logs/gs_recon.log

# Should return nothing (empty)
```

---

## Troubleshooting

### Issue: Timeout on API calls

**Solution**: Increase timeout or retry

```python
recon = GSReconInventory()
# Internal timeouts are already generous (10-15s)
# If still timing out, check network connectivity
```

### Issue: Missing subdomains

**Solution**: Verify API responses

```bash
# Enable verbose logging
python -m recon.gs_recon nnip.com --verbose

# Check logs for API response sizes
grep "discovered" logs/gs_recon.log
```

### Issue: Rate limiting too restrictive

**Solution**: Verify it's actually 50 RPS (not lower)

```python
# Check configured rate limit
recon = GSReconInventory(rate_limit=50)
print(recon.client.rate_limit)  # Should be 50
```

### Issue: JSON export fails

**Solution**: Ensure logs directory exists

```bash
# Create logs directory if missing
mkdir -p logs/

# Run again
python -m recon.gs_recon nnip.com
```

---

## Output Files

### Main Inventory (JSON)

Location: `logs/nnip_inventory_YYYYMMDD_HHMMSS.json`

```json
{
  "target": "nnip.com",
  "discovery_timestamp": "2026-02-02T15:30:45.123456",
  "subdomains": [47 items],
  "live_hosts": [12 items],
  "tech_stack": [12 items with full details],
  "asn_mapping": [3 items],
  "summary": {
    "total_subdomains_discovered": 47,
    "live_hosts_found": 12,
    "tech_stack_aggregation": {...},
    "asn_in_scope_count": 3,
    "asn_out_of_scope_count": 2,
    "recommended_next_steps": [...]
  }
}
```

### Debug Logs

Location: `logs/gs_recon.log`

Contains:
- Phase transitions
- API queries and responses
- Host fingerprinting details
- Rate limiting metrics
- Errors and warnings

---

## Next Steps

After reconnaissance:

1. **Service Enumeration**: Use discovered tech stack to guide vulnerability scanners
2. **Historical Analysis**: Cross-reference 2015 rebrand and 2024 migration subdomains
3. **Organizational Mapping**: Match IPs to Goldman Sachs org charts
4. **Vulnerability Scanning**: Focus Nessus/OpenVAS on identified services
5. **Bug Bounty Submission**: Use findings for HackerOne reports

---

## Support & Reference

- **Full Documentation**: [GS_RECON_DOCUMENTATION.md](GS_RECON_DOCUMENTATION.md)
- **Test Suite**: [tests/test_gs_recon.py](../tests/test_gs_recon.py)
- **Module Source**: [recon/gs_recon.py](gs_recon.py)
- **LuciusClient**: [core/client.py](../core/client.py)
- **Architecture**: [ARCHITECTURE.md](../ARCHITECTURE.md)

---

**Version**: 1.0.0  
**Last Updated**: February 2, 2026  
**Status**: Production Ready ✅
