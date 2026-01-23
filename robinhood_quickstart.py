#!/usr/bin/env python3
"""
Robinhood Bug Bounty Quick Start Helper
Generates and validates Lucius scans for Robinhood's program
"""


# Robinhood Tier 1 targets
ROBINHOOD_TARGETS = {
    "main_domain": "robinhood.com",
    "api": "api.robinhood.com",
    "crypto": "nummus.robinhood.com",
    "internal_apollo": "rhapollo.net",
    "internal_net": "rhinternal.net",
    "admin": "oak.robinhood.net",
}

# Recommended scan profiles
SCAN_PROFILES = {
    "quick": {
        "description": "Quick subdomain + CVE lookup",
        "flags": "--enable-cve",
    },
    "comprehensive": {
        "description": "Full recon: subdomains, CVEs, API fuzzing, auth tests",
        "flags": "--enable-cve --enable-fuzz --enable-auth",
    },
    "auth_focused": {
        "description": "Authentication & authorization testing only",
        "flags": "--enable-auth --auth-user <test-user> --auth-pass <test-pass>",
    },
    "api_focused": {
        "description": "API fuzzing and IDOR testing",
        "flags": "--enable-fuzz",
    },
}


def print_robinhood_header():
    """Print Robinhood bug bounty program info."""
    print("=" * 70)
    print("ROBINHOOD BUG BOUNTY PROGRAM — LUCIUS QUICK START")
    print("=" * 70)
    print()
    print("Program Highlights:")
    print("  • Gold Standard Safe Harbor")
    print("  • 90%+ response efficiency")
    print("  • 8 hours avg time to first response")
    print("  • Bounties: $100–$25,000 based on CVSS")
    print()
    print("Tier 1 Targets (Highest Bounties):")
    for key, target in ROBINHOOD_TARGETS.items():
        print(f"  • {target:<30} ({key})")
    print()


def print_submission_requirements():
    """Print required headers for Robinhood submissions."""
    print("=" * 70)
    print("ROBINHOOD SUBMISSION REQUIREMENTS")
    print("=" * 70)
    print()
    print("Include these headers in bug reports:")
    print("  X-Bug-Bounty: <your-hackerone-username>")
    print("  X-Test-Account-Email: <your-test-account-email>")
    print()
    print("High-Value Vectors:")
    print("  1. Authenticated bugs (bypass, privilege escalation)")
    print("  2. Business logic flaws (circumvent UI via API)")
    print("  3. Sensitive data disclosure (SSN, PII)")
    print("  4. Admin tool access (oak.robinhood.net)")
    print()
    print("Bounty Guidelines:")
    print("  • Demonstrate actual impact (not theoretical)")
    print("  • CVSS scores adjusted for effective mitigations")
    print("  • Account takeover (ATO) = limited bonuses")
    print("  • Out of scope: Default config issues, SPF/DKIM, DDos")
    print()


def print_scan_profiles():
    """Print available scan profiles."""
    print("=" * 70)
    print("AVAILABLE SCAN PROFILES")
    print("=" * 70)
    print()
    for profile_name, profile_config in SCAN_PROFILES.items():
        print(f"{profile_name.upper()}")
        print(f"  Description: {profile_config['description']}")
        print(f"  Flags: {profile_config['flags']}")
        print()


def print_example_commands():
    """Print example Lucius commands for Robinhood targets."""
    print("=" * 70)
    print("EXAMPLE COMMANDS")
    print("=" * 70)
    print()

    examples = [
        ("Quick scan (subdomains + CVEs)", "python script.py robinhood.com --enable-cve --verbose"),
        (
            "Full reconnaissance",
            "python script.py robinhood.com --enable-cve --enable-fuzz --enable-auth --output report.json --verbose",
        ),
        (
            "Target high-value admin tool",
            "python script.py oak.robinhood.net --enable-auth --enable-fuzz --verbose",
        ),
        (
            "Crypto trading endpoint",
            "python script.py nummus.robinhood.com --enable-fuzz --enable-auth --verbose",
        ),
        (
            "Test with credentials",
            "python script.py robinhood.com --enable-auth --auth-user testuser --auth-pass testpass --verbose",
        ),
        (
            "Dry-run (simulation mode)",
            "python script.py robinhood.com --dry-run --enable-cve --enable-fuzz --enable-auth",
        ),
    ]

    for desc, cmd in examples:
        print(f"# {desc}")
        print(f"{cmd}")
        print()


def print_responsible_disclosure():
    """Print responsible disclosure guidelines."""
    print("=" * 70)
    print("RESPONSIBLE DISCLOSURE")
    print("=" * 70)
    print()
    print("✓ DO:")
    print("  • Test only accounts you own")
    print("  • Report findings immediately")
    print("  • Stop if you find sensitive data (SSN, credentials)")
    print("  • Use --dry-run before live testing")
    print("  • Follow Robinhood's Program Rules")
    print()
    print("✗ DON'T:")
    print("  • Test other user accounts")
    print("  • Make financial transactions")
    print("  • Perform DoS/resource exhaustion tests")
    print("  • Disclose findings outside HackerOne")
    print("  • Exceed $1,000 USD on unbounded loss tests")
    print()
    print("Program Rules: https://hackerone.com/robinhood?type=team")
    print()


def main():
    """Main entry point."""
    print_robinhood_header()
    print_submission_requirements()
    print_scan_profiles()
    print_example_commands()
    print_responsible_disclosure()

    print("=" * 70)
    print("NEXT STEPS")
    print("=" * 70)
    print()
    print("1. Create a Robinhood test account")
    print("2. Start with --dry-run to validate payloads")
    print("3. Run comprehensive scans on Tier 1 targets")
    print("4. Review results.json for high-impact findings")
    print("5. Calculate CVSS scores (use --enable-cvss)")
    print("6. Submit findings with required headers to HackerOne")
    print()


if __name__ == "__main__":
    main()
