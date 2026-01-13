"""
Example usage of ML-based threat scoring system.

Demonstrates:
1. Training a model
2. Loading and using a trained model
3. Feature importance analysis
4. Batch scoring
"""

from datetime import datetime, timedelta
from uuid import uuid4

# Mock Vulnerability for demonstration
class MockVulnerability:
    def __init__(self, **kwargs):
        self.id = uuid4()
        self.cve_id = kwargs.get("cve_id", "CVE-2024-0000")
        self.severity = kwargs.get("severity", "HIGH")
        self.cvss_score = kwargs.get("cvss_score", 7.5)
        self.cvss_vector = kwargs.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.description = kwargs.get("description", "Test vulnerability")
        self.affected_packages = kwargs.get("affected_packages", [])
        self.references = kwargs.get("references", [])
        self.published_date = kwargs.get("published_date", datetime.utcnow())
        self.modified_date = kwargs.get("modified_date", datetime.utcnow())


def example_1_train_and_save():
    """Example 1: Train a model on synthetic data and save it."""
    print("=" * 70)
    print("Example 1: Training ML Threat Scoring Model")
    print("=" * 70)

    from talon.ml.model_trainer import ThreatModelTrainer
    from talon.ml.threat_model import MLThreatScorer

    # Initialize trainer
    trainer = ThreatModelTrainer()

    # Generate synthetic training data
    print("\n1. Generating 1000 synthetic training samples...")
    vulnerabilities, scores = trainer.generate_synthetic_training_data(
        n_samples=1000
    )
    print(f"   ✓ Generated {len(vulnerabilities)} samples")
    print(f"   Score range: {min(scores):.2f} - {max(scores):.2f}")

    # Train model
    print("\n2. Training Random Forest model...")
    model = trainer.train(
        vulnerabilities=vulnerabilities,
        ground_truth_scores=scores,
        model_type="random_forest",
        test_size=0.2,
    )
    print(f"   ✓ Model trained (version: {model.version})")
    print(f"   Test R² Score: {model.metrics['test_r2']:.4f}")
    print(f"   MAE: {model.metrics['mae']:.2f} points")

    # Show feature importance
    print("\n3. Top 5 Most Important Features:")
    importance = model.get_feature_importance()
    sorted_features = sorted(
        importance.items(),
        key=lambda x: x[1],
        reverse=True
    )
    for i, (feature, score) in enumerate(sorted_features[:5], 1):
        print(f"   {i}. {feature:30s}: {score:.4f}")

    # Save model
    print("\n4. Saving model...")
    model_path = "talon/models/example_model.pkl"
    MLThreatScorer.save_model(model, model_path)
    print(f"   ✓ Model saved to {model_path}")

    return model_path


def example_2_load_and_score():
    """Example 2: Load a trained model and score vulnerabilities."""
    print("\n\n" + "=" * 70)
    print("Example 2: Loading Model and Scoring Vulnerabilities")
    print("=" * 70)

    from talon.ml.threat_model import MLThreatScorer

    # Load model
    print("\n1. Loading trained model...")
    scorer = MLThreatScorer(model_path="talon/models/example_model.pkl")

    if scorer.model is None:
        print("   ✗ No model found. Run Example 1 first!")
        return

    print(f"   ✓ Loaded model version: {scorer.model.version}")

    # Create test vulnerabilities
    print("\n2. Creating test vulnerabilities...")
    test_vulns = [
        MockVulnerability(
            cve_id="CVE-2024-1111",
            severity="CRITICAL",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            affected_packages=[{"name": "react", "version": "16.0.0"}],
            references=[
                {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1111"},
                {"url": "https://exploit-db.com/exploits/12345"},
            ],
            published_date=datetime.utcnow() - timedelta(days=5),
        ),
        MockVulnerability(
            cve_id="CVE-2024-2222",
            severity="MEDIUM",
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
            affected_packages=[{"name": "unknown-package", "version": "1.0.0"}],
            references=[{"url": "https://example.com/vuln"}],
            published_date=datetime.utcnow() - timedelta(days=300),
        ),
        MockVulnerability(
            cve_id="CVE-2024-3333",
            severity="HIGH",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            affected_packages=[
                {"name": "lodash", "version": "4.17.0"},
                {"name": "express", "version": "4.16.0"},
            ],
            references=[
                {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3333"},
            ],
            published_date=datetime.utcnow() - timedelta(days=15),
        ),
    ]
    print(f"   ✓ Created {len(test_vulns)} test vulnerabilities")

    # Score vulnerabilities
    print("\n3. Scoring vulnerabilities with ML model:")
    print(f"   {'CVE ID':<18} {'Severity':<10} {'CVSS':<6} {'Threat Score'}")
    print("   " + "-" * 55)

    for vuln in test_vulns:
        score, features = scorer.calculate_threat_score(vuln)
        print(f"   {vuln.cve_id:<18} {vuln.severity:<10} {vuln.cvss_score:<6.1f} {score:.2f}")

    # Show detailed analysis for first vulnerability
    print("\n4. Detailed Feature Analysis (CVE-2024-1111):")
    score, features = scorer.calculate_threat_score(test_vulns[0])
    print(f"   Final Threat Score: {score:.2f}/100")
    print(f"\n   Key Features Contributing to Score:")

    # Show top contributing features
    sorted_features = sorted(
        features.items(),
        key=lambda x: x[1],
        reverse=True
    )
    for feature, value in sorted_features[:8]:
        bar = "█" * int(value * 30)
        print(f"   {feature:30s}: {bar} {value:.3f}")


def example_3_batch_scoring():
    """Example 3: Batch scoring multiple vulnerabilities."""
    print("\n\n" + "=" * 70)
    print("Example 3: Batch Scoring")
    print("=" * 70)

    from talon.ml.threat_model import MLThreatScorer

    # Load model
    scorer = MLThreatScorer(model_path="talon/models/example_model.pkl")

    if scorer.model is None:
        print("   ✗ No model found. Run Example 1 first!")
        return

    # Generate many vulnerabilities
    print("\n1. Generating 50 test vulnerabilities...")
    test_vulns = []
    for i in range(50):
        vuln = MockVulnerability(
            cve_id=f"CVE-2024-{1000+i}",
            severity=["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4],
            cvss_score=3.0 + (i % 8),
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            published_date=datetime.utcnow() - timedelta(days=i*5),
        )
        test_vulns.append(vuln)
    print(f"   ✓ Generated {len(test_vulns)} vulnerabilities")

    # Batch score
    print("\n2. Batch scoring all vulnerabilities...")
    results = scorer.batch_calculate(test_vulns)
    print(f"   ✓ Scored {len(results)} vulnerabilities")

    # Show top 10 highest threats
    print("\n3. Top 10 Highest Threat Vulnerabilities:")
    print(f"   {'Rank':<6} {'CVE ID':<18} {'Threat Score'}")
    print("   " + "-" * 40)

    for rank, (cve_id, score) in enumerate(results[:10], 1):
        print(f"   #{rank:<5} {cve_id:<18} {score:.2f}")


def example_4_feature_importance():
    """Example 4: Analyze feature importance."""
    print("\n\n" + "=" * 70)
    print("Example 4: Feature Importance Analysis")
    print("=" * 70)

    from talon.ml.threat_model import MLThreatScorer

    # Load model
    scorer = MLThreatScorer(model_path="talon/models/example_model.pkl")

    if scorer.model is None:
        print("   ✗ No model found. Run Example 1 first!")
        return

    # Get feature importance
    print("\n1. Feature Importance from Random Forest Model:")
    importance = scorer.get_feature_importance()

    print(f"\n   {'Feature':<35} {'Importance':<12} {'Visual'}")
    print("   " + "-" * 70)

    sorted_features = sorted(
        importance.items(),
        key=lambda x: x[1],
        reverse=True
    )

    for feature, score in sorted_features:
        bar = "█" * int(score * 40)
        print(f"   {feature:<35} {score:>6.4f}       {bar}")

    print("\n2. Interpretation:")
    print("   Features with higher importance have more influence on")
    print("   the final threat score prediction. Use this to:")
    print("   - Understand model behavior")
    print("   - Focus security efforts on high-impact factors")
    print("   - Validate model makes sense for domain")


def main():
    """Run all examples."""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "ML Threat Scoring System Examples" + " " * 19 + "║")
    print("╚" + "═" * 68 + "╝")

    try:
        # Example 1: Train and save
        model_path = example_1_train_and_save()

        # Example 2: Load and score
        example_2_load_and_score()

        # Example 3: Batch scoring
        example_3_batch_scoring()

        # Example 4: Feature importance
        example_4_feature_importance()

        print("\n\n" + "=" * 70)
        print("✓ All examples completed successfully!")
        print("=" * 70)
        print("\nNext steps:")
        print("  1. Integrate with VulnerabilityService")
        print("  2. Train on real database data")
        print("  3. Deploy model to production")
        print("  4. Monitor prediction accuracy")

    except Exception as e:
        print(f"\n✗ Error running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
