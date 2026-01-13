#!/usr/bin/env python3
"""
CLI script for training threat scoring models.

Usage:
    python train_model.py --synthetic --n-samples 1000
    python train_model.py --from-database --model-type random_forest
    python train_model.py --evaluate --model-path models/threat_model_latest.pkl
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from talon.ml.model_trainer import ThreatModelTrainer
from talon.ml.threat_model import MLThreatScorer
from talon.ml.feature_engineering import VulnerabilityFeatureExtractor
from shared.logging import get_logger

logger = get_logger(__name__)


def train_synthetic(args):
    """Train model on synthetic data."""
    logger.info("=" * 60)
    logger.info("Training Threat Scoring Model on Synthetic Data")
    logger.info("=" * 60)

    trainer = ThreatModelTrainer()

    # Generate synthetic data
    logger.info(f"Generating {args.n_samples} synthetic training samples...")
    vulnerabilities, scores = trainer.generate_synthetic_training_data(
        n_samples=args.n_samples
    )

    logger.info(f"Score distribution:")
    import numpy as np
    logger.info(f"  Min: {np.min(scores):.2f}")
    logger.info(f"  Max: {np.max(scores):.2f}")
    logger.info(f"  Mean: {np.mean(scores):.2f}")
    logger.info(f"  Std: {np.std(scores):.2f}")

    # Train model
    logger.info(f"\nTraining {args.model_type} model...")
    model = trainer.train(
        vulnerabilities=vulnerabilities,
        ground_truth_scores=scores,
        model_type=args.model_type,
        test_size=args.test_size,
    )

    # Display results
    logger.info("\n" + "=" * 60)
    logger.info("Training Results")
    logger.info("=" * 60)
    logger.info(f"Model Version: {model.version}")
    logger.info(f"Features Used: {len(model.feature_names)}")
    logger.info("\nPerformance Metrics:")
    for metric, value in model.metrics.items():
        logger.info(f"  {metric}: {value:.4f}")

    # Feature importance
    logger.info("\nTop 10 Feature Importances:")
    importance = model.get_feature_importance()
    sorted_features = sorted(
        importance.items(),
        key=lambda x: x[1],
        reverse=True
    )
    for feature, score in sorted_features[:10]:
        logger.info(f"  {feature:30s}: {score:.4f}")

    # Save model
    output_path = args.output or "talon/models/threat_model_latest.pkl"
    logger.info(f"\nSaving model to {output_path}...")
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    MLThreatScorer.save_model(model, output_path)

    logger.info("\n✓ Training complete!")
    return model


def train_from_database(args):
    """Train model on real database data."""
    logger.info("=" * 60)
    logger.info("Training Threat Scoring Model from Database")
    logger.info("=" * 60)

    from talon.app import create_app
    from talon.models import Vulnerability

    app = create_app()
    with app.app_context():
        # Load vulnerabilities with existing threat scores
        vulnerabilities = Vulnerability.query.filter(
            Vulnerability.threat_score.isnot(None)
        ).all()

        if len(vulnerabilities) < 100:
            logger.warning(
                f"Only {len(vulnerabilities)} vulnerabilities found with scores. "
                "Consider using --synthetic for initial training."
            )
            return

        logger.info(f"Loaded {len(vulnerabilities)} vulnerabilities from database")

        # Extract ground truth scores
        scores = [float(v.threat_score) for v in vulnerabilities]

        trainer = ThreatModelTrainer()

        # Train model
        logger.info(f"Training {args.model_type} model...")
        model = trainer.train(
            vulnerabilities=vulnerabilities,
            ground_truth_scores=scores,
            model_type=args.model_type,
            test_size=args.test_size,
        )

        # Display results
        logger.info("\n" + "=" * 60)
        logger.info("Training Results")
        logger.info("=" * 60)
        for metric, value in model.metrics.items():
            logger.info(f"  {metric}: {value:.4f}")

        # Save model
        output_path = args.output or "talon/models/threat_model_latest.pkl"
        logger.info(f"\nSaving model to {output_path}...")
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        MLThreatScorer.save_model(model, output_path)

        logger.info("\n✓ Training complete!")
        return model


def evaluate_model(args):
    """Evaluate a trained model."""
    logger.info("=" * 60)
    logger.info("Evaluating Threat Scoring Model")
    logger.info("=" * 60)

    # Load model
    logger.info(f"Loading model from {args.model_path}...")
    scorer = MLThreatScorer(model_path=args.model_path)

    if scorer.model is None:
        logger.error("Failed to load model!")
        return

    logger.info(f"Loaded model version: {scorer.model.version}")
    logger.info(f"Training metrics:")
    for metric, value in scorer.model.metrics.items():
        logger.info(f"  {metric}: {value:.4f}")

    # Feature importance
    logger.info("\nFeature Importances:")
    importance = scorer.get_feature_importance()
    sorted_features = sorted(
        importance.items(),
        key=lambda x: x[1],
        reverse=True
    )
    for feature, score in sorted_features:
        bar = "█" * int(score * 50)
        logger.info(f"  {feature:30s}: {bar} {score:.4f}")

    # Generate test data for evaluation
    logger.info("\nGenerating test data for evaluation...")
    trainer = ThreatModelTrainer()
    test_vulns, test_scores = trainer.generate_synthetic_training_data(
        n_samples=200
    )

    # Evaluate
    logger.info("Running evaluation...")
    metrics = trainer.evaluate(scorer.model, test_vulns, test_scores)

    logger.info("\nEvaluation Results:")
    for metric, value in metrics.items():
        logger.info(f"  {metric}: {value:.4f}")

    # Sample predictions
    logger.info("\nSample Predictions (first 10):")
    logger.info(f"{'CVE ID':<20} {'Severity':<10} {'True':<8} {'Predicted':<10} {'Error':<8}")
    logger.info("-" * 66)

    for i in range(min(10, len(test_vulns))):
        vuln = test_vulns[i]
        true_score = test_scores[i]
        pred_score, _ = scorer.calculate_threat_score(vuln)
        error = abs(true_score - pred_score)

        logger.info(
            f"{vuln.cve_id:<20} {vuln.severity:<10} "
            f"{true_score:>6.2f}  {pred_score:>8.2f}  {error:>6.2f}"
        )

    logger.info("\n✓ Evaluation complete!")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Train and evaluate threat scoring models"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Train synthetic
    train_syn_parser = subparsers.add_parser(
        "train-synthetic",
        help="Train model on synthetic data"
    )
    train_syn_parser.add_argument(
        "--n-samples",
        type=int,
        default=1000,
        help="Number of synthetic samples to generate"
    )
    train_syn_parser.add_argument(
        "--model-type",
        choices=["random_forest", "gradient_boosting"],
        default="random_forest",
        help="Type of model to train"
    )
    train_syn_parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of data for testing"
    )
    train_syn_parser.add_argument(
        "--output",
        type=str,
        help="Output path for trained model"
    )

    # Train from database
    train_db_parser = subparsers.add_parser(
        "train-database",
        help="Train model on real database data"
    )
    train_db_parser.add_argument(
        "--model-type",
        choices=["random_forest", "gradient_boosting"],
        default="random_forest",
        help="Type of model to train"
    )
    train_db_parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of data for testing"
    )
    train_db_parser.add_argument(
        "--output",
        type=str,
        help="Output path for trained model"
    )

    # Evaluate
    eval_parser = subparsers.add_parser(
        "evaluate",
        help="Evaluate a trained model"
    )
    eval_parser.add_argument(
        "--model-path",
        type=str,
        default="talon/models/threat_model_latest.pkl",
        help="Path to trained model"
    )

    args = parser.parse_args()

    if args.command == "train-synthetic":
        train_synthetic(args)
    elif args.command == "train-database":
        train_from_database(args)
    elif args.command == "evaluate":
        evaluate_model(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
