"""
Model trainer for threat scoring system.

Trains ML models on historical CVE data to predict threat scores.
Includes synthetic data generation for testing/bootstrapping.
"""

import random
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from uuid import uuid4

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    mean_squared_error,
    mean_absolute_error,
    r2_score
)

from talon.models import Vulnerability
from .feature_engineering import VulnerabilityFeatureExtractor
from .threat_model import ThreatModel, create_threat_model
from shared.logging import get_logger

logger = get_logger(__name__)


class ThreatModelTrainer:
    """
    Trainer for ML-based threat scoring models.

    Handles:
    - Data loading and preprocessing
    - Feature extraction
    - Model training and evaluation
    - Model serialization
    """

    def __init__(
        self,
        feature_extractor: VulnerabilityFeatureExtractor = None
    ):
        """Initialize trainer with feature extractor."""
        self.feature_extractor = (
            feature_extractor or VulnerabilityFeatureExtractor()
        )

    def train(
        self,
        vulnerabilities: List[Vulnerability],
        ground_truth_scores: List[float],
        model_type: str = "random_forest",
        test_size: float = 0.2,
        **model_kwargs
    ) -> ThreatModel:
        """
        Train a threat scoring model.

        Args:
            vulnerabilities: List of vulnerability instances
            ground_truth_scores: True threat scores (0-100) for training
            model_type: Type of model to train
            test_size: Fraction of data for testing
            **model_kwargs: Additional model parameters

        Returns:
            Trained ThreatModel instance
        """
        logger.info(f"Training {model_type} model on {len(vulnerabilities)} samples")

        # Extract features
        features = self.feature_extractor.extract_features_batch(
            vulnerabilities
        )
        feature_names = self.feature_extractor.get_feature_names()

        logger.info(f"Extracted {features.shape[1]} features")

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features,
            ground_truth_scores,
            test_size=test_size,
            random_state=42
        )

        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # Create and train model
        model = create_threat_model(model_type, **model_kwargs)

        logger.info("Training model...")
        model.fit(X_train_scaled, y_train)

        # Evaluate
        train_score = model.score(X_train_scaled, y_train)
        test_score = model.score(X_test_scaled, y_test)

        y_pred = model.predict(X_test_scaled)
        mse = mean_squared_error(y_test, y_pred)
        mae = mean_absolute_error(y_test, y_pred)
        r2 = r2_score(y_test, y_pred)

        # Cross-validation
        cv_scores = cross_val_score(
            model,
            X_train_scaled,
            y_train,
            cv=5,
            scoring="r2"
        )

        metrics = {
            "train_r2": train_score,
            "test_r2": test_score,
            "mse": mse,
            "mae": mae,
            "r2": r2,
            "cv_mean": cv_scores.mean(),
            "cv_std": cv_scores.std(),
        }

        logger.info(f"Training complete. Test R²: {test_score:.4f}, MAE: {mae:.2f}")

        # Create ThreatModel
        threat_model = ThreatModel(
            model=model,
            scaler=scaler,
            feature_names=feature_names,
            version=self._generate_version(),
            trained_at=datetime.utcnow(),
            metrics=metrics,
        )

        return threat_model

    def evaluate(
        self,
        model: ThreatModel,
        vulnerabilities: List[Vulnerability],
        ground_truth_scores: List[float]
    ) -> Dict[str, float]:
        """
        Evaluate a trained model on new data.

        Args:
            model: Trained ThreatModel
            vulnerabilities: Validation vulnerabilities
            ground_truth_scores: True threat scores

        Returns:
            Dictionary of evaluation metrics
        """
        # Extract features
        features = self.feature_extractor.extract_features_batch(
            vulnerabilities
        )

        # Predict
        predictions = model.predict(features)

        # Calculate metrics
        mse = mean_squared_error(ground_truth_scores, predictions)
        mae = mean_absolute_error(ground_truth_scores, predictions)
        r2 = r2_score(ground_truth_scores, predictions)

        return {
            "mse": mse,
            "mae": mae,
            "r2": r2,
            "rmse": np.sqrt(mse),
        }

    def generate_synthetic_training_data(
        self,
        n_samples: int = 1000
    ) -> Tuple[List[Vulnerability], List[float]]:
        """
        Generate synthetic CVE data for training.

        Creates realistic vulnerability data with ground truth scores
        based on known patterns from historical CVE data.

        Args:
            n_samples: Number of synthetic samples to generate

        Returns:
            Tuple of (vulnerabilities, ground_truth_scores)
        """
        logger.info(f"Generating {n_samples} synthetic training samples")

        vulnerabilities = []
        scores = []

        for _ in range(n_samples):
            vuln, score = self._generate_synthetic_vulnerability()
            vulnerabilities.append(vuln)
            scores.append(score)

        return vulnerabilities, scores

    def _generate_synthetic_vulnerability(
        self
    ) -> Tuple[Vulnerability, float]:
        """
        Generate a single synthetic vulnerability with ground truth score.

        Returns:
            Tuple of (Vulnerability, threat_score)
        """
        # Randomly choose severity
        severity = random.choices(
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
            weights=[0.05, 0.15, 0.40, 0.35, 0.05]
        )[0]

        # Generate CVSS score based on severity
        cvss_ranges = {
            "CRITICAL": (9.0, 10.0),
            "HIGH": (7.0, 8.9),
            "MEDIUM": (4.0, 6.9),
            "LOW": (0.1, 3.9),
            "UNKNOWN": (0.0, 10.0),
        }
        cvss_min, cvss_max = cvss_ranges[severity]
        cvss_score = round(random.uniform(cvss_min, cvss_max), 1)

        # Generate CVSS vector
        cvss_vector = self._generate_cvss_vector(cvss_score)

        # Generate age (more recent = higher threat)
        days_ago = int(random.expovariate(1/180))  # Exponential distribution
        published_date = datetime.utcnow() - timedelta(days=days_ago)

        # Generate affected packages
        n_packages = random.choices(
            [1, 2, 3, 5, 10],
            weights=[0.5, 0.25, 0.15, 0.08, 0.02]
        )[0]

        affected_packages = [
            {
                "name": random.choice(list(
                    self.feature_extractor.POPULAR_PACKAGES
                )),
                "version": f"{random.randint(1,5)}.{random.randint(0,20)}.{random.randint(0,10)}",
                "ecosystem": random.choice(["npm", "pip", "maven", "composer"])
            }
            for _ in range(n_packages)
        ]

        # Generate references
        n_refs = random.randint(1, 8)
        references = [
            {"url": f"https://example.com/ref{i}"}
            for i in range(n_refs)
        ]

        # Add NVD reference sometimes
        if random.random() < 0.7:
            references.append({
                "url": f"https://nvd.nist.gov/vuln/detail/CVE-2024-{random.randint(1000, 9999)}"
            })

        # Add exploit reference sometimes
        has_exploit = random.random() < 0.3
        if has_exploit:
            references.append({
                "url": f"https://exploit-db.com/exploits/{random.randint(10000, 99999)}"
            })

        # Create vulnerability object
        cve_id = f"CVE-{random.randint(2020, 2024)}-{random.randint(1000, 99999)}"

        vuln = Vulnerability(
            id=uuid4(),
            cve_id=cve_id,
            severity=severity,
            description=f"Synthetic vulnerability {cve_id}",
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_packages=affected_packages,
            references=references,
            published_date=published_date,
            modified_date=published_date,
        )

        # Calculate ground truth score based on features
        ground_truth = self._calculate_ground_truth_score(
            severity=severity,
            cvss_score=cvss_score,
            days_ago=days_ago,
            has_exploit=has_exploit,
            n_packages=n_packages,
            is_network=("AV:N" in cvss_vector),
            is_low_complexity=("AC:L" in cvss_vector),
        )

        return vuln, ground_truth

    def _generate_cvss_vector(self, cvss_score: float) -> str:
        """Generate realistic CVSS vector based on score."""
        # Higher scores tend to have easier exploitation
        if cvss_score >= 9.0:
            av = "N"  # Network
            ac = "L"  # Low complexity
            pr = "N"  # No privileges
            ui = "N"  # No interaction
        elif cvss_score >= 7.0:
            av = random.choice(["N", "A", "L"])
            ac = random.choice(["L", "H"])
            pr = random.choice(["N", "L"])
            ui = random.choice(["N", "R"])
        else:
            av = random.choice(["N", "A", "L", "P"])
            ac = random.choice(["L", "H"])
            pr = random.choice(["N", "L", "H"])
            ui = random.choice(["N", "R"])

        c = random.choice(["N", "L", "H"])
        i = random.choice(["N", "L", "H"])
        a = random.choice(["N", "L", "H"])

        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:U/C:{c}/I:{i}/A:{a}"

    def _calculate_ground_truth_score(
        self,
        severity: str,
        cvss_score: float,
        days_ago: int,
        has_exploit: bool,
        n_packages: int,
        is_network: bool,
        is_low_complexity: bool,
    ) -> float:
        """
        Calculate ground truth threat score for synthetic data.

        Uses known relationships between features and threat level.
        """
        # Base score from CVSS
        score = (cvss_score / 10.0) * 40  # 0-40 points

        # Severity boost
        severity_boost = {
            "CRITICAL": 20,
            "HIGH": 15,
            "MEDIUM": 8,
            "LOW": 3,
            "UNKNOWN": 5,
        }
        score += severity_boost[severity]

        # Exploit availability
        if has_exploit:
            score += 20

        # Freshness (newer = higher threat)
        if days_ago < 30:
            score += 15
        elif days_ago < 90:
            score += 10
        elif days_ago < 180:
            score += 5

        # Network attack vector
        if is_network:
            score += 8

        # Low complexity
        if is_low_complexity:
            score += 7

        # Package popularity/scope
        if n_packages >= 5:
            score += 5
        elif n_packages >= 3:
            score += 3

        # Add some noise
        noise = random.gauss(0, 3)
        score += noise

        # Clamp to 0-100
        score = max(0, min(100, score))

        return round(score, 2)

    def _generate_version(self) -> str:
        """Generate model version string."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return f"v1.0_{timestamp}"
