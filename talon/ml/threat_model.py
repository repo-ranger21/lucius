"""
ML-based threat scoring model using scikit-learn.

Uses Random Forest Regressor to predict threat scores (0-100)
based on vulnerability features.
"""

import os
import pickle
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import cross_val_score
import joblib

from talon.models import Vulnerability
from .feature_engineering import VulnerabilityFeatureExtractor
from shared.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ThreatModel:
    """
    Container for trained threat scoring model.

    Attributes:
        model: Trained scikit-learn model
        scaler: Feature scaler
        feature_names: List of feature names
        version: Model version string
        trained_at: Training timestamp
        metrics: Model performance metrics
    """

    model: any  # RandomForestRegressor or similar
    scaler: StandardScaler
    feature_names: List[str]
    version: str
    trained_at: datetime
    metrics: Dict[str, float]

    def predict(self, features: np.ndarray) -> np.ndarray:
        """
        Predict threat scores for feature matrix.

        Args:
            features: 2D array of shape (n_samples, n_features)

        Returns:
            1D array of threat scores (0-100)
        """
        # Scale features
        features_scaled = self.scaler.transform(features)

        # Predict
        scores = self.model.predict(features_scaled)

        # Clamp to 0-100 range
        scores = np.clip(scores, 0, 100)

        return scores

    def get_feature_importance(self) -> Dict[str, float]:
        """
        Get feature importances from the model.

        Returns:
            Dictionary mapping feature names to importance scores
        """
        if not hasattr(self.model, "feature_importances_"):
            return {}

        importances = self.model.feature_importances_
        return dict(zip(self.feature_names, importances))


class MLThreatScorer:
    """
    Production ML-based threat scorer.

    Loads trained model and provides threat scoring interface.
    Falls back to rule-based scoring if model unavailable.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        feature_extractor: Optional[VulnerabilityFeatureExtractor] = None
    ):
        """
        Initialize ML threat scorer.

        Args:
            model_path: Path to saved model file (.pkl)
            feature_extractor: Feature extractor instance
        """
        self.feature_extractor = (
            feature_extractor or VulnerabilityFeatureExtractor()
        )
        self.model: Optional[ThreatModel] = None

        # Default model path
        if model_path is None:
            model_path = self._get_default_model_path()

        # Load model if available
        if os.path.exists(model_path):
            try:
                self.model = self.load_model(model_path)
                logger.info(
                    f"Loaded ML threat model v{self.model.version} "
                    f"from {model_path}"
                )
            except Exception as e:
                logger.warning(
                    f"Failed to load ML model: {e}. "
                    "Using rule-based fallback."
                )
        else:
            logger.info(
                f"ML model not found at {model_path}. "
                "Using rule-based fallback."
            )

    def calculate_threat_score(
        self,
        vulnerability: Vulnerability,
        package_stats: Optional[Dict] = None
    ) -> Tuple[float, Dict[str, float]]:
        """
        Calculate threat score for a vulnerability.

        Args:
            vulnerability: Vulnerability instance
            package_stats: Optional package popularity stats

        Returns:
            Tuple of (threat_score, feature_dict)
        """
        # Extract features
        features = self.feature_extractor.extract_features(
            vulnerability,
            package_stats
        )

        # Use ML model if available
        if self.model is not None:
            try:
                score = self._predict_ml_score(features)
                return score, features
            except Exception as e:
                logger.error(f"ML prediction failed: {e}. Using fallback.")

        # Fallback to rule-based scoring
        score = self._calculate_rule_based_score(features)
        return score, features

    def batch_calculate(
        self,
        vulnerabilities: List[Vulnerability],
        package_stats: Optional[Dict] = None
    ) -> List[Tuple[str, float]]:
        """
        Calculate threat scores for multiple vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability instances
            package_stats: Optional package popularity stats

        Returns:
            List of (cve_id, threat_score) tuples, sorted by score
        """
        results = []

        for vuln in vulnerabilities:
            score, _ = self.calculate_threat_score(vuln, package_stats)
            results.append((vuln.cve_id, score))

        return sorted(results, key=lambda x: x[1], reverse=True)

    def _predict_ml_score(self, features: Dict[str, float]) -> float:
        """Predict threat score using ML model."""
        if self.model is None:
            raise ValueError("Model not loaded")

        # Convert features dict to array
        feature_values = [
            features[name] for name in self.model.feature_names
        ]
        feature_array = np.array([feature_values])

        # Predict
        scores = self.model.predict(feature_array)

        return round(float(scores[0]), 2)

    def _calculate_rule_based_score(
        self,
        features: Dict[str, float]
    ) -> float:
        """
        Fallback rule-based scoring when ML model unavailable.

        Uses weighted combination of features.
        """
        weights = {
            "cvss_score": 0.25,
            "cvss_exploitability": 0.20,
            "package_popularity": 0.15,
            "exploit_availability": 0.15,
            "cve_freshness": 0.10,
            "is_network_attack": 0.05,
            "affected_packages_count": 0.05,
            "is_critical": 0.03,
            "is_high": 0.02,
        }

        score = 0.0
        for feature, weight in weights.items():
            score += features.get(feature, 0.0) * weight

        # Scale to 0-100
        score *= 100

        # Boost for critical/high severity
        if features.get("is_critical", 0) > 0:
            score = min(100, score * 1.2)
        elif features.get("is_high", 0) > 0:
            score = min(100, score * 1.1)

        return round(score, 2)

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from loaded model."""
        if self.model is None:
            return {}
        return self.model.get_feature_importance()

    @staticmethod
    def load_model(model_path: str) -> ThreatModel:
        """
        Load trained model from file.

        Args:
            model_path: Path to .pkl model file

        Returns:
            ThreatModel instance
        """
        with open(model_path, "rb") as f:
            model_data = pickle.load(f)

        return ThreatModel(**model_data)

    @staticmethod
    def save_model(model: ThreatModel, model_path: str) -> None:
        """
        Save trained model to file.

        Args:
            model: ThreatModel instance
            model_path: Path to save .pkl file
        """
        # Ensure directory exists
        Path(model_path).parent.mkdir(parents=True, exist_ok=True)

        model_data = {
            "model": model.model,
            "scaler": model.scaler,
            "feature_names": model.feature_names,
            "version": model.version,
            "trained_at": model.trained_at,
            "metrics": model.metrics,
        }

        with open(model_path, "wb") as f:
            pickle.dump(model_data, f)

        # Also save with joblib for better sklearn compatibility
        joblib_path = model_path.replace(".pkl", ".joblib")
        joblib.dump(model_data, joblib_path)

        logger.info(f"Saved model to {model_path} and {joblib_path}")

    def _get_default_model_path(self) -> str:
        """Get default model file path."""
        base_dir = Path(__file__).parent.parent
        models_dir = base_dir / "models"
        return str(models_dir / "threat_model_latest.pkl")


def create_threat_model(
    model_type: str = "random_forest",
    **model_kwargs
) -> any:
    """
    Create a scikit-learn model for threat scoring.

    Args:
        model_type: Type of model ('random_forest', 'gradient_boosting')
        **model_kwargs: Additional model parameters

    Returns:
        Untrained scikit-learn model
    """
    if model_type == "random_forest":
        default_params = {
            "n_estimators": 100,
            "max_depth": 15,
            "min_samples_split": 5,
            "min_samples_leaf": 2,
            "random_state": 42,
            "n_jobs": -1,
        }
        default_params.update(model_kwargs)
        return RandomForestRegressor(**default_params)

    elif model_type == "gradient_boosting":
        default_params = {
            "n_estimators": 100,
            "max_depth": 5,
            "learning_rate": 0.1,
            "random_state": 42,
        }
        default_params.update(model_kwargs)
        return GradientBoostingRegressor(**default_params)

    else:
        raise ValueError(f"Unknown model type: {model_type}")
