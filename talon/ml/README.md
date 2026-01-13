: # ML-Based Threat Scoring System

Scikit-learn powered machine learning system for predicting vulnerability threat scores (0-100).

## Overview

The threat scoring system uses ensemble machine learning models to predict how dangerous a vulnerability is based on multiple factors:

- **CVSS Score**: Base severity rating (0-10)
- **Package Popularity**: How widely used the affected packages are
- **Exploit Availability**: Whether public exploits exist
- **CVE Age**: How recent the vulnerability is
- **Attack Vector**: Network, adjacent, local, or physical
- **Attack Complexity**: How difficult to exploit
- **Privileges Required**: What access level needed
- **Impact Metrics**: Confidentiality, integrity, availability impacts

## Architecture

```
┌─────────────────────────────────────────┐
│     Vulnerability Data Input            │
│  (CVE ID, CVSS, packages, references)   │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│   Feature Engineering Module            │
│  - Extract 16 normalized features       │
│  - CVSS vector parsing                  │
│  - Exploit detection                    │
│  - Package popularity lookup            │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│   ML Model (Random Forest/GBM)          │
│  - Trained on historical CVE data       │
│  - StandardScaler preprocessing         │
│  - Ensemble predictions                 │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│     Threat Score Output (0-100)         │
│  + Feature importance breakdown         │
└─────────────────────────────────────────┘
```

## Features Extracted

### Core CVSS Features (3 features)
- `cvss_score`: Normalized CVSS base score (0-1)
- `cvss_impact`: Impact subscore from vector (0-1)
- `cvss_exploitability`: Exploitability subscore (0-1)

### Package Features (2 features)
- `package_popularity`: How popular affected packages are (0-1)
- `affected_packages_count`: Number of affected packages (log scale, 0-1)

### Exploit Features (2 features)
- `exploit_availability`: Public exploit existence (0 or 1)
- `exploit_complexity`: How easy to exploit (0-1, inverse of AC)

### Temporal Features (2 features)
- `cve_age_days`: Days since publication (normalized, 0-1)
- `cve_freshness`: Inverse of age - newer = higher (0-1)

### Attention Features (2 features)
- `reference_count`: Number of references (log scale, 0-1)
- `has_nvd_reference`: NVD listing (0 or 1)

### Attack Vector Features (3 features)
- `is_network_attack`: Network attackable (0 or 1)
- `requires_privileges`: Privilege requirements (0-1, inverse)
- `requires_user_interaction`: UI needed (0-1, inverse)

### Severity Features (2 features)
- `is_critical`: Critical severity flag (0 or 1)
- `is_high`: High severity flag (0 or 1)

**Total: 16 features**

## Training the Model

### Option 1: Train on Synthetic Data (Quickstart)

For initial model training or testing:

```bash
cd /Users/christopherpeterson/Documents/GitHub/lucius

# Train with 1000 synthetic samples
python talon/ml/train_model.py train-synthetic --n-samples 1000

# Train with different model type
python talon/ml/train_model.py train-synthetic \
    --n-samples 5000 \
    --model-type gradient_boosting

# Specify custom output path
python talon/ml/train_model.py train-synthetic \
    --n-samples 2000 \
    --output talon/models/my_model.pkl
```

The synthetic data generator creates realistic CVE data with:
- Proper CVSS score distributions by severity
- Realistic exploit availability patterns
- Age-based threat decay
- Package popularity simulation
- Ground truth scores based on known vulnerability patterns

### Option 2: Train on Real Database Data

When you have real vulnerabilities with existing threat scores:

```bash
# Train on database data
python talon/ml/train_model.py train-database

# With custom settings
python talon/ml/train_model.py train-database \
    --model-type random_forest \
    --test-size 0.25
```

Requirements:
- At least 100 vulnerabilities with `threat_score` populated
- Database configured and accessible

### Model Types

**Random Forest** (default, recommended)
- Robust to overfitting
- Handles non-linear relationships well
- Provides feature importance
- Fast prediction

```python
model_kwargs = {
    "n_estimators": 100,      # Number of trees
    "max_depth": 15,          # Tree depth
    "min_samples_split": 5,   # Min samples to split
    "min_samples_leaf": 2,    # Min samples per leaf
}
```

**Gradient Boosting**
- Often higher accuracy
- Better handling of complex patterns
- Slower training and prediction
- More prone to overfitting

```python
model_kwargs = {
    "n_estimators": 100,
    "max_depth": 5,
    "learning_rate": 0.1,
}
```

## Evaluating the Model

```bash
# Evaluate trained model
python talon/ml/train_model.py evaluate \
    --model-path talon/models/threat_model_latest.pkl
```

Output includes:
- Performance metrics (R², MSE, MAE)
- Feature importance visualization
- Sample predictions with errors
- Distribution analysis

### Performance Metrics

- **R² Score**: Proportion of variance explained (target: > 0.85)
- **MAE (Mean Absolute Error)**: Average prediction error in score points (target: < 5.0)
- **MSE (Mean Squared Error)**: Squared error metric (target: < 50)
- **CV Score**: Cross-validation R² (should be close to test R²)

## Using the Model in Production

### Integration with VulnerabilityService

The ML model integrates seamlessly with the existing service:

```python
from talon.services.vulnerability_service import VulnerabilityService

service = VulnerabilityService()

# Create vulnerability - automatically uses ML scoring
vuln = service.create_vulnerability(
    cve_id="CVE-2024-1234",
    severity="CRITICAL",
    cvss_score=9.8,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    calculate_threat=True  # Uses ML model
)

print(f"Threat score: {vuln.threat_score}")
```

### Direct ML Scorer Usage

```python
from talon.ml.threat_model import MLThreatScorer
from talon.models import Vulnerability

# Initialize scorer (loads latest model)
scorer = MLThreatScorer()

# Score a vulnerability
vulnerability = Vulnerability.query.first()
score, features = scorer.calculate_threat_score(vulnerability)

print(f"Threat score: {score}")
print("Feature contributions:")
for feature, value in features.items():
    print(f"  {feature}: {value:.3f}")
```

### Feature Importance Analysis

```python
scorer = MLThreatScorer()
importance = scorer.get_feature_importance()

print("Most important features:")
for feature, score in sorted(importance.items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f"  {feature}: {score:.4f}")
```

### Batch Scoring

```python
# Score multiple vulnerabilities efficiently
vulnerabilities = Vulnerability.query.filter_by(severity="CRITICAL").all()
results = scorer.batch_calculate(vulnerabilities)

for cve_id, score in results[:10]:
    print(f"{cve_id}: {score}")
```

## Model Serialization

Models are saved in two formats:

1. **Pickle format** (`.pkl`): Standard Python serialization
2. **Joblib format** (`.joblib`): Optimized for sklearn models

Both formats include:
- Trained model object
- StandardScaler for feature normalization
- Feature names list
- Model version string
- Training timestamp
- Performance metrics

### Model File Structure

```python
{
    "model": RandomForestRegressor(...),
    "scaler": StandardScaler(...),
    "feature_names": ["cvss_score", "exploit_availability", ...],
    "version": "v1.0_20240115_143022",
    "trained_at": datetime(...),
    "metrics": {
        "train_r2": 0.92,
        "test_r2": 0.88,
        "mae": 4.23,
        ...
    }
}
```

### Loading Custom Models

```python
from talon.ml.threat_model import MLThreatScorer

# Load specific model version
scorer = MLThreatScorer(
    model_path="talon/models/threat_model_v1.0_20240115.pkl"
)

# Check model info
print(f"Model version: {scorer.model.version}")
print(f"Trained: {scorer.model.trained_at}")
print(f"Test R²: {scorer.model.metrics['test_r2']:.4f}")
```

## Fallback Behavior

If ML model fails to load or predict, the system automatically falls back to rule-based scoring:

```
ML Model (Primary)
        ↓
    [Fails?]
        ↓
Rule-Based Scoring (Fallback)
```

The fallback uses weighted feature combination:
- CVSS score: 25%
- CVSS exploitability: 20%
- Package popularity: 15%
- Exploit availability: 15%
- CVE freshness: 10%
- Other factors: 15%

## Continuous Improvement

### Retraining Workflow

1. **Collect new data**: Vulnerabilities scored by security team
2. **Retrain model**: `python talon/ml/train_model.py train-database`
3. **Evaluate**: Compare metrics to previous version
4. **Deploy**: Replace model file if metrics improve
5. **Monitor**: Track prediction accuracy in production

### Adding Custom Features

To add new features:

1. **Update `VulnerabilityFeatureExtractor`**:
```python
def _extract_my_new_feature(self, vuln: Vulnerability) -> float:
    # Feature extraction logic
    return normalized_value
```

2. **Add to `extract_features()`**:
```python
features["my_new_feature"] = self._extract_my_new_feature(vuln)
```

3. **Update `get_feature_names()`**:
```python
return [..., "my_new_feature"]
```

4. **Retrain model** with new features

### Hyperparameter Tuning

```python
from sklearn.model_selection import GridSearchCV
from talon.ml.threat_model import create_threat_model

param_grid = {
    'n_estimators': [50, 100, 200],
    'max_depth': [10, 15, 20],
    'min_samples_split': [2, 5, 10],
}

model = create_threat_model("random_forest")
grid_search = GridSearchCV(model, param_grid, cv=5, scoring='r2')
grid_search.fit(X_train_scaled, y_train)

print("Best parameters:", grid_search.best_params_)
print("Best score:", grid_search.best_score_)
```

## API Integration

The ML scorer integrates with the REST API automatically:

```bash
# Create vulnerability - ML scoring happens automatically
curl -X POST http://localhost:5000/api/v1/vulnerabilities \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2024-5678",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "calculate_threat": true
  }'

# Response includes ML-generated threat_score
{
  "id": "...",
  "cve_id": "CVE-2024-5678",
  "threat_score": 92.5,
  ...
}
```

## Performance Considerations

### Prediction Speed
- **Single prediction**: ~5-10ms
- **Batch (100)**: ~20-30ms
- **Feature extraction**: ~1-2ms per vulnerability

### Memory Usage
- Model file: ~5-10 MB
- Runtime memory: ~50-100 MB
- Feature matrix: ~1 KB per vulnerability

### Optimization Tips

1. **Use batch predictions** for multiple vulnerabilities
2. **Cache model** in service instance (don't reload per request)
3. **Precompute popular package lists** for faster lookups
4. **Use joblib format** for faster loading
5. **Profile feature extraction** if performance critical

## Troubleshooting

### Model won't load
- Check file path is correct
- Verify pickle/joblib file not corrupted
- Check sklearn version compatibility

### Poor predictions
- Insufficient training data (need 500+ samples)
- Feature distribution mismatch (train vs production)
- Model overfitting (tune hyperparameters)

### High prediction errors
- Retrain with more diverse data
- Add relevant features
- Try different model type (GBM vs RF)

### Fallback always triggered
- ML model file missing or corrupted
- Feature extraction failing
- Check logs for specific errors

## Example: Complete Training Pipeline

```python
from talon.ml.model_trainer import ThreatModelTrainer
from talon.ml.threat_model import MLThreatScorer

# 1. Generate or load data
trainer = ThreatModelTrainer()
vulns, scores = trainer.generate_synthetic_training_data(n_samples=2000)

# 2. Train model
model = trainer.train(
    vulnerabilities=vulns,
    ground_truth_scores=scores,
    model_type="random_forest",
    n_estimators=150,
    max_depth=20,
)

# 3. Evaluate
test_vulns, test_scores = trainer.generate_synthetic_training_data(n_samples=500)
metrics = trainer.evaluate(model, test_vulns, test_scores)
print(f"Test MAE: {metrics['mae']:.2f}")

# 4. Save
MLThreatScorer.save_model(model, "talon/models/my_model.pkl")

# 5. Deploy
scorer = MLThreatScorer(model_path="talon/models/my_model.pkl")
```

## References

- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds)
- [Scikit-learn Random Forest](https://scikit-learn.org/stable/modules/ensemble.html#random-forests)
- [Feature Engineering Best Practices](https://scikit-learn.org/stable/modules/preprocessing.html)
