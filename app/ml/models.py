"""
ML Models
=========
Implementations of three anomaly detection models with consistent interfaces.

Models:
    RandomForestModel   — Ensemble classifier (supervised)
    XGBoostModel        — Gradient boosting classifier (supervised)
    IsolationForestModel — Unsupervised anomaly detection

Each model implements train(), predict(), evaluate(), and get_model() methods
for a consistent API across the pipeline.
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
)

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except Exception:
    HAS_XGBOOST = False


class BaseModel:
    """
    Base class for all ML models.
    Provides a consistent interface for training, prediction, and evaluation.
    """

    def __init__(self):
        self.model = None
        self.is_trained = False

    def train(self, X_train, y_train):
        """Train the model on training data."""
        raise NotImplementedError

    def predict(self, X):
        """Generate predictions."""
        raise NotImplementedError

    def predict_proba(self, X):
        """Generate prediction probabilities (if available)."""
        raise NotImplementedError

    def evaluate(self, X_test, y_test):
        """
        Evaluate model performance on test data.

        Returns:
            Dict with accuracy, precision, recall, f1_score, roc_auc.
        """
        y_pred = self.predict(X_test)

        # Convert to binary for standard detection metrics (anomaly vs normal)
        y_test_bin = (np.asarray(y_test) > 0).astype(int)
        y_pred_bin = (np.asarray(y_pred) > 0).astype(int)

        metrics = {
            'accuracy': float(accuracy_score(y_test_bin, y_pred_bin)),
            'precision': float(precision_score(y_test_bin, y_pred_bin, average='binary', zero_division=0)),
            'recall': float(recall_score(y_test_bin, y_pred_bin, average='binary', zero_division=0)),
            'f1_score': float(f1_score(y_test_bin, y_pred_bin, average='binary', zero_division=0)),
            'roc_auc': 0.0,
        }

        # ROC AUC requires probability scores
        try:
            y_proba = self.predict_proba(X_test)
            if y_proba is not None and len(np.unique(y_test_bin)) == 2:
                # If multiclass probability prediction, reduce to single anomaly probability
                if len(y_proba.shape) > 1 and y_proba.shape[1] > 1:
                    anomaly_proba = y_proba[:, 1:].sum(axis=1)
                else:
                    anomaly_proba = y_proba
                metrics['roc_auc'] = float(roc_auc_score(y_test_bin, anomaly_proba))
        except Exception:
            pass

        return metrics

    def get_model(self):
        """Return the underlying sklearn/xgboost model for SHAP."""
        return self.model


class RandomForestModel(BaseModel):
    """
    Random Forest Classifier for network anomaly detection.

    Strengths:
        - Robust to overfitting
        - Handles mixed feature types well
        - Built-in feature importance
        - Parallelisable training
    """

    def __init__(self, n_estimators=100, max_depth=None, random_state=42):
        super().__init__()
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1,              # Use all CPU cores
            class_weight='balanced', # Handle class imbalance
            min_samples_split=5,
            min_samples_leaf=2,
        )

    def train(self, X_train, y_train):
        """Train the Random Forest classifier."""
        self.model.fit(X_train, y_train)
        self.is_trained = True
        return self

    def predict(self, X):
        """Generate binary predictions (0=normal, 1=anomaly)."""
        return self.model.predict(X)

    def predict_proba(self, X):
        """Get full probability matrix for all classes."""
        classes = getattr(self.model, 'classes_', [])
        if len(classes) == 1:
            if classes[0] == 0:
                return np.zeros(len(X))
            else:
                return np.ones(len(X))
        return self.model.predict_proba(X)


class XGBoostModel(BaseModel):
    """
    XGBoost Gradient Boosting Classifier for network anomaly detection.

    Strengths:
        - Superior accuracy on tabular data
        - Built-in regularisation (L1/L2)
        - Handles missing values natively
        - Feature importance via gain metrics
    """

    def __init__(self, n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42):
        super().__init__()
        if not HAS_XGBOOST:
            raise ImportError('XGBoost is not installed. Install with: pip install xgboost')

        self.model = xgb.XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            random_state=random_state,
            n_jobs=-1,
            eval_metric='logloss',
            use_label_encoder=False,
            scale_pos_weight=1,     # Adjusted dynamically in train()
            reg_alpha=0.1,          # L1 regularisation
            reg_lambda=1.0,         # L2 regularisation
        )

    def train(self, X_train, y_train):
        """Train the XGBoost classifier with early stopping awareness."""
        # Compute class weight ratio for imbalanced datasets
        n_positive = np.sum(y_train == 1)
        n_negative = np.sum(y_train == 0)
        if n_positive > 0 and len(np.unique(y_train)) == 2:
            self.model.set_params(scale_pos_weight=n_negative / n_positive)

        self.model.fit(X_train, y_train)
        self.is_trained = True
        return self

    def predict(self, X):
        """Generate binary predictions."""
        return self.model.predict(X)

    def predict_proba(self, X):
        """Get full probability matrix for all classes."""
        classes = getattr(self.model, 'classes_', [])
        if len(classes) == 1:
            if classes[0] == 0:
                return np.zeros(len(X))
            else:
                return np.ones(len(X))
        return self.model.predict_proba(X)


class IsolationForestModel(BaseModel):
    """
    Isolation Forest for unsupervised anomaly detection.

    Strengths:
        - No labelled data required
        - Efficient on high-dimensional data
        - Linear time complexity
        - Detects novel/unknown anomalies

    Note: This model does not use the target column. It detects anomalies
    purely based on feature isolation properties.
    """

    def __init__(self, n_estimators=100, contamination=0.1, random_state=42):
        super().__init__()
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,  # Expected anomaly proportion
            random_state=random_state,
            n_jobs=-1,
            max_samples='auto',
        )

    def train(self, X_train, y_train=None):
        """
        Train the Isolation Forest (unsupervised — ignores y_train).
        """
        self.model.fit(X_train)
        self.is_trained = True
        return self

    def predict(self, X):
        """
        Generate binary predictions.
        Isolation Forest returns 1 for normal, -1 for anomaly.
        We convert to 0=normal, 1=anomaly for consistency.
        """
        raw_predictions = self.model.predict(X)
        # Convert: -1 (anomaly) → 1, 1 (normal) → 0
        return np.where(raw_predictions == -1, 1, 0)

    def predict_proba(self, X):
        """
        Get anomaly scores.
        Uses the decision function (negative = more anomalous).
        Normalised to [0, 1] range.
        """
        scores = self.model.decision_function(X)
        # Normalise: more negative = higher anomaly probability
        min_score = scores.min()
        max_score = scores.max()
        if max_score - min_score == 0:
            return np.zeros(len(X))
        normalised = 1 - (scores - min_score) / (max_score - min_score)
        return normalised


# --- Factory ---

def get_model(model_type):
    """
    Factory function to create a model instance by type string.

    Args:
        model_type: One of 'random_forest', 'xgboost', 'isolation_forest'.

    Returns:
        Model instance.

    Raises:
        ValueError: If model_type is not recognised.
    """
    models = {
        'random_forest': RandomForestModel,
        'xgboost': XGBoostModel,
        'isolation_forest': IsolationForestModel,
    }

    if model_type not in models:
        raise ValueError(f'Unknown model type: {model_type}. Choose from: {list(models.keys())}')

    return models[model_type]()
