"""
SHAP Explainability
===================
Provides model-agnostic explainability using SHAP (SHapley Additive exPlanations).

Features:
    - TreeExplainer for Random Forest and XGBoost (fast, exact)
    - KernelExplainer for Isolation Forest (model-agnostic)
    - Feature importance rankings
    - Per-sample explanations
    - Summary statistics for reports
"""

import numpy as np

try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False


class SHAPExplainer:
    """
    Generates SHAP explanations for model predictions.
    Adapts the explainer type based on the model architecture.
    """

    def __init__(self, model, model_type, feature_names, max_samples=100):
        """
        Args:
            model: Trained model instance (sklearn/xgboost).
            model_type: Model type string for explainer selection.
            feature_names: List of feature column names.
            max_samples: Maximum samples for SHAP computation (performance).
        """
        self.model = model
        self.model_type = model_type
        self.feature_names = feature_names
        self.max_samples = max_samples
        self.explainer = None
        self.shap_values = None

    def explain(self, X):
        """
        Compute SHAP values for the given data.

        Args:
            X: Feature matrix (np.ndarray).

        Returns:
            Dict with feature importance and SHAP summary data.
        """
        if not HAS_SHAP:
            return self._fallback_importance(X)

        try:
            # Subsample for performance on large datasets
            if len(X) > self.max_samples:
                indices = np.random.choice(len(X), self.max_samples, replace=False)
                X_sample = X[indices]
            else:
                X_sample = X

            # Select appropriate SHAP explainer
            if self.model_type in ('random_forest', 'xgboost'):
                # TreeExplainer is fast and exact for tree-based models
                self.explainer = shap.TreeExplainer(self.model)
                self.shap_values = self.explainer.shap_values(X_sample)
            else:
                # KernelExplainer for model-agnostic explanation (Isolation Forest)
                # Use a small background sample for efficiency
                bg_size = min(50, len(X_sample))
                background = shap.sample(X_sample, bg_size)

                # Wrap prediction function
                def predict_fn(x):
                    return self.model.decision_function(x)

                self.explainer = shap.KernelExplainer(predict_fn, background)
                self.shap_values = self.explainer.shap_values(X_sample, nsamples=100)

            # Process SHAP values
            return self._process_shap_values()

        except Exception as e:
            # Fall back to model's built-in feature importance
            print(f'SHAP computation failed: {str(e)}. Using fallback.')
            return self._fallback_importance(X)

    def _process_shap_values(self):
        """
        Process raw SHAP values into feature importance rankings.

        Returns:
            Dict with:
                - feature_importance: {feature_name: importance_score}
                - shap_summary: {feature_name: mean_abs_shap_value}
                - top_features: List of top 10 most important features
        """
        values = self.shap_values

        # Handle multi-class SHAP values (take positive class)
        if isinstance(values, list):
            values = values[1] if len(values) > 1 else values[0]

        # Compute mean absolute SHAP values per feature
        mean_abs_shap = np.abs(values).mean(axis=0)

        # Build feature importance dict
        feature_importance = {}
        shap_summary = {}

        for i, name in enumerate(self.feature_names):
            if i < len(mean_abs_shap):
                importance = float(mean_abs_shap[i])
                feature_importance[name] = round(importance, 6)
                shap_summary[name] = round(importance, 6)

        # Sort by importance
        sorted_features = sorted(
            feature_importance.items(), key=lambda x: x[1], reverse=True
        )

        # Top 10 features
        top_features = [
            {'feature': name, 'importance': score}
            for name, score in sorted_features[:10]
        ]

        return {
            'feature_importance': feature_importance,
            'shap_summary': shap_summary,
            'top_features': top_features,
        }

    def _fallback_importance(self, X):
        """
        Fallback: use the model's built-in feature importance if SHAP fails.

        Returns:
            Dict with feature importance from the model's native method.
        """
        feature_importance = {}

        try:
            if hasattr(self.model, 'feature_importances_'):
                importances = self.model.feature_importances_
                for i, name in enumerate(self.feature_names):
                    if i < len(importances):
                        feature_importance[name] = round(float(importances[i]), 6)
            else:
                # Equal importance if no method available
                for name in self.feature_names:
                    feature_importance[name] = round(1.0 / len(self.feature_names), 6)
        except Exception:
            for name in self.feature_names:
                feature_importance[name] = round(1.0 / max(len(self.feature_names), 1), 6)

        sorted_features = sorted(
            feature_importance.items(), key=lambda x: x[1], reverse=True
        )

        return {
            'feature_importance': feature_importance,
            'shap_summary': feature_importance,
            'top_features': [
                {'feature': name, 'importance': score}
                for name, score in sorted_features[:10]
            ],
        }
