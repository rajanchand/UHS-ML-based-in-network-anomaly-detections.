"""
Threat Scoring System
=====================
Computes composite threat scores (0-100) for detected anomalies
based on model confidence, feature deviation, and anomaly density.

Severity Levels:
    Critical (75-100): Immediate action required
    High     (50-74):  Priority investigation needed
    Medium   (25-49):  Review during regular security cycle
    Low      (0-24):   Normal activity, routine monitoring
"""

import numpy as np


class ThreatScorer:
    """
    Computes a composite threat score for network anomaly detection results.

    The score combines:
        1. Anomaly density (what % of records are anomalous)
        2. Model confidence (average prediction probability)
        3. Feature deviation (how far anomalies deviate from normal)
    """

    # Severity level thresholds
    SEVERITY_LEVELS = {
        'critical': (75, 100),
        'high': (50, 74),
        'medium': (25, 49),
        'low': (0, 24),
    }

    # Component weights for composite score
    WEIGHTS = {
        'anomaly_density': 0.3,
        'model_confidence': 0.4,
        'feature_deviation': 0.3,
    }

    @staticmethod
    def compute_threat_score(predictions, probabilities, X_data):
        """
        Compute the composite threat score.

        Args:
            predictions: Binary predictions array (0=normal, 1=anomaly).
            probabilities: Prediction probability scores.
            X_data: Feature matrix for deviation analysis.

        Returns:
            Dict with threat_score, severity, component scores, and per-record scores.
        """
        predictions = np.asarray(predictions)
        probabilities = np.asarray(probabilities) if probabilities is not None else None

        total = len(predictions)
        anomaly_count = int(np.sum(predictions == 1))

        if total == 0:
            return ThreatScorer._empty_result()

        # Convert probabilities to a 1D array of anomaly probabilities (0 to 1)
        if probabilities is not None:
            if len(probabilities.shape) > 1:
                if probabilities.shape[1] > 1:
                    anomaly_probs = probabilities[:, 1:].sum(axis=1)
                else:
                    anomaly_probs = np.zeros(len(probabilities))
            else:
                anomaly_probs = probabilities
        else:
            anomaly_probs = None

        # --- Component 1: Anomaly Density Score (0-100) ---
        anomaly_rate = anomaly_count / total
        density_score = min(anomaly_rate * 200, 100)  # 50% anomalies = max score

        # --- Component 2: Model Confidence Score (0-100) ---
        if anomaly_probs is not None and len(anomaly_probs) > 0:
            # Average confidence for anomaly predictions
            anomaly_mask = predictions == 1
            if anomaly_mask.any():
                avg_confidence = float(np.mean(anomaly_probs[anomaly_mask]))
                confidence_score = avg_confidence * 100
            else:
                confidence_score = 0.0
        else:
            confidence_score = 50.0  # Default if no probabilities

        # --- Component 3: Feature Deviation Score (0-100) ---
        deviation_score = ThreatScorer._compute_deviation_score(X_data, predictions)

        # --- Composite Threat Score ---
        composite = (
            ThreatScorer.WEIGHTS['anomaly_density'] * density_score +
            ThreatScorer.WEIGHTS['model_confidence'] * confidence_score +
            ThreatScorer.WEIGHTS['feature_deviation'] * deviation_score
        )
        composite = round(min(max(composite, 0), 100), 1)

        # --- Severity Classification ---
        severity = ThreatScorer.classify_severity(composite)

        # --- Per-Record Threat Scores ---
        per_record_scores = ThreatScorer._compute_per_record_scores(
            predictions, anomaly_probs
        )

        return {
            'threat_score': composite,
            'severity': severity,
            'anomaly_count': anomaly_count,
            'anomaly_rate': round(anomaly_rate * 100, 2),
            'components': {
                'anomaly_density': round(density_score, 1),
                'model_confidence': round(confidence_score, 1),
                'feature_deviation': round(deviation_score, 1),
            },
            'per_record_scores': per_record_scores.tolist() if isinstance(per_record_scores, np.ndarray) else per_record_scores,
        }

    @staticmethod
    def _compute_deviation_score(X_data, predictions):
        """
        Compute how much anomalous records deviate from normal patterns.
        Uses z-score based deviation from the normal class mean.
        """
        try:
            X = np.asarray(X_data)
            normal_mask = predictions == 0
            anomaly_mask = predictions == 1

            if not normal_mask.any() or not anomaly_mask.any():
                return 0.0

            # Compute mean and std of normal traffic
            normal_mean = X[normal_mask].mean(axis=0)
            normal_std = X[normal_mask].std(axis=0)
            normal_std[normal_std == 0] = 1  # Prevent division by zero

            # Compute average z-score deviation of anomalies
            anomaly_deviations = np.abs(X[anomaly_mask] - normal_mean) / normal_std
            avg_deviation = float(np.mean(anomaly_deviations))

            # Normalise to 0-100 (z-score of 3 = score of 100)
            deviation_score = min(avg_deviation / 3.0 * 100, 100)
            return round(deviation_score, 1)

        except Exception:
            return 0.0

    @staticmethod
    def _compute_per_record_scores(predictions, anomaly_probs):
        """
        Compute threat scores for each individual record.

        Returns:
            Array of per-record threat scores (0-100).
        """
        if anomaly_probs is None:
            return (predictions * 50).tolist()

        # Scale probabilities to 0-100 and apply prediction mask
        scores = anomaly_probs * 100
        # Only anomalous records get a threat score
        scores = scores * (predictions > 0)
        return np.round(scores, 1)

    @staticmethod
    def classify_severity(score):
        """
        Classify a threat score into a severity level.

        Args:
            score: Numeric threat score (0-100).

        Returns:
            Severity string: 'critical', 'high', 'medium', or 'low'.
        """
        if score >= 75:
            return 'critical'
        elif score >= 50:
            return 'high'
        elif score >= 25:
            return 'medium'
        else:
            return 'low'

    @staticmethod
    def _empty_result():
        """Return an empty threat score result for edge cases."""
        return {
            'threat_score': 0.0,
            'severity': 'low',
            'anomaly_count': 0,
            'anomaly_rate': 0.0,
            'components': {
                'anomaly_density': 0.0,
                'model_confidence': 0.0,
                'feature_deviation': 0.0,
            },
            'per_record_scores': [],
        }
