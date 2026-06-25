import numpy as np
from scipy.stats import ks_2samp

class DriftDetector:
    """
    Detects concept/data drift in network traffic profiles by comparing
    a reference dataset (e.g., training distribution) to a target dataset (e.g., test or live streams).
    Uses the Kolmogorov-Smirnov (KS) test for distribution comparison.
    """

    def __init__(self, significance_level=0.05, drift_threshold=0.3):
        """
        Args:
            significance_level: Alpha level for KS test (default 0.05).
            drift_threshold: Percentage of drifted features required to trigger a general alert.
        """
        self.significance_level = significance_level
        self.drift_threshold = drift_threshold

    def detect_drift(self, reference_data, target_data, feature_names):
        """
        Evaluate drift for each feature.

        Args:
            reference_data: Reference feature matrix (np.ndarray or pd.DataFrame).
            target_data: Target feature matrix to check (np.ndarray or pd.DataFrame).
            feature_names: List of feature names matching the column order.

        Returns:
            Dict containing feature-level p-values, drift flags, overall drift status, and drift score.
        """
        if reference_data.shape[1] != target_data.shape[1]:
            raise ValueError("Reference and target data must have the same number of features.")

        num_features = reference_data.shape[1]
        drifted_features_count = 0
        features_drift_details = {}

        # Loop through each feature column
        for idx in range(num_features):
            ref_col = reference_data[:, idx]
            target_col = target_data[:, idx]
            feature_name = feature_names[idx]

            # Perform the two-sample KS test
            stat, p_val = ks_2samp(ref_col, target_col)

            # Check if statistically significant
            is_drifted = bool(p_val < self.significance_level)
            if is_drifted:
                drifted_features_count += 1

            features_drift_details[feature_name] = {
                'ks_statistic': float(stat),
                'p_value': float(p_val),
                'drifted': is_drifted
            }

        # Calculate drift ratio
        drift_ratio = float(drifted_features_count / num_features) if num_features > 0 else 0.0
        drift_detected = bool(drift_ratio >= self.drift_threshold)

        return {
            'drift_detected': drift_detected,
            'drift_ratio': round(drift_ratio, 4),
            'drifted_features_count': drifted_features_count,
            'total_features': num_features,
            'features': features_drift_details,
            'message': (
                f"Concept drift detected! {drifted_features_count}/{num_features} "
                f"({drift_ratio*100:.1f}%) features have significantly drifted."
                if drift_detected else
                f"Traffic profile stable. {drifted_features_count}/{num_features} "
                f"({drift_ratio*100:.1f}%) features have drifted."
            )
        }
