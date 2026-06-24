"""
ML Pipeline Orchestrator
========================
Orchestrates the full ML workflow: preprocessing → model training →
evaluation → SHAP explanation → threat scoring.

This is the main entry point called by AnalysisService.
"""

from app.ml.preprocessing import DataPreprocessor
from app.ml.models import get_model
from app.ml.explainability import SHAPExplainer
from app.ml.threat_scoring import ThreatScorer


class MLPipeline:
    """
    End-to-end ML pipeline for network anomaly detection.

    Workflow:
        1. Load and validate dataset
        2. Preprocess features (encoding, scaling, imputation)
        3. Train selected model
        4. Evaluate performance metrics
        5. Generate SHAP explanations
        6. Compute threat scores
        7. Return comprehensive results
    """

    def __init__(self, file_path, model_type, target_column='label'):
        """
        Args:
            file_path: Path to the CSV dataset.
            model_type: ML model to use ('random_forest', 'xgboost', 'isolation_forest').
            target_column: Name of the target/label column.
        """
        self.file_path = file_path
        self.model_type = model_type
        self.target_column = target_column

    def execute(self):
        """
        Execute the full ML pipeline.

        Returns:
            Dict with all results: metrics, predictions, SHAP, threat scores.

        Raises:
            ValueError: If data validation fails.
            RuntimeError: If model training or evaluation fails.
        """
        # --- Step 1: Preprocess Data ---
        preprocessor = DataPreprocessor(target_column=self.target_column)
        data = preprocessor.prepare_train_test(self.file_path)

        X_train = data['X_train']
        X_test = data['X_test']
        y_train = data['y_train']
        y_test = data['y_test']
        feature_names = data['feature_names']
        total_records = data['total_records']

        # --- Step 2: Train Model ---
        model = get_model(self.model_type)
        model.train(X_train, y_train)

        # --- Step 3: Evaluate Model ---
        metrics = model.evaluate(X_test, y_test)

        # --- Step 4: Generate Predictions on Full Test Set ---
        predictions = model.predict(X_test)
        try:
            probabilities = model.predict_proba(X_test)
        except Exception:
            probabilities = None

        # --- Step 5: SHAP Explainability ---
        explainer = SHAPExplainer(
            model=model.get_model(),
            model_type=self.model_type,
            feature_names=feature_names,
        )
        shap_results = explainer.explain(X_test)

        # --- Step 6: Threat Scoring ---
        threat_results = ThreatScorer.compute_threat_score(
            predictions=predictions,
            probabilities=probabilities,
            X_data=X_test,
        )

        # --- Step 7: Compile Results ---
        import numpy as np
        from sklearn.metrics import confusion_matrix, roc_curve
        
        # Binarize for evaluation metrics comparison
        y_test_bin = (np.asarray(y_test) > 0).astype(int)
        y_pred_bin = (np.asarray(predictions) > 0).astype(int)
        
        anomalies_detected = int(np.sum(y_pred_bin == 1))
        
        # Compute Confusion Matrix
        cm = confusion_matrix(y_test_bin, y_pred_bin)
        
        # Compute ROC Curve points
        try:
            if probabilities is not None and len(np.unique(y_test_bin)) == 2:
                if len(probabilities.shape) > 1 and probabilities.shape[1] > 1:
                    anomaly_proba = probabilities[:, 1:].sum(axis=1)
                else:
                    anomaly_proba = probabilities
                fpr, tpr, _ = roc_curve(y_test_bin, anomaly_proba)
            else:
                fpr, tpr = np.array([0.0, 1.0]), np.array([0.0, 1.0])
        except Exception:
            fpr, tpr = np.array([0.0, 1.0]), np.array([0.0, 1.0])
            
        # Get count of each class in predictions
        unique_vals, counts = np.unique(predictions, return_counts=True)
        class_counts = dict(zip(unique_vals, counts))
        
        class_names = {
            0: 'Normal',
            1: 'DDoS',
            2: 'DoS',
            3: 'Port Scan',
            4: 'Brute Force',
            5: 'Bot Attack'
        }
        
        attack_distribution = {}
        for c_val, count in class_counts.items():
            name = class_names.get(int(c_val), 'General Anomaly')
            attack_distribution[name] = int(count)

        # Build prediction details (top anomalies for the report)
        prediction_details = []
        anomaly_indices = np.where(predictions > 0)[0]
        for idx in anomaly_indices[:100]:  # Cap at 100 for storage
            # Resolve probabilities safely
            if probabilities is not None:
                if len(probabilities.shape) > 1 and probabilities.shape[1] > 1:
                    prob_val = float(probabilities[idx].max())  # get max class probability
                else:
                    prob_val = float(probabilities[idx])
            else:
                prob_val = 0.0
                
            detail = {
                'index': int(idx),
                'prediction': int(predictions[idx]),
                'probability': prob_val,
                'threat_score': float(threat_results['per_record_scores'][idx]) if idx < len(threat_results['per_record_scores']) else 0.0,
            }
            prediction_details.append(detail)

        return {
            # Model performance
            'accuracy': metrics['accuracy'],
            'precision': metrics['precision'],
            'recall': metrics['recall'],
            'f1_score': metrics['f1_score'],
            'roc_auc': metrics['roc_auc'],

            # Detection results
            'total_records': total_records,
            'anomalies_detected': anomalies_detected,

            # Threat assessment
            'threat_score': threat_results['threat_score'],
            'severity': threat_results['severity'],
            'threat_components': threat_results['components'],

            # Explainability
            'feature_importance': shap_results['feature_importance'],
            'shap_summary': shap_results['shap_summary'],
            'top_features': shap_results['top_features'],

            # Detailed predictions
            'predictions': prediction_details,
            
            # ROC & Confusion Matrix
            'confusion_matrix': cm.tolist(),
            'roc_curve': {'fpr': fpr.tolist(), 'tpr': tpr.tolist()},
            'attack_distribution': attack_distribution
        }
