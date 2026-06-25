"""
Analysis Service
================
Orchestrates ML analysis runs by coordinating the ML pipeline,
persisting results, and managing analysis lifecycle.
"""

import json
from datetime import datetime, timezone

from flask import current_app

from app.extensions import db
from app.models.analysis import Analysis
from app.models.dataset import Dataset
from app.services.dataset_service import DatasetService


class AnalysisService:
    """Business logic for ML analysis execution and management."""

    @staticmethod
    def run_analysis(dataset_id, model_type, user_id, target_column='label'):
        """
        Execute an ML analysis on a dataset.

        Args:
            dataset_id: ID of the dataset to analyse.
            model_type: ML model to use (random_forest, xgboost, isolation_forest).
            user_id: ID of the user running the analysis.
            target_column: Name of the target/label column.

        Returns:
            Tuple of (analysis: Analysis or None, error: str or None).
        """
        # Validate model type
        if model_type not in Analysis.VALID_MODELS:
            return (None, f'Invalid model type. Choose from: {", ".join(Analysis.VALID_MODELS)}')

        # Verify dataset exists and belongs to user
        dataset = DatasetService.get_dataset(dataset_id, user_id)
        if not dataset:
            return (None, 'Dataset not found or access denied')

        if dataset.status != 'validated':
            return (None, 'Dataset has not been validated yet')

        # Create analysis record
        analysis = Analysis(
            dataset_id=dataset_id,
            user_id=user_id,
            model_type=model_type,
            status='running',
            started_at=datetime.now(timezone.utc),
        )
        db.session.add(analysis)
        db.session.commit()

        try:
            # Import ML pipeline (deferred to avoid circular imports)
            from app.ml.pipeline import MLPipeline

            # Get the dataset file path
            import os
            file_path = os.path.join(
                current_app.config['UPLOAD_FOLDER'], dataset.filename
            )

            # Recreate file from database if missing on disk (Vercel serverless)
            if not os.path.exists(file_path) and dataset.file_content:
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(dataset.file_content)

            # Execute the ML pipeline
            pipeline = MLPipeline(file_path, model_type, target_column)
            results = pipeline.execute()

            # Update analysis with results
            analysis.accuracy = results.get('accuracy', 0.0)
            analysis.precision_score = results.get('precision', 0.0)
            analysis.recall = results.get('recall', 0.0)
            analysis.f1_score = results.get('f1_score', 0.0)
            analysis.roc_auc = results.get('roc_auc', 0.0)
            analysis.total_records = results.get('total_records', 0)
            analysis.anomalies_detected = results.get('anomalies_detected', 0)
            analysis.threat_score = results.get('threat_score', 0.0)
            analysis.shap_summary = json.dumps(results.get('shap_summary', {}))
            analysis.feature_importance = json.dumps(results.get('feature_importance', {}))
            analysis.predictions_data = json.dumps({
                'predictions': results.get('predictions', []),
                'confusion_matrix': results.get('confusion_matrix', []),
                'roc_curve': results.get('roc_curve', {}),
                'attack_distribution': results.get('attack_distribution', {})
            })
            analysis.status = 'completed'
            analysis.completed_at = datetime.now(timezone.utc)

            db.session.commit()

            current_app.logger.info(
                f'Analysis #{analysis.id} completed: '
                f'{model_type} on dataset {dataset_id}, '
                f'threat_score={analysis.threat_score:.1f}'
            )
            return (analysis, None)

        except Exception as e:
            analysis.status = 'failed'
            analysis.error_message = str(e)[:500]
            analysis.completed_at = datetime.now(timezone.utc)
            db.session.commit()

            current_app.logger.error(f'Analysis #{analysis.id} failed: {str(e)}')
            return (None, f'Analysis failed: {str(e)}')

    @staticmethod
    def get_analysis(analysis_id, user_id=None):
        """Retrieve an analysis by ID, optionally scoped to a user."""
        query = Analysis.query.filter_by(id=analysis_id)
        if user_id:
            query = query.filter_by(user_id=user_id)
        return query.first()

    @staticmethod
    def get_user_analyses(user_id, page=1, per_page=20):
        """Get paginated analyses for a user."""
        return Analysis.query.filter_by(user_id=user_id) \
            .order_by(Analysis.created_at.desc()) \
            .paginate(page=page, per_page=per_page, error_out=False)

    @staticmethod
    def get_dashboard_stats(user_id):
        """
        Compute aggregate statistics for the dashboard.

        Returns:
            Dict with total counts, averages, and recent trends.
        """
        total_datasets = Dataset.query.filter_by(user_id=user_id).count()
        total_analyses = Analysis.query.filter_by(user_id=user_id).count()

        completed = Analysis.query.filter_by(user_id=user_id, status='completed')
        total_anomalies = sum(a.anomalies_detected for a in completed.all())

        # Average threat score
        scores = [a.threat_score for a in completed.all() if a.threat_score > 0]
        avg_threat_score = round(sum(scores) / len(scores), 1) if scores else 0.0

        # Recent analyses for trend data
        recent = Analysis.query.filter_by(user_id=user_id, status='completed') \
            .order_by(Analysis.completed_at.desc()) \
            .limit(10).all()

        trend_data = [{
            'date': a.completed_at.strftime('%Y-%m-%d') if a.completed_at else '',
            'threat_score': a.threat_score,
            'anomalies': a.anomalies_detected,
        } for a in reversed(recent)]

        return {
            'total_datasets': total_datasets,
            'total_analyses': total_analyses,
            'total_anomalies': total_anomalies,
            'avg_threat_score': avg_threat_score,
            'trend_data': trend_data,
        }

    @staticmethod
    def retrain_analysis(analysis_id, user_id):
        """
        Retrain a model using original dataset plus user active learning feedback overrides.
        """
        from app.models.analysis import ThreatFeedback
        import pandas as pd
        import os

        analysis = AnalysisService.get_analysis(analysis_id, user_id)
        if not analysis:
            return None, "Analysis run not found or access denied."

        dataset = DatasetService.get_dataset(analysis.dataset_id, user_id)
        if not dataset:
            return None, "Dataset not found."

        # Fetch all feedback overrides for this dataset
        feedbacks = ThreatFeedback.query.filter_by(dataset_id=dataset.id).all()
        if not feedbacks:
            return None, "No active learning feedback has been registered for this dataset yet."

        # Locate original dataset path
        from flask import current_app
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], dataset.filename)
        if not os.path.exists(file_path) and dataset.file_content:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(dataset.file_content)

        if not os.path.exists(file_path):
            return None, "Original dataset CSV file is missing."

        try:
            # Load original dataset and apply label updates
            df = pd.read_csv(file_path)
            
            # Resolve label column name
            from app.ml.preprocessing import DataPreprocessor
            preprocessor = DataPreprocessor(target_column='label')
            target_col = preprocessor._resolve_target_column(df)
            if not target_col:
                target_col = 'label'
                df[target_col] = 0  # Create label column if missing

            # Apply user feedbacks
            feedback_count = 0
            for fb in feedbacks:
                if 0 <= fb.row_index < len(df):
                    # If feedback label is normal (0), set to 0. Otherwise set to corresponding attack int.
                    df.loc[fb.row_index, target_col] = fb.label
                    feedback_count += 1

            # Write to a temporary file for retraining pipeline consumption
            retrain_filename = f"{dataset.filename}.retrain"
            retrain_path = os.path.join(current_app.config['UPLOAD_FOLDER'], retrain_filename)
            df.to_csv(retrain_path, index=False)

            # Execute pipeline on the adjusted dataset
            from app.ml.pipeline import MLPipeline
            pipeline = MLPipeline(retrain_path, analysis.model_type, target_col)
            results = pipeline.execute()

            # Clean up temp file
            if os.path.exists(retrain_path):
                os.remove(retrain_path)

            # Update analysis record with new metrics and threat scores
            analysis.accuracy = results.get('accuracy', 0.0)
            analysis.precision_score = results.get('precision', 0.0)
            analysis.recall = results.get('recall', 0.0)
            analysis.f1_score = results.get('f1_score', 0.0)
            analysis.roc_auc = results.get('roc_auc', 0.0)
            analysis.total_records = results.get('total_records', 0)
            analysis.anomalies_detected = results.get('anomalies_detected', 0)
            analysis.threat_score = results.get('threat_score', 0.0)
            analysis.shap_summary = json.dumps(results.get('shap_summary', {}))
            analysis.feature_importance = json.dumps(results.get('feature_importance', {}))
            analysis.predictions_data = json.dumps({
                'predictions': results.get('predictions', []),
                'confusion_matrix': results.get('confusion_matrix', []),
                'roc_curve': results.get('roc_curve', {}),
                'attack_distribution': results.get('attack_distribution', {})
            })
            analysis.completed_at = datetime.now(timezone.utc)
            db.session.commit()

            return analysis, f"Retrained successfully using {feedback_count} feedback overrides."

        except Exception as e:
            db.session.rollback()
            return None, f"Retraining failed: {str(e)}"
