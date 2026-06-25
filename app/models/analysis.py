"""
Analysis Model
==============
Stores ML analysis results including model metrics, anomaly counts,
threat scores, and SHAP explainability summaries.
"""

from datetime import datetime, timezone

from app.extensions import db


class Analysis(db.Model):
    """
    Records the results of an ML analysis run on a dataset.
    Each analysis uses one model type and produces metrics + threat scores.
    """

    __tablename__ = 'analyses'

    # --- Columns ---
    id = db.Column(db.Integer, primary_key=True)
    dataset_id = db.Column(
        db.Integer, db.ForeignKey('datasets.id'), nullable=False, index=True,
        comment='Dataset that was analysed'
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=False, index=True,
        comment='User who initiated the analysis'
    )
    model_type = db.Column(
        db.String(50), nullable=False,
        comment='ML model used: random_forest, xgboost, isolation_forest'
    )

    # --- Model Performance Metrics ---
    accuracy = db.Column(db.Float, default=0.0, comment='Overall accuracy')
    precision_score = db.Column(db.Float, default=0.0, comment='Precision metric')
    recall = db.Column(db.Float, default=0.0, comment='Recall / sensitivity')
    f1_score = db.Column(db.Float, default=0.0, comment='F1 harmonic mean')
    roc_auc = db.Column(db.Float, default=0.0, comment='ROC AUC score')

    # --- Detection Results ---
    total_records = db.Column(db.Integer, default=0, comment='Total records analysed')
    anomalies_detected = db.Column(db.Integer, default=0, comment='Number of anomalies found')
    threat_score = db.Column(
        db.Float, default=0.0,
        comment='Composite threat score (0-100)'
    )

    # --- Explainability ---
    shap_summary = db.Column(
        db.Text, default='',
        comment='JSON-encoded SHAP feature importance data'
    )
    feature_importance = db.Column(
        db.Text, default='',
        comment='JSON-encoded feature importance rankings'
    )

    # --- Predictions Data ---
    predictions_data = db.Column(
        db.Text, default='',
        comment='JSON-encoded predictions with threat scores per record'
    )

    # --- Status & Timing ---
    status = db.Column(
        db.String(20), nullable=False, default='pending',
        comment='Status: pending, running, completed, failed'
    )
    error_message = db.Column(
        db.Text, default='',
        comment='Error details if analysis failed'
    )
    started_at = db.Column(db.DateTime, comment='When analysis started')
    completed_at = db.Column(db.DateTime, comment='When analysis finished')
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # --- Relationships ---
    reports = db.relationship(
        'Report', backref='analysis', lazy='dynamic',
        cascade='all, delete-orphan'
    )

    # --- Valid model types ---
    VALID_MODELS = ('random_forest', 'xgboost', 'isolation_forest', 'lstm', 'autoencoder')
    VALID_STATUSES = ('pending', 'running', 'completed', 'failed')

    @property
    def anomaly_rate(self):
        """Calculate the percentage of records flagged as anomalous."""
        if self.total_records == 0:
            return 0.0
        return round((self.anomalies_detected / self.total_records) * 100, 2)

    @property
    def duration_seconds(self):
        """Calculate analysis duration in seconds."""
        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            return round(delta.total_seconds(), 2)
        return None

    def to_dict(self):
        """Serialize analysis results for API responses."""
        return {
            'id': self.id,
            'dataset_id': self.dataset_id,
            'model_type': self.model_type,
            'metrics': {
                'accuracy': self.accuracy,
                'precision': self.precision_score,
                'recall': self.recall,
                'f1_score': self.f1_score,
                'roc_auc': self.roc_auc,
            },
            'total_records': self.total_records,
            'anomalies_detected': self.anomalies_detected,
            'anomaly_rate': self.anomaly_rate,
            'threat_score': self.threat_score,
            'status': self.status,
            'duration_seconds': self.duration_seconds,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f'<Analysis #{self.id} {self.model_type} ({self.status})>'


class ThreatFeedback(db.Model):
    """
    Stores analyst feedback for active learning.
    Allows labeling individual records in a dataset as false positives or confirmed threats.
    """
    __tablename__ = 'threat_feedback'

    id = db.Column(db.Integer, primary_key=True)
    dataset_id = db.Column(db.Integer, db.ForeignKey('datasets.id'), nullable=False, index=True)
    row_index = db.Column(db.Integer, nullable=False)
    # 0 = normal (false positive), >0 represents verified attack classes (e.g. 1=DDoS, etc.)
    label = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    dataset = db.relationship('Dataset', backref=db.backref('feedbacks', lazy='dynamic', cascade='all, delete-orphan'))
    user = db.relationship('User', backref=db.backref('feedbacks', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'dataset_id': self.dataset_id,
            'row_index': self.row_index,
            'label': self.label,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat()
        }

