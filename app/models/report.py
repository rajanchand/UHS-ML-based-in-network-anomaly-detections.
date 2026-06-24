"""
Report Model
============
Tracks generated PDF reports linked to specific analyses.
"""

from datetime import datetime, timezone

from app.extensions import db


class Report(db.Model):
    """
    Stores metadata about generated PDF reports.
    The actual PDF file is stored on disk in the reports directory.
    """

    __tablename__ = 'reports'

    # --- Columns ---
    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(
        db.Integer, db.ForeignKey('analyses.id'), nullable=False, index=True,
        comment='Analysis this report was generated from'
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=False, index=True,
        comment='User who generated this report'
    )
    filename = db.Column(
        db.String(255), nullable=False,
        comment='PDF filename on disk'
    )
    report_type = db.Column(
        db.String(50), nullable=False, default='full',
        comment='Report type: full, summary, executive'
    )
    generated_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def to_dict(self):
        """Serialize report metadata for API responses."""
        return {
            'id': self.id,
            'analysis_id': self.analysis_id,
            'filename': self.filename,
            'report_type': self.report_type,
            'generated_at': self.generated_at.isoformat() if self.generated_at else None,
        }

    def __repr__(self):
        return f'<Report #{self.id} ({self.report_type})>'
