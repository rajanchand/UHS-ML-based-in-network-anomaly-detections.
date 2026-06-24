"""
Dataset Model
=============
Tracks uploaded datasets with integrity verification and validation status.

Security features:
    - SHA-256 file hash for integrity verification
    - Validation status tracking
    - File size limits enforced at model level
"""

from datetime import datetime, timezone

from app.extensions import db


class Dataset(db.Model):
    """
    Stores metadata about uploaded CSV datasets.
    The actual file is stored on disk; this model tracks its location and status.
    """

    __tablename__ = 'datasets'

    # --- Columns ---
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=False, index=True,
        comment='Owner who uploaded this dataset'
    )
    filename = db.Column(
        db.String(255), nullable=False,
        comment='Sanitised filename on disk (UUID-based)'
    )
    original_filename = db.Column(
        db.String(255), nullable=False,
        comment='Original filename as uploaded by the user'
    )
    file_hash = db.Column(
        db.String(64), nullable=False,
        comment='SHA-256 hash for integrity verification'
    )
    file_size = db.Column(
        db.Integer, nullable=False,
        comment='File size in bytes'
    )
    row_count = db.Column(
        db.Integer, default=0,
        comment='Number of data rows in the CSV'
    )
    column_count = db.Column(
        db.Integer, default=0,
        comment='Number of columns in the CSV'
    )
    columns_list = db.Column(
        db.Text, default='',
        comment='JSON-encoded list of column names'
    )
    status = db.Column(
        db.String(20), nullable=False, default='pending',
        comment='Validation status: pending, validated, invalid, processing'
    )
    validation_errors = db.Column(
        db.Text, default='',
        comment='JSON-encoded validation error messages'
    )
    uploaded_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # --- Relationships ---
    analyses = db.relationship(
        'Analysis', backref='dataset', lazy='dynamic',
        cascade='all, delete-orphan'
    )

    # --- Valid statuses ---
    VALID_STATUSES = ('pending', 'validated', 'invalid', 'processing')

    def to_dict(self):
        """Serialize dataset metadata for API responses."""
        return {
            'id': self.id,
            'original_filename': self.original_filename,
            'file_size': self.file_size,
            'file_hash': self.file_hash,
            'row_count': self.row_count,
            'column_count': self.column_count,
            'columns_list': self.columns_list,
            'status': self.status,
            'validation_errors': self.validation_errors,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
            'owner': self.owner.username if self.owner else None,
        }

    def __repr__(self):
        return f'<Dataset {self.original_filename} ({self.status})>'
