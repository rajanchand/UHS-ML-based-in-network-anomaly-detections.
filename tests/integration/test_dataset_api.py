"""
Integration Tests - Datasets Pipeline
====================================
Verifies uploading, listing, details viewing, and access controls for datasets.
"""

import io
from flask_login import login_user

from app.models.dataset import Dataset


def test_dataset_upload_unauthorized(client):
    """Verify unauthenticated requests cannot access upload endpoints."""
    res = client.get('/datasets/upload')
    assert res.status_code == 302  # redirects to login


def test_dataset_upload_success(client, app, seed_users, db_session):
    """Verify an authenticated analyst can upload and validate a dataset successfully."""
    # Authenticate analyst
    with client.session_transaction() as sess:
        sess['_user_id'] = str(seed_users['analyst'].id)
        sess['_fresh'] = True

    # Generate mock CSV data file
    csv_content = "duration,protocol_type,src_bytes,dst_bytes,label\n0.1,tcp,120,400,0\n0.2,udp,45,0,1\n"
    data = {
        'file': (io.BytesIO(csv_content.encode('utf-8')), 'test_dataset.csv')
    }

    # Upload CSV file
    res = client.post('/datasets/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 200
    assert b'Dataset uploaded and validated successfully' in res.data
    
    # Verify DB entry
    dataset = Dataset.query.filter_by(original_filename='test_dataset.csv').first()
    assert dataset is not None
    assert dataset.row_count == 2
    assert dataset.column_count == 5
    assert dataset.status == 'validated'
