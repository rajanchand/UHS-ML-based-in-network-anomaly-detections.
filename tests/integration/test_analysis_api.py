"""
Integration Tests - ML Analysis Pipeline
=========================================
Runs end-to-end orchestration tests checking dataset-to-ML processing flows.
"""

import io
from app.models.dataset import Dataset
from app.models.analysis import Analysis


def test_analysis_run_integration(client, app, seed_users, db_session):
    """Verify full loop: login, upload dataset, execute ML model, verify metrics output."""
    # 1. Authenticate analyst
    with client.session_transaction() as sess:
        sess['_user_id'] = str(seed_users['analyst'].id)
        sess['_fresh'] = True

    # 2. Upload dataset
    # We write multiple rows (at least 10 rows required by DataPreprocessor)
    csv_content = (
        "duration,protocol_type,src_bytes,dst_bytes,label\n"
        "0.1,tcp,120,400,0\n"
        "0.2,udp,45,0,1\n"
        "0.1,tcp,120,400,0\n"
        "0.2,udp,45,0,1\n"
        "0.1,tcp,120,400,0\n"
        "0.2,udp,45,0,1\n"
        "0.1,tcp,120,400,0\n"
        "0.2,udp,45,0,1\n"
        "0.1,tcp,120,400,0\n"
        "0.2,udp,45,0,1\n"
    )
    
    data = {
        'file': (io.BytesIO(csv_content.encode('utf-8')), 'traffic_large.csv')
    }
    
    res_upload = client.post('/datasets/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert res_upload.status_code == 200

    dataset = Dataset.query.filter_by(original_filename='traffic_large.csv').first()
    assert dataset is not None

    # 3. Trigger ML analysis run via API
    analysis_payload = {
        'dataset_id': dataset.id,
        'model_type': 'random_forest',
        'target_column': 'label'
    }
    
    res_analysis = client.post('/analysis/run', data=analysis_payload, follow_redirects=True)
    assert res_analysis.status_code == 200
    
    # 4. Verify DB Analysis results
    analysis = Analysis.query.filter_by(dataset_id=dataset.id).first()
    assert analysis is not None
    assert analysis.status == 'completed'
    assert analysis.total_records == 10
    assert analysis.accuracy >= 0.0
    assert analysis.threat_score >= 0.0
