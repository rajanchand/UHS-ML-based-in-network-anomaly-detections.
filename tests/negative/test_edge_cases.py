"""
Negative Edge Cases Tests
=========================
Verifies error boundaries on missing items, empty payloads, and malformed database IDs.
"""

import io


def test_empty_csv_upload_handling(client, seed_users):
    """Verify system blocks and safely alerts on empty files uploads."""
    with client.session_transaction() as sess:
        sess['_user_id'] = str(seed_users['analyst'].id)
        sess['_fresh'] = True

    data = {
        'file': (io.BytesIO(b''), 'empty.csv')
    }
    
    res = client.post('/datasets/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 200
    assert b'validation failed: File is empty' in res.data or b'empty' in res.data


def test_run_analysis_on_missing_dataset(client, seed_users):
    """Verify triggering analysis jobs with invalid dataset IDs triggers a 404/400 alert."""
    with client.session_transaction() as sess:
        sess['_user_id'] = str(seed_users['analyst'].id)
        sess['_fresh'] = True

    payload = {
        'dataset_id': 9999, # non-existent ID
        'model_type': 'random_forest'
    }
    
    res = client.post('/analysis/run', data=payload, follow_redirects=True)
    assert res.status_code == 200 # redirected with danger alert
    assert b'Dataset not found' in res.data or b'error' in res.data
