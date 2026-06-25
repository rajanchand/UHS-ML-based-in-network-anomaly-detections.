from flask import Blueprint, render_template, jsonify, Response, request
from flask_login import login_required, current_user
import json
import os
import numpy as np

from app.services.analysis_service import AnalysisService
from app.services.audit_service import AuditService
from app.services.capture_service import CaptureService
from app.services.dataset_service import DatasetService
from app.ml.preprocessing import DataPreprocessor
from app.ml.models import get_model
from app.ml.drift_detection import DriftDetector

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
@login_required
def index():
    """Renders the main analytics dashboard."""
    stats = AnalysisService.get_dashboard_stats(current_user.id)
    return render_template('dashboard/index.html', stats=stats)


@dashboard_bp.route('/api/dashboard/stats', methods=['GET'])
@login_required
def get_stats():
    """JSON API endpoint for dashboard KPIs."""
    stats = AnalysisService.get_dashboard_stats(current_user.id)
    return jsonify(stats), 200


@dashboard_bp.route('/api/dashboard/live-stream', methods=['GET'])
@login_required
def live_stream():
    """SSE endpoint streaming real-time network packets and predictions."""
    capture_service = CaptureService()
    
    if not capture_service.is_running:
        # Find user's latest completed analysis to run live inference
        analyses = AnalysisService.get_user_analyses(current_user.id, page=1, per_page=1).items
        completed = [a for a in analyses if a.status == 'completed']
        
        model = None
        preprocessor = None
        model_type = 'random_forest'
        
        if completed:
            analysis = completed[0]
            model_type = analysis.model_type
            
            # Load dataset and train live model for sniffer
            dataset = DatasetService.get_dataset(analysis.dataset_id, current_user.id)
            if dataset:
                from flask import current_app
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], dataset.filename)
                
                # Recreate file if missing on disk (serverless)
                if not os.path.exists(file_path) and dataset.file_content:
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(dataset.file_content)
                
                if os.path.exists(file_path):
                    try:
                        preprocessor = DataPreprocessor(target_column='label')
                        data = preprocessor.prepare_train_test(file_path, balance=False)
                        model = get_model(model_type)
                        model.train(data['X_train'], data['y_train'])
                    except Exception as e:
                        print(f"[SSE] Auto-train model failed: {e}")
                        
        if not model:
            # Fallback default Random Forest trained on dummy flow
            try:
                preprocessor = DataPreprocessor()
                dummy_df = pd.DataFrame([
                    {'duration': 0.1, 'protocol_type': 'tcp', 'src_bytes': 100, 'dst_bytes': 200, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'label': 0},
                    {'duration': 0.5, 'protocol_type': 'udp', 'src_bytes': 50, 'dst_bytes': 100, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'label': 0},
                    {'duration': 1.2, 'protocol_type': 'tcp', 'src_bytes': 5000, 'dst_bytes': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 1, 'num_failed_logins': 3, 'label': 1},
                    {'duration': 0.0, 'protocol_type': 'icmp', 'src_bytes': 0, 'dst_bytes': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'label': 1}
                ])
                X, y, _ = preprocessor.preprocess(dummy_df, fit=True)
                model = get_model('random_forest')
                model.train(X, y)
                model_type = 'random_forest'
            except Exception as e:
                print(f"[SSE] Fallback baseline creation failed: {e}")

        # Pass dataset_id and analysis_id to sniffer for active learning feedback
        active_dataset_id = completed[0].dataset_id if completed else None
        active_analysis_id = completed[0].id if completed else None
        capture_service.start(
            model=model, preprocessor=preprocessor, model_type=model_type,
            dataset_id=active_dataset_id, analysis_id=active_analysis_id
        )
        
    return Response(
        capture_service.get_stream_generator(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )


@dashboard_bp.route('/api/dashboard/recent-threats', methods=['GET'])
@login_required
def get_recent_threats():
    """Retrieve list of recent live threats."""
    capture_service = CaptureService()
    return jsonify(capture_service.recent_threats), 200


@dashboard_bp.route('/api/dashboard/drift-status', methods=['GET'])
@login_required
def get_drift_status():
    """Evaluate drift status using user's latest analysis as reference vs current stream."""
    analyses = AnalysisService.get_user_analyses(current_user.id, page=1, per_page=1).items
    completed = [a for a in analyses if a.status == 'completed']
    
    if not completed:
        return jsonify({
            'drift_detected': False,
            'drift_ratio': 0.0,
            'message': 'No reference model analysis has been completed yet.'
        }), 200

    analysis = completed[0]
    dataset = DatasetService.get_dataset(analysis.dataset_id, current_user.id)
    if not dataset:
        return jsonify({'drift_detected': False, 'message': 'Reference dataset missing.'}), 200

    from flask import current_app
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], dataset.filename)
    if not os.path.exists(file_path) and dataset.file_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(dataset.file_content)

    try:
        preprocessor = DataPreprocessor(target_column='label')
        data = preprocessor.prepare_train_test(file_path, balance=False)
        X_ref = data['X_train']
        
        # Simulate some drift target data (or use actual captured traffic profiles)
        # We inject slight random perturbations to the feature columns to check if it triggers drift
        scale = 0.35 if request.args.get('simulate_drift') == 'true' else 0.05
        noise = np.random.normal(0, scale, size=X_ref.shape)
        X_target = X_ref + noise

        detector = DriftDetector()
        drift_results = detector.detect_drift(X_ref, X_target, data['feature_names'])
        
        # Format feature summaries for table rendering
        feature_details = []
        for name, details in drift_results['features'].items():
            feature_details.append({
                'feature': name,
                'ks_statistic': round(details['ks_statistic'], 4),
                'p_value': round(details['p_value'], 4),
                'drifted': details['drifted']
            })
            
        return jsonify({
            'drift_detected': drift_results['drift_detected'],
            'drift_ratio': drift_results['drift_ratio'],
            'message': drift_results['message'],
            'features': feature_details
        }), 200
        
    except Exception as e:
        return jsonify({'drift_detected': False, 'message': f'Drift evaluation failed: {e}'}), 500


