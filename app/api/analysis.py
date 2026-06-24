"""
Analysis Blueprint
==================
Handles ML model configuration, job launching, result viewing, and dashboard metrics.
"""

from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from marshmallow import ValidationError

from app.services.analysis_service import AnalysisService
from app.services.dataset_service import DatasetService
from app.services.audit_service import AuditService
from app.utils.validators import AnalysisSchema
from app.utils.decorators import role_required

analysis_bp = Blueprint('analysis', __name__)
analysis_schema = AnalysisSchema()


@analysis_bp.route('/analysis', methods=['GET'])
@login_required
def list_view():
    """Renders the analysis history list."""
    page = request.args.get('page', 1, type=int)
    pagination = AnalysisService.get_user_analyses(current_user.id, page=page, per_page=10)
    return render_template('analysis/list.html', pagination=pagination)


@analysis_bp.route('/analysis/run', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'analyst')
def run():
    """Renders run setup view and initiates ML analysis runs."""
    if request.method == 'POST':
        # Accept JSON or form inputs
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()

        try:
            validated_data = analysis_schema.load(data)
        except ValidationError as err:
            if request.is_json:
                return jsonify({'error': 'Validation error', 'messages': err.messages}), 400
            for field, messages in err.messages.items():
                for msg in messages:
                    flash(f"{field.capitalize()}: {msg}", 'danger')
            return redirect(url_for('analysis.run'))

        # Run analysis
        analysis, error = AnalysisService.run_analysis(
            dataset_id=validated_data['dataset_id'],
            model_type=validated_data['model_type'],
            user_id=current_user.id,
            target_column=validated_data.get('target_column', 'label')
        )

        if error:
            if request.is_json:
                return jsonify({'error': 'Analysis run failed', 'message': error}), 400
            flash(error, 'danger')
            return redirect(url_for('analysis.run'))

        # Audit successful analysis initiation and completion
        AuditService.log_action(
            action='analysis_run',
            resource=f'analysis:{analysis.id}',
            details=f'Model: {analysis.model_type}, Dataset: {analysis.dataset_id}, Anomaly count: {analysis.anomalies_detected}',
            user_id=current_user.id
        )

        flash('Analysis completed successfully!', 'success')
        if request.is_json:
            return jsonify({'message': 'Analysis completed', 'analysis': analysis.to_dict()}), 200
        return redirect(url_for('analysis.results', analysis_id=analysis.id))

    # For GET requests, fetch datasets to choose from
    from app.ml.models import HAS_XGBOOST
    datasets_pagination = DatasetService.get_user_datasets(current_user.id, page=1, per_page=100)
    return render_template('analysis/run.html', datasets=datasets_pagination.items, has_xgboost=HAS_XGBOOST)


@analysis_bp.route('/analysis/<int:analysis_id>', methods=['GET'])
@login_required
def results(analysis_id):
    """Displays the detail metrics and interactive SHAP/threat scores for an analysis."""
    analysis = AnalysisService.get_analysis(analysis_id, current_user.id)
    if not analysis:
        flash('Analysis not found or access denied.', 'danger')
        return redirect(url_for('analysis.list_view'))

    return render_template('analysis/results.html', analysis=analysis)


@analysis_bp.route('/api/analysis/<int:analysis_id>', methods=['GET'])
@login_required
def get_analysis_api(analysis_id):
    """JSON API to fetch full results of a specific analysis run."""
    analysis = AnalysisService.get_analysis(analysis_id, current_user.id)
    if not analysis:
        return jsonify({'error': 'Analysis not found or access denied'}), 404
        
    return jsonify(analysis.to_dict()), 200


@analysis_bp.route('/analysis/<int:analysis_id>/shap', methods=['GET'])
@login_required
def shap_detail(analysis_id):
    """Renders a dedicated, highly detailed SHAP explanation page."""
    analysis = AnalysisService.get_analysis(analysis_id, current_user.id)
    if not analysis or analysis.status != 'completed':
        flash('Analysis not found, incomplete, or access denied.', 'danger')
        return redirect(url_for('analysis.list_view'))
    return render_template('analysis/shap_detail.html', analysis=analysis)


@analysis_bp.route('/model-comparison', methods=['GET'])
@login_required
def model_comparison():
    """Renders the Model Comparison Dashboard comparing RF vs XGBoost vs IF."""
    analyses = AnalysisService.get_user_analyses(current_user.id, page=1, per_page=100).items
    completed_analyses = [a for a in analyses if a.status == 'completed']
    return render_template('analysis/model_comparison.html', analyses=completed_analyses)


@analysis_bp.route('/research-comparison', methods=['GET'])
@login_required
def research_comparison():
    """Renders the Research Comparison Module against SOTA literature benchmarks."""
    analyses = AnalysisService.get_user_analyses(current_user.id, page=1, per_page=100).items
    latest = next((a for a in analyses if a.status == 'completed'), None)
    return render_template('analysis/research_comparison.html', latest=latest)
