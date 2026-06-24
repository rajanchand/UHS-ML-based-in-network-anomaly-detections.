"""
Datasets Blueprint
==================
Manages dataset uploads, lists datasets, provides preview/details, and deletes datasets.
"""

from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from app.services.dataset_service import DatasetService
from app.services.audit_service import AuditService
from app.utils.decorators import role_required, audit_action

datasets_bp = Blueprint('datasets', __name__)


@datasets_bp.route('/datasets', methods=['GET'])
@login_required
def list_view():
    """Renders the dataset list page."""
    page = request.args.get('page', 1, type=int)
    pagination = DatasetService.get_user_datasets(current_user.id, page=page, per_page=10)
    return render_template('datasets/list.html', pagination=pagination)


@datasets_bp.route('/datasets/upload', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'analyst')
def upload():
    """Renders upload form and processes dataset uploads."""
    if request.method == 'POST':
        # Verify file presence in request
        if 'file' not in request.files:
            flash('No file part in the request', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)

        dataset, error = DatasetService.process_upload(file, current_user.id)

        if error:
            flash(error, 'danger')
            return render_template('datasets/upload.html')

        # Audit dataset upload
        AuditService.log_action(
            action='dataset_upload',
            resource=f'dataset:{dataset.id}',
            details=f'Uploaded: {dataset.original_filename} ({dataset.row_count} rows)',
            user_id=current_user.id
        )

        flash('Dataset uploaded and validated successfully!', 'success')
        return redirect(url_for('datasets.list_view'))

    return render_template('datasets/upload.html')


@datasets_bp.route('/datasets/<int:dataset_id>', methods=['GET'])
@login_required
def detail(dataset_id):
    """Renders details of a specific dataset along with a preview."""
    dataset = DatasetService.get_dataset(dataset_id, current_user.id)
    if not dataset:
        flash('Dataset not found or access denied.', 'danger')
        return redirect(url_for('datasets.list_view'))

    preview = DatasetService.get_dataset_preview(dataset_id, current_user.id)
    return render_template('datasets/detail.html', dataset=dataset, preview=preview)


@datasets_bp.route('/api/datasets', methods=['GET'])
@login_required
def get_datasets_api():
    """Paginated JSON endpoint to list datasets."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    pagination = DatasetService.get_user_datasets(
        current_user.id, page=page, per_page=per_page
    )
    
    return jsonify({
        'datasets': [d.to_dict() for d in pagination.items],
        'page': pagination.page,
        'pages': pagination.pages,
        'total': pagination.total,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev
    }), 200


@datasets_bp.route('/api/datasets/<int:dataset_id>/preview', methods=['GET'])
@login_required
def get_preview_api(dataset_id):
    """JSON API to preview dataset rows."""
    preview = DatasetService.get_dataset_preview(dataset_id, current_user.id)
    if not preview:
        return jsonify({'error': 'Dataset not found or preview unavailable'}), 404
    return jsonify(preview), 200


@datasets_bp.route('/datasets/<int:dataset_id>/delete', methods=['POST'])
@login_required
@role_required('admin', 'analyst')
def delete(dataset_id):
    """Deletes a dataset and redirects to list view."""
    success, error = DatasetService.delete_dataset(dataset_id, current_user.id)
    
    if not success:
        flash(error or 'Deletion failed', 'danger')
    else:
        AuditService.log_action(
            action='dataset_delete',
            resource=f'dataset:{dataset_id}',
            details='Dataset deleted',
            user_id=current_user.id
        )
        flash('Dataset deleted successfully.', 'success')
        
    return redirect(url_for('datasets.list_view'))


@datasets_bp.route('/api/datasets/<int:dataset_id>', methods=['DELETE'])
@login_required
@role_required('admin', 'analyst')
def delete_api(dataset_id):
    """JSON API endpoint to delete a dataset."""
    success, error = DatasetService.delete_dataset(dataset_id, current_user.id)
    if not success:
        return jsonify({'error': error or 'Failed to delete dataset'}), 400
        
    AuditService.log_action(
        action='dataset_delete',
        resource=f'dataset:{dataset_id}',
        details='Dataset deleted via API',
        user_id=current_user.id
    )
    return jsonify({'message': 'Dataset deleted successfully'}), 200


@datasets_bp.route('/datasets/<int:dataset_id>/traffic-analysis', methods=['GET'])
@login_required
def traffic_analysis(dataset_id):
    """Renders traffic analysis for a specific dataset."""
    analysis_data = DatasetService.get_traffic_analysis(dataset_id, current_user.id)
    if not analysis_data:
        flash('Dataset not found or traffic analysis unavailable.', 'danger')
        return redirect(url_for('datasets.list_view'))
    return render_template('datasets/traffic_analysis.html', data=analysis_data)
