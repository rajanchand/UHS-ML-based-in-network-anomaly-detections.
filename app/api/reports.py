"""
Reports Blueprint
=================
Generates PDF reports, lists generated reports, and handles downloads securely.
"""

import os
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, send_file
from flask_login import login_required, current_user

from app.services.report_service import ReportService
from app.services.audit_service import AuditService

reports_bp = Blueprint('reports', __name__)


@reports_bp.route('/reports', methods=['GET'])
@login_required
def list_view():
    """Renders the reports list page."""
    page = request.args.get('page', 1, type=int)
    pagination = ReportService.get_user_reports(current_user.id, page=page, per_page=10)
    return render_template('reports/list.html', pagination=pagination)


@reports_bp.route('/reports/generate', methods=['POST'])
@login_required
def generate():
    """Triggers report generation for a completed analysis."""
    # Handle both JSON and Form inputs
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()

    analysis_id = data.get('analysis_id')
    report_type = data.get('report_type', 'full')

    if not analysis_id:
        if request.is_json:
            return jsonify({'error': 'Missing analysis_id'}), 400
        flash('Missing analysis ID', 'danger')
        return redirect(url_for('reports.list_view'))

    try:
        analysis_id = int(analysis_id)
    except ValueError:
        if request.is_json:
            return jsonify({'error': 'Invalid analysis_id'}), 400
        flash('Invalid analysis ID', 'danger')
        return redirect(url_for('reports.list_view'))

    report, error = ReportService.generate_report(
        analysis_id=analysis_id,
        user_id=current_user.id,
        report_type=report_type
    )

    if error:
        if request.is_json:
            return jsonify({'error': error}), 400
        flash(error, 'danger')
        return redirect(url_for('reports.list_view'))

    AuditService.log_action(
        action='report_generate',
        resource=f'report:{report.id}',
        details=f'Generated {report_type} report for analysis {analysis_id}',
        user_id=current_user.id
    )

    flash('Report generated successfully!', 'success')
    if request.is_json:
        return jsonify({'message': 'Report generated', 'report': report.to_dict()}), 201
    return redirect(url_for('reports.list_view'))


@reports_bp.route('/reports/<int:report_id>/download', methods=['GET'])
@login_required
def download(report_id):
    """Downloads a specific report PDF file securely."""
    report = ReportService.get_report(report_id, current_user.id)
    if not report:
        flash('Report not found or access denied.', 'danger')
        return redirect(url_for('reports.list_view'))

    path = ReportService.get_report_path(report)
    if not os.path.exists(path):
        flash('PDF report file does not exist on server.', 'danger')
        return redirect(url_for('reports.list_view'))

    # Log PDF download action
    AuditService.log_action(
        action='report_download',
        resource=f'report:{report.id}',
        details=f'Downloaded: {report.filename}',
        user_id=current_user.id
    )

    return send_file(
        path,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=report.filename
    )
