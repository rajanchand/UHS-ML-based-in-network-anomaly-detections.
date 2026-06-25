"""
Dashboard Blueprint
===================
Serves the user dashboard and exposes API endpoints for telemetry and stats.
"""

from flask import Blueprint, render_template, jsonify, redirect, url_for
from flask_login import login_required, current_user

from app.services.analysis_service import AnalysisService
from app.services.audit_service import AuditService

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

