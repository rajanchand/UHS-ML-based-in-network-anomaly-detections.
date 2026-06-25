"""
Admin Blueprint
===============
Admin-only routes for system management and security audit logs.
"""

from flask import Blueprint, render_template, request
from flask_login import login_required

from app.services.audit_service import AuditService
from app.utils.decorators import role_required

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/admin/security-logs')
@login_required
@role_required('admin')
def security_logs():
    """Show all security audit log entries."""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    logs = AuditService.get_recent_logs(limit=500)

    # Simple manual pagination
    total = len(logs)
    start = (page - 1) * per_page
    end = start + per_page
    page_logs = logs[start:end]
    total_pages = (total + per_page - 1) // per_page

    return render_template(
        'admin/security_logs.html',
        logs=page_logs,
        page=page,
        total_pages=total_pages,
        total=total
    )
