"""
Report Service
==============
Generates professional PDF reports from analysis results using ReportLab.

Features:
    - Executive summary with key metrics
    - Model performance metrics table
    - SHAP feature importance visualization
    - Threat score breakdown
    - Recommendations based on findings
    - Professional formatting with headers/footers
"""

import json
import os
import uuid
from datetime import datetime, timezone

from flask import current_app
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)

from app.extensions import db
from app.models.report import Report
from app.models.analysis import Analysis


class ReportService:
    """Business logic for PDF report generation."""

    @staticmethod
    def generate_report(analysis_id, user_id, report_type='full'):
        """
        Generate a PDF report from an analysis.

        Args:
            analysis_id: ID of the completed analysis.
            user_id: ID of the requesting user.
            report_type: Type of report (full, summary, executive).

        Returns:
            Tuple of (report: Report or None, error: str or None).
        """
        analysis = Analysis.query.filter_by(
            id=analysis_id, user_id=user_id, status='completed'
        ).first()

        if not analysis:
            return (None, 'Completed analysis not found')

        # Generate unique filename
        filename = f'report_{analysis_id}_{uuid.uuid4().hex[:8]}.pdf'
        reports_dir = current_app.config['REPORTS_DIR']
        os.makedirs(reports_dir, exist_ok=True)
        file_path = os.path.join(reports_dir, filename)

        try:
            # Build the PDF document
            ReportService._build_pdf(file_path, analysis, report_type)

            # Create report record
            report = Report(
                analysis_id=analysis_id,
                user_id=user_id,
                filename=filename,
                report_type=report_type,
            )
            db.session.add(report)
            db.session.commit()

            current_app.logger.info(f'Report generated: {filename}')
            return (report, None)

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f'Report generation failed: {str(e)}')
            return (None, f'Report generation failed: {str(e)}')

    @staticmethod
    def _build_pdf(file_path, analysis, report_type):
        """
        Build the PDF document with ReportLab.

        Args:
            file_path: Output PDF file path.
            analysis: Analysis model instance.
            report_type: Type of report to generate.
        """
        doc = SimpleDocTemplate(
            file_path,
            pagesize=A4,
            rightMargin=20 * mm,
            leftMargin=20 * mm,
            topMargin=25 * mm,
            bottomMargin=25 * mm,
        )

        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=22,
            spaceAfter=20,
            textColor=colors.HexColor('#1a1a2e'),
        )
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceBefore=15,
            spaceAfter=10,
            textColor=colors.HexColor('#16213e'),
        )
        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=8,
            leading=14,
        )

        elements = []

        # --- Title ---
        elements.append(Paragraph(
            'Network Anomaly Detection Report',
            title_style
        ))
        elements.append(Paragraph(
            f'Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}',
            body_style
        ))
        elements.append(HRFlowable(
            width='100%', thickness=2,
            color=colors.HexColor('#0f3460')
        ))
        elements.append(Spacer(1, 15))

        # --- Executive Summary ---
        elements.append(Paragraph('Executive Summary', heading_style))

        severity = 'Critical' if analysis.threat_score >= 75 else \
                   'High' if analysis.threat_score >= 50 else \
                   'Medium' if analysis.threat_score >= 25 else 'Low'

        elements.append(Paragraph(
            f'Analysis of <b>{analysis.total_records:,}</b> network traffic records '
            f'using <b>{analysis.model_type.replace("_", " ").title()}</b> model identified '
            f'<b>{analysis.anomalies_detected:,}</b> anomalies '
            f'({analysis.anomaly_rate}% anomaly rate). '
            f'The composite threat score is <b>{analysis.threat_score:.1f}/100</b> '
            f'(Severity: <b>{severity}</b>).',
            body_style
        ))
        elements.append(Spacer(1, 10))

        # --- Model Performance Metrics ---
        elements.append(Paragraph('Model Performance Metrics', heading_style))

        metrics_data = [
            ['Metric', 'Value', 'Rating'],
            ['Accuracy', f'{analysis.accuracy:.4f}',
             'Good' if analysis.accuracy >= 0.9 else 'Fair'],
            ['Precision', f'{analysis.precision_score:.4f}',
             'Good' if analysis.precision_score >= 0.9 else 'Fair'],
            ['Recall', f'{analysis.recall:.4f}',
             'Good' if analysis.recall >= 0.9 else 'Fair'],
            ['F1 Score', f'{analysis.f1_score:.4f}',
             'Good' if analysis.f1_score >= 0.9 else 'Fair'],
            ['ROC AUC', f'{analysis.roc_auc:.4f}',
             'Good' if analysis.roc_auc >= 0.9 else 'Fair'],
        ]

        metrics_table = Table(metrics_data, colWidths=[2.5 * inch, 2 * inch, 1.5 * inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f3460')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
        ]))
        elements.append(metrics_table)
        elements.append(Spacer(1, 15))

        # --- Threat Assessment ---
        elements.append(Paragraph('Threat Assessment', heading_style))

        threat_data = [
            ['Parameter', 'Value'],
            ['Threat Score', f'{analysis.threat_score:.1f} / 100'],
            ['Severity Level', severity],
            ['Total Records Analysed', f'{analysis.total_records:,}'],
            ['Anomalies Detected', f'{analysis.anomalies_detected:,}'],
            ['Anomaly Rate', f'{analysis.anomaly_rate}%'],
            ['Model Used', analysis.model_type.replace('_', ' ').title()],
        ]

        if analysis.duration_seconds:
            threat_data.append(['Analysis Duration', f'{analysis.duration_seconds}s'])

        threat_table = Table(threat_data, colWidths=[3 * inch, 3 * inch])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e94560')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fff5f5')]),
        ]))
        elements.append(threat_table)
        elements.append(Spacer(1, 15))

        # --- Feature Importance (from SHAP) ---
        if analysis.feature_importance:
            elements.append(Paragraph('Feature Importance (SHAP Analysis)', heading_style))
            try:
                importance = json.loads(analysis.feature_importance)
                if isinstance(importance, dict):
                    fi_data = [['Feature', 'Importance Score']]
                    # Sort by importance and take top 10
                    sorted_features = sorted(
                        importance.items(), key=lambda x: abs(x[1]), reverse=True
                    )[:10]
                    for feature, score in sorted_features:
                        fi_data.append([str(feature), f'{score:.4f}'])

                    fi_table = Table(fi_data, colWidths=[3.5 * inch, 2.5 * inch])
                    fi_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#533483')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                        ('TOPPADDING', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                         [colors.white, colors.HexColor('#f8f5ff')]),
                    ]))
                    elements.append(fi_table)
                    elements.append(Spacer(1, 15))
            except (json.JSONDecodeError, TypeError):
                pass

        # --- Recommendations ---
        elements.append(Paragraph('Recommendations', heading_style))

        if analysis.threat_score >= 75:
            recs = [
                'CRITICAL: Immediate investigation required for detected anomalies.',
                'Isolate affected network segments pending investigation.',
                'Enable enhanced monitoring on flagged IP addresses and ports.',
                'Review firewall rules and IDS/IPS signatures.',
                'Conduct incident response procedures as per your security policy.',
            ]
        elif analysis.threat_score >= 50:
            recs = [
                'HIGH: Elevated threat level detected. Prioritise review.',
                'Investigate top anomalies flagged by the model.',
                'Update network monitoring rules based on identified patterns.',
                'Consider additional data collection for affected segments.',
            ]
        elif analysis.threat_score >= 25:
            recs = [
                'MEDIUM: Some anomalous activity detected.',
                'Review flagged records during regular security reviews.',
                'Monitor trends over time for escalation patterns.',
            ]
        else:
            recs = [
                'LOW: Normal network activity observed.',
                'Continue routine monitoring and periodic analysis.',
                'Consider running analysis on newer data for continued assurance.',
            ]

        for rec in recs:
            elements.append(Paragraph(f'• {rec}', body_style))

        elements.append(Spacer(1, 20))

        # --- Footer ---
        elements.append(HRFlowable(
            width='100%', thickness=1,
            color=colors.HexColor('#cccccc')
        ))
        elements.append(Paragraph(
            '<i>This report was generated by the ML Network Anomaly Detection System. '
            'Results are based on the ML model\'s predictions and should be reviewed '
            'by qualified security analysts before taking action.</i>',
            ParagraphStyle('Disclaimer', parent=body_style, fontSize=8,
                           textColor=colors.grey)
        ))

        # Build the PDF
        doc.build(elements)

    @staticmethod
    def get_report(report_id, user_id):
        """Retrieve a report by ID, scoped to user."""
        return Report.query.filter_by(id=report_id, user_id=user_id).first()

    @staticmethod
    def get_user_reports(user_id, page=1, per_page=20):
        """Get paginated reports for a user."""
        return Report.query.filter_by(user_id=user_id) \
            .order_by(Report.generated_at.desc()) \
            .paginate(page=page, per_page=per_page, error_out=False)

    @staticmethod
    def get_report_path(report):
        """Get the full filesystem path to a report PDF."""
        return os.path.join(current_app.config['REPORTS_DIR'], report.filename)
