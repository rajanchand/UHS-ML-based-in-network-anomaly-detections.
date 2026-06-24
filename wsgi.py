"""
WSGI Entry Point
================
Production entry point for Gunicorn. Creates the Flask application
using the app factory pattern.

Usage:
    gunicorn wsgi:app -w 4 -b 0.0.0.0:5000
"""

from app import create_app
from app.extensions import db

# Create the Flask application instance using the factory
app = create_app()

with app.app_context():
    if db.engine.url.drivername == 'sqlite':
        db.create_all()
