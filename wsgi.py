"""
WSGI Entry Point
================
Production entry point for Gunicorn. Creates the Flask application
using the app factory pattern.

Usage:
    gunicorn wsgi:app -w 4 -b 0.0.0.0:5000
"""

from app import create_app

# Create the Flask application instance using the factory
app = create_app()
