# ML-Network Anomaly Detections

This is a production-ready, security-first Intrusion Detection System (IDS) that applies machine learning classifiers to raw network traffic metadata to identify threat signatures and malicious intrusions.

## Core Features
* **ML Engines**: Random Forest (Supervised Ensemble), XGBoost (Gradient Boosted Trees), and Isolation Forest (Unsupervised Anomaly).
* **Explainability**: SHAP integration to provide clear explanations of features driving threat flags.
* **Threat Scoring**: Dynamic composite scoring system (0-100) classifying threat severity (Low, Medium, High, Critical).
* **Security Controls**: Parameterized DB queries (SQLi safe), HTML sanitizers (XSS safe), CSRF tokens, strict security headers, and endpoint request limits.
* **Telemetry Auditing**: Immutable user activity and request trails.
* **Reporting**: Executive and full-scale PDF report downloads.
* **Deployment**: Docker Compose orchestration containing Gunicorn and Nginx reverse proxy.

---

## Directory Structure
```
machine replica/
├── app/
│   ├── __init__.py                 # Flask app factory
│   ├── config.py                   # Environment configurations
│   ├── extensions.py               # Extensions initialization
│   ├── api/                        # API route blueprints
│   ├── models/                     # SQLAlchemy DB models
│   ├── ml/                         # ML pipeline & SHAP math
│   ├── services/                   # Business logics
│   ├── templates/                  # Responsive Bootstrap layouts
│   └── static/                     # Custom stylesheet & assets
├── docker/
│   ├── Dockerfile                  # Flask app container
│   ├── Dockerfile.nginx            # Nginx proxy container
│   └── nginx.conf                  # Nginx proxy routing
├── docs/                           # Comprehensive guides
├── tests/                          # Automated test suites
├── docker-compose.yml              # Production compose file
├── requirements.txt                # Python dependencies
└── wsgi.py                         # Gunicorn entry point
```

---

## Quickstart (Production via Docker)
1. Clone the repository and configure environments:
   ```bash
   cp .env.example .env
   # Update credentials in .env
   ```
2. Build and launch the stack:
   ```bash
   docker-compose up --build -d
   ```
3. Open your browser and navigate to `http://localhost`.

For a local development configuration, refer to the [Setup Guide](docs/SETUP.md).
