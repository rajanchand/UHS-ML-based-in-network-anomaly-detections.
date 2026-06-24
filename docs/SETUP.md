# Local Development Setup Guide

Instructions for running Aegis locally for debugging or enhancements.

---

## 1. Clone & Configure Virtualenv
1. Prepare a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
2. Install Python packages:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

---

## 2. Local Database & Configs
1. Copy configurations:
   ```bash
   cp .env.example .env
   ```
2. Initialize SQLite or local Postgres DB:
   ```bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

---

## 3. Run the Development Server
Start the Flask built-in debugger:
```bash
flask run --port=5000
```
Navigate to `http://127.0.0.1:5000` in your web browser.

---

## 4. Execution of Test Suites
Run unit and integration suites using pytest:
```bash
# Run all tests
pytest -v

# Run with coverage report
pytest --cov=app tests/
```
