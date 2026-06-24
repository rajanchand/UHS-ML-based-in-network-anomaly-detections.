# REST API Reference Guide

Aegis implements standard REST architectures using JSON payload structures.

---

## Authentication Endpoints

### 1. User Registration
* **Endpoint**: `POST /register`
* **Content-Type**: `application/json`
* **Payload**:
  ```json
  {
    "username": "sec_analyst",
    "email": "analyst@aegis.com",
    "password": "SecureP@ssword1!",
    "confirm_password": "SecureP@ssword1!"
  }
  ```
* **Success Response (201 Created)**:
  ```json
  {
    "message": "Registration successful",
    "user": {
      "id": 1,
      "username": "sec_analyst",
      "email": "analyst@aegis.com",
      "role": "analyst"
    }
  }
  ```

### 2. Login
* **Endpoint**: `POST /login`
* **Content-Type**: `application/json`
* **Payload**:
  ```json
  {
    "username": "sec_analyst",
    "password": "SecureP@ssword1!"
  }
  ```
* **Success Response (200 OK)**:
  ```json
  {
    "message": "Login successful",
    "user": {
      "id": 1,
      "username": "sec_analyst",
      "email": "analyst@aegis.com",
      "role": "analyst"
    }
  }
  ```

---

## Datasets Endpoints

### 1. Upload Dataset
* **Endpoint**: `POST /datasets/upload`
* **Content-Type**: `multipart/form-data`
* **Payload**: `file` (CSV file data)
* **Success Response (200 OK)**:
  ```json
  {
    "message": "Dataset uploaded and validated successfully",
    "dataset_id": 4
  }
  ```

### 2. Dataset Preview
* **Endpoint**: `GET /api/datasets/<id>/preview`
* **Authentication**: Required (Analyst or Admin)
* **Success Response (200 OK)**:
  ```json
  {
    "headers": ["duration", "protocol_type", "src_bytes", "label"],
    "rows": [
      [0.1, "tcp", 120, 0],
      [0.5, "udp", 45, 1]
    ],
    "total_rows": 2
  }
  ```

---

## ML Analysis Endpoints

### 1. Launch Analysis Job
* **Endpoint**: `POST /analysis/run`
* **Content-Type**: `application/json`
* **Payload**:
  ```json
  {
    "dataset_id": 4,
    "model_type": "random_forest",
    "target_column": "label"
  }
  ```
* **Success Response (200 OK)**:
  ```json
  {
    "message": "Analysis completed",
    "analysis": {
      "id": 1,
      "dataset_id": 4,
      "model_type": "random_forest",
      "total_records": 100,
      "anomalies_detected": 12,
      "threat_score": 38.5,
      "status": "completed"
    }
  }
  ```
